# A proxy interface to initiate and interact with candlepin.
#
# Copyright (c) 2010 - 2012 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# Red Hat trademarks are not licensed under GPLv2. No permission is
# granted to use or replicate Red Hat trademarks that are incorporated
# in this software or its documentation.
#

import certificate
import datetime
import dateutil.parser
import locale
import logging
import os
import socket
import ssl
import sys
import urllib

import requests
import requests.exceptions
import requests.adapters
import requests.auth
from requests.packages.urllib3.poolmanager import PoolManager


from urllib import urlencode

from config import initConfig

import version
python_rhsm_version = version.rpm_version

try:
    import subscription_manager.version
    subman_version = subscription_manager.version.rpm_version
except ImportError:
    subman_version = "unknown"

from rhsm import ourjson as json
from rhsm.utils import get_env_proxy_info

global_socket_timeout = 60
timeout_altered = None


def set_default_socket_timeout_if_python_2_3():
    """If using python 2.3 set a global socket default timeout.

    On EL5/python2.3, there is a really long socket timeout. The
    best thing we can do is set a process wide default socket timeout.
    Limit this to affected python versions only, just to minimize any
    problems the default timeout might cause.

    Return True if we change it.
    """

    global timeout_altered

    # once per module instance should be plenty
    if timeout_altered:
        return timeout_altered

    if sys.version_info[0] == 2 and sys.version_info[1] < 4:
        socket.setdefaulttimeout(global_socket_timeout)
        timeout_altered = True
        return

    timeout_altered = False


class NullHandler(logging.Handler):
    def emit(self, record):
        pass


def safe_int(value, safe_value=None):
    try:
        return int(value)
    except Exception:
        return safe_value


h = NullHandler()
logging.getLogger("rhsm").addHandler(h)

log = logging.getLogger(__name__)

config = initConfig()


def drift_check(utc_time_string, hours=1):
    """
    Takes in a RFC 1123 date and returns True if the currnet time
    is greater then the supplied number of hours
    """
    drift = False
    if utc_time_string:
        try:
            # This may have a timezone (utc)
            utc_datetime = dateutil.parser.parse(utc_time_string)
            # This should not have a timezone, but we know it will be utc.
            # We need our timezones to match in order to compare
            local_datetime = datetime.datetime.utcnow().replace(tzinfo=utc_datetime.tzinfo)
            delta = datetime.timedelta(hours=hours)
            drift = abs((utc_datetime - local_datetime)) > delta
        except Exception, e:
            log.error(e)

    return drift


class ConnectionException(Exception):
    pass


class ConnectionSetupException(ConnectionException):
    pass


class RhsmSSLError(ssl.SSLError):
    def __init__(self, args=None):
        self.args = args
        self.message = "FIXME"

    def __str__(self):
        return "<RhsmSSLError %s %s>" % (self.args, self.message)


class BadCertificateException(ConnectionException):
    """ Thrown when an error parsing a certificate is encountered. """

    def __init__(self, cert_path):
        """ Pass the full path to the bad certificate. """
        self.cert_path = cert_path

    def __str__(self):
        return "Bad certificate at %s" % self.cert_path


class RestlibException(ConnectionException):
    """
    Raised when a response with a valid json body is received along with a status code
    that is not in [200, 202, 204, 410, 429]
    See RestLib.validateResponse to see when this and other exceptions are raised.
    """

    def __init__(self, code, msg=None):
        self.code = code
        self.msg = msg or ""

    def __str__(self):
        return self.msg


class GoneException(RestlibException):
    """
    GoneException is used to detect when a consumer has been deleted on the candlepin side.

    A client handling a GoneException should verify that GoneException.deleted_id
    matches the consumer uuid before taking any action (like deleting the consumer
    cert from disk).

    This is to prevent an errant 410 response from candlepin (or a reverse_proxy in
    front of it, or it's app server, or an injected response) from causing
    accidental consumer cert deletion.
    """
    def __init__(self, code, msg, deleted_id):
        # Exception doesn't inherit from object on el5 python version
        RestlibException.__init__(self, code, msg)
        self.deleted_id = deleted_id


class NetworkException(ConnectionException):
    """
    Thrown when the response of a request has no valid json content
    and the http status code is anything other than the following:
    [200, 202, 204, 401, 403, 410, 429, 500, 502, 503, 504]
    """

    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "Network error code: %s" % self.code


class RemoteServerException(ConnectionException):
    """
    Thrown when the response to a request has no valid json content and
    one of these http status codes: [404, 410, 500, 502, 503, 504]
    """
    def __init__(self, code,
                 request_type=None,
                 handler=None):
        self.code = code
        self.request_type = request_type
        self.handler = handler

    def __str__(self):
        if self.request_type and self.handler:
            return "Server error attempting a %s to %s returned status %s" % (self.request_type,
                                                                              self.handler,
                                                                              self.code)
        return "Server returned %s" % self.code


class AuthenticationException(RemoteServerException):
    prefix = "Authentication error"

    def __str__(self):
        buf = super(AuthenticationException, self).__str__()
        buf += "\n"
        buf += "%s: Invalid credentials for request." % self.prefix
        return buf


class RateLimitExceededException(RestlibException):
    """
    Thrown in response to a http code 429.
    This means that too many requests have been made in a given time period.
    The retry_after attribute is an int of seconds to retry the request after.
    The retry_after attribute may not be included in the response.
    """
    def __init__(self, code,
                 msg=None,
                 headers=None):
        super(RateLimitExceededException, self).__init__(code,
                                                         msg)
        self.headers = headers or {}
        self.msg = msg or ""
        self.retry_after = safe_int(self.headers.get('Retry-After'))


class UnauthorizedException(AuthenticationException):
    """
    Thrown in response to http status code 401 with no valid json content
    """
    prefix = "Unauthorized"


class ForbiddenException(AuthenticationException):
    """
    Thrown in response to http status code 403 with no valid json content
    """
    prefix = "Forbidden"


class ExpiredIdentityCertException(ConnectionException):
    pass


class ContentHTTPError(requests.exceptions.HTTPError):
    """Http errors when making requests to content cdn"""
    pass


def _get_locale():
    l = None
    try:
        l = locale.getlocale()
    except locale.Error:
        pass

    try:
        l = locale.getdefaultlocale()
    except locale.Error:
        pass
    except ValueError:
        pass

    if l and l != (None, None):
        return l[0]

    return None


class JsonDecoder(object):
    @classmethod
    def decode_list(cls, data):
        rv = []
        for item in data:
            if isinstance(item, unicode):
                item = item.encode('utf-8')
            elif isinstance(item, list):
                item = cls.decode_list(item)
            elif isinstance(item, dict):
                item = cls.decode_dict(item)
            rv.append(item)
        return rv

    @classmethod
    def decode_dict(cls, data):
        rv = {}
        for key, value in data.iteritems():
            if isinstance(key, unicode):
                key = key.encode('utf-8')
            if isinstance(value, unicode):
                value = value.encode('utf-8')
            elif isinstance(value, list):
                value = cls.decode_list(value)
            elif isinstance(value, dict):
                value = cls.decode_dict(value)
            rv[key] = value
        return rv


class RhsmResponseValidator(object):
    def __init__(self):
        self.json_decoder = JsonDecoder.decode_dict

    def try_to_parse(self, response):
        # got some status code that might be an error
        # try vaguely to see if it had a json parseable body
        try:
            return json.loads(response.text,
                              object_hook=self.json_decoder)
        except ValueError, e:
            log.info("Response: %s" % response.status_code)
            log.info("JSON parsing error: %s" % e)
        except Exception, e:
            log.error("Response: %s" % response.status_code)
            log.exception(e)

        return None

    def validate(self, response):
        status_code = response.status_code
        if status_code in [200, 202, 204]:
            return

        parsed_response = None

        if response.text:
            parsed_response = self.try_to_parse(response)

        # A better replacement would be to use the
        # request.Request.raise_for_status() and
        # map
        if not parsed_response:
            self.raise_exception_based_on_just_status_code(response)
            return

        # see if we have been deleted and hit a 410
        self.check_for_gone(status_code, parsed_response)

        # I guess this is where we would have an exception mapper if we
        # had more meaningful exceptions. We've gotten a response from
        # the server that means something.

        # FIXME: we can get here with a valid json response that
        # could be anything, we don't verify it anymore
        error_msg = self._parse_msg_from_error_response_body(parsed_response)
        raise RestlibException(status_code, error_msg)

    def check_for_gone(self, status_code, parsed_response):
        # find and raise a GoneException on '410' with 'deleteId' in the
        # content, implying that the resource has been deleted
        # NOTE: a 410 with a unparseable content will raise
        # RemoteServerException
        if status_code != 410:
            return

        if 'deletedId' in parsed_response:
            raise GoneException(status_code,
                                parsed_response['displayMessage'],
                                parsed_response['deletedId'])

    def raise_exception_based_on_just_status_code(self, response):
        # This really needs an exception mapper too...
        status_code = response.status_code
        request_type = response.request.method
        handler = response.request.path_url

        if status_code in [404, 410, 500, 502, 503, 504]:
            raise RemoteServerException(status_code,
                                        request_type=request_type,
                                        handler=handler)
        elif status_code in [401]:
            raise UnauthorizedException(status_code,
                                        request_type=request_type,
                                        handler=handler)
        elif status_code in [403]:
            raise ForbiddenException(status_code,
                                     request_type=request_type,
                                     handler=handler)
#        elif status code in [429]:
#            raise RateLimitExceededException(status_code)

        else:
            # unexpected with no valid content
            raise NetworkException(status_code)

    def _parse_msg_from_error_response_body(self, body):

        # Old style with a single displayMessage:
        if 'displayMessage' in body:
            return body['displayMessage']

        # New style list of error messages:
        if 'errors' in body:
            return " ".join("%s" % errmsg for errmsg in body['errors'])


class ProxyInfo(object):
    def __init__(self, hostname, port, username=None, password=None):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.auth_slug = None
        self.url = None
        self.scheme_map = {}
        self.scheme = "http://"

        if self.username:
            self.auth_slug = "%s" % self.username
        if self.password:
            self.auth_slug += ":%s" % self.password
        if self.auth_slug:
            self.auth_slug += '@'

        if self.hostname and self.port:
            self.url = "%s%s%s:%s/" % (self.scheme,
                                       self.auth_slug or '',
                                       self.hostname,
                                       self.port)
        log.debug("proxy_info.url=%s", self.url)
        self.scheme_map = {'https': self.url,
                           'http': self.url}


class ClientCertInfo(object):
    def __init__(self, cert_file=None, key_file=None):
        self.cert_file = cert_file
        self.key_file = key_file

        self.cert_pair = (self.cert_file,
                          self.key_file)

    def validate_cert(self):
        id_cert = certificate.create_from_file(self.cert_file)
        if not id_cert.is_valid():
            raise ExpiredIdentityCertException()


class ServerCertInfo(object):
    def __init__(self, ca_bundle, ca_dir=None, verify=True, verify_depth=None):
        self.ca_bundle = ca_bundle  # ?
        self.ca_dir = ca_dir
        self.verify = verify
        # 3?
        self.verify_depth = verify_depth or 3


class RequestsSessionFactory(object):
    @classmethod
    def https_no_auth(cls, auth=None,
                      server_cert_info=None,
                      client_cert_info=None,
                      proxy_info=None):
        pass

    def __init__(self, auth=None, server_cert_info=None,
                client_cert_info=None, proxy_info=None):

        session = self.create_session()
        session = self.setup_proxy(session, proxy_info)
        session = self.setup_server_cert_verify(session, server_cert_info)
        session = self.setup_client_cert_auth(session, client_cert_info)
        session = self.setup_auth(session, auth)
        # Use an HttpAdaptor and overrides it's cert_verify
        #  ... then we could map specific url subpaths to different auth setups
        #      ie, /consumers is consumer cert while and /status are Plain https
        self.session = session
        log.debug("session %s", session)

    def create_session(self):
        return requests.Session()

    def setup_proxy(self, session, proxy_info):
        if not proxy_info:
            return session
        if not proxy_info.url:
            return session

        session.proxy = proxy_info.scheme_map
        log.debug("session.proxy=%s", session.proxy)
        return session

    def setup_auth(self, session, auth):
        session.auth = auth
        log.debug("session.auth = %s", session.auth)
        log.debug("auth = %s", auth)
        return session

    def setup_client_cert_auth(self, session, client_cert_info):
        if not client_cert_info:
            return session

        session.cert = client_cert_info.cert_pair
        log.debug("session.cert=%s", session.cert)
        return session

    def setup_server_cert_verify(self, session, server_cert_info):
        if not server_cert_info:
            return session

        # verify by default in base
        if not server_cert_info.verify:
            session.verify = False
        else:
            session.verify = server_cert_info.ca_bundle

        # verify depth
        log.debug("session=%s verify=%s", session, session.verify)
        return session


class RhsmHTTPAdapter(requests.adapters.HTTPAdapter):
    pass


class MyAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_SSLv23)


# FIXME: it would be nice if the ssl server connection stuff
# was decomposed from the api handling parts
class Restlib(object):
    """
     A wrapper around httplib to make rest calls easier
     See validateResponse() to learn when exceptions are raised as a result
     of communication with the server.
    """
    def __init__(self, host, ssl_port, apihandler,
                 session=None):
        self.host = host
        self.ssl_port = ssl_port
        self.apihandler = apihandler

        self.session = session

        lc = _get_locale()

        self.headers = {"Content-type": "application/json",
                        "Accept": "application/json",
                        "x-python-rhsm-version": python_rhsm_version,
                        "x-subscription-manager-version": subman_version}

        if lc:
            self.headers["Accept-Language"] = lc.lower().replace('_', '-')

        #self.host = "grimlock.usersys.redhat.com"
        #self.ssl_port = 443
        #self.apihandler = "/candlepin"
        self.base_url = "https://%s:%s%s" % (self.host, self.ssl_port, self.apihandler)
        log.debug("bu1 %s", self.base_url)
        #self.host = "grimlock.usersys.redhat.com"
        #self.ssl_port = 8443
        #self.apihandler = "/candlepin"
        self.base_url = "https://%s:%s%s" % (self.host, self.ssl_port, self.apihandler)
        log.debug("bu %s", self.base_url)

        # We could set connect and read timeouts
        # we could setup response hooks for caching

        #self.session = requests.Session()
        #self.session.mount('https://', MyAdapter())
        #self.session.auth = self.auth
        #self.session.verify = self.server_cert_info.ca_bundle
        log.debug("self.base_url=%s", self.base_url)
        log.debug("self.session %s", self.session)
    # restlib should be api info, requestsSession connection info
    # give restlib a host/port and a requestsSession, and UepConnection can
    # assemble those

    def json_dumps(self, info=None):
        data = None
        if info is not None:
            data = json.dumps(info, default=json.encode)
        return data

    def json_loads(self, response_body):
        # handle empty, but succesful responses, ala 204
        if not len(response_body):
            return None

        return json.loads(response_body, object_hook=JsonDecoder.decode_dict)

    # can and will raise exceptions
    def check_response(self, response):
        self.log_response(response)
        self.drift_check(response)
        self.validate_response(response)

    # FIXME: should be able to move this to just per session
    def drift_check(self, response):
        # Look for server drift, and log a warning
        if drift_check(response.headers.get('date')):
            log.warn("Clock skew detected, please check your system time")

    def log_response(self, response):
        log.debug("request headers %s", response.request.headers)
        log.debug("Response: status=%s requestUuid=%s",
                  response.status_code, response.headers.get('x-candepin-request-uuid') or '')

    def validate_response(self, response):
        validator = RhsmResponseValidator()
        validator.validate(response)

    # FIXME: do we need to provide compat for validateResponse?

    def full_url(self, url_fragment):
        # url join? candlepin is picky about extra /'s
        return "%s%s" % (self.base_url, url_fragment)

    def _request_wrapper(self, verb, full_url, data=None):
        """Try to catch the case where we get TLS errors because of an expired cert."""
        try:
            log.debug("self.session=%s", self.session)
            log.debug("full_url=%s verb=%s", full_url, verb)
            log.debug("self.session.request=%s %s", self.session.request, dir(self.session.request))
            request = self.session.request(verb, full_url, data=data)
            log.debug("wrapper ession=%s dir=%s", request, dir(request))
            return request
        # FIXME: for reasons unknown, ssl.SSLError.message is not a string and
        #        and causes str() to fail and that causes chaos
        except ssl.SSLError, e:
            raise RhsmSSLError(args=e.args)
        # FIXME: use underlying SSL errors
        except Exception, e:
            #log.exception(e)
            if self.client_cert_info:
                self.client_cert_info.validate_cert()
            raise ConnectionException()

    # return request.Request objects
    def _requests_request(self, verb, method, data=None):
        full_url = self.full_url(method)
        log.debug("requests_request %s", full_url)
        return self._request_wrapper(verb, full_url, data=data)

    # return text
    def get(self, method):
        log.debug("get method %s session.auth=%s", method, self.session.auth)
        #r = self._requests_request(verb='GET', method=method)
        r = self.session.get(self.full_url(method))
        self.check_response(r)
        return r.text

    # return objects
    def request_get(self, method):
        log.debug("request_get=%s", method)
        response_body = self.get(method)
        return self.json_loads(response_body)

    # returns the body of the content or raises exceptions
    def post(self, method, data=None):
        r = self._requests_request(verb='POST', method=method, data=data)
        self.check_response(r)
        return r.text

    # takes in python objects and returns python objects
    def request_post(self, method, params=None):
        # params is dict to be serialized to json
        data = self.json_dumps(params)
        response_body = self.post(method, data=data)
        return self.json_loads(response_body)

    # returns the body of the content or raises exceptions
    def put(self, method, data=None):
        r = self._requests_request(verb='PUT', method=method, data=data)
        self.check_response(r)
        return r.text

    # takes in python objects and returns python objects
    def request_put(self, method, params=None):
        # params is dict to be serialized to json
        data = self.json_dumps(params)
        response_body = self.put(method, data=data)
        return self.json_loads(response_body)

    # return text
    def head(self, method):
        r = self._requests_request(verb='HEAD', method=method)
        self.check_response(r)
        return r.text

    def request_head(self, method):
        response_body = self.get(method)
        return self.json_loads(response_body)

    def delete(self, method, data=None):
        r = self._requests_request(verb='DELETE', method=method, data=data)
        self.check_response(r)
        return r.text

    def request_delete(self, method, params=None):
        data = self.json_dumps(params)
        response_body = self.delete(method, data=data)
        return self.json_loads(response_body)


class EntitlementCertRestlib(Restlib):
    ent_dir = "/etc/pki/entitlement"

    def __init__(self, host, *args, **kwargs):
        # cdn is always 443 and / handler
        # get the proxy information from the environment variable
        # if available
        #info = get_env_proxy_info()
        super(EntitlementCertRestlib, self).__init__(host, 443, '/', args, kwargs)

        # TODO: plug in env proxy info

    def _setup_server_cert_verify(self):
        log.error("FIXME REMOVE ME FIXME REMOVE ME")
        self.requests_session.verify = False

    def get_versions(self, path):
        try:
            return self.get(path)
        except requests.exceptions.HTTPError, e:
            log.debug(e)
            log.debug("Error getting listing from %s", e.response.request.url)
        return ''

    def validate_response(self, response):
        response.raise_for_status()

ContentConnection = EntitlementCertRestlib


class RhsmAuth(requests.auth.AuthBase):
    def __init__(self):
        self.log = logging.getLogger("%s.%s" % (__name__, type(self).__name__))

#    def __call__(self, r):
#        self.log.debug("base_auth %s", r)
#        return r


class RhsmBasicAuth(requests.auth.HTTPBasicAuth):
    def __init__(self, username, password):
        super(RhsmBasicAuth, self).__init__(username, password)
        self.log = logging.getLogger(type(self).__name__)
        self.log.debug("rhsmBasicAuth %s", username)

    def __call__(self, r):
        super(RhsmBasicAuth, self).__call__(r)
        r.headers["some-rhsm-header"] = "caneatcheese(1)=true"
        self.log.debug("rhsmBasicAuth.call")
        return r

#RhsmBasicAuth = requests.auth.HTTPBasicAuth


class RhsmClientCertAuth(RhsmAuth):
    has_client_cert = True

    def __init__(self, cert_file, key_file):
        super(RhsmClientCertAuth, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file

    def __call__(self, r):
        super(RhsmClientCertAuth, self).__call__(r)
        r.cert = (self.cert_file, self.key_file)
        self.log.debug("client cert auth %s %s", self.cert_file, self.key_file)
        return r


class RhsmEntitlementCertAuth(RhsmAuth):
    ent_dir = "/etc/pki/entitlement"

    def __call__(self, r):
        super(RhsmEntitlementCertAuth, self).__call__(r)
        return r

    def _setup_ent_certs(self):
        try:
            cert_key_paths = self._find_cert_key_paths()

            cert_key_path = self._pick_one(cert_key_paths)

            self.cert_file = cert_key_path[0]
            self.key_path = cert_key_path[1]
        except OSError, e:
            raise ConnectionSetupException(e.strerror)

    def _find_cert_key_paths(self):
        cert_dir_files = os.listdir(self.ent_dir)
        cert_files = [x for x in cert_dir_files if self._cert_mach(x)]

        return [self._cert_key_paths(y) for y in cert_files]

    def _cert_key_paths(self, cert_file):
        cert_path = os.path.join(self.ent_dir, cert_file)
        key_path = os.path.join(self.ent_dir, "%s-key.pem" % cert_file.split('.', 1)[0])
        return (cert_path, key_path)

    # we have many potential ent certs. Pick one.
    # For now, the first one. But it should learn to pick the right
    # one for the url.
    # FIXME
    def _pick_one(self, cert_key_paths):
        return cert_key_paths[0]

    def _cert_match(self, cert_file):
        return cert_file.endswith(".pem") and not cert_file.endswith("-key.pem")


class RhsmPlainHttpsAuth(RhsmAuth):
    verify = True

    def __call__(self, r):
        super(RhsmPlainHttpsAuth, self).__call__(r)
        # default to verify
        # verify is a 3 value boolean, True, False, or a ca_bundle path
        r.verify = self.verify
        return r


# FIXME: there should probably be a class here for just
# the connection bits, then a sub class for the api
# stuff
class UEPConnection:
    """
    Class for communicating with the REST interface of a Red Hat Unified
    Entitlement Platform.
    """

    def __init__(self,
            host=None,
            ssl_port=None,
            handler=None,
            proxy_hostname=None,
            proxy_port=None,
            proxy_user=None,
            proxy_password=None,
            username=None, password=None,
            cert_file=None, key_file=None,
            insecure=None):
        """
        Two ways to authenticate:
            - username/password for HTTP basic authentication. (owner admin role)
            - uuid/key_file/cert_file for identity cert authentication.
              (consumer role)

        Must specify one method of authentication or the other, not both.
        """
        self.host = host or config.get('server', 'hostname')
        self.ssl_port = ssl_port or safe_int(config.get('server', 'port'))
        self.handler = handler or config.get('server', 'prefix')

        log.debug("HANDLER %s", self.handler)
        # remove trailing "/" from the prefix if it is there
        # BZ848836
        self.handler = self.handler.rstrip("/")

        # get the proxy information from the environment variable
        # if available
        info = get_env_proxy_info()

        self.proxy_hostname = proxy_hostname or config.get('server', 'proxy_hostname') or info['proxy_hostname']
        self.proxy_port = proxy_port or config.get('server', 'proxy_port') or info['proxy_port']
        self.proxy_user = proxy_user or config.get('server', 'proxy_user') or info['proxy_username']
        self.proxy_password = proxy_password or config.get('server', 'proxy_password') or info['proxy_password']
        self.proxy_info = ProxyInfo(self.proxy_hostname, self.proxy_port,
                                    self.proxy_user, self.proxy_password)

        self.cert_file = cert_file
        self.key_file = key_file
        self.client_cert_info = ClientCertInfo(self.cert_file, self.key_file)

        self.username = username
        self.password = password
        # AuthInfo ?

        self.capabilities = None
        self.ca_cert_dir = config.get('rhsm', 'ca_cert_dir')
        self.ssl_verify_depth = safe_int(config.get('server', 'ssl_verify_depth'))

        self.insecure = insecure
        if insecure is None:
            self.insecure = False
            config_insecure = safe_int(config.get('server', 'insecure'))
            if config_insecure:
                self.insecure = True

        # for logging, for now, FIXME
        self.verify = not self.insecure

        self.ca_bundle = os.path.join(self.ca_cert_dir, 'ca_bundle.pem')
        self.server_cert_info = ServerCertInfo(self.ca_bundle,
                                               self.verify,
                                               self.ssl_verify_depth)

        log.debug("self.ca_bundle=%s", self.ca_bundle)
        using_basic_auth = False
        using_id_cert_auth = False

        if username and password:
            using_basic_auth = True
        elif cert_file and key_file:
            using_id_cert_auth = True

        if using_basic_auth and using_id_cert_auth:
            raise Exception("Cannot specify both username/password and "
                    "cert_file/key_file")
        #if not (using_basic_auth or using_id_cert_auth):
        #    raise Exception("Must specify either username/password or "
        #            "cert_file/key_file")

        proxy_description = None
        if self.proxy_hostname and self.proxy_port:
            proxy_description = "http_proxy=%s:%s " % (self.proxy_hostname, self.proxy_port)
        auth_description = None

        log.debug("using_basic_auth=%s using_id_cert_auth=%s", using_basic_auth, using_id_cert_auth)

        # FIXME: replace with url url->auth mapper thing?
        # initialize connection
        self.auth = self._setup_auth()

        self.session_factory = RequestsSessionFactory(auth=self.auth,
                                                      server_cert_info=self.server_cert_info,
                                                      client_cert_info=self.client_cert_info,
                                                      proxy_info=self.proxy_info)

        self.session = self.session_factory.session

        self.conn = Restlib(self.host, self.ssl_port, self.handler,
                            session=self.session)

        self.resources = None

        connection_description = ""
        if proxy_description:
            connection_description += proxy_description
        connection_description += "host=%s port=%s handler=%s %s" % (self.host, self.ssl_port,
                                                                    self.handler, auth_description)
        log.info("Connection built: %s", connection_description)

    def _setup_auth(self):
        using_basic_auth = False
        using_id_cert_auth = False

        auth = None
        if self.username and self.password:
            using_basic_auth = True
            auth = RhsmBasicAuth(self.username, self.password)
        elif self.cert_file and self.key_file:
            auth = RhsmClientCertAuth(self.cert_file, self.key_file)
            using_id_cert_auth = True

        if using_basic_auth and using_id_cert_auth:
            raise Exception("Cannot specify both username/password and "
                    "cert_file/key_file")

        # initialize connection
        return auth

    def _load_supported_resources(self):
        """
        Load the list of supported resources by doing a GET on the root
        of the web application we're configured to use.

        Need to handle exceptions here because sometimes UEPConnections are
        created in a state where they can't actually be used. (they get
        replaced later) If something goes wrong making this request, just
        leave the list of supported resources empty.
        """
        self.resources = {}
        resources_list = self.conn.request_get("/")
        for r in resources_list:
            self.resources[r['rel']] = r['href']
        log.debug("Server supports the following resources: %s",
                  self.resources)

    def supports_resource(self, resource_name):
        """
        Check if the server we're connecting too supports a particular
        resource. For our use cases this is generally the plural form
        of the resource.
        """
        if self.resources is None:
            self._load_supported_resources()

        return resource_name in self.resources

    def _load_manager_capabilities(self):
        """
        Loads manager capabilities by doing a GET on the status
        resource located at '/status'
        """
        status = self.getStatus()
        capabilities = status.get('managerCapabilities')
        if capabilities is None:
            log.debug("The status retrieved did not \
                      include key 'managerCapabilities'.\nStatus:'%s'" % status)
            capabilities = []
        elif isinstance(capabilities, list) and not capabilities:
            log.debug("The managerCapabilities list \
                      was empty\nStatus:'%s'" % status)
        else:
            log.debug("Server has the following capabilities: %s", capabilities)
        return capabilities

    def has_capability(self, capability):
        """
        Check if the server we're connected to has a particular capability.
        """
        if self.capabilities is None:
            self.capabilities = self._load_manager_capabilities()
        return capability in self.capabilities

    def shutDown(self):
        self.conn.close()
        log.info("remote connection closed")

    def ping(self, username=None, password=None):
        return self.conn.request_get("/status/")

    def registerConsumer(self, name="unknown", type="system", facts={},
            owner=None, environment=None, keys=None,
            installed_products=None, uuid=None, hypervisor_id=None,
            content_tags=None):
        """
        Creates a consumer on candlepin server
        """
        params = {"type": type,
                  "name": name,
                  "facts": facts}
        if installed_products:
            params['installedProducts'] = installed_products

        if uuid:
            params['uuid'] = uuid

        if hypervisor_id is not None:
            params['hypervisorId'] = {'hypervisorId': hypervisor_id}

        if content_tags is not None:
            params['contentTags'] = content_tags

        url = "/consumers"
        if environment:
            url = "/environments/%s/consumers" % self.sanitize(environment)
        elif owner:
            query_param = urlencode({"owner": owner})
            url = "%s?%s" % (url, query_param)
            prepend = ""
            if keys:
                url = url + "&activation_keys="
                for key in keys:
                    url = url + prepend + self.sanitize(key)
                    prepend = ","

        return self.conn.request_post(url, params)

    def hypervisorCheckIn(self, owner, env, host_guest_mapping, options=None):
        """
        Sends a mapping of hostIds to list of guestIds to candlepin
        to be registered/updated.
        This method can raise the following exceptions:
            - RestLibException with http code 400: this means no mapping
            (or a bad one) was provided.
            - RestLibException with other http codes: Please see the
            definition of RestLibException above for info about this.
            - RateLimitExceededException: This means that too many requests
            have been made in the given time period.

        """
        if (self.has_capability("hypervisors_async")):
            pass
            # FIXME:
            #           priorContentType = self.conn.headers['Content-type']
            #           self.conn.headers['Content-type'] = 'text/plain'
            #           query_params = urlencode({"env": env, "cloaked": False})
            #           url = "/hypervisors/%s?%s" % (owner, query_params)
            #           res = self.conn.request_post(url, host_guest_mapping)
            #           self.conn.headers['Content-type'] = priorContentType
            raise Exception("adrian hasn't fixed this yet")
        else:
            # fall back to original report api
            # this results in the same json as in the result_data field
            # of the new api method
            query_params = urlencode({"owner": owner, "env": env})
            url = "/hypervisors?%s" % (query_params)
            res = self.conn.request_post(url, host_guest_mapping)
            return res

    def updateConsumerFacts(self, consumer_uuid, facts={}):
        """
        Update a consumers facts on candlepin server
        """
        return self.updateConsumer(consumer_uuid, facts=facts)

    def updateConsumer(self, uuid, facts=None, installed_products=None,
            guest_uuids=None, service_level=None, release=None,
            autoheal=None, hypervisor_id=None, content_tags=None):
        """
        Update a consumer on the server.

        Rather than requiring a full representation of the consumer, only some
        information is passed depending on what we wish to update.

        Note that installed_products and guest_uuids expects a certain format,
        example parsing is in subscription-manager's format_for_server() method.

        This can raise the following exceptions:
            - RestlibException - This will include an http error code and a
            translated message that provides some detail as to what happend.
            - GoneException - This indicates that the consumer has been deleted
        """
        params = {}
        if installed_products is not None:
            params['installedProducts'] = installed_products
        if guest_uuids is not None:
            params['guestIds'] = self.sanitizeGuestIds(guest_uuids)
        if facts is not None:
            params['facts'] = facts
        if release is not None:
            params['releaseVer'] = release
        if autoheal is not None:
            params['autoheal'] = autoheal
        if hypervisor_id is not None:
            params['hypervisorId'] = {'hypervisorId': hypervisor_id}
        if content_tags is not None:
            params['contentTags'] = content_tags

        # The server will reject a service level that is not available
        # in the consumer's organization, so no need to check if it's safe
        # here:
        if service_level is not None:
            params['serviceLevel'] = service_level

        method = "/consumers/%s" % self.sanitize(uuid)
        ret = self.conn.request_put(method, params)
        return ret

    def addOrUpdateGuestId(self, uuid, guestId):
        if isinstance(guestId, basestring):
            guest_uuid = guestId
            guestId = {}
        else:
            guest_uuid = guestId['guestId']
        method = "/consumers/%s/guestids/%s" % (self.sanitize(uuid), self.sanitize(guest_uuid))
        return self.conn.request_put(method, guestId)

    def getGuestIds(self, uuid):
        method = "/consumers/%s/guestids" % self.sanitize(uuid)
        return self.conn.request_get(method)

    def getGuestId(self, uuid, guest_uuid):
        method = "/consumers/%s/guestids/%s" % (self.sanitize(uuid), self.sanitize(guest_uuid))
        return self.conn.request_get(method)

    def removeGuestId(self, uuid, guest_uuid):
        method = "/consumers/%s/guestids/%s" % (self.sanitize(uuid), self.sanitize(guest_uuid))
        return self.conn.request_delete(method)

    def sanitizeGuestIds(self, guestIds):
        return [self.sanitizeGuestId(guestId) for guestId in guestIds or []]

    def sanitizeGuestId(self, guestId):
        if isinstance(guestId, basestring):
            return guestId
        elif isinstance(guestId, dict) and "guestId" in guestId.keys():
            if self.supports_resource('guestids'):
                # Upload full json
                return guestId
            # Does not support the full guestId json, use the id string
            return guestId["guestId"]

    def updatePackageProfile(self, consumer_uuid, pkg_dicts):
        """
        Updates the consumer's package profile on the server.

        pkg_dicts expected to be a list of dicts, each containing the
        package headers we're interested in. See profile.py.
        """
        method = "/consumers/%s/packages" % self.sanitize(consumer_uuid)
        ret = self.conn.request_put(method, pkg_dicts)
        return ret

    # FIXME: username and password not used here
    def getConsumer(self, uuid, username=None, password=None):
        """
        Returns a consumer object with pem/key for existing consumers
        """
        method = '/consumers/%s' % self.sanitize(uuid)
        return self.conn.request_get(method)

    def getConsumers(self, owner=None):
        """
        Returns a list of consumers
        """
        method = '/consumers/'
        if owner:
            method = "%s?owner=%s" % (method, owner)

        return self.conn.request_get(method)

    def getCompliance(self, uuid, on_date=None):
        """
        Returns a compliance object with compliance status information
        """
        method = '/consumers/%s/compliance' % self.sanitize(uuid)
        if on_date:
            method = "%s?on_date=%s" % (method,
                    self.sanitize(on_date.isoformat(), plus=True))
        return self.conn.request_get(method)

    def createOwner(self, ownerKey, ownerDisplayName=None):
        params = {"key": ownerKey}
        if ownerDisplayName:
            params['displayName'] = ownerDisplayName
        method = '/owners/'
        return self.conn.request_post(method, params)

    def getOwner(self, uuid):
        """
        Returns an owner object with pem/key for existing consumers
        """
        method = '/consumers/%s/owner' % self.sanitize(uuid)
        return self.conn.request_get(method)

    def deleteOwner(self, key):
        """
        deletes an owner
        """
        method = '/owners/%s' % self.sanitize(key)
        return self.conn.request_delete(method)

    def getOwners(self):
        """
        Returns a list of all owners
        """
        method = '/owners'
        return self.conn.request_get(method)

    def getOwnerInfo(self, owner):
        """
        Returns an owner info
        """
        method = '/owners/%s/info' % self.sanitize(owner)
        return self.conn.request_get(method)

    def getOwnerList(self, username):
        """
        Returns an owner objects with pem/key for existing consumers
        """
        method = '/users/%s/owners' % self.sanitize(username)
        return self.conn.request_get(method)

    def getOwnerHypervisors(self, owner_key, hypervisor_ids=None):
        """
        If hypervisor_ids is populated, only hypervisors with those ids will be returned
        """
        method = '/owners/%s/hypervisors?' % owner_key
        for hypervisor_id in hypervisor_ids or []:
            method += '&hypervisor_id=%s' % self.sanitize(hypervisor_id)
        return self.conn.request_get(method)

    def unregisterConsumer(self, consumerId):
        """
         Deletes a consumer from candlepin server
        """
        method = '/consumers/%s' % self.sanitize(consumerId)
        return self.conn.request_delete(method)

    def getCertificates(self, consumer_uuid, serials=[]):
        """
        Fetch all entitlement certificates for this consumer.
        Specify a list of serial numbers to filter if desired.
        """
        method = '/consumers/%s/certificates' % (self.sanitize(consumer_uuid))
        if len(serials) > 0:
            serials_str = ','.join(serials)
            method = "%s?serials=%s" % (method, serials_str)
        return self.conn.request_get(method)

    def getCertificateSerials(self, consumerId):
        """
        Get serial numbers for certs for a given consumer
        """
        method = '/consumers/%s/certificates/serials' % self.sanitize(consumerId)
        return self.conn.request_get(method)

    def bindByEntitlementPool(self, consumerId, poolId, quantity=None):
        """
         Subscribe consumer to a subscription by pool ID.
        """
        method = "/consumers/%s/entitlements?pool=%s" % (self.sanitize(consumerId), self.sanitize(poolId))
        if quantity:
            method = "%s&quantity=%s" % (method, quantity)
        return self.conn.request_post(method)

    def bindByProduct(self, consumerId, products):
        """
        Subscribe consumer directly to one or more products by their ID.
        This will cause the UEP to look for one or more pools which provide
        access to the given product.
        """
        args = "&".join(["product=" + product.replace(" ", "%20")
                        for product in products])
        method = "/consumers/%s/entitlements?%s" % (str(consumerId), args)
        return self.conn.request_post(method)

    def bind(self, consumerId, entitle_date=None):
        """
        Same as bindByProduct, but assume the server has a list of the
        system's products. This is useful for autosubscribe. Note that this is
        done on a best-effort basis, and there are cases when the server will
        not be able to fulfill the client's product certs with entitlements.
        """
        method = "/consumers/%s/entitlements" % (self.sanitize(consumerId))

        # add the optional date to the url
        if entitle_date:
            method = "%s?entitle_date=%s" % (method,
                    self.sanitize(entitle_date.isoformat(), plus=True))

        return self.conn.request_post(method)

    def dryRunBind(self, consumer_uuid, service_level):
        """
        Performs a dry-run autobind on the server and returns the results of
        what we would get. Callers can use this information to determine if
        they wish to perform the autobind, and to explicitly grab entitlements
        from each pool returned.

        Return will be a dict containing a "quantity" and a "pool".
        """
        method = "/consumers/%s/entitlements/dry-run?service_level=%s" % \
                (self.sanitize(consumer_uuid), self.sanitize(service_level))
        return self.conn.request_get(method)

    def unbindBySerial(self, consumerId, serial):
        method = "/consumers/%s/certificates/%s" % (self.sanitize(consumerId), self.sanitize(str(serial)))
        return self.conn.request_delete(method)

    def unbindByPoolId(self, consumer_uuid, pool_id):
        method = "/consumers/%s/entitlements/pool/%s" % (self.sanitize(consumer_uuid), self.sanitize(pool_id))
        return self.conn.request_delete(method)

    def unbindAll(self, consumerId):
        method = "/consumers/%s/entitlements" % self.sanitize(consumerId)
        return self.conn.request_delete(method)

    def checkin(self, consumerId, checkin_date=None):
        method = "/consumers/%s/checkin" % self.sanitize(consumerId)
        # add the optional date to the url
        if checkin_date:
            method = "%s?checkin_date=%s" % (method,
                    self.sanitize(checkin_date.isoformat(), plus=True))

        return self.conn.request_put(method)

    def getPoolsList(self, consumer=None, listAll=False, active_on=None, owner=None, filter_string=None):
        """
        List pools for a given consumer or owner.

        Ideally, try to always pass the owner key argument. The old method is deprecated
        and may eventually be removed.
        """

        if owner:
            # Use the new preferred URL structure if possible:
            method = "/owners/%s/pools?" % self.sanitize(owner)
            if consumer:
                method = "%sconsumer=%s" % (method, consumer)

        elif consumer:
            # Just consumer specified, this URL is deprecated and may go away someday:
            method = "/pools?consumer=%s" % consumer

        else:
            raise Exception("Must specify an owner or a consumer to list pools.")

        if listAll:
            method = "%s&listall=true" % method
        if active_on:
            method = "%s&activeon=%s" % (method,
                    self.sanitize(active_on.isoformat(), plus=True))
        if filter_string:
            method = "%s&matches=%s" % (method, self.sanitize(filter_string, plus=True))
        results = self.conn.request_get(method)
        return results

    def getPool(self, poolId, consumerId=None):
        method = "/pools/%s" % self.sanitize(poolId)
        if consumerId:
            method = "%s?consumer=%s" % (method, self.sanitize(consumerId))
        return self.conn.request_get(method)

    def getProduct(self, product_id):
        method = "/products/%s" % self.sanitize(product_id)
        return self.conn.request_get(method)

    def getRelease(self, consumerId):
        method = "/consumers/%s/release" % self.sanitize(consumerId)
        results = self.conn.request_get(method)
        return results

    def getAvailableReleases(self, consumerId):
        """
        Gets the available content releases for a consumer.

        NOTE: Used for getting the available release versions
              from katello. In hosted candlepin scenario, the
              release versions will come from the CDN directly
              (API not implemented in candlepin).
        """
        method = "/consumers/%s/available_releases" % self.sanitize(consumerId)
        return self.conn.request_get(method)

    def getEntitlementList(self, consumerId, request_certs=False):
        method = "/consumers/%s/entitlements" % self.sanitize(consumerId)
        if not request_certs:
            # It is unnecessary to download the certificate and key here
            filters = "?exclude=certificates.key&exclude=certificates.cert"
        else:
            filters = ""
        results = self.conn.request_get(method + filters)
        return results

    def getServiceLevelList(self, owner_key):
        """
        List the service levels available for an owner.
        """
        method = "/owners/%s/servicelevels" % self.sanitize(owner_key)
        results = self.conn.request_get(method)
        return results

    def getEnvironmentList(self, owner_key):
        """
        List the environments for a particular owner.

        Some servers may not support this and will error out. The caller
        can always check with supports_resource("environments").
        """
        method = "/owners/%s/environments" % self.sanitize(owner_key)
        results = self.conn.request_get(method)
        return results

    def getEnvironment(self, owner_key=None, name=None):
        """
        Fetch an environment for an owner.

        If querying by name, owner is required as environment names are only
        unique within the context of an owner.

        TODO: Add support for querying by ID, this will likely hit an entirely
        different URL.
        """
        if name and not owner_key:
            raise Exception("Must specify owner key to query environment "
                    "by name")

        query_param = urlencode({"name": name})
        url = "/owners/%s/environments?%s" % (self.sanitize(owner_key), query_param)
        results = self.conn.request_get(url)
        if len(results) == 0:
            return None
        return results[0]

    def getEntitlement(self, entId):
        method = "/entitlements/%s" % self.sanitize(entId)
        return self.conn.request_get(method)

    def regenIdCertificate(self, consumerId):
        method = "/consumers/%s" % self.sanitize(consumerId)
        return self.conn.request_post(method)

    def getStatus(self):
        method = "/status"
        return self.conn.request_get(method)

    def getContentOverrides(self, consumerId):
        """
        Get all the overrides for the specified consumer.
        """
        method = "/consumers/%s/content_overrides" % self.sanitize(consumerId)
        return self.conn.request_get(method)

    def setContentOverrides(self, consumerId, overrides):
        """
        Set an override on a content object.
        """
        method = "/consumers/%s/content_overrides" % self.sanitize(consumerId)
        return self.conn.request_put(method, overrides)

    def deleteContentOverrides(self, consumerId, params=None):
        """
        Delete an override on a content object.
        """
        method = "/consumers/%s/content_overrides" % self.sanitize(consumerId)
        if not params:
            params = []
        return self.conn.request_delete(method, params)

    def activateMachine(self, consumerId, email=None, lang=None):
        """
        Activate a subscription by machine, information is located in the
        consumer facts
        """
        method = "/subscriptions?consumer_uuid=%s" % consumerId
        if email:
            method += "&email=%s" % email
            if (not lang) and (locale.getdefaultlocale()[0] is not None):
                lang = locale.getdefaultlocale()[0].lower().replace('_', '-')

            if lang:
                method += "&email_locale=%s" % lang
        return self.conn.request_post(method)

    def getSubscriptionList(self, owner_key):
        """
        List the subscriptions for a particular owner.
        """
        method = "/owners/%s/subscriptions" % self.sanitize(owner_key)
        results = self.conn.request_get(method)
        return results

    def getJob(self, job_id):
        """
        Returns the status of a candlepin job.
        """
        query_params = urlencode({"result_data": True})
        method = "/jobs/%s?%s" % (job_id, query_params)
        results = self.conn.request_get(method)
        return results

    def updateJobStatus(self, job_status):
        """
        Given a dict representing a candlepin JobStatus, check it's status.
        """
        # let key error bubble up
        method = job_status['statusPath']
        results = self.conn.request_get(method)
        return results

    def sanitize(self, url_param, plus=False):
        #This is a wrapper around urllib.quote to avoid issues like the one
        #discussed in http://bugs.python.org/issue9301
        if plus:
            sane_string = urllib.quote_plus(str(url_param))
        else:
            sane_string = urllib.quote(str(url_param))
        return sane_string
