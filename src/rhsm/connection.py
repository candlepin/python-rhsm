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

import certificate2
import datetime
import dateutil.parser
import locale
import logging
import os
import socket
import ssl
import sys
import urllib
import urllib3
import warnings

import requests
import requests.exceptions
import requests.adapters
import requests.auth

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
from rhsm.utils import get_env_proxy_info, safe_int

global_socket_timeout = 60
timeout_altered = None

# requests/urllib likes to warn about server certs that do not have a
# SubjectAltName set (ie, a self signed cert often). So quiet that.
warnings.simplefilter('ignore', urllib3.exceptions.SecurityWarning)


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


h = NullHandler()
logging.getLogger("rhsm").addHandler(h)

log = logging.getLogger(__name__)

config = initConfig()


def drift_check(utc_time_string, hours=1):
    """
    Takes in a RFC 1123 date and returns True if the current time
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

    def __init__(self, code, msg=None, handler=None):
        self.code = code
        self.msg = msg or ""
        self.handler = handler

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
                 request_type=None,
                 handler=None,
                 response=None):
        super(RateLimitExceededException, self).__init__(code, request_type, handler)

        self.response = response
        self.headers = self.response.headers or {}
        self.msg = self.response.text or ""
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
        # FIXME: sort out when/where we want status_code as int vs string
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

        if status_code == 429:
            raise RateLimitExceededException(status_code,
                                             request_type=response.request.method,
                                             handler=response.request.path_url,
                                             response=response)

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
        # This really needs an exception mapper too.
        # TODO: Can we make better use of Response.raise_for_status() here?
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
        elif status_code in [429]:
            raise RateLimitExceededException(status_code,
                                             request_type=request_type,
                                             handler=handler,
                                             response=response)

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

    @classmethod
    def from_args_and_config(cls, proxy_hostname, proxy_port, proxy_user, proxy_password, config):
        # get the proxy information from the environment variable
        # if available
        # Does requests/urllib3 do this?
        info = get_env_proxy_info()

        _proxy_hostname = proxy_hostname or config.get('server', 'proxy_hostname') or info['proxy_hostname']
        _proxy_port = proxy_port or config.get('server', 'proxy_port') or info['proxy_port']
        _proxy_user = proxy_user or config.get('server', 'proxy_user') or info['proxy_username']
        _proxy_password = proxy_password or config.get('server', 'proxy_password') or info['proxy_password']

        proxy_info = cls(_proxy_hostname, _proxy_port,
                         _proxy_user, _proxy_password)

        return proxy_info

    # FIXME: really from_config_and_env
    @classmethod
    def from_config(cls, config):
        info = get_env_proxy_info()

        _proxy_hostname = config.get('server', 'proxy_hostname') or info['proxy_hostname']
        _proxy_port = config.get('server', 'proxy_port') or info['proxy_port']
        _proxy_user = config.get('server', 'proxy_user') or info['proxy_username']
        _proxy_password = config.get('server', 'proxy_password') or info['proxy_password']

        proxy_info = cls(_proxy_hostname, _proxy_port,
                         _proxy_user, _proxy_password)
        return proxy_info


class UserAuthInfo(object):
    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password


class ClientCertInfo(object):
    def __init__(self, cert_file=None, key_file=None):
        self.cert_file = cert_file
        self.key_file = key_file

        self.cert_pair = (self.cert_file,
                          self.key_file)

    def validate_cert(self):
        id_cert = certificate2._CertFactory().create_from_file(self.cert_file)
        if not id_cert.is_valid():
            raise ExpiredIdentityCertException()


class ServerCertInfo(object):
    def __init__(self, ca_bundle, ca_dir=None,
                 verify=True, verify_depth=None, insecure=False):
        self.ca_bundle = ca_bundle  # ?
        self.ca_dir = ca_dir
        self.verify = verify
        # 3?
        self.verify_depth = verify_depth or 3
        # Mostly for logging/reporting since verify is not quite ! insecure
        self.insecure = insecure

    @classmethod
    def from_config(cls, config, insecure=None):

        ssl_verify_depth = safe_int(config.get('server', 'ssl_verify_depth'))

        if insecure is None:
            insecure = False

        config_insecure = safe_int(config.get('server', 'insecure'))
        if config_insecure:
            insecure = True

        verify = not insecure

        # FIXME: requests requires a single ca bundle file, so there is
        #       likely more work to support ca cert dir as currently used
        ca_cert_dir = config.get('rhsm', 'ca_cert_dir')

        # FIXME: ca_bundle filename likely needs to be configurable
        ca_bundle = os.path.join(ca_cert_dir, 'ca_bundle.pem')
        log.debug("ca_bundle=%s", ca_bundle)

        server_cert_info = cls(ca_bundle=ca_bundle,
                               verify=verify,
                               verify_depth=ssl_verify_depth,
                               insecure=insecure)
        return server_cert_info


# TODO: enforce no sslv3 (though SSLv23 should do that now...)
class RhsmTLSAdapter(requests.adapters.HTTPAdapter):
    ssl_version = ssl.PROTOCOL_SSLv23

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.poolmanager.PoolManager(num_pools=connections,
                                                           maxsize=maxsize,
                                                           block=block,
                                                           ssl_version=self.ssl_version)


class RhsmSession(requests.Session):
    def __init__(self, *args, **kwargs):
        super(RhsmSession, self).__init__(*args, **kwargs)

        log.debug("self.headers=%s", self.headers)
        self.headers.update({"Content-type": "application/json",
                             "Accept": "application/json",
                             "x-python-rhsm-version": python_rhsm_version,
                             "x-subscription-manager-version": subman_version})

        # move to kwarg
        lc = _get_locale()
        if lc:
            self.headers.update({"Accept-Language": lc.lower().replace('_', '-')})

        # TODO: move to classes, with reset/clean/update
        self.capabilities = None
        self.resources = None

        self.drift_checked = None

        # Use an HttpAdaptor and overrides it's cert_verify
        #  ... then we could map specific url subpaths to different auth setups
        #      ie, /consumers is consumer cert while and /status are Plain https
        self.mount('https://', RhsmTLSAdapter())

    def __repr__(self):
        buf = "<RhsmSession auth=%s proxies=%s verify=%s cert=%s>" % \
            (self.auth, self.proxies, self.verify, self.cert)
        return buf

    def setup_proxy_info(self, proxy_info):
        if not proxy_info:
            return
        if not proxy_info.url:
            return

        self.proxies = proxy_info.scheme_map
        log.debug("self.proxy=%s", self.proxies)

    def setup_auth(self, auth):
        self.auth = auth
        log.debug("self.auth = %s", self.auth)
        log.debug("auth = %s", auth)

    def setup_server_cert_verify(self, server_cert_info):
        if not server_cert_info:
            return

        # verify by default in base
        if not server_cert_info.verify:
            self.verify = False
        else:
            self.verify = server_cert_info.ca_bundle

        # verify depth
        log.debug("verify=%s", self.verify)

    def setup_client_cert_info(self, client_cert_info):
        self.cert = (client_cert_info.cert_file,
                     client_cert_info.key_file)

        log.debug("client cert %s", client_cert_info)
        log.debug("self.cert=%s", self.cert)


class Restlib(object):
    """
     A wrapper around httplib to make rest calls easier
     See validateResponse() to learn when exceptions are raised as a result
     of communication with the server.
    """
    def __init__(self, session, base_url=None):
        self.session = session

        self.base_url = base_url
        log.debug("self.base_url=%s", self.base_url)
        log.debug("self.session %s", self.session)

        self.validator = RhsmResponseValidator()
        self.session.hooks = {'response': self.check_response}

    # FIXME: do we need to provide compat for validateResponse?
    def check_response(self, response, **kwargs):
        log.debug("check_response response=%s kwargs=%s", response, kwargs)
        self.log_response(response)
        self.drift_check(response)
        self.validate_response(response)
        return response

    def full_url(self, url_fragment):
        # handler in base_url does not have a trailing slash, but
        # path url_fragements should if they need it.
        full_url = "%s%s" % (self.base_url, url_fragment)
        log.debug("full_url: %s", full_url)
        return full_url

    def request(self, url, **kwargs):
        """This passes kwargs to requests.request, so needs more details.

        ie, it needs a full url for the 'url' kwarg instead of the slug the
        rest of the methods here use.

        Note, request's 'method' arg is the http method ('GET', etc)
        where we usually use that to mean the REST api slug ('/candlepin/consumers/release')
        """
        method = kwargs.pop('method', 'GET')
        headers = {}
        headers.update(self.session.headers)
        log.debug("headers0=%s", headers)
        headers.update(kwargs.pop('headers', {}))
        log.debug("headers=%s", headers)

        r = self.session.request(method=method,
                                 url=url,
                                 headers=headers,
                                 **kwargs)
        return r.text

    # return text
    def get(self, url):
        log.debug("get url %s session.auth=%s", url, self.session.auth)
        r = self.session.get(url)
        # TODO: maybe a raw response validate and a json validate?
        # check_response coulds/should be a 'response' hook
        return r.text

    # returns the body of the content or raises exceptions
    def post(self, url, data=None):
        r = self.session.post(url, data=data)
        return r.text

    # returns the body of the content or raises exceptions
    def put(self, url, data=None):
        r = self.session.put(url, data=data)
        return r.text

    # return text
    def head(self, url):
        r = self.session.head(url)
        return r.text

    def delete(self, url, data=None):
        r = self.session.delete(url, data=data)
        return r.text

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

    # FIXME: should be able to move this to just per session, as
    #        opposed to once per RhsmRestlib as current
    def drift_check(self, response):
        # Look for server drift, and log a warning

        # Already checked for this session
        if self.session.drift_checked:
            return

        if drift_check(response.headers.get('date')):
            log.warn("Clock skew detected, please check your system time")

    def log_response(self, response):
        log.debug("request headers %s", response.request.headers)
        log.debug("Response: status=%s requestUuid=%s",
                  response.status_code, response.headers.get('x-candepin-request-uuid') or '')
        log.debug("self.session.auth=%s", self.session.auth)
        log.debug("self.session.cert=%s", self.session.cert)

    def validate_response(self, response):
        # if we keep Restlib generic, may make sense to pass in a validator
        # or provide RhsmResponseValidator in a subclass
        return self.validator.validate(response)

    # The name... self.request is plain wrapper to requests.Session.request that returns
    # txt. This returns python objects. Use self.request() if you need the Response object
    def request_request(self, sub_url, **kwargs):
        response_body = self.request(self.full_url(sub_url), **kwargs)
        return self.json_loads(response_body)

    # return objects
    def request_get(self, method):
        log.debug("request_get=%s", method)
        response_body = self.get(self.full_url(method))
        return self.json_loads(response_body)

    # takes in python objects and returns python objects
    def request_post(self, method, params=None):
        # params is dict to be serialized to json
        data = self.json_dumps(params)
        response_body = self.post(self.full_url(method),
                                  data=data)
        return self.json_loads(response_body)

    # takes in python objects and returns python objects
    def request_put(self, method, params=None):
        # params is dict to be serialized to json
        data = self.json_dumps(params)
        response_body = self.put(self.full_url(method),
                                 data=data)
        return self.json_loads(response_body)

    def request_head(self, method):
        response_body = self.head(self.full_url(method))
        return self.json_loads(response_body)

    def request_delete(self, method, params=None):
        data = self.json_dumps(params)
        response_body = self.delete(self.full_url(method),
                                    data=data)
        return self.json_loads(response_body)


# TODO: Needs to be a wrapper class for setting up auth/session for cdn access
# This won'tt be a a Restlib subclass, likely just a request.Session with the right setup
class EntitlementCertRestlib(Restlib):
    ent_dir = "/etc/pki/entitlement"

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
    pass


class RhsmNoAuthAuth(RhsmAuth):
    def __init__(self):
        log.debug("init of RhsmNoAuthAuth")


class RhsmBasicAuth(requests.auth.HTTPBasicAuth):
    def __init__(self, user_auth_info):
        super(RhsmBasicAuth, self).__init__(user_auth_info.username,
                                            user_auth_info.password)
        log.debug("rhsmBasicAuth %s", user_auth_info.username)

    def __call__(self, r):
        super(RhsmBasicAuth, self).__call__(r)
        r.headers["some-rhsm-header"] = "caneatcheese(1)=true"
        log.debug("rhsmBasicAuth.call r=%s", r)
        return r


# FIXME: This is ununused at the moment, will replace ContentConnection for talking to CDN
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


class BaseRhsmConnection(object):
    def __init__(self,
                 base_url=None,
                 session=None):
        self.session = session

        # ? Restlib arg?
        self.conn = Restlib(self.session, base_url=base_url)

    def shutDown(self):
        self.conn.close()
        log.info("remote connection closed")

    def _load_supported_resources(self):
        """
        Load the list of supported resources by doing a GET on the root
        of the web application we're configured to use.

        Need to handle exceptions here because sometimes UEPConnections are
        created in a state where they can't actually be used. (they get
        replaced later) If something goes wrong making this request, just
        leave the list of supported resources empty.
        """
        resources = {}
        resources_list = self.conn.request_get("/")
        for r in resources_list:
            resources[r['rel']] = r['href']
        log.debug("Server supports the following resources: %s",
                  resources)
        return resources

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
        if self.session.capabilities is None:
            self.session.capabilities = self._load_manager_capabilities()
        return capability in self.session.capabilities

    def supports_resource(self, resource_name):
        """
        Check if the server we're connecting too supports a particular
        resource. For our use cases this is generally the plural form
        of the resource.
        """
        if self.session.resources is None:
            self.session.resources = self._load_supported_resources()

        return resource_name in self.session.resources

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
            # POST /hypervisors is two different APIS, one for posting text/plain
            # and one for posting text/json
            content_type = 'text/plain'
            new_headers = {'Content-type': content_type}
            query_params = urlencode({"env": env, "cloaked": False})
            data = self.conn.json_dumps(host_guest_mapping)
            url = "/hypervisors/%s?%s" % (owner, query_params)

            # Make a request via our restlib and session but provide
            # additional headers.
            res = self.conn.request_request(url,
                                            method="POST",
                                            headers=new_headers,
                                            data=data)
            return res
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

    def getProduct(self, product_uuid):
        method = "/products/%s" % self.sanitize(product_uuid)
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
        # This is a wrapper around urllib.quote to avoid issues like the one
        # discussed in http://bugs.python.org/issue9301
        if plus:
            sane_string = urllib.quote_plus(str(url_param))
        else:
            sane_string = urllib.quote(str(url_param))
        return sane_string


class RhsmConnection(BaseRhsmConnection):
    def __init__(self,
                 base_url=None,
                 session=None):

        # prefix/handler needs to start with leading /
        base_url = base_url or "https://%s:%s%s" % (config.get('server', 'hostname'),
                                                    safe_int(config.get('server', 'port')),
                                                    config.get('server', 'prefix'))

        # TODO: do we use the insecure arg here?
        server_cert_info = ServerCertInfo.from_config(config=config)

        proxy_info = ProxyInfo.from_config(config)

        session = session or RhsmSession()
        session.setup_proxy_info(proxy_info)
        session.setup_server_cert_verify(server_cert_info)

        super(RhsmConnection, self).__init__(base_url=base_url,
                                             session=session)


class RhsmBasicAuthConnection(RhsmConnection):
    def __init__(self, user_auth_info=None):
        session = RhsmSession()
        session.setup_auth(RhsmBasicAuth(user_auth_info))

        super(RhsmBasicAuthConnection, self).__init__(session=session)
        log.debug("rhsmBasicAuthConnection.session=%s", self.session)


class RhsmClientCertAuthConnection(RhsmConnection):
    def __init__(self, client_cert_info=None):
        session = RhsmSession()
        session.setup_client_cert_info(client_cert_info)
        super(RhsmBasicAuthConnection, self).__init__(session=session)


# TODO: this is 90% auth/session setup stuff
# TODO: Move this guy and RhsmSessionFactory to a different compat
#       module, and import into here so we don't break anything that
#       users rhsm.connection.UepConnection
#
# TODO: remove use of UepConnection in subscription-manager, and replace with
#       either RhsmNoAuthConnection, RhsmBasicAuthConnection, or RhsmClientCertAuthConnection
#       or a single RhsmConnection that gets it's Session replaced.
#
# FIXME: This class and Rhsm*Connection are too complicated, mostly to support compat
#        for UEPConnection which works like a connection factory.
#
class UEPConnection(RhsmConnection):
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
        self.handler = self.handler.rstrip("/")

        # prefix/handler needs to start with leading /
        base_url = "https://%s:%s%s" % (self.host, self.ssl_port, self.handler)

        proxy_info = ProxyInfo.from_args_and_config(proxy_hostname, proxy_port,
                                                    proxy_user, proxy_password,
                                                    config)

        client_cert_info = None
        if cert_file and key_file:
            client_cert_info = ClientCertInfo(cert_file=cert_file,
                                              key_file=key_file)

        session = RhsmSession()

        user_auth_info = None
        if username and password:
            user_auth_info = UserAuthInfo(username=username,
                                          password=password)

        if client_cert_info and user_auth_info:
            raise Exception("Can't use client cert auth and user/pass.")

        if cert_file and key_file:
            session.setup_client_cert_info(client_cert_info)

        if username and password:
            ra = RhsmBasicAuth(user_auth_info)
            session.setup_auth(ra)

        if proxy_info:
            session.setup_proxy_info(proxy_info)

        super(UEPConnection, self).__init__(base_url=base_url,
                                            session=session)
        log.debug("self.session.auth=%s", self.session.auth)
        log.debug("self.session.cert=%s", self.session.cert)
