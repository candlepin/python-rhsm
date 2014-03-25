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

import base64
import certificate
import datetime
import locale
import logging
import os
import socket
import sys
import time
import urllib

from M2Crypto import SSL, httpslib
from M2Crypto.SSL import SSLError
from urllib import urlencode

from config import initConfig
from version import Versions

from rhsm import ourjson as json
from rhsm.utils import get_env_proxy_info

# on EL5, there is a really long socket timeout. The
# best thing we can do is set a process wide default socket timeout.
# Limit this to affected python versions only, just to minimize any
# problems the default timeout might cause.
if sys.version_info[0] == 2 and sys.version_info[0] <= 4:
    socket.setdefaulttimeout(60)

# The module name changes between el5 and el6
try:
    import email.utils as eut
except ImportError:
    import email.Utils as eut


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


def drift_check(utc_time_string, hours=6):
    """
    Takes in a RFC 1123 date and returns True if the currnet time
    is greater then the supplied number of hours
    """
    drift = False
    if utc_time_string:
        try:
            utc_timestamp = time.mktime(eut.parsedate(utc_time_string))
            utc_datetime = datetime.datetime.fromtimestamp(utc_timestamp)
            local_datetime = datetime.datetime.utcnow()
            delta = datetime.timedelta(hours=1)
            drift = abs((utc_datetime - local_datetime)) > delta
        except Exception, e:
            log.error(e)

        return drift


class ConnectionException(Exception):
    pass


class ConnectionSetupException(ConnectionException):
    pass


class BadCertificateException(ConnectionException):
    """ Thrown when an error parsing a certificate is encountered. """

    def __init__(self, cert_path):
        """ Pass the full path to the bad certificate. """
        self.cert_path = cert_path

    def __str__(self):
        return "Bad certificate at %s" % self.cert_path


class RestlibException(ConnectionException):

    def __init__(self, code, msg=None):
        self.code = code
        self.msg = msg or ""

    def __str__(self):
        return self.msg


class GoneException(RestlibException):
    """
    GoneException - used to detect when a consumer has been deleted on the
    candlepin side.
    """
    def __init__(self, code, msg, deleted_id):
        # Exception doesn't inherit from object on el5 python version
        RestlibException.__init__(self, code, msg)
        self.deleted_id = deleted_id


class NetworkException(ConnectionException):

    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "Network error code: %s" % self.code


class RemoteServerException(ConnectionException):

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


class UnauthorizedException(AuthenticationException):
    prefix = "Unauthorized"


class ForbiddenException(AuthenticationException):
    prefix = "Forbidden"


class ExpiredIdentityCertException(ConnectionException):

    pass


class NoOpChecker:

    def __init__(self, host=None, peerCertHash=None, peerCertDigest='sha1'):
        self.host = host
        self.fingerprint = peerCertHash
        self.digest = peerCertDigest

    def __call__(self, peerCert, host=None):
        return True


class RhsmProxyHTTPSConnection(httpslib.ProxyHTTPSConnection):
    # 2.7 httplib expects to be able to pass a body argument to
    # endheaders, which the m2crypto.httpslib.ProxyHTTPSConnect does
    # not support
    def endheaders(self, body=None):
        if not self._proxy_auth:
            self._proxy_auth = self._encode_auth()

        if body:
            httpslib.HTTPSConnection.endheaders(self, body)
        else:
            httpslib.HTTPSConnection.endheaders(self)

    def _get_connect_msg(self):
        """ Return an HTTP CONNECT request to send to the proxy. """
        port = safe_int(self._real_port)
        msg = "CONNECT %s:%d HTTP/1.1\r\n" % (self._real_host, port)
        msg = msg + "Host: %s:%d\r\n" % (self._real_host, port)
        if self._proxy_UA:
            msg = msg + "%s: %s\r\n" % (self._UA_HEADER, self._proxy_UA)
        if self._proxy_auth:
            msg = msg + "%s: %s\r\n" % (self._AUTH_HEADER, self._proxy_auth)
        msg = msg + "\r\n"
        return msg


# FIXME: this is terrible, we need to refactor
# Restlib to be Restlib based on a https client class
class ContentConnection(object):
    def __init__(self, host, ssl_port=None,
                 username=None, password=None,
                 proxy_hostname=None, proxy_port=None,
                 proxy_user=None, proxy_password=None,
                 ca_dir=None, insecure=False,
                 ssl_verify_depth=1):

        log.debug("ContectConnection")
        # FIXME
        self.ent_dir = "/etc/pki/entitlement"
        self.handler = "/"
        self.ssl_verify_depth = ssl_verify_depth

        self.host = host or config.get('server', 'hostname')
        self.ssl_port = ssl_port or safe_int(config.get('server', 'port'))
        self.ca_dir = ca_dir
        self.insecure = insecure
        self.username = username
        self.password = password
        self.ssl_verify_depth = ssl_verify_depth

        # get the proxy information from the environment variable
        # if available
        info = get_env_proxy_info()

        self.proxy_hostname = proxy_hostname or config.get('server', 'proxy_hostname') or info['proxy_hostname']
        self.proxy_port = proxy_port or config.get('server', 'proxy_port') or info['proxy_port']
        self.proxy_user = proxy_user or config.get('server', 'proxy_user') or info['proxy_username']
        self.proxy_password = proxy_password or config.get('server', 'proxy_password') or info['proxy_password']

    def _request(self, request_type, handler, body=None):
        context = SSL.Context("tlsv1")

        self._load_ca_certificates(context)

        if self.proxy_hostname and self.proxy_port:
            log.debug("Using proxy: %s:%s" % (self.proxy_hostname, self.proxy_port))
            conn = RhsmProxyHTTPSConnection(self.proxy_hostname, self.proxy_port,
                                            username=self.proxy_user,
                                            password=self.proxy_password,
                                            ssl_context=context)
            # this connection class wants the full url
            handler = "https://%s:%s%s" % (self.host, self.ssl_port, handler)
        else:
            conn = httpslib.HTTPSConnection(self.host, safe_int(self.ssl_port), ssl_context=context)

        conn.request("GET", handler, body="", headers={"Host": "%s:%s" % (self.host, self.ssl_port), "Content-Length": "0"})
        response = conn.getresponse()
        result = {
            "content": response.read(),
            "status": response.status}

        return result

    def _load_ca_certificates(self, context):
        try:
            for cert_file in os.listdir(self.ent_dir):
                if cert_file.endswith(".pem") and not cert_file.endswith("-key.pem"):
                    cert_path = os.path.join(self.ent_dir, cert_file)
                    key_path = os.path.join(self.ent_dir, "%s-key.pem" % cert_file.split('.', 1)[0])
                    log.debug("Loading CA certificate: '%s'" % cert_path)

                    #FIXME: reenable res =
                    context.load_verify_info(cert_path)
                    context.load_cert(cert_path, key_path)
                    #if res == 0:
                    #    raise BadCertificateException(cert_path)
        except OSError, e:
            raise ConnectionSetupException(e.strerror)

    def test(self):
        pass

    def request_get(self, method):
        return self._request("GET", method)

    def get_versions(self, path):
        handler = "%s/%s" % (self.handler, path)
        results = self._request("GET", handler, body="")

        if results['status'] == 200:
            return results['content']
        return ''

    def _get_versions_for_product(self, product_id):
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


# FIXME: it would be nice if the ssl server connection stuff
# was decomposed from the api handling parts
class Restlib(object):
    """
     A wrapper around httplib to make rest calls easier
    """

    def __init__(self, host, ssl_port, apihandler,
            username=None, password=None,
            proxy_hostname=None, proxy_port=None,
            proxy_user=None, proxy_password=None,
            cert_file=None, key_file=None,
            ca_dir=None, insecure=False, ssl_verify_depth=1):
        self.host = host
        self.ssl_port = ssl_port
        self.apihandler = apihandler
        lc = _get_locale()
        #collect some version data
        v = Versions()
        subman_version = ("%s-%s") % \
            (v.get_version("subscription-manager"), v.get_release("subscription-manager"))
        python_rhsm_version = ("%s-%s") % \
            (v.get_version("python-rhsm"), v.get_release("python-rhsm"))

        self.headers = {"Content-type": "application/json",
                        "Accept": "application/json",
                        "x-python-rhsm-version": python_rhsm_version,
                        "x-subscription-manager-version": subman_version}

        if lc:
            self.headers["Accept-Language"] = lc.lower().replace('_', '-')

        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_dir = ca_dir
        self.insecure = insecure
        self.username = username
        self.password = password
        self.ssl_verify_depth = ssl_verify_depth
        self.proxy_hostname = proxy_hostname
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_password = proxy_password

        # Setup basic authentication if specified:
        if username and password:
            encoded = base64.b64encode(':'.join((username, password)))
            basic = 'Basic %s' % encoded
            self.headers['Authorization'] = basic

    def _decode_list(self, data):
        rv = []
        for item in data:
            if isinstance(item, unicode):
                item = item.encode('utf-8')
            elif isinstance(item, list):
                item = self._decode_list(item)
            elif isinstance(item, dict):
                item = self._decode_dict(item)
            rv.append(item)
        return rv

    def _decode_dict(self, data):
        rv = {}
        for key, value in data.iteritems():
            if isinstance(key, unicode):
                key = key.encode('utf-8')
            if isinstance(value, unicode):
                value = value.encode('utf-8')
            elif isinstance(value, list):
                value = self._decode_list(value)
            elif isinstance(value, dict):
                value = self._decode_dict(value)
            rv[key] = value
        return rv

    def _load_ca_certificates(self, context):
        loaded_ca_certs = []
        try:
            for cert_file in os.listdir(self.ca_dir):
                if cert_file.endswith(".pem"):
                    cert_path = os.path.join(self.ca_dir, cert_file)
                    res = context.load_verify_info(cert_path)
                    loaded_ca_certs.append(cert_file)
                    if res == 0:
                        raise BadCertificateException(cert_path)
        except OSError, e:
            raise ConnectionSetupException(e.strerror)

        if loaded_ca_certs:
            log.debug("Loaded CA certificates from %s: %s" % (self.ca_dir, ', '.join(loaded_ca_certs)))

    # FIXME: can method be emtpty?
    def _request(self, request_type, method, info=None):
        handler = self.apihandler + method
        context = SSL.Context("tlsv1")

        if self.insecure:  # allow clients to work insecure mode if required..
            context.post_connection_check = NoOpChecker()
        else:
            context.set_verify(SSL.verify_fail_if_no_peer_cert, self.ssl_verify_depth)
            if self.ca_dir is not None:
                self._load_ca_certificates(context)
        if self.cert_file and os.path.exists(self.cert_file):
            context.load_cert(self.cert_file, keyfile=self.key_file)

        if self.proxy_hostname and self.proxy_port:
            log.debug("Using proxy: %s:%s" % (self.proxy_hostname, self.proxy_port))
            conn = RhsmProxyHTTPSConnection(self.proxy_hostname, self.proxy_port,
                                            username=self.proxy_user,
                                            password=self.proxy_password,
                                            ssl_context=context)
            # this connection class wants the full url
            handler = "https://%s:%s%s" % (self.host, self.ssl_port, handler)
        else:
            conn = httpslib.HTTPSConnection(self.host, self.ssl_port, ssl_context=context)

        if info is not None:
            body = json.dumps(info)
        else:
            body = None

        log.debug("Making request: %s %s" % (request_type, handler))

        headers = self.headers
        if body is None:
            headers = dict(self.headers.items() +
                           {"Content-Length": "0"}.items())
        try:
            conn.request(request_type, handler, body=body, headers=headers)
        except SSLError:
            if self.cert_file:
                id_cert = certificate.create_from_file(self.cert_file)
                if not id_cert.is_valid():
                    raise ExpiredIdentityCertException()
            raise
        response = conn.getresponse()
        result = {
            "content": response.read(),
            "status": response.status,
        }
        response_log = 'Response: status=' + str(result['status'])
        if response.getheader('x-candlepin-request-uuid'):
            response_log = "%s, requestUuid=%s" % (response_log,
                    response.getheader('x-candlepin-request-uuid'))
        log.debug(response_log)

        # Look for server drift, and log a warning
        if drift_check(response.getheader('date')):
            log.warn("Clock skew detected, please check your system time")

        # FIXME: we should probably do this in a wrapper method
        # so we can use the request method for normal http

        self.validateResponse(result, request_type, handler)

        # handle empty, but succesful responses, ala 204
        if not len(result['content']):
            return None

        return json.loads(result['content'], object_hook=self._decode_dict)

    def validateResponse(self, response, request_type=None, handler=None):

        # FIXME: what are we supposed to do with a 204?
        if str(response['status']) not in ["200", "204"]:
            parsed = {}
            if not response.get('content'):
                parsed = {}
            else:
                # try vaguely to see if it had a json parseable body
                try:
                    parsed = json.loads(response['content'], object_hook=self._decode_dict)
                except ValueError, e:
                    log.error("Response: %s" % response['status'])
                    log.error("JSON parsing error: %s" % e)
                except Exception, e:
                    log.error("Response: %s" % response['status'])
                    log.exception(e)

            if parsed:
                # find and raise a GoneException on '410' with 'deleteId' in the
                # content, implying that the resource has been deleted
                # NOTE: a 410 with a unparseable content will raise
                # RemoteServerException
                if str(response['status']) == "410":
                    raise GoneException(response['status'],
                        parsed['displayMessage'], parsed['deletedId'])

                # I guess this is where we would have an exception mapper if we
                # had more meaningful exceptions. We've gotten a response from
                # the server that means something.

                # FIXME: we can get here with a valid json response that
                # could be anything, we don't verify it anymore
                error_msg = self._parse_msg_from_error_response_body(parsed)
                raise RestlibException(response['status'], error_msg)
            else:
                # This really needs an exception mapper too...
                if str(response['status']) in ["404", "410", "500", "502", "503", "504"]:
                    raise RemoteServerException(response['status'],
                                                request_type=request_type,
                                                handler=handler)
                elif str(response['status']) in ["401"]:
                    raise UnauthorizedException(response['status'],
                                                request_type=request_type,
                                                handler=handler)
                elif str(response['status']) in ["403"]:
                    raise ForbiddenException(response['status'],
                                             request_type=request_type,
                                             handler=handler)
                else:
                    # unexpected with no valid content
                    raise NetworkException(response['status'])

    def _parse_msg_from_error_response_body(self, body):

        # Old style with a single displayMessage:
        if 'displayMessage' in body:
            return body['displayMessage']

        # New style list of error messages:
        if 'errors' in body:
            return " ".join("%s" % errmsg for errmsg in body['errors'])

    def request_get(self, method):
        return self._request("GET", method)

    def request_post(self, method, params=None):
        return self._request("POST", method, params)

    def request_head(self, method):
        return self._request("HEAD", method)

    def request_put(self, method, params=None):
        return self._request("PUT", method, params)

    def request_delete(self, method, params=None):
        return self._request("DELETE", method, params)


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

        self.cert_file = cert_file
        self.key_file = key_file
        self.username = username
        self.password = password

        self.ca_cert_dir = config.get('rhsm', 'ca_cert_dir')
        self.ssl_verify_depth = safe_int(config.get('server', 'ssl_verify_depth'))

        self.insecure = insecure
        if insecure is None:
            self.insecure = False
            config_insecure = safe_int(config.get('server', 'insecure'))
            if config_insecure:
                self.insecure = True

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

        # initialize connection
        if using_basic_auth:
            self.conn = Restlib(self.host, self.ssl_port, self.handler,
                    username=self.username, password=self.password,
                    proxy_hostname=self.proxy_hostname, proxy_port=self.proxy_port,
                    proxy_user=self.proxy_user, proxy_password=self.proxy_password,
                    ca_dir=self.ca_cert_dir, insecure=self.insecure,
                    ssl_verify_depth=self.ssl_verify_depth)
            log.info("Using basic authentication as: %s" % username)
        elif using_id_cert_auth:
            self.conn = Restlib(self.host, self.ssl_port, self.handler,
                                cert_file=self.cert_file, key_file=self.key_file,
                                proxy_hostname=self.proxy_hostname, proxy_port=self.proxy_port,
                                proxy_user=self.proxy_user, proxy_password=self.proxy_password,
                                ca_dir=self.ca_cert_dir, insecure=self.insecure,
                                ssl_verify_depth=self.ssl_verify_depth)
            log.info("Using certificate authentication: key = %s, cert = %s, "
                     "ca = %s, insecure = %s" %
                     (self.key_file, self.cert_file, self.ca_cert_dir,
                      self.insecure))
        else:
            self.conn = Restlib(self.host, self.ssl_port, self.handler,
                    proxy_hostname=self.proxy_hostname, proxy_port=self.proxy_port,
                    proxy_user=self.proxy_user, proxy_password=self.proxy_password,
                    ca_dir=self.ca_cert_dir, insecure=self.insecure,
                    ssl_verify_depth=self.ssl_verify_depth)
            log.info("Using no auth")

        self.resources = None
        log.info("Connection Built: host: %s, port: %s, handler: %s" %
                (self.host, self.ssl_port, self.handler))

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
            self.resources[r['rel']] = r
        log.debug("Server supports the following resources:")
        log.debug(self.resources)

    def supports_resource(self, resource_name, version=None):
        """
        Check if the server we're connecting too supports a particular
        resource. For our use cases this is generally the plural form
        of the resource.
        """
        if self.resources is None:
            self._load_supported_resources()

        if resource_name in self.resources:
            required_version = version or 0
            # Default version zero if not present
            server_version = self.resources[resource_name].get('version', 0)
            return server_version >= required_version

        return False

    def shutDown(self):
        self.conn.close()
        log.info("remote connection closed")

    def ping(self, username=None, password=None):
        return self.conn.request_get("/status/")

    def registerConsumer(self, name="unknown", type="system", facts={},
            owner=None, environment=None, keys=None,
            installed_products=None, uuid=None, hypervisor_id=None):
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

    def hypervisorCheckIn(self, owner, env, host_guest_mapping):
        """
        Sends a mapping of hostIds to list of guestIds to candlepin
        to be registered/updated.

        host_guest_mapping is as follows:

        {
            'host-id-1': ['guest-id-1', 'guest-id-2'],
            'host-id-2': ['guest-id-3', 'guest-id-4']
        }
        """
        query_params = urlencode({"owner": owner, "env": env})
        url = "/hypervisors?%s" % (query_params)
        return self.conn.request_post(url, host_guest_mapping)

    def updateConsumerFacts(self, consumer_uuid, facts={}):
        """
        Update a consumers facts on candlepin server
        """
        return self.updateConsumer(consumer_uuid, facts=facts)

    def updateConsumer(self, uuid, facts=None, installed_products=None,
            guest_uuids=None, service_level=None, release=None,
            autoheal=None, hypervisor_id=None):
        """
        Update a consumer on the server.

        Rather than requiring a full representation of the consumer, only some
        information is passed depending on what we wish to update.

        Note that installed_products and guest_uuids expects a certain format,
        example parsing is in subscription-manager's format_for_server() method.
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

    def getPoolsList(self, consumer=None, listAll=False, active_on=None, owner=None):
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

    def sanitize(self, url_param, plus=False):
        #This is a wrapper around urllib.quote to avoid issues like the one
        #discussed in http://bugs.python.org/issue9301
        if plus:
            sane_string = urllib.quote_plus(str(url_param))
        else:
            sane_string = urllib.quote(str(url_param))
        return sane_string
