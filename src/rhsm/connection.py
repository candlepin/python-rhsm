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

import dateutil.parser

import errno
import httplib

import locale
import logging
import os
import socket
import StringIO
import sys
import urllib

from M2Crypto import SSL, httpslib
from M2Crypto.SSL import SSLError
from M2Crypto import m2

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
import gio
import gio.unix
import glib
import gobject
import gobject

#FIXME:

import debug_logger
# on EL5, there is a really long socket timeout. The
# best thing we can do is set a process wide default socket timeout.
# Limit this to affected python versions only, just to minimize any
# problems the default timeout might cause.
if sys.version_info[0] == 2 and sys.version_info[0] <= 4:
    socket.setdefaulttimeout(60)

socket.setdefaulttimeout(5)

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


READ_SIZE = 1024 * 32


class GObjectHTTPResponseReader(gobject.GObject):
    def __init__(self, sock, read_amt=-1, *args, **kwargs):
        log.debug("GObjectHTTPResponseReader init %s %s" % (args, kwargs))
        gobject.GObject.__init__(self)
        # probably move to a StringIO
        self.content = ""
        self.count = 0
        self.read_amt = read_amt
        self.read_buf = ""
        self._finished = None
        self.idle_src = None
        #self.response = NonBlockingHTTPResponse(sock, *args, **kwargs)
        self.result_buf = ""
        self.http_status = None
        self.http_version = None
        self.http_reason = None

    def timeout_callback(self, response):
        self.count += 1
        if response.isclosed():
            print "request hit timeout %s times" % self.count
            return False
        print "timeout: %s" % self.count
        return True

    def headers_callback(self, source, condition, response):
        log.debug("headers callbacl %s %s %s" % (source, condition, response))
        buf = ""
        try:
            buf = source.read(256)
            self.result_buf += buf
        except socket.error, v:
            if v.errno == errno.EAGAIN:
                print "error"
                return True
            raise

        if buf == "":
            return False

        # could read byte by byte looking for lines, well see
        log.debug("looking for end of headers")
        print self.result_buf
        lines = self.result_buf.splitlines()
        #print self.result_buf.replace("\n", "NEWLINE\n")
        #index = self.result_buf.find("i\n\n")
        #print "index", index
        #if "" in lines:
        #    header_buf = lines
        index = None
        try:
            index = lines.index("")
        except ValueError:
            return True
        if index:
            self.header_buf = "\n".join(lines[:index])
            self.content = "\n".join(lines[index:])
            print self.header_buf
            print "-------------"
            print self.content
            header_io = StringIO.StringIO(self.header_buf)
            self.header_msg = httplib.HTTPMessage(header_io, 0)
            print self.header_msg
            self.length = self.header_msg.getheader('content-length')
            self.headers_finished()
            return False

        return True

        if index >= 0:
            log.debug("found empty line in headers")
            offset = index + 1
            self.header_buf = StringIO()
            self.header_buf.write(self.result_buf[:offset])
            log.debug("header_buf\n %s" % self.header_buf.getvalue())

            self.header_msg = httplib.HTTPMessage(self.header_buf, 0)
            self.length = self.header_msg.getheader('content-length')
            self.headers_finished()
            return False

        log.debug("reading more headers")
        return True

    def status_callback(self, source, condition, response):
        log.debug("status_callback 1 %s %s %s" % (source, condition, response))
        buf = ""
        try:
            buf = source.read(256)
            self.result_buf += buf
        except socket.error, v:
            if v.errno == errno.EAGAIN:
                print "error"
                return True
            raise

        lines = self.result_buf.splitlines()
        if lines:
            # got the status line
            self.status_line = lines[0]
            [version, status, reason] = lines[0].split(None, 2)
            self.http_version = version
            self.http_status = status
            self.http_reason = reason
            log.debug("lines[0] %s" % lines[0])
            log.debug("%s %s %s" % (version, status, reason))
            #self.setup_read_callback(source)

            self.status_finished()
            #self.read_headers()
            return False

        log.debug("status_callback 2")
        return True

    def http_callback(self, source, condition, response, read_amt=READ_SIZE, *args):
        #print ".",
        #log.debug("http_callback args %s %s %s" % (source, condition, self.length))
        #path, http_conn, http_response, str(args)
        #print source, path

        # it's faster if we just let it read till it blocks, but setting
        # a read size offers more events.
        #READ_SIZE=-1

        print "gh1", condition
        self.read_buf = ""
        buf = ""
        try:
            buf = source.read(read_amt)
            print "gh5"
        except socket.error, v:
            #log.exception(v)
            if v.errno == errno.EAGAIN:
                log.debug("socket.error: %s" % v)
                return True
            raise

        print "gh10"

        # callback? emit a signal?
        if read_amt >= 0 and buf >= read_amt:
            log.debug("read up to read_amt %s %s" % (read_amt, len(buf)))
            self.content += buf
            self.read_buf = buf
            return False

        #log.debug("len(buf) %s" % len(buf))
        #print http_conn, http_response, len(buf), http_response.length
        #global finished
        if buf != '':
    #        print "%s read on %s %s" % (len(buf), method, url)
            self.content += buf
    #        self.close()
            return True

        log.debug("----- end")
        #response.close()
        log.debug("empty buf")
        log.debug("len:%s len(buf): %s len(content): %s" % (response.length, len(buf), len(self.content)))
        self.finished()
        response.close()
        return False

    def idle_callback(self, *args):
        log.debug("\t idle callback: %s" % str(args))
        if self._finished:
            log.debug("idle finished")
            return False
       # time.sleep(.3)
        return True

    def error_callback(self, source, *args):
        print "oops", source, str(args)
        return False

    def hup_callback(self, source, *args):
        print "HUP HUP", source, str(args)
        return False

    def _finished_callback(self, *args):
        log.debug("_finished_callback %s" % args)

    def _status_finished_callback(self, *args):
        log.debug("_status_finished_callback %s" % args)

    def setup_read_callback(self, response):
        # currently no hup, or error callbacks
        # add status_callback to read headers? then http_callback when we get
        # done with headers?
        log.debug("setup_read_callback %s %s %s" % (response, self.http_callback, self.read_amt))
        log.debug("%s" % dir(response))
        self.http_src = gobject.io_add_watch(response.fp, gobject.IO_IN, self.http_callback, response, self.read_amt)

    def remove_read_callback(self):
        log.debug("removing response read callback")
        gobject.source_remove(self.http_src)

    def setup_status_callback(self, response, response_status_finished_callback=None):
        log.debug("setup_status_callback %s %s %s" % (response, self.http_callback, self.read_amt))
        log.debug("response_status_finished_callback %s" % response_status_finished_callback)

        # callback from response object to start reading rest of response after
        # status read
        self.status_finished_callback = response_status_finished_callback

        # when done, it will run self.status_finished_callback and remove it
        # self as a src
        #self.status_src = gobject.io_add_watch(response.fp._sock, gobject.IO_IN, self.status_callback, response)
        self.status_src = gobject.io_add_watch(response.fp, gobject.IO_IN, self.status_callback, response)

    def remove_status_callback(self):
        log.debug("remove_status_callback")
        gobject.source_remove(self.status_src)

    def setup_headers_callback(self, response, response_headers_finished_callback=None):
        log.debug("setup_headers_callback %s %s" % (response, response_headers_finished_callback))

        self.headers_finished_callback = response_headers_finished_callback

        self.headers_src = gobject.io_add_watch(response.fp, gobject.IO_IN, self.headers_callback, response)

    def remove_headers_callback(self):
        log.debug("remove_headers_callback")
        gobject.source_remove(self.headers_src)

    def setup_error_callback(self, response):
        log.debug("setup_error_callback")
        self.error_src = gobject.io_add_watch(response.fp, gobject.IO_ERR, self.error_callback)

    def setup_hup_callback(self, response):
        log.debug("setup_hup_callback")
        self.hup_src = gobject.io_add_watch(response.fp, gobject.IO_HUP, self.hup_callback)

    def setup_timeout_callback(self, response):
        log.debug("setup timeout callback")
        self.timeout_src = gobject.timeout_add(1000, self.timeout_callback, response)

    def remove_timeout_callback(self):
        log.debug("removing response timeout callback")
        gobject.source_remove(self.timeout_src)

    def setup_idle_callback(self):
        log.debug("setup_idle_callback %s" % self)
        self.idle_src = gobject.idle_add(self.idle_callback)

    def remove_idle_callback(self):
        log.debug("remove_idle_callback")
        gobject.source_remove(self.idle_src)

    # finish gsignal?
    def setup_finished_callback(self, response_finished_callback=None):
        log.debug("setup_finished_callback %s" % response_finished_callback)
        self.finished_callback = response_finished_callback or self._finished_callback

    def status_finished(self):
        log.debug("status finished")
        # FIXME: status finished signal?
        self.status_finished_callback()
        # FIXME: should be unneeded
        self.remove_status_callback()

    def headers_finished(self):
        log.debug("headers finished")
        self.headers_finished_callback()
        self.remove_headers_callback()

    def finished(self):
        log.debug("finished")
        self._finished = True
        self.remove_timeout_callback()
        self.remove_read_callback()
        self.finished_callback()
        if self.idle_src:
            self.remove_idle_callback()

gobject.type_register(GObjectHTTPResponseReader)


class NonBlockingHTTPResponse(httplib.HTTPResponse):
    def __init__(self, sock, *args, **kwargs):
        httplib.HTTPResponse.__init__(self, sock, *args, **kwargs)
        log.debug("NonBlocking self.fp %s" % (self.fp))
        log.debug("NonBlocking sock %s" % sock)
        self.gresponse = GObjectHTTPResponseReader(sock, *args, **kwargs)
        self.gresponse.read_amt = -1

        # not _UNKNOWN
        self.will_close = 1

        # Header wrapper
        self.msg = None
        self.length = None

        self.loop_end = None
        # read up to amt from the response
        # note if called with amt, the callback is removed, and needs to
        # be setup again
        #self.gresponse.read_amt = amt
        #self.gresponse.setup_idle_callback()
        self.gresponse.setup_error_callback(self)
        self.gresponse.setup_hup_callback(self)
        self.gresponse.setup_timeout_callback(self)
        # better as an emitted signal?
        self.gresponse.setup_finished_callback(self.finish_read)
        #self.gresponse.setup_read_callback(self)
        self.gresponse.setup_status_callback(self, self.finish_status)
        #self.gresponse.finished_callback = self.finish_read
        #self.gresponse.idle_callback = self.idle_callback
        # loop iteration here till finished callback?

    def finish_status(self):
        log.debug("finish_status")
        #self.gresponse.setup_read_callback(self)
        self.status = self.gresponse.http_status
        self.version = self.gresponse.http_version
        self.reason = self.gresponse.http_reason

        self.gresponse.setup_headers_callback(self, self.finish_headers)

    def finish_headers(self):
        log.debug("finish_headers")

        log.debug("about to setup read callback")
        self.msg = self.gresponse.header_msg
        self.length = self.gresponse.length
        self.gresponse.setup_read_callback(self)

    def finish_read(self):
        # return all the read content
        log.debug("finished_callback")
        self.content = self.gresponse.content
        #self.finished_callback()

        print "self.content"
        print self.content
        # pop out of main event loop, should use signals
        if self.loop_end:
            self.loop_end()
        print "I could quite the mainloop here"

    def begin(self):
        log.debug("%s begin" % self.__class__.__name__)
        # HTTPResponse.begin doesnt really deal well with non
        # blocking sockets (some docs point finger at it's use of readline)
        # so, get the response header, with the content length (ie, begin)
        # then set the socket to non blocking
        #httplib.HTTPResponse.begin(self)
        self.set_blocking(False)
        #self._read_status()

    def close(self):
        log.debug("close %s" % self)
        httplib.HTTPResponse.close(self)

    def set_blocking(self, blocking=True):
        # HTTPResponse uses a file object like interface to it's socket
        #  (socket._fileobject), so this sets the response objects
        # file object's socket to be non blocking.
        # Almost surely a better way to do this, and it will also depend
        # on the httplib implemtation (ie, httpslib stuff)
        self.fp._sock.setblocking(blocking)


class GobjectHTTPConnection(httpslib.HTTPSConnection):

    response_class = NonBlockingHTTPResponse

    def __init__(self, finished_callback, *args, **kwargs):
        log.debug("GobjectHTTPCOnnection %s %s" % (args, kwargs))
        httpslib.HTTPSConnection.__init__(self, *args, **kwargs)
        #GobjectHTTPConnection.__init__(*args, **kwargs)
        self.debuglevel = 5
        self.content = ""
        self.count = 0
        self.timeout = 5
        self.finished_callback = finished_callback

    def close(self):
        log.debug("Connection close")
        httplib.HTTPConnection.close(self)
        self.finished_callback()

    #def read_finished_callback(self):

    #    log.debug("removing callbacks")
    #    log.debug("self.count: %s" % self.count)
    #    gobject.source_remove(self.idle_src)
    #    #self.content = self.http_response.content
    #    log.debug("finished  with len(content): %s" % len(self.http_response.content))


# FIXME: this is terrible, we need to refactor
# Restlib to be Restlib based on a https client class
#
# Or... ditch this entirely, and use yum's tools to get this?
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

        self.timeout_altered = False

        # get the proxy information from the environment variable
        # if available
        info = get_env_proxy_info()

        self.proxy_hostname = proxy_hostname or config.get('server', 'proxy_hostname') or info['proxy_hostname']
        self.proxy_port = proxy_port or config.get('server', 'proxy_port') or info['proxy_port']
        self.proxy_user = proxy_user or config.get('server', 'proxy_user') or info['proxy_username']
        self.proxy_password = proxy_password or config.get('server', 'proxy_password') or info['proxy_password']

    def _request(self, request_type, handler, body=None):
        # See note in Restlib._request
        context = SSL.Context("sslv23")

        # Disable SSLv2 and SSLv3 support to avoid poodles.
        context.set_options(m2.SSL_OP_NO_SSLv2 | m2.SSL_OP_NO_SSLv3)

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

        set_default_socket_timeout_if_python_2_3()

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

    main_loop_factory = gobject.MainLoop

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

        self.main_loop = None

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

    def start_main_loop(self):
        if self.main_loop:
            return self.main_loop

        if self.main_loop_factory:
            self.main_loop = self.main_loop_factory()
            return self.main_loop

        raise Exception("No main loop provided")

    def end_main_loop(self):
        print "end main loop"
        if self.main_loop:
            self.main_loop.quit()
        else:
            raise Exception("No main loop provided to end")

    # FIXME: can method be emtpty?
    def _request(self, request_type, method, info=None):
        handler = self.apihandler + method

        # See M2Crypto/SSL/Context.py in m2crypto source and
        # https://www.openssl.org/docs/ssl/SSL_CTX_new.html
        # This ends up invoking SSLv23_method, which is the catch all
        # "be compatible" protocol, even though it explicitly is not
        # using sslv2. This will by default potentially include sslv3
        # if not used with post-poodle openssl. If however, the server
        # intends to not offer sslv3, it's workable.
        #
        # So this supports tls1.2, 1.1, 1.0, and/or sslv3 if supported.
        context = SSL.Context("sslv23")

        # Disable SSLv2 and SSLv3 support to avoid poodles.
        context.set_options(m2.SSL_OP_NO_SSLv2 | m2.SSL_OP_NO_SSLv3)


        self.start_main_loop()
        # NOTE: this should probably be part of connection class
        if self.insecure:  # allow clients to work insecure mode if required..
            context.post_connection_check = NoOpChecker()
        else:
            # Proper peer verification is essential to prevent MITM attacks.
            context.set_verify(
                    SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                    self.ssl_verify_depth)
            if self.ca_dir is not None:
                self._load_ca_certificates(context)
        if self.cert_file and os.path.exists(self.cert_file):
            context.load_cert(self.cert_file, keyfile=self.key_file)

        # need a connection factory
        if self.proxy_hostname and self.proxy_port:
            log.debug("Using proxy: %s:%s" % (self.proxy_hostname, self.proxy_port))
            conn = RhsmProxyHTTPSConnection(self.proxy_hostname, self.proxy_port,
                                            username=self.proxy_user,
                                            password=self.proxy_password,
                                            ssl_context=context)
            # this connection class wants the full url
            handler = "https://%s:%s%s" % (self.host, self.ssl_port, handler)
        else:
            conn = GobjectHTTPConnection(self.end_main_loop, self.host, self.ssl_port, ssl_context=context)
#            conn = httpslib.HTTPSConnection(self.host, self.ssl_port, ssl_context=context)

        if info is not None:
            body = json.dumps(info, default=json.encode)
        else:
            body = None

        log.debug("Making request: %s %s" % (request_type, handler))

        headers = self.headers
        if body is None:
            headers = dict(self.headers.items() +
                           {"Content-Length": "0"}.items())

        # NOTE: alters global timeout_altered (and socket timeout)
        set_default_socket_timeout_if_python_2_3()

        try:
            conn.request(request_type, handler, body=body, headers=headers)
            #conn.start_get(request_type, handler, body=body, headers=headers)
        except SSLError:
            if self.cert_file:
                id_cert = certificate.create_from_file(self.cert_file)
                if not id_cert.is_valid():
                    raise ExpiredIdentityCertException()
            raise

        # need to make a HttpConnection that can return a response object
        # that knows how to use the mainloop and/or GIO.
        #
        # We should be able to make the requests connections fileno an
        # unix.InputStream, and let mainloop take care of the rest

        # this will need to  return a gobject/mainloop/gio aware http response
        response = conn.getresponse()
        print "conn", conn, conn.sock
        #conn.start_get()
        print "response", response, response.fp

        # hook a way to exit the loop
        response.loop_end = self.end_main_loop
        #response.fp._sock.setblocking(0)
        #gis = gio.unix.InputStream(response.fp.fileno(), True)
        #print "gis", gis

        #buf = "___"
        #read_res = gis.read_async(4096, callback, user_data=buf)
        #print "read_res", read_res

        # should have io channels being watched by here
        #print "has_pending", gis.has_pending()
        #conn.start_get()
        #response.sread()

        # FIXME: could provide some event loop abstraction I suppose
        self.main_loop.run()

        #ctx = self.main_loop.get_context()
        #while gis.has_pending():
        #    ctx.iteration()
        #while ctx.pending():
        #    ctx.iteration()

        log.debug(response.status)

        result = {
            # .read can wrap a mainloop till we hit finish callback?
            "content": response.content,
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

        proxy_description = None
        if self.proxy_hostname and self.proxy_port:
            proxy_description = "http_proxy=%s:%s " % (self.proxy_hostname, self.proxy_port)
        auth_description = None
        # initialize connection
        if using_basic_auth:
            self.conn = Restlib(self.host, self.ssl_port, self.handler,
                    username=self.username, password=self.password,
                    proxy_hostname=self.proxy_hostname, proxy_port=self.proxy_port,
                    proxy_user=self.proxy_user, proxy_password=self.proxy_password,
                    ca_dir=self.ca_cert_dir, insecure=self.insecure,
                    ssl_verify_depth=self.ssl_verify_depth)
            auth_description = "auth=basic username=%s" % username
        elif using_id_cert_auth:
            self.conn = Restlib(self.host, self.ssl_port, self.handler,
                                cert_file=self.cert_file, key_file=self.key_file,
                                proxy_hostname=self.proxy_hostname, proxy_port=self.proxy_port,
                                proxy_user=self.proxy_user, proxy_password=self.proxy_password,
                                ca_dir=self.ca_cert_dir, insecure=self.insecure,
                                ssl_verify_depth=self.ssl_verify_depth)
            auth_description = "auth=identity_cert ca_dir=%s verify=%s" % (self.ca_cert_dir, self.insecure)
        else:
            self.conn = Restlib(self.host, self.ssl_port, self.handler,
                    proxy_hostname=self.proxy_hostname, proxy_port=self.proxy_port,
                    proxy_user=self.proxy_user, proxy_password=self.proxy_password,
                    ca_dir=self.ca_cert_dir, insecure=self.insecure,
                    ssl_verify_depth=self.ssl_verify_depth)
            auth_description = "auth=none"

        self.resources = None
        connection_description = ""
        if proxy_description:
            connection_description += proxy_description
        connection_description += "host=%s port=%s handler=%s %s" % (self.host, self.ssl_port,
                                                                    self.handler, auth_description)
        log.info("Connection built: %s", connection_description)

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
            autoheal=None, hypervisor_id=None, content_tags=None):
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

    def sanitize(self, url_param, plus=False):
        #This is a wrapper around urllib.quote to avoid issues like the one
        #discussed in http://bugs.python.org/issue9301
        if plus:
            sane_string = urllib.quote_plus(str(url_param))
        else:
            sane_string = urllib.quote(str(url_param))
        return sane_string
