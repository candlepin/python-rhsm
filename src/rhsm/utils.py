#
# Copyright (c) 2012 Red Hat, Inc.
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

import gettext
import os
import re
from urlparse import urlparse
from rhsm.config import DEFAULT_PROXY_PORT

_ = lambda x: gettext.ldgettext("rhsm", x)


def remove_scheme(uri):
    """Remove the scheme component from a URI."""
    return re.sub("^[A-Za-z][A-Za-z0-9+-.]*://", "", uri)


class ServerUrlParseError(Exception):
    def __init__(self, serverurl, msg=None):
        self.serverurl = serverurl
        self.msg = msg


class ServerUrlParseErrorEmpty(ServerUrlParseError):
    pass


class ServerUrlParseErrorNone(ServerUrlParseError):
    pass


class ServerUrlParseErrorPort(ServerUrlParseError):
    pass


class ServerUrlParseErrorPath(ServerUrlParseError):
    pass


class ServerUrlParseErrorScheme(ServerUrlParseError):
    pass


class ServerUrlParseErrorJustScheme(ServerUrlParseError):
    pass


class UnsupportedOperationException(Exception):
    """Thrown when a call is made that is unsupported in the current
    state.  For example, if a call is made to a deprecated API when
    a newer API is available.
    """
    pass


def has_bad_scheme(url):
    # Don't allow urls to start with :/ http/ https/ non http/httpsm or http(s) with single /
    match_bad = '(https?[:/])|(:/)|(\S+://)'
    match_good = 'https?://'
    # Testing good first allows us to exclude some regex for bad
    if re.match(match_good, url):
        return False
    if re.match(match_bad, url):
        return True
    return False


def has_good_scheme(url):
    match = re.match("https?://(\S+)?", url)
    if not match:
        return False
    # a good scheme alone is not really a good scheme
    if not match.group(1):
        raise ServerUrlParseErrorJustScheme(url)
    return True


def parse_url(local_server_entry,
              default_hostname=None,
              default_port=None,
              default_prefix=None,
              default_username=None,
              default_password=None):
    """
    Parse hostname, port, and webapp prefix from the string a user entered.

    Expected format: username:password@hostname:port/prefix

    Username, password, port and prefix are optional.

    Returns:
        a tuple of (username, password, hostname, port, path)
    """
    # Adding http:// onto the front of the hostname

    if local_server_entry == "":
        raise ServerUrlParseErrorEmpty(local_server_entry)

    if local_server_entry is None:
        raise ServerUrlParseErrorNone(local_server_entry)

    # good_url in this case meaning a schema we support, and
    # _something_ else. This is to make urlparse happy
    good_url = None

    # handle any known or troublesome or bogus typo's, etc
    if has_bad_scheme(local_server_entry):
        raise ServerUrlParseErrorScheme(local_server_entry)

    # we want to see if we have a good scheme, and
    # at least _something_ else
    if has_good_scheme(local_server_entry):
        good_url = local_server_entry

    # not having a good scheme could just mean we don't have a scheme,
    # so let's include one so urlparse doesn't freak
    if not good_url:
        good_url = "https://%s" % local_server_entry

    #FIXME: need a try except here? docs
    # don't seem to indicate any expected exceptions
    result = urlparse(good_url)
    username = default_username
    password = default_password
    #netloc = result[1].split(":")

    # to support username and password, let's split on @
    # since the format will be username:password@hostname:port
    foo = result[1].split("@")

    # handle username/password portion, then deal with host:port
    # just in case someone passed in @hostname without
    # a username,  we default to the default_username
    if len(foo) > 1:
        creds = foo[0].split(":")
        netloc = foo[1].split(":")

        if len(creds) > 1:
            password = creds[1]
        if creds[0] is not None and len(creds[0]) > 0:
            username = creds[0]
    else:
        netloc = foo[0].split(":")

    # in some cases, if we try the attr accessors, we'll
    # get a ValueError deep down in urlparse, particular if
    # port ends up being None
    #
    # So maybe check result.port/path/hostname for None, and
    # throw an exception in those cases.
    # adding the schem seems to avoid this though
    port = default_port
    if len(netloc) > 1:
        if netloc[1] != "":
            port = str(netloc[1])
        else:
            raise ServerUrlParseErrorPort(local_server_entry)

    # path can be None?
    prefix = default_prefix
    if result[2] is not None:
        if result[2] != '':
            prefix = result[2]

    hostname = default_hostname
    if netloc[0] is not None:
        if netloc[0] != "":
            hostname = netloc[0]

    try:
        if port:
            int(port)
    except TypeError:
        raise ServerUrlParseErrorPort(local_server_entry)
    except ValueError:
        raise ServerUrlParseErrorPort(local_server_entry)

    return (username, password, hostname, port, prefix)


def get_env_proxy_info():
    the_proxy = {'proxy_username': '',
                 'proxy_hostname': '',
                 'proxy_port': '',
                 'proxy_password': ''}

    # get the proxy information from the environment variable
    # if available
    # look in the following order:
    #   HTTPS_PROXY
    #   https_proxy
    #   HTTP_PROXY
    #   http_proxy
    # look through the list for the first one to match
    info = ()
    env_vars = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
    for ev in env_vars:
        proxy_info = os.getenv(ev)
        if proxy_info:
            info = parse_url(proxy_info, default_port=DEFAULT_PROXY_PORT)
            break

    if info:
        the_proxy['proxy_username'] = info[0]
        the_proxy['proxy_password'] = info[1]
        the_proxy['proxy_hostname'] = info[2]
        if info[3] is None or info[3] == "":
            the_proxy['proxy_port'] = None
        else:
            the_proxy['proxy_port'] = int(info[3])
    return the_proxy


class Resource(object):

    def __init__(self, rel=None, href=None, version=None):
        self.href = href
        self.rel = rel
        # Resource version is not reported on old candlepins
        self.version = version or 0

    def get_href(self):
        return self.href

    def get_rel(self):
        return self.rel

    def get_version(self):
        return self.version

    def supports_version(self, required_version):
        return self.version >= required_version
