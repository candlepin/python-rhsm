#
# Copyright (c) 2014 Red Hat, Inc.
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

import logging
import os

from M2Crypto import SSL
from M2Crypto import m2

SSL_DEBUG = False
if 'RHSM_SSL_DEBUG' in os.environ:
    SSL_DEBUG = True

ssl_log = logging.getLogger("rhsm-ssl")

def verify_callback(ok, store):
    ssl_log.debug("ok: %s", ok)
    ssl_log.debug("store: %s", store)
    cert = store.get_current_cert()
    ssl_log.debug("store.get_current_cert: %s", cert)
    log_cert(cert)
    return 1

def verify_callback1(context, cert, errnum, errdepth, ok):
    log_ssl_context(context)
    log_cert(cert)
    ssl_log.debug("errnum: %s", errnum)
    ssl_log.debug("errdepth: %s", errdepth)
    ssl_log.debug("ok: %s", ok)
    return 1


def log_cert(cert):

    ssl_log.debug("certificate:")
    ssl_log.debug("subject: %s", cert.get_subject().as_text())
    ssl_log.debug("issuer: %s", cert.get_issuer().as_text())
    ssl_log.debug("serial: %s", cert.get_serial_number())
    ssl_log.debug("fingerprint(md5): %s", cert.get_fingerprint())
    ssl_log.debug("fingerprint(sha1): %s", cert.get_fingerprint(md="sha1"))
    ssl_log.debug("fingerprint(sha2): %s", cert.get_fingerprint(md="sha256"))
    ssl_log.debug("check_ca: %s", cert.check_ca())

    ssl_log.debug("check_purpose(SSL_SERVER): %s",
                  cert.check_purpose(m2.X509_PURPOSE_SSL_SERVER, 0))

    for i in range(cert.get_ext_count()):
        ext = cert.get_ext_at(i)
        ssl_log.debug("extension: %s = %s  (critcal: %s)",
                      ext.get_name(), ext.get_value(),
                      ext.get_critical() or False)
    #print "as_txt"
    #print peer_cert.as_text()


def log_ssl_context(context):
    ssl_log.debug("context: %s", context)


def log_ssl_info(connection, context):
    if not SSL_DEBUG:
        return

    ssl_log.debug("connection: %s", connection)
    log_ssl_context(context)

    session = connection.get_session()
    ssl_log.debug("session: %s", session)
    ssl_log.debug("session text: %s", session.as_text())

    #print "ssl_socket"
    ssl_socket = connection.sock
    ssl_log.debug("cipher_list: %s", ssl_socket.get_cipher_list())

    peer_cert = ssl_socket.get_peer_cert()
    log_cert(peer_cert)

    peer_chain = ssl_socket.get_peer_cert_chain()
    ssl_log.debug("peer chain length: %s", len(peer_chain))

    inc = 0
    for chain_link in peer_chain:
        ssl_log.debug("peer chain link %s", inc)
        log_cert(chain_link)
        inc += 1

    ssl_log.debug("veryify_mode: %s", ssl_socket.get_verify_mode())
    ssl_log.debug("verify_result: %s", ssl_socket.get_verify_result())
    ssl_log.debug("tls version: %s", ssl_socket.get_version())

    # This would be useful, but there are ref counting weirdness
    #cert_store = ssl_context.get_cert_store()
    #print "cert_store"
    #ssl_log.debug(cert_store)

    #print "cert_store.store"
    #ssl_log.debug(cert_store.store)


class LoggingChecker(SSL.Checker.Checker):
    name = "Logging Default Checker"

    def __call__(self, peerCert, host=None):
        self._log(peerCert, host)
        res = SSL.Checker.Checker.__call__(self, peerCert, host)
        if not SSL_DEBUG:
            ssl_log.debug("%s results: %s", self.name, res)
        return res

    def _log(self, peerCert, host):
        if not SSL_DEBUG:
            return
        #ssl_log.debug("%s host: %s fingerprint: %s digest: %s", self.name, self.host, self.fingerprint, self.digest)

        ssl_log.debug("%s peerCert: %s host: %s", self.name, peerCert, host)
        log_cert(peerCert)


class NoOpChecker(LoggingChecker):
    name = "insecure=1 Checker"

    def __call__(self, peerCert, host=None):
        self._log(peerCert, host)
        ssl_log.debug("%s results: N/A", self.name)
        return True
