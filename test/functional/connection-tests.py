#
# Copyright (c) 2011 - 2012 Red Hat, Inc.
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

import unittest

import json
from rhsm.connection import ContentConnection, UEPConnection, \
    SpliceConnection, AcceptedException, RemoteServerException


class ConnectionTests(unittest.TestCase):

    def setUp(self):
        self.cp = UEPConnection(username="admin", password="admin",
                insecure=True)

        consumerInfo = self.cp.registerConsumer("test-consumer", "system", owner="admin")
        self.consumer_uuid = consumerInfo['uuid']

    def test_supports_resource(self):
        self.assertTrue(self.cp.supports_resource('consumers'))
        self.assertTrue(self.cp.supports_resource('admin'))
        self.assertFalse(self.cp.supports_resource('boogity'))

    def test_update_consumer_can_update_guests_with_empty_list(self):
        self.cp.updateConsumer(self.consumer_uuid, guest_uuids=[])

    def test_update_consumer_can_update_facts_with_empty_dict(self):
        self.cp.updateConsumer(self.consumer_uuid, facts={})

    def test_update_consumer_can_update_installed_products_with_empty_list(self):
        self.cp.updateConsumer(self.consumer_uuid, installed_products=[])

    def tearDown(self):
        self.cp.unregisterConsumer(self.consumer_uuid)


class ContentConnectionTests(unittest.TestCase):

#    def setUp(self):
#        self.cc = ContentConnection(insecure=True)

    def testInsecure(self):
        ContentConnection(host="127.0.0.1", insecure=True)


class HypervisorCheckinTests(unittest.TestCase):

    def setUp(self):
        self.cp = UEPConnection(username="admin", password="admin",
                insecure=True)

    def test_hypervisor_checkin_can_pass_empty_map_and_updates_nothing(self):
        response = self.cp.hypervisorCheckIn("admin", "", {})

        self.assertEqual(len(response['failedUpdate']), 0)
        self.assertEqual(len(response['updated']), 0)
        self.assertEqual(len(response['created']), 0)


class StubRestlib():

    def __init__(self, retcode=None):
        self.retcode = retcode

    def request_put(self, url=None, params={}):
        if self.retcode == 202:
            raise AcceptedException("accepted!")
        elif self.retcode == 404:
            raise RemoteServerException(code=404)


class StubRhic():

    class StubX509():
        def as_pem(self):
            return "PEMPEMPEM"

    def __init__(self, retcode=None):
        self.x509 = self.StubX509()
        self.subject = {}
        self.subject['CN'] = 'CN=ABLOOBLAABLOOO'


class SpliceConnectionTests(unittest.TestCase):

    def test_202(self):
        splice_conn = SpliceConnection(host="127.0.0.1", ssl_port=443, handler='/foo', rhic='/foo/bar',
                            insecure=True, ca_cert_dir='/baz', rhic_ca_cert='/qux')

        splice_conn.conn = StubRestlib(202)

        with self.assertRaises(AcceptedException):
            splice_conn.getCerts(identity_cert=StubRhic(), consumer_identifier=None)

    def test_404(self):
        splice_conn = SpliceConnection(host="127.0.0.1", ssl_port=443, handler='/foo', rhic='/foo/bar',
                            insecure=True, ca_cert_dir='/baz', rhic_ca_cert='/qux')

        splice_conn.conn = StubRestlib(404)

        with self.assertRaises(RemoteServerException) as rse:
            splice_conn.getCerts(identity_cert=StubRhic(), consumer_identifier=None)

        self.assertEqual(rse.exception.code, 404)
