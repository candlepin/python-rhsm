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

from iniparse.compat import NoOptionError, InterpolationMissingOptionError, InterpolationDepthError, NoSectionError
from tempfile import NamedTemporaryFile
import types
import unittest


from rhsm.config import RhsmConfigParser

TEST_CONFIG = """
[foo]
bar =
bigger_than_32_bit = 21474836470
bigger_than_64_bit = 123456789009876543211234567890
[server]
hostname = server.example.conf
prefix = /candlepin
port = 8443
insecure = 1
ssl_verify_depth = 3
proxy_hostname =
proxy_port =
proxy_user =
proxy_password =

[rhsm]
ca_cert_dir = /etc/rhsm/ca-test/
baseurl= https://content.example.com
repo_ca_cert = %(ca_cert_dir)sredhat-uep-non-default.pem
productCertDir = /etc/pki/product
entitlementCertDir = /etc/pki/entitlement
consumerCertDir = /etc/pki/consumer
report_package_profile = 1
pluginDir = /usr/lib/rhsm-plugins
some_option = %(repo_ca_cert)stest

[rhsmcertd]
certCheckInterval = 245
"""

OLD_CONFIG = """
[foo]
bar =
bigger_than_32_bit = 21474836470
bigger_than_64_bit = 123456789009876543211234567890
[server]
hostname = server.example.conf
prefix = /candlepin
port = 8443
insecure = 1
ssl_verify_depth = 3
ca_cert_dir = /etc/rhsm/ca-old/
proxy_hostname =
proxy_port =
proxy_user =
proxy_password =

[rhsm]
baseurl= https://content.example.com
repo_ca_cert = %(ca_cert_dir)sredhat-uep.pem
productCertDir = /etc/pki/product
entitlementCertDir = /etc/pki/entitlement
consumerCertDir = /etc/pki/consumer
report_package_profile = 1
pluginDir = /usr/lib/rhsm-plugins

[rhsmcertd]
certCheckInterval = 245
"""

BROKEN_CONFIG = """
[foo]
bar =
bigger_than_32_bit = 21474836470
bigger_than_64_bit = 123456789009876543211234567890
[server]
hostname = server.example.conf
prefix = /candlepin
port = 8443
insecure = 1
ssl_verify_depth = 3
ca_cert_dir = /etc/rhsm/ca-broken/
proxy_hostname =
proxy_port =
proxy_user =
proxy_password =

[rhsm]
baseurl= https://content.example.com
repo_ca_cert = %(s %%(ca_cert_dir)sredhat-uep.pem
productCertDir = /etc/pki/product
entitlementCertDir = /etc/pki/entitlement
consumerCertDir = /etc/pki/consumer
report_package_profile = 1
pluginDir = /usr/lib/rhsm-plugins
some_option = %(repo_ca_cert)s-%(consumerCertDir)s-foo

[rhsmcertd]
certCheckInterval = 245
"""

INTERPOLATION_ERROR_CONFIG = """
[foo]
blip = blip_value
[bar]
interp_key = %(blip)s_and_more
[deeper]
deep = level_one
deeper = %(deep)s_1
deepest = %(deeper)s_2
one_more = %(eleven)s
eleven = %(one_more)s
"""

CA_CERT_DIR_CONFIG = """
[rhsm]
ca_cert_dir = /etc/not-default/
repo_ca_cert = %(ca_cert_dir)snon_default.pem
"""

NO_CA_CERT_DIR_CONFIG = """
[rhsm]
repo_ca_cert = %(ca_cert_dir)snon_default.pem
"""


class BaseConfigTests(unittest.TestCase):
    def setUp(self):

        # create a temp file for use as a config file. This should get cleaned
        # up magically at the end of the run.
        self.fid = NamedTemporaryFile(mode='w+b', suffix='.tmp')
        self.fid.write(self.cfgfile_data)
        self.fid.seek(0)

        self.cfgParser = RhsmConfigParser(self.fid.name)


class ConfigTests(BaseConfigTests):
    cfgfile_data = TEST_CONFIG

    def testRead(self):
        self.assertEquals(self.cfgParser.get('server', 'hostname'), 'server.example.conf')

    def testSet(self):
        self.cfgParser.set('rhsm', 'baseurl', 'cod')
        self.assertEquals(self.cfgParser.get('rhsm', 'baseurl'), 'cod')

    def test_get(self):
        value = self.cfgParser.get("rhsm", "baseurl")
        self.assertEquals("https://content.example.com", value)

    def test_get_empty(self):
        value = self.cfgParser.get("foo", "bar")
        self.assertEquals("", value)

    def test_get_repo_ca_cert(self):
        value = self.cfgParser.get("rhsm", "repo_ca_cert")
        self.assertEquals("/etc/rhsm/ca-test/redhat-uep-non-default.pem", value)

    def test_has_default_true(self):
        value = self.cfgParser.has_default('server', 'hostname')
        self.assertTrue(value)

    def test_has_default_false(self):
        value = self.cfgParser.has_default('foo', 'port')
        self.assertFalse(value)

    def test_is_default_true(self):
        value = self.cfgParser.is_default('server', 'hostname', 'subscription.rhn.redhat.com')
        self.assertTrue(value)

    def test_is_default_false(self):
        value = self.cfgParser.is_default('server', 'hostname', 'localhost')
        self.assertFalse(value)

    def test_get_default_camel_case(self):
        value = self.cfgParser.get_default('rhsmcertd', 'certCheckInterval')
        self.assertEquals('240', value)

    def test_get_default(self):
        value = self.cfgParser.get_default('rhsmcertd', 'certcheckinterval')
        self.assertEquals('240', value)

    def test_get_int(self):
        value = self.cfgParser.get_int("server", "port")
        self.assertTrue(isinstance(value, types.IntType))
        self.assertEquals(8443, value)

    def test_interpolation(self):
        value = self.cfgParser.get("rhsm", "repo_ca_cert")
        self.assertEquals("/etc/rhsm/ca-test/redhat-uep-non-default.pem", value)

    def test_get_item_does_not_exist(self):
        self.assertRaises(NoOptionError,
                          self.cfgParser.get,
                          "rhsm",
                          "this_isnt_a_thing")

    def test_get_int_un_set(self):
        value = self.cfgParser.get_int("server", "proxy_port")
        self.assertEquals(None, value)

    def test_get_int_does_not_exist(self):
        self.assertRaises(NoOptionError,
                          self.cfgParser.get_int,
                          "rhsm",
                          "this_isnt_a_thing")

    def test_get_int_not_an_int(self):
        self.assertRaises(ValueError,
                          self.cfgParser.get_int,
                          "rhsm",
                          "baseurl")

    def test_get_int_big_int(self):
        value = self.cfgParser.get_int("foo", "bigger_than_32_bit")
        self.assertEquals(21474836470, value)
        value = self.cfgParser.get_int("foo", "bigger_than_64_bit")
        self.assertEquals(123456789009876543211234567890, value)


class SomeOptionConfigTest(BaseConfigTests):
    cfgfile_data = TEST_CONFIG

    def test_interpolation_nested(self):
        value = self.cfgParser.get("rhsm", "some_option")
        self.assertEquals("/etc/rhsm/ca-test/redhat-uep-non-default.pemtest", value)


class OldConfigTests(ConfigTests):
    cfgfile_data = OLD_CONFIG

    def test_get_repo_ca_cert(self):
        value = self.cfgParser.get("rhsm", "repo_ca_cert")
        # for old style configs, with ca_cert_dir in 'server', we
        #  expect to ignore that (as we did by accident before), and
        # get the default of '/etc/rhsm/ca'
        self.assertEquals("/etc/rhsm/ca/redhat-uep.pem", value)

    def test_interpolation(self):
        value = self.cfgParser.get("rhsm", "repo_ca_cert")
        self.assertEquals("/etc/rhsm/ca/redhat-uep.pem", value)


# this config has an invalid value for repo_ca_cert
class BrokenConfigTests(ConfigTests):
    cfgfile_data = BROKEN_CONFIG

    # our repo_ca_cert is busted, so expect an exception
    def test_get_repo_ca_cert(self):
        self.assertRaises(InterpolationMissingOptionError,
                self.cfgParser.get, "rhsm", "repo_ca_cert")

    # interp fails, expect interpolation exception
    def test_interpolation(self):
        self.assertRaises(InterpolationMissingOptionError,
                self.cfgParser.get, "rhsm", "repo_ca_cert")

    def test_nested_interpolation(self):
        self.assertRaises(InterpolationMissingOptionError,
                self.cfgParser.get, "rhsm", "some_option")

    def test_not_a_section(self):
        self.assertRaises(NoSectionError,
                self.cfgParser.get, "not_a_section", "not_an_option")

class InterpErrorTests(BaseConfigTests):
    cfgfile_data = INTERPOLATION_ERROR_CONFIG

    def test_get_interp_key(self):
        self.assertRaises(InterpolationMissingOptionError,
                          self.cfgParser.get,
                          "bar", "interp_key")

    def test_deeper(self):
        value = self.cfgParser.get("deeper", "deeper")
        self.assertEquals("level_one_1", value)

    def test_deepest(self):
        value = self.cfgParser.get("deeper", "deepest")
        self.assertEquals("level_one_1_2", value)

    def test_one_more(self):
        self.assertRaises(InterpolationDepthError,
                          self.cfgParser.get,
                          "deeper", "one_more")


class CaCertDirTests(BaseConfigTests):
    cfgfile_data = CA_CERT_DIR_CONFIG

    def test_get_repo_ca_cert(self):
        value = self.cfgParser.get("rhsm", "repo_ca_cert")
        self.assertEquals("/etc/not-default/non_default.pem", value)


class NoCaCertDirTests(BaseConfigTests):
    cfgfile_data = NO_CA_CERT_DIR_CONFIG

    def test_get_repo_ca_cert(self):
        value = self.cfgParser.get("rhsm", "repo_ca_cert")
        self.assertEquals("/etc/rhsm/ca/non_default.pem", value)
