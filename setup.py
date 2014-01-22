#!/usr/bin/env python
#
# Copyright (c) 2009 - 2012 Red Hat, Inc.
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

import os

from subprocess import Popen, PIPE

from setuptools import setup, find_packages, Extension
from setuptools.command.build_py import build_py


# subclass build_py so we can generate
# version.py based on either args passed
# in (--rpm-version, --rpm-release) or
# from a guess generated from 'git describe'
#
class rpm_version_release_build_py(build_py):
    user_options = build_py.user_options + \
            [('rpm-version=',
              None,
              'version of the rpm this is built for'),
            ('rpm-release=',
             None,
             'release of the rpm this is built for')]

    def initialize_options(self):
        build_py.initialize_options(self)
        self.rpm_version = None
        self.rpm_release = None

    def get_git_describe(self):
        cmd = ["git", "describe"]
        process = Popen(cmd, stdout=PIPE)
        output = process.communicate()[0].strip()
        if output.startswith('python-rhsm-'):
            return output[len('python-rhsm-'):]
        return 'unknown'

    def run(self):
        # create a "version.py" that includes the rpm version
        # info passed to our new build_py args
        if not self.dry_run:
            version_dir = os.path.join(self.package_dir['rhsm'])
            version_file = os.path.join(version_dir, 'version.py')
            version_release = "unknown"
            if self.rpm_version and self.rpm_release:
                version_release = "%s-%s" % (self.rpm_version,
                                               self.rpm_release)
            else:
                version_release = self.get_git_describe()
            try:
                self.mkpath(version_dir)
                f = open(version_file, 'w')
                f.write("rpm_version = '%s'\n" % version_release)
                f.close()
            except EnvironmentError:
                raise
        build_py.run(self)


setup(
    cmdclass={'build_py': rpm_version_release_build_py},
    name="rhsm",
    version='1.10.11',
    description='A Python library to communicate with a Red Hat Unified Entitlement Platform',
    author='Devan Goodwin',
    author_email='dgoodwin@redhat.com',
    url='http://fedorahosted.org/candlepin',
    license='GPLv2',

    package_dir={
        'rhsm': 'src/rhsm',
    },
    packages = find_packages('src'),
    include_package_data = True,

    ext_modules=[Extension('rhsm._certificate', ['src/certificate.c'],
                           libraries=['ssl'])],

    test_suite = 'nose.collector',

    classifiers = [
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python'
    ],
)


