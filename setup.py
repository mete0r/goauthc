# -*- coding: utf-8 -*-
#
#   goauthc : mete0r's Google OAuth 2.0 client
#   Copyright (C) 2014 mete0r <mete0r@sarangbang.or.kr>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import with_statement
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import os.path


SETUP_DIR = os.path.dirname(__file__)


def read_file(path):
    path = os.path.join(SETUP_DIR, path)
    with file(path) as f:
        return f.read()


setup_info = {
    'name': 'mete0r.goauthc',
    'version': read_file('VERSION.txt').strip(),
    'description': 'mete0r\'s Google OAuth 2.0 client',
    'long_description': read_file('README.rst'),

    'author': 'mete0r',
    'author_email': 'mete0r@sarangbang.or.kr',
    'license': 'GNU Affero General Public License v3 or later (AGPLv3+)',
    'url': 'https://github.com/mete0r/goauthc',

    'packages': [
        'mete0r_goauthc'
    ],
    'package_dir': {'': '.'},
    'install_requires': [
        'requests',
        'docopt',
        'sqlalchemy',
        'sqlalchemy-continuum',
        'tabulate',
    ],
    'entry_points': {
        'console_scripts': ['goauthc = mete0r_goauthc.cli:main'],
    }
}

setup(**setup_info)
