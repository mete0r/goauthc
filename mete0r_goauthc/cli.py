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
'''
Usage: goauthc list
       goauthc show <alias>
       goauthc dump <client-id>
       goauthc save <client_secrets.json> [<alias>] [--delete]
       goauthc aliases
       goauthc auth <alias> [<scope>...] [--flow=<type>]


       --flow=<type>    "installed" or "device" (default: "installed")
'''
from __future__ import print_function
import json
import logging
import os.path
import sys

from docopt import docopt

from mete0r_goauthc import InstalledAppFlow
from mete0r_goauthc import DeviceFlow
from mete0r_goauthc import get_flow_type
from mete0r_goauthc.repo import get_default_user_repo


logger = logging.getLogger(__name__)


SCOPES = {
    'userinfo.email': 'https://www.googleapis.com/auth/userinfo.email'
}


def load_client_secrets(path):
    with file(path) as f:
        return json.load(f)


def main():

    args = docopt(__doc__)
    logging.basicConfig()

    repo = get_default_user_repo()

    if args['list']:
        repo_list(repo, args)
    elif args['aliases']:
        repo_aliases(repo, args)
    elif args['show']:
        repo_show(repo, args)
    elif args['dump']:
        repo_dump(repo, args)
    elif args['save']:
        repo_save(repo, args)
    elif args['auth']:
        repo_auth(repo, args)


def repo_list(repo, args):
    for client in repo.get_clients():
        flow_type = get_flow_type(client)
        client_id = client[flow_type]['client_id']
        print('%s %s' % (client_id, flow_type))


def repo_aliases(repo, args):
    for alias, client_id in repo.get_aliases():
        print('%s %s' % (client_id, alias))


def repo_show(repo, args):
    alias = args['<alias>']
    client_id = repo.get_alias(alias)
    client = repo.get_client(client_id)
    json.dump(client, sys.stdout, indent=2, sort_keys=True)
    if sys.stdout.isatty():
        sys.stdout.write('\n')


def repo_dump(repo, args):
    client_id = args['<client-id>']
    client = repo.get_client(client_id)
    json.dump(client, sys.stdout, indent=2, sort_keys=True)
    if sys.stdout.isatty():
        sys.stdout.write('\n')


def repo_save(repo, args):
    path = args['<client_secrets.json>']
    with file(path) as f:
        client = json.load(f)
    client_id = repo.put_client(client)
    if args['--delete']:
        os.unlink(path)
    if args['<alias>']:
        repo.put_alias(args['<alias>'], client_id)


def repo_auth(repo, args):
    alias = args['<alias>']
    scope = args['<scope>']
    flow = args['--flow']

    scope = list(canonicalize_scope(x)
                 for x in scope)
    for x in scope:
        logger.info('scope: %s', x)

    client_id = repo.get_alias(alias)
    client = repo.get_client(client_id)

    if flow == 'device':
        flow_class = DeviceFlow
    elif flow in ('installed', None):
        flow_class = InstalledAppFlow
    else:
        logger.error('unsupported flow: %s', flow)
        raise SystemExit(1)

    flow = flow_class(client)
    token = flow.auth(scope)

    json.dump(token, sys.stdout, indent=2, sort_keys=True)
    if sys.stdout.isatty():
        sys.stdout.write('\n')


def canonicalize_scope(scope):
    if scope in SCOPES:
        return SCOPES[scope]
    else:
        return scope
