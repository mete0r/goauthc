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
import json
import logging
import os.path

from mete0r_goauthc import get_flow_type


logger = logging.getLogger(__name__)


class Repo:

    def __init__(self, base_dir):
        self._base_dir = base_dir

    @property
    def base_dir(self):
        base_dir = os.path.normpath(self._base_dir)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        return base_dir

    @property
    def clients_dir(self):
        clients_dir = os.path.join(self.base_dir, 'clients')
        clients_dir = os.path.normpath(clients_dir)
        if not os.path.exists(clients_dir):
            os.makedirs(clients_dir)
        return clients_dir

    def get_client_path(self, client_id):
        path = os.path.join(self.clients_dir, client_id + '.json')
        path = os.path.normpath(path)
        return path

    def get_client_id_from_path(self, client_path):
        return os.path.basename(client_path)[:-5]

    def get_clients(self):
        for name in os.listdir(self.clients_dir):
            path = os.path.join(self.clients_dir, name)
            try:
                with file(path) as f:
                    yield json.load(f)
            except Exception as e:
                logger.warning('An error occured in opening %s', path)
                logger.warning('%s', e)

    def get_client(self, client_id):
        client_path = self.get_client_path(client_id)
        with file(client_path) as f:
            return json.load(f)

    def put_client(self, client):
        flow_type = get_flow_type(client)
        client_id = client[flow_type]['client_id']
        path = self.get_client_path(client_id)
        with file(path, 'w') as f:
            json.dump(client, f, indent=2, sort_keys=True)
        return client_id

    def delete_client(self, client_id):
        client_path = self.get_client_path(client_id)
        if os.path.exists(client_path):
            os.unlink(client_path)

    @property
    def aliases_dir(self):
        aliases_dir = os.path.join(self.base_dir, 'aliases')
        aliases_dir = os.path.normpath(aliases_dir)
        if not os.path.exists(aliases_dir):
            os.makedirs(aliases_dir)
        return aliases_dir

    def get_alias_path(self, alias):
        alias_path = os.path.join(self.aliases_dir, alias)
        alias_path = os.path.normpath(alias_path)
        return alias_path

    def get_aliases(self):
        for alias in os.listdir(self.aliases_dir):
            try:
                client_id = self.get_alias(alias)
                yield alias, client_id
            except Exception as e:
                logger.warning('An error occured in opening %s', alias)
                logger.warning('%s', e)

    def get_alias(self, alias):
        alias_path = self.get_alias_path(alias)
        client_path = os.readlink(alias_path)
        client_id = self.get_client_id_from_path(client_path)
        return client_id

    def put_alias(self, alias, client_id):
        self.delete_alias(alias)

        alias_path = self.get_alias_path(alias)
        client_path = self.get_client_path(client_id)
        client_path = os.path.relpath(client_path, os.path.dirname(alias_path))
        os.symlink(client_path, alias_path)

    def delete_alias(self, alias):
        alias_path = self.get_alias_path(alias)
        if os.path.lexists(alias_path) or os.path.exists(alias_path):
            os.unlink(alias_path)


def get_default_user_repo():
    user_dir = os.path.expanduser('~')
    repo_dir = os.path.join(user_dir, '.goauthc')
    repo = Repo(repo_dir)
    return repo
