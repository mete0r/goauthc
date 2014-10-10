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
from contextlib import contextmanager
from datetime import datetime
import json
import logging
import os.path

from sqlalchemy import create_engine
from sqlalchemy import or_
from sqlalchemy.orm import Session

from mete0r_goauthc.flows import get_flow_type
from mete0r_goauthc.models import metadata
from mete0r_goauthc.models import AccessToken
from mete0r_goauthc.models import BaseToken
from mete0r_goauthc.models import Client
from mete0r_goauthc.models import TokenScope
from mete0r_goauthc.models import User


logger = logging.getLogger(__name__)


class Repo:

    def __init__(self, session):
        self.session = session

    @classmethod
    @contextmanager
    def open_db_url(cls, db_url):
        engine = create_engine(db_url)
        session = Session(bind=engine)
        try:
            yield cls(session)
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    DEFAULT_REPO_DB = 'sqlite:///${REPO_DIR}/repo.db'

    @classmethod
    @contextmanager
    def open_dir(cls, base_dir):
        config_path = os.path.join(base_dir, 'config.json')
        with file(config_path, 'r') as f:
            config = json.load(f)

        db_url = config.get('db.url', cls.DEFAULT_REPO_DB)
        db_url = db_url.replace('${REPO_DIR}', base_dir)
        with cls.open_db_url(db_url) as repo:
            repo.config = config

            @contextmanager
            def config_edit():
                config = repo.config
                yield config
                with file(config_path, 'w') as f:
                    json.dump(config, f, indent=2, sort_keys=True)

            repo.config_edit = config_edit

            yield repo

    @classmethod
    @contextmanager
    def create(cls, base_dir):
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        config = {
            'db.url': cls.DEFAULT_REPO_DB
        }
        config_path = os.path.join(base_dir, 'config.json')
        with file(config_path, 'w') as f:
            json.dump(config, f, indent=2, sort_keys=True)

        db_url = config['db.url']
        db_url = db_url.replace('${REPO_DIR}', base_dir)
        engine = create_engine(db_url)
        metadata.create_all(engine)

    @property
    def clients(self):
        return self.session.query(Client)

    def get_client(self, identifier):
        return (self.get_client_by_alias(identifier) or
                self.get_client_by_client_id(identifier) or
                self.get_client_by_id(identifier))

    def get_client_by_alias(self, alias):
        for client in self.clients.filter_by(alias=alias):
            return client

    def get_client_by_client_id(self, client_id):
        for client in self.clients.filter_by(client_id=client_id):
            return client

    def get_client_by_id(self, _id):
        try:
            _id = int(_id)
        except ValueError:
            return
        for client in self.clients.filter_by(_id=_id):
            return client

    def put_client(self, credentials, alias=None):
        flow_type = get_flow_type(credentials)
        client_id = credentials[flow_type]['client_id']
        client_secret = credentials[flow_type]['client_secret']

        client = Client(client_id=client_id, client_secret=client_secret,
                        alias=alias, flow_type=flow_type,
                        data=credentials[flow_type])

        self.session.add(client)
        self.session.flush()
        return client

    def delete_client(self, identifier):
        client = self.get_client(identifier)
        if client:
            self.session.delete(client)
            self.session.flush()

    @property
    def users(self):
        return self.session.query(User)

    def get_user(self, identifier):
        return (self.get_user_by_email(identifier) or
                self.get_user_by_user_id(identifier) or
                self.get_user_by_id(identifier))

    def get_user_by_email(self, email):
        for user in self.users.filter_by(email=email):
            return user

    def get_user_by_user_id(self, user_id):
        for user in self.users.filter_by(user_id=user_id):
            return user

    def get_user_by_id(self, _id):
        try:
            _id = int(_id)
        except ValueError:
            return
        try:
            for user in self.users.filter_by(_id=_id):
                return user
        except OverflowError:
            return

    def put_user(self, user_data):
        user_id = user_data['user_id']
        user = self.get_user(user_id) or User(user_id=user_id)
        user.email = user_data.get('email')
        user.verified_email = user_data.get('verified_email')
        self.session.add(user)
        self.session.flush()
        return user

    def delete_user(self, identifier):
        user = self.get_user(identifier)
        if user:
            self.session.delete(user)

    @property
    def tokens(self):
        return self.session.query(AccessToken)

    def get_tokens(self, client_id=None, user_id=None, scopes=(),
                   exclude_revoked=False, exclude_expired=False):

        tokens = self.tokens

        if exclude_expired:
            tokens = tokens.filter(AccessToken.expires_at > datetime.now())

        if exclude_revoked:
            tokens = tokens.filter(AccessToken.base_token_id == BaseToken._id)
            tokens = tokens.filter(BaseToken.revoked == 0)

        if client_id:
            tokens = tokens.filter(AccessToken.base_token_id == BaseToken._id)
            tokens = tokens.filter(BaseToken.client_id == Client.client_id)
            tokens = tokens.filter(or_(Client.client_id == client_id,
                                       Client.alias == client_id))
        if user_id:
            tokens = tokens.filter(AccessToken.base_token_id == BaseToken._id)
            tokens = tokens.filter(BaseToken.user_id == User.user_id)
            tokens = tokens.filter(or_(User.email == user_id,
                                       User.user_id == user_id))

        for scope in scopes:
            tokens = tokens.filter(AccessToken.base_token_id == BaseToken._id)
            tokens = tokens.filter(BaseToken.scope_objects.any(value=scope))

        return tokens

    def get_token(self, token_id):
        for token in self.tokens.filter(AccessToken._id == token_id):
            return token

    def put_token(self, client_id, user_id, credentials):
        base_token = BaseToken(client_id=client_id, user_id=user_id)
        if 'refresh_token' in credentials:
            base_token.refresh_token = credentials['refresh_token']
        for scope in credentials['scope']:
            base_token.scope_objects.append(TokenScope(value=scope))
        self.session.add(base_token)
        return self.add_access_token(base_token, credentials)

    def add_access_token(self, base_token, credentials):
        expires_at = datetime.fromtimestamp(credentials['expires_at'])
        access_token = AccessToken(base_token=base_token,
                                   access_token=credentials['access_token'],
                                   id_token=credentials.get('id_token'),
                                   expires_in=credentials['expires_in'],
                                   expires_at=expires_at,
                                   token_type=credentials['token_type'])
        self.session.add(access_token)
        return access_token

    def delete_token(self, token_id):
        token = self.get_token(token_id)
        if token:
            self.session.delete(token)

    @property
    def basetokens(self):
        return self.session.query(BaseToken)

    def get_basetoken(self, basetoken_id):
        for basetoken in self.basetokens.filter(BaseToken._id == basetoken_id):
            return basetoken

    def delete_basetoken(self, basetoken_id):
        basetoken = self.get_basetoken(basetoken_id)
        if basetoken:
            self.session.delete(basetoken)
