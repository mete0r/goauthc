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
from unittest import TestCase
from unittest import makeSuite
from unittest import TestSuite
import shutil
import os.path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from ..models import metadata
from ..repo import Repo


class RepoCreateTest(TestCase):

    def test_create(self):
        repo_dir = 'test-repo'
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)
        Repo.create(repo_dir)
        self.assertTrue(os.path.isdir(repo_dir))
        self.assertTrue(os.path.exists(os.path.join(repo_dir, 'config.json')))
        self.assertTrue(os.path.exists(os.path.join(repo_dir, 'repo.db')))


@contextmanager
def repo_session(repo):
    session = repo.session = Session(bind=repo.engine)
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()
        repo.session = None


@contextmanager
def session(*args, **kwargs):
    session = Session(*args, **kwargs)
    try:
        yield session
        session.commit()
    except:
        session.rollback()
    finally:
        session.close()


class DBLayer:

    @classmethod
    def setUp(cls):
        cls.engine = create_engine('sqlite://')
        metadata.create_all(cls.engine)


class SessionLayer(DBLayer):

    @classmethod
    def setUp(cls):
        cls.sessioncontext = session(bind=cls.engine)
        cls.session = cls.sessioncontext.__enter__()

    @classmethod
    def tearDown(cls):
        cls.sessioncontext.__exit__(None, None, None)


class RepoLayer(SessionLayer):

    @classmethod
    def setUp(cls):
        cls.repo = Repo(cls.session)


class SampleClientLayer(RepoLayer):

    @classmethod
    def setUp(cls):
        credentials = {
            'installed': {
                'client_id': 'c-1234',
                'client_secret': 's-1234'
            }
        }
        cls.client = cls.repo.put_client(credentials)
        cls.repo.session.commit()


class SampleUserLayer(RepoLayer):

    @classmethod
    def setUp(cls):
        user_json = {
            'user_id': 'u-1234',
            'email': 'foo@example.tld',
            'verified_email': True
        }
        cls.user = cls.repo.put_user(user_json)
        cls.repo.session.commit()


class SampleUserClientLayer(SampleClientLayer, SampleUserLayer):

    @classmethod
    def setUp(cls):
        pass

    @classmethod
    def tearDown(cls):
        pass


class RepoTest(TestCase):

    layer = DBLayer

    @property
    def engine(self):
        return self.layer.engine

    def test_client(self):

        credentials = {
            'installed': {
                'client_id': 'c-1234',
                'client_secret': 's-1234'
            }
        }
        with session(bind=self.engine) as sess:
            repo = Repo(sess)
            client = repo.put_client(credentials, 'sample')
            self.assertEquals('c-1234', client.client_id)
            self.assertEquals('s-1234', client.client_secret)
            self.assertEquals('installed', client.flow_type)
            self.assertEquals(credentials['installed'], client.data)
            self.assertEquals(credentials, client.raw)

        with session(bind=self.engine) as sess:
            repo = Repo(sess)
            client = repo.get_client('c-1234')
            self.assertEquals('c-1234', client.client_id)
            self.assertEquals('installed', client.flow_type)
            self.assertEquals(credentials['installed'], client.data)

        with session(bind=self.engine) as sess:
            repo = Repo(sess)
            repo.delete_client('c-1234')
            client = repo.get_client('c-1234')
            self.assertEquals(None, client)

    def test_user(self):

        user_data = {
            'user_id': 'u-1234',
            'email': 'test@example.tld',
            'verified_email': True
        }

        with session(bind=self.engine) as sess:
            repo = Repo(sess)
            user = repo.put_user(user_data)
            self.assertEquals('u-1234', user.user_id)
            self.assertEquals('test@example.tld', user.email)
            self.assertTrue(user.verified_email)
            user__id = user._id

        with session(bind=self.engine) as sess:
            repo = Repo(sess)
            user = repo.get_user('u-1234')
            self.assertEquals('u-1234', user.user_id)
            self.assertEquals('test@example.tld', user.email)
            self.assertTrue(user.verified_email)
            self.assertEquals(user__id, user._id)

            user = repo.get_user_by_email('test@example.tld')
            self.assertEquals(user__id, user._id)

            repo.delete_user('u-1234')

        with session(bind=self.engine) as sess:
            repo = Repo(sess)
            self.assertEquals(None, repo.get_user('u-1234'))
            self.assertEquals(None, repo.get_user_by_email('test@example.tld'))


class TokenTest(TestCase):

    layer = SampleUserClientLayer

    def test_hello(self):
        repo = self.layer.repo
        client = self.layer.client
        user = self.layer.user

        client_id = client.client_id
        user_id = user.user_id

        credentials = {
            'access_token': 'a-1234',
            'expires_in': 3600,
            'expires_at': 7200,
            'id_token': 'i-1234',
            'refresh_token': 'r-1234',
            'scope': [
                'email',
                'profile',
            ],
            'token_type': 'Bearer',
        }
        token = repo.put_token(client_id, user_id, credentials)
        token_id = token._id
        self.assertEquals('email profile', token.scope)
        self.assertEquals('r-1234', token.refresh_token)
        self.assertEquals('a-1234', token.access_token)
        self.assertEquals(3600, token.expires_in)
        self.assertEquals(datetime.fromtimestamp(7200), token.expires_at)

        repo.delete_token(token_id)
        self.assertEquals(None, repo.get_token(token_id))


class TransformTest(TestCase):

    def test_find_transforms(self):
        from ..cli import find_shortest_transforms
        from ..cli import transformer_client_list_into_table
        from ..cli import transformer_table_into_tabulate
        source_format = 'client', list
        target_format = 'tabulate',
        transformers = find_shortest_transforms(source_format, target_format)
        transformers = tuple(transformers)
        self.assertEquals((transformer_client_list_into_table,
                           transformer_table_into_tabulate),
                          transformers)

    def test_resolve_table_renderer(self):
        from ..cli import resolve_renderers_for_format
        renderer = None
        for renderer in resolve_renderers_for_format('table'):
            print renderer
        self.assertTrue(renderer)


def test_suite():
    return TestSuite((makeSuite(RepoCreateTest),
                      makeSuite(RepoTest),
                      makeSuite(TokenTest),
                      makeSuite(TransformTest)))
