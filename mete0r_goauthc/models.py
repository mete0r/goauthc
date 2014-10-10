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
from datetime import datetime
from copy import deepcopy
import json
import time

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.types import Boolean
from sqlalchemy.types import DateTime
from sqlalchemy.types import Enum
from sqlalchemy.types import Integer
from sqlalchemy.types import String
from sqlalchemy.types import Text
from sqlalchemy.types import TypeDecorator


Base = declarative_base()
metadata = Base.metadata


class JSONEncodedText(TypeDecorator):

    impl = Text

    def process_bind_param(self, value, dialect):
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        return json.loads(value)


class Client(Base):
    __tablename__ = 'Client'

    _id = Column(Integer, primary_key=True)
    client_id = Column(String, unique=True)
    client_secret = Column(String, nullable=False)
    alias = Column(String, unique=True, nullable=True)
    flow_type = Column(Enum('installed', 'web'))
    data = Column(JSONEncodedText)
    base_tokens = relationship('BaseToken', backref='client')

    def __repr__(self):
        return '<Client %r:%r>' % (self._id, self.client_id)

    @property
    def raw(self):
        return {
            self.flow_type: deepcopy(self.data)
        }


class User(Base):
    __tablename__ = 'User'

    _id = Column(Integer, primary_key=True)
    user_id = Column(String, unique=True)
    email = Column(String, unique=True)
    verified_email = Column(Boolean)
    base_tokens = relationship('BaseToken', backref='user')

    def __repr__(self):
        return '<User %r:%r>' % (self._id, self.user_id)


class BaseToken(Base):
    __tablename__ = 'BaseToken'

    _id = Column(Integer, primary_key=True)
    client_id = Column(String, ForeignKey('Client.client_id'))
    user_id = Column(String, ForeignKey('User.user_id'))
    refresh_token = Column(String)
    revoked = Column(Boolean, default=False)

    access_tokens = relationship('AccessToken',
                                 backref='base_token',
                                 cascade='all, delete-orphan')
    scope_objects = relationship('TokenScope',
                                 backref='base_token',
                                 cascade='all, delete-orphan')

    @property
    def client_alias(self):
        if self.client:
            return self.client.alias

    @property
    def user_email(self):
        if self.user:
            return self.user.email

    @property
    def scope_tuple(self):
        return tuple(scope.value for scope in self.scope_objects)

    @property
    def scope(self):
        return ' '.join(self.scope_tuple)


class AccessToken(Base):
    __tablename__ = 'AccessToken'

    _id = Column(Integer, primary_key=True)
    base_token_id = Column(Integer, ForeignKey('BaseToken._id'))

    access_token = Column(String)
    id_token = Column(String)
    expires_in = Column(Integer)
    expires_at = Column(DateTime)
    token_type = Column(String)

    @property
    def client(self):
        return self.base_token.client

    @property
    def client_id(self):
        return self.base_token.client_id

    @property
    def client_alias(self):
        return self.base_token.client_alias

    @property
    def user(self):
        return self.base_token.user

    @property
    def user_id(self):
        return self.base_token.user_id

    @property
    def user_email(self):
        return self.base_token.user_email

    @property
    def refresh_token(self):
        return self.base_token.refresh_token

    @property
    def scope(self):
        return self.base_token.scope

    @property
    def scope_tuple(self):
        return self.base_token.scope_tuple

    def get_revoked(self):
        return self.base_token.revoked

    def set_revoked(self, revoked):
        self.base_token.revoked = revoked

    revoked = property(get_revoked, set_revoked)

    def get_expires_at_as_timestamp(self):
        return int(time.mktime(self.expires_at.timetuple()))

    def set_expires_at_as_timestamp(self, timestamp):
        self.expires_at = datetime.fromtimestamp(timestamp)

    expires_at_as_timestamp = property(get_expires_at_as_timestamp,
                                       set_expires_at_as_timestamp)

    @property
    def expired(self):
        return self.expires_at < datetime.now()

    @property
    def raw(self):
        return {
            'access_token': self.access_token,
            'expires_in': self.expires_in,
            'expires_at': self.expires_at_as_timestamp,
            'id_token': self.id_token,
            'refresh_token': self.refresh_token,
            'scope': self.scope_tuple,
        }


class TokenScope(Base):
    __tablename__ = 'TokenScope'

    _id = Column(Integer, primary_key=True)
    base_token_id = Column(Integer, ForeignKey('BaseToken._id'))
    value = Column(String)

    def __repr__(self):
        return '<TokenScope %r of BaseToken %r>' % (self.value,
                                                    self.base_token_id)
