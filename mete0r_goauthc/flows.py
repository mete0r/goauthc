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
import sys
import time
import urllib
import webbrowser

from requests import Session
import requests


logger = logging.getLogger(__name__)


def get_flow_type(client_credentials):
    if 'installed' in client_credentials:
        return 'installed'
    if 'web' in client_credentials:
        return 'web'
    raise ValueError()


class OAuthException(Exception):
    pass


class InstalledAppFlow:

    def __init__(self, client_credentials, redirect_uri=None):
        self.client = client_credentials['installed']
        self.redirect_uri = redirect_uri or 'urn:ietf:wg:oauth:2.0:oob'

    def auth(self, scope, state=None, login_hint=None,
             include_granted_scope=None):

        incremental = include_granted_scope
        auth_url = self.get_auth_url(scope, state=state, login_hint=login_hint,
                                     include_granted_scope=incremental)
        code = self.ask_code(auth_url)
        token = self.exchange_code_for_token(code)
        return token

    def get_auth_url(self, scope, state=None, login_hint=None,
                     include_granted_scope=None):

        client = self.client

        params = {
            'response_type': 'code',
            'client_id': client['client_id'],
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(scope),
        }
        if state:
            params['state'] = state
        if login_hint:
            params['login_hint'] = login_hint
        if include_granted_scope:
            params['include_granted_scope'] = include_granted_scope
        return client['auth_uri'] + '?' + urllib.urlencode(params)

    def ask_code(self, auth_url):
        webbrowser.open(auth_url)
        sys.stderr.write('Authorization code: ')
        return raw_input().strip()

    def exchange_code_for_token(self, code):
        params = {
            'code': code,
            'client_id': self.client['client_id'],
            'client_secret': self.client['client_secret'],
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code'
        }
        logger.info('exchanging code for token...')
        r = requests.post(self.client['token_uri'], data=params)
        resp = r.json()
        if 'access_token' in resp:
            return resp
        raise OAuthException(resp['error'], resp)


class DeviceFlow:

    def __init__(self, client_credentials):
        self.client = client_credentials['installed']
        self.session = Session()

    def auth(self, scope):
        logger.info('requesting code...')
        resp = self.request_code(scope)
        self.ask_to_verify(resp['verification_url'],
                           resp['user_code'])

        token = self.poll_token(resp['device_code'],
                                resp['expires_in'] + time.time(),
                                resp['interval'])
        return token

    def request_code(self, scope):
        client = self.client

        params = {
            'client_id': client['client_id'],
            'scope': ' '.join(scope)
        }
        url = 'https://accounts.google.com/o/oauth2/device/code'
        r = self.session.post(url, data=params)
        resp = r.json()
        if 'error' in resp:
            raise OAuthException(resp['error'], resp)
        return resp

    def ask_to_verify(self, verification_url, user_code):

        def println(message):
            sys.stderr.write(message)
            sys.stderr.write('\n')

        println('Navigate to following url:')
        println('')
        println(verification_url)
        println('')
        println('And enter the following code:')
        println('')
        println(user_code)

    def poll_token(self, device_code, expires_at, interval):

        client = self.client

        params = {
            'client_id': client['client_id'],
            'client_secret': client['client_secret'],
            'code': device_code,
            'grant_type': 'http://oauth.net/grant_type/device/1.0'
        }
        while True:
            if time.time() > expires_at:
                raise Exception()

            logger.info('polling token...')
            r = self.session.post(client['token_uri'], data=params)
            resp = r.json()
            if 'access_token' in resp:
                return resp

            error = resp['error']
            if error == 'slow_down':
                interval += 1
            if error in ('slow_down', 'authorization_pending'):
                time.sleep(interval)
                continue
            raise OAuthException(resp['error'], resp)


def refresh_token(client, refresh_token):
    if 'installed' in client:
        client = client['installed']
    elif 'web' in client:
        client = client['web']

    endpoint = client['token_uri']
    query = {
        'grant_type': 'refresh_token',
        'client_id': client['client_id'],
        'client_secret': client['client_secret'],
        'refresh_token': refresh_token
    }

    logger.info('google refresh_token query: %s',
                json.dumps(query, indent=2, sort_keys=True))

    query = urllib.urlencode(query)
    r = requests.post(endpoint, data=query, headers={
        'content-type': 'application/x-www-form-urlencoded'
    })
    resp = r.json()

    logger.info('google refresh_token response: %s',
                json.dumps(resp, indent=2, sort_keys=True))

    if 'error' in resp:
        raise OAuthException(resp['error'], resp)
    return resp


def revoke_token(token):
    ''' Revoke a token.

    See https://developers.google.com/accounts/docs/OAuth2WebServer?hl=ko#tokenrevoke

    token: an access token or refresh token to revoke.
    '''  # noqa

    endpoint = 'https://accounts.google.com/o/oauth2/revoke'
    query = {
        'token': token
    }

    r = requests.get(endpoint, params=query)
    if r.status_code == 200:
        return
    resp = r.json()
    if 'error' in resp:
        raise OAuthException(resp['error'], resp)
    return resp


def get_token_info(access_token):
    endpoint = 'https://www.googleapis.com/oauth2/v1/tokeninfo'
    query = {
        'access_token': access_token
    }
    query = urllib.urlencode(query)
    url = endpoint + '?' + query
    r = requests.get(url)
    resp = r.json()

    logger.info('google token_info response: %s',
                json.dumps(resp, indent=2, sort_keys=True))

    if 'error' in resp:
        raise OAuthException(resp['error'], resp)
    return resp

