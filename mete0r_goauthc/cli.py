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
Usage:
       goauthc init
       goauthc client list
       goauthc client import <client_secret.json> [<client-alias>] [--delete]
       goauthc client delete <client>
       goauthc client show <client>
       goauthc client dump <client>
       goauthc user list
       goauthc user show <user>
       goauthc user delete <user>
       goauthc auth [--flow=<type>] <client> [--login=<email>] <scope>...
       goauthc token list [--client=<client>] [--user=<user>] [<scope>...]
       goauthc token show <token>
       goauthc token dump <token>
       goauthc token info <token>
       goauthc token refresh <token>
       goauthc token revoke <token>
       goauthc token delete <token>
       goauthc token acquire [--client=<client>] [--user=<user>] <scope>...
       goauthc basetoken list
       goauthc basetoken show <basetoken>
       goauthc basetoken delete <basetoken>
       goauthc config set <name> <value>
       goauthc config list
       goauthc config delete <name>


       --flow=<type>    "installed" or "device" (default: "installed")


        <basetoken>     <row-id> of a basetoken.
        <client>        <client-alias>, <client-id> or <row-id> (_id)
        <client-alias>  an alias of a client specified by you
        <client-id>     "client_id" field in a <client_secret.json> file.
        <email>         an email address of a user
        <scope>         Google OAuth2 scope. You can omit common google prefix
                        i.e.  'https://www.googleapis.com/auth/'
        <token>         <row-id> of a token.
        <user>          <email>, <user_id> or <row-id> (_id)
'''
from __future__ import print_function
from __future__ import unicode_literals
from contextlib import contextmanager
from contextlib import nested
import json
import logging
import os.path
import sys
import time

from docopt import docopt
from tabulate import tabulate

from mete0r_goauthc.flows import InstalledAppFlow
from mete0r_goauthc.flows import DeviceFlow
from mete0r_goauthc.flows import get_token_info
from mete0r_goauthc.flows import refresh_token
from mete0r_goauthc.flows import revoke_token
from mete0r_goauthc.repo import Repo


logger = logging.getLogger(__name__)


def setupLogging(config):
    loglevel_root = parse_loglevel(config['loglevel.root'])
    loglevel_db = parse_loglevel(config['loglevel.db'])

    logging.basicConfig(level=loglevel_root)
    logging.getLogger('sqlalchemy.engine').setLevel(loglevel_db)


def parse_loglevel(loglevel):
    try:
        return int(loglevel)
    except ValueError:
        pass

    mapping = {
        'CRITICAL': logging.CRITICAL,
        'ERROR': logging.ERROR,
        'WARNING': logging.WARNING,
        'INFO': logging.INFO,
        'DEBUG': logging.DEBUG,
    }
    try:
        return mapping[loglevel.upper()]
    except KeyError:
        raise ValueError(loglevel)


def main():
    config = {
        'loglevel.root': logging.WARNING,
        'loglevel.db': logging.WARNING,
        'loglevel.http': logging.WARNING,
        'repo.dir': '.goauthc',
    }
    setupLogging(config)

    args = docopt(__doc__)

    f = resolve_dispatch(args)

    if f is None:
        logger.error('Nothing to do.')
        raise SystemExit(1)

    resource_resolvers = resolve_resource_resolver(f)
    resource_contexts = [resolve_resource(args, config)
                         for resolve_resource
                         in resource_resolvers]
    with nested(*resource_contexts) as resources:
        renderable = f(*resources)
        renderer = resolve_renderer(f)
        logger.debug('main: resolved renderer for user %r: %r', f, renderer)
        render = renderer(args, config)
        bytechunks = render(renderable)
        for bytes in bytechunks:
            sys.stdout.write(bytes)


#
# command dispatch by function names
#

dispatch_map = {}


def dispatch(f):
    name = f.__name__
    components = tuple(name.split('_'))
    dispatch_map[components] = f
    return f


def resolve_dispatch(args):
    for components in sorted(dispatch_map):
        if all(args[component] for component in components):
            return dispatch_map[components]


#
# contexts
#


resource_resolver_map = {}
with_resource_map = {}


def resource_resolver(resource_key):
    def decorator(resolver_fn):
        resource_resolver_map[resource_key] = contextmanager(resolver_fn)
        return resolver_fn
    return decorator


def resource_resolver_from_args(key):
    @contextmanager
    def resource_from_args(args, config):
        yield args[key]
    return resource_from_args


def with_resource(*resource_keys):
    def decorator(f):
        resolvers = tuple(resource_resolver_map.get(key) or
                          resource_resolver_from_args(key)
                          for key in resource_keys)
        with_resource_map[f] = resolvers
        return f
    return decorator


def resolve_resource_resolver(f):
    return with_resource_map.get(f, resource_args)


@resource_resolver('args')
def resource_args(args, config):
    yield args


@resource_resolver('config')
def resource_config(args, config):
    yield config


@resource_resolver('repo')
def resource_repo(args, config):
    repo_dir = config['repo.dir']
    with Repo.open_dir(repo_dir) as repo:
        config.update(repo.config)
        setupLogging(config)
        yield repo


@resource_resolver('create_repo')
def resource_create_repo(args, config):
    def create_repo():
        repo_dir = config['repo.dir']
        Repo.create(repo_dir)
        return repo_dir
    yield create_repo


#
# renderers
#

renderer_map = {}
with_renderer_map = {}


def renderer(*key):
    def decorator(render_fn):
        renderer_map[key] = render_fn
        return render_fn
    return decorator


def with_renderer(*key):
    def decorator(f):
        render_fn = renderer_map[key]
        with_renderer_map[f.__module__, f.__name__] = render_fn
        return f
    return decorator


def resolve_renderer(f):
    key = (f.__module__, f.__name__)
    return with_renderer_map.get(key, render_nothing)


def render_nothing(args, config):
    def render(renderable):
        return []
    return render


@renderer('text')
def render_text(args, config):
    encoding = sys.stdout.encoding or 'utf-8'

    def render(text):
        yield text.encode(encoding)
    return render


@renderer('json')
def render_json(args, config):
    def render(renderable):
        yield json.dumps(renderable, indent=2, sort_keys=True)
        yield '\n'
    return render


@renderer('table')
def render_table(args, config):
    render_tabulate = renderer_tabulate(args, config)

    def render(renderable):
        if renderable:
            header = renderable.get('header')
            body = renderable.get('body', [])
            return render_tabulate({
                'table': body,
                'headers': header
            })
    return render


@renderer('tabulate')
def renderer_tabulate(args, config):
    options = dict((key[len('tabulate.'):], value)
                   for key, value in config.items()
                   if key.startswith('tabulate.'))
    if 'headers' in options:
        del options['headers']

    def render(renderable):
        if renderable:
            renderable = dict(renderable)
            table = renderable.pop('table')
            kwargs = dict(options)
            kwargs.update(renderable)
            yield tabulate(table, **kwargs)
            yield '\n'
    return render


@renderer('client')
def render_client(args, config):
    render_list = render_client_list(args, config)

    def render(client):
        clients = [client] if client else []
        return render_list(clients)
    return render


@renderer('client', list)
def render_client_list(args, config):
    render_tbl = render_table(args, config)

    def render(clients):
        table = make_clients_table(clients)
        return render_tbl(table)
    return render


@renderer('token')
def render_token(args, config):
    render_list = render_token_list(args, config)

    def render(token):
        tokens = [token] if token else []
        return render_list(tokens)
    return render


@renderer('token', list)
def render_token_list(args, config):
    render_tbl = render_table(args, config)

    def render(tokens):
        table = make_tokens_table(tokens)
        return render_tbl(table)
    return render


@renderer('basetoken')
def render_basetoken(args, config):
    render_list = render_basetoken_list(args, config)

    def render(basetoken):
        list = [basetoken] if basetoken else []
        return render_list(list)
    return render


@renderer('basetoken', list)
def render_basetoken_list(args, config):
    render_tbl = render_table(args, config)

    def render(basetokens):
        table = make_basetoken_table(basetokens)
        return render_tbl(table)
    return render


@renderer('user')
def render_user(args, config):
    render_list = render_user_list(args, config)

    def render(user):
        list = [user] if user else []
        return render_list(list)
    return render


@renderer('user', list)
def render_user_list(args, config):
    render_tbl = render_table(args, config)

    def render(users):
        table = make_users_table(users)
        return render_tbl(table)
    return render


#
# renderables
#


def make_clients_table(clients):
    header = [
        '_id',
        'client_id',
        'Alias',
        'Flow Type',
    ]
    body = [[
        client._id,
        client.client_id,
        client.alias,
        client.flow_type
    ] for client in clients]
    return {
        'header': header,
        'body': body,
    }


def make_tokens_table(tokens):
    header = [
        '_id',
        'Client',
        'User',
        'Access Token',
        'Expires At',
        'Refresh Token',
        'Token Type',
        'Revoked',
        'Scope',
    ]
    body = []
    for token in tokens:
        body.append([
            token._id,
            token.client_alias or token.client_id,
            token.user_email or token.user_id,
            token.access_token,
            'Expired' if token.expired else str(token.expires_at),
            token.refresh_token,
            token.token_type,
            'Revoked' if token.revoked else '',
            ' '.join(shortify_scope(s) for s in token.scope_tuple),
        ])
    return {
        'header': header,
        'body': body,
    }


def make_basetoken_table(basetokens):
    header = [
        '_id',
        'Client',
        'User',
        'Refresh Token',
        'Revoked',
        'Scope',
    ]
    body = []
    for basetoken in basetokens:
        body.append([
            basetoken._id,
            basetoken.client_alias or basetoken.client_id,
            basetoken.user_email or basetoken.user_id,
            basetoken.refresh_token,
            'Revoked' if basetoken.revoked else '',
            ' '.join(shortify_scope(s) for s in basetoken.scope_tuple),
        ])

    return {
        'header': header,
        'body': body,
    }


def make_users_table(users):
    header = [
        '_id',
        'user_id',
        'Email',
        'Verified Email',
    ]
    body = []
    for user in users:
        body.append([
            user._id,
            user.user_id,
            user.email,
            str(user.verified_email),
        ])
    return {
        'header': header,
        'body': body,
    }


#
# command handlers
#


@dispatch
@with_resource('create_repo')
@with_renderer('text')
def init(create_repo):
    repo_dir = create_repo()
    return 'goauthc repository created at ' + os.path.abspath(repo_dir) + '\n'


@dispatch
@with_resource('repo')
@with_renderer('table')
def config_list(repo):
    header = ['Name', 'Value']
    body = sorted(repo.config.items())
    return {
        'header': header,
        'body': body,
    }


@dispatch
@with_resource('repo', '<name>', '<value>')
def config_set(repo, name, value):
    with repo.config_edit() as config:
        config[name] = value


@dispatch
@with_resource('repo', '<name>')
def config_delete(repo, name):
    with repo.config_edit() as config:
        del config[name]


@dispatch
@with_resource('repo')
@with_renderer('client', list)
def client_list(repo):
    return repo.clients


@dispatch
@with_resource('repo', '<client>')
@with_renderer('client')
def client_show(repo, client_id):
    return repo.get_client(client_id)


@dispatch
@with_resource('repo', '<client>')
@with_renderer('json')
def client_dump(repo, client_id):
    client = repo.get_client(client_id)
    return client.raw


@dispatch
@with_resource('repo', '<client-alias>', '<client_secret.json>', '--delete')
@with_renderer('client')
def client_import(repo, alias, path, delete_after_import):
    with file(path) as f:
        client_credentials = json.load(f)
    client = repo.put_client(client_credentials, alias=alias)
    if delete_after_import:
        try:
            os.unlink(path)
        except Exception as e:
            logger.error(e)
            logger.warning('Can\'t delete %s', path)
    return client


@dispatch
@with_resource('repo', '<client>')
def client_delete(repo, client_id):
    repo.delete_client(client_id)


@dispatch
@with_resource('repo', '<client>', '<scope>', '--flow', '--login')
@with_renderer('json')
def auth(repo, client_id, scope, flow_type, login_hint):
    scope = [canonicalize_scope(s) for s in scope]

    client = repo.get_client(client_id)
    client_id = client.client_id

    if flow_type == 'device':
        if login_hint:
            logger.warning('--login is not suppored in "device" flow type. '
                           'Ignoring...')
        flow = DeviceFlow(client.raw)
        credentials = flow.auth(scope)
    elif flow_type in ('installed', None):
        flow = InstalledAppFlow(client.raw)
        credentials = flow.auth(scope, login_hint=login_hint)
    else:
        logger.error('unrecognized --flow type: %s', flow_type)
        raise SystemExit(1)

    token_update_expires_at(credentials)
    credentials['scope'] = scope

    info = get_token_info(credentials['access_token'])
    user_data = pick(info, ['email', 'user_id', 'verified_email'])
    user_id = user_data.get('user_id')
    if user_id:
        user = repo.get_user_by_user_id(user_id)
        if user:
            if 'email' in user_data:
                user.email = user_data['email']
            if 'verified_email' in user_data:
                user.verified_email = user_data['verified_email']
        else:
            repo.put_user(user_data)

    repo.put_token(client_id, user_id, credentials)
    return credentials


@dispatch
@with_resource('repo')
@with_renderer('user', list)
def user_list(repo):
    return repo.users


@dispatch
@with_resource('repo', '<user>')
@with_renderer('user')
def user_show(repo, user_id):
    return repo.get_user(user_id)


@dispatch
@with_resource('repo', '<user>')
def user_delete(repo, user_id):
    repo.delete_user(user_id)


@dispatch
@with_resource('repo', '--client', '--user', '<scope>')
@with_renderer('token', list)
def token_list(repo, client_id, user_id, scopes):
    scopes = [canonicalize_scope(s) for s in scopes]

    return repo.get_tokens(client_id=client_id,
                           user_id=user_id,
                           scopes=scopes)


@dispatch
@with_resource('repo', '<token>')
@with_renderer('token')
def token_show(repo, token_id):
    return repo.get_token(token_id)


@dispatch
@with_resource('repo', '<token>')
@with_renderer('json')
def token_dump(repo, token_id):
    token = repo.get_token(token_id)
    return token.raw


@dispatch
@with_resource('repo', '--client', '--user', '<scope>')
@with_renderer('json')
def token_acquire(repo, client_id, user_id, scopes):
    scopes = [canonicalize_scope(s) for s in scopes]

    from .models import AccessToken
    tokens = repo.get_tokens(client_id=client_id,
                             user_id=user_id,
                             scopes=scopes,
                             exclude_expired=True,
                             exclude_revoked=True)
    tokens = tokens.order_by(AccessToken.expires_at.desc())
    tokens = list(tokens)
    if tokens:
        return tokens[0].raw

    refreshable_tokens = repo.get_tokens(client_id=client_id,
                                         user_id=user_id,
                                         scopes=scopes,
                                         exclude_revoked=True)
    refreshable_tokens = list(refreshable_tokens)
    if not refreshable_tokens:
        logger.error('No refreshable tokens.')
        raise SystemExit(1)

    token = refreshable_tokens[0]

    credentials = refresh_token(token.client.raw, token.refresh_token)
    token_update_expires_at(credentials)
    new_token = repo.add_access_token(token.base_token, credentials)
    return new_token.raw


@dispatch
@with_resource('repo', '<token>')
@with_renderer('json')
def token_info(repo, token_id):
    token = repo.get_token(token_id)
    info = get_token_info(token.access_token)
    return info


@dispatch
@with_resource('repo', '<token>')
@with_renderer('token')
def token_refresh(repo, token_id):
    token = repo.get_token(token_id)

    credentials = refresh_token(token.client.raw, token.refresh_token)
    token_update_expires_at(credentials)
    new_token = repo.add_access_token(token.base_token, credentials)
    repo.session.flush()
    return new_token


@dispatch
@with_resource('repo', '<token>')
@with_renderer('token', list)
def token_revoke(repo, token_id):
    token_id_list = [token_id]
    tokens = (repo.get_token(token_id) for token_id in token_id_list)
    tokens = (token for token in tokens if token)
    tokens = list(tokens)

    revoked = {}
    for token in tokens:
        if token._id in revoked:
            continue
        try:
            revoke_token(token.refresh_token)
        except Exception as e:
            logger.error(e)
        else:
            token.revoked = True
            for token in token.base_token.access_tokens:
                revoked[token._id] = token
    return revoked.values()


@dispatch
@with_resource('repo', '<token>')
def token_delete(repo, token_id):
    repo.delete_token(token_id)


def token_update_expires_at(token):
    token['expires_at'] = int(time.time()) + token['expires_in']


@dispatch
@with_resource('repo')
@with_renderer('basetoken', list)
def basetoken_list(repo):
    return repo.basetokens


@dispatch
@with_resource('repo', '<basetoken>')
@with_renderer('basetoken')
def basetoken_show(repo, basetoken_id):
    return repo.get_basetoken(basetoken_id)


@dispatch
@with_resource('repo', '<basetoken>')
def basetoken_delete(repo, basetoken_id):
    repo.delete_basetoken(basetoken_id)


HTTPS_GOOGLEAPIS_AUTH = 'https://www.googleapis.com/auth/'


def canonicalize_scope(scope):
    if scope in ('email', 'profile'):
        return scope

    if '/' not in scope:
        return HTTPS_GOOGLEAPIS_AUTH + scope

    return scope


def shortify_scope(scope):
    if scope.startswith(HTTPS_GOOGLEAPIS_AUTH):
        return scope[len(HTTPS_GOOGLEAPIS_AUTH):]
    return scope


def pick(d, keys):
    return dict((k, d[k]) for k in keys if k in d)
