import falcon
from .base import auth, application, attach_user


class MyResource:

    def on_get(self, req, resp, **kwargs):
        resp.body = '{"foo": "bar"}'

    @auth.protect
    def on_post(self, req, resp, **kwargs):
        resp.body = '{"foo": "bar"}'

application.add_route('/resource', MyResource())


class TokenResource:

    @auth.token_endpoint
    def on_post(self, req, resp, **kwargs):
        pass
application.add_route('/auth/token', TokenResource())


def test_simple_get(client):
    resp = client.get('/resource')
    assert resp.json['foo'] == 'bar'


def test_protected_without_auth_return_401(client):
    resp = client.post('/resource', {})
    assert resp.status == falcon.HTTP_401


def test_protected_with_authorization_header(client, token):
    token(access_token="tokenvalue")
    resp = client.post('/resource', {},
                       headers={'Authorization': 'Bearer tokenvalue'})
    assert resp.status == falcon.HTTP_200


def test_protected_with_authorization_header_and_scopes(client, token):

    class Resource:

        @auth.protect('perm2')
        def on_post(self, req, resp, **kwargs):
            pass

    application.add_route('/resource', Resource())

    token(access_token="tokenvalue", scope="perm1 perm2")
    resp = client.post('/resource', {},
                       headers={'Authorization': 'Bearer tokenvalue'})
    assert resp.status == falcon.HTTP_200


def test_protected_with_authorization_header_and_bad_scopes(client, token):

    class Resource:

        @auth.protect('perm3')
        def on_post(self, req, resp, **kwargs):
            pass

    application.add_route('/resource', Resource())

    token(access_token="tokenvalue", scope="perm1 perm2")
    resp = client.post('/resource', {},
                       headers={'Authorization': 'Bearer tokenvalue'})
    assert resp.status == falcon.HTTP_401


@attach_user
def test_client_credentials(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'client_credentials',
        'client_id': c.client_id,
        'client_secret': c.client_secret,
    })
    assert resp.status == falcon.HTTP_200
    assert 'access_token' in resp.json


@attach_user
def test_client_credentials_unkown_client_id(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'client_credentials',
        'client_id': 'xxxblahxxx',
        'client_secret': c.client_secret,
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_client_credentials_missing_client_id(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'client_credentials',
        'client_secret': c.client_secret,
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_client_credentials_missing_client_secret(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'client_credentials',
        'client_id': c.client_id,
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_client_credentials_wrong_client_secret(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'client_credentials',
        'client_id': c.client_id,
        'client_secret': 'xxxblahxxx',
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_password(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'password',
        'username': 'user',
        'password': 'right',
        'client_id': c.client_id,
        'client_secret': c.client_secret,
    })
    assert 'error' in resp.json


@attach_user
def test_password_wrong_password(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'password',
        'username': 'user',
        'password': 'wrong',
        'client_id': c.client_id,
        'client_secret': c.client_secret,
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_password_wrong_username(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'password',
        'username': 'blah',
        'password': 'right',
        'client_id': c.client_id,
        'client_secret': c.client_secret,
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_password_wrong_client_id(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'password',
        'username': 'user',
        'password': 'right',
        'client_id': 'xxxblahxxx',
        'client_secret': c.client_secret,
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_password_missing_client_id(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'password',
        'username': 'user',
        'password': 'right',
        'client_secret': c.client_secret,
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_password_missing_client_secret(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'password',
        'username': 'user',
        'password': 'right',
        'client_id': c.client_id,
    })
    assert resp.status == falcon.HTTP_401


@attach_user
def test_password_wrong_client_secret(client, clientmodel):
    c = clientmodel()
    resp = client.post('/auth/token', data={
        'grant_type': 'password',
        'username': 'user',
        'password': 'right',
        'client_id': c.client_id,
        'client_secret': 'xxxblahxxx',
    })
    assert resp.status == falcon.HTTP_401
