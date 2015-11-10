from datetime import datetime, timedelta
from functools import wraps

import falcon
from falcon_oauth.provider.oauth2 import OAuthProvider
import peewee


db = peewee.SqliteDatabase(':memory:')


class BaseModel(peewee.Model):

    class Meta:
        database = db


class User(BaseModel):
    username = peewee.CharField(max_length=100)

    def check_password(self, password):
        return password != 'wrong'


class Client(BaseModel):

    GRANT_TYPES = (
        ('authorization_code', 'Authorization code'),
        ('implicit', 'Implicit'),
        ('password', 'Resource owner password-based'),
        ('client_credentials', 'Client credentials'),
    )

    name = peewee.CharField(max_length=100)
    user = peewee.ForeignKeyField(User)
    client_id = peewee.CharField(primary_key=True, unique=True)
    client_secret = peewee.CharField(unique=True, max_length=55, index=True)
    _redirect_uris = peewee.CharField()
    _default_scopes = peewee.CharField(default='email')
    grant_type = peewee.CharField(choices=GRANT_TYPES, default='password')
    is_confidential = peewee.BooleanField(default=False)

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0] if self.redirect_uris else None

    @property
    def allowed_grant_types(self):
        return [id for id, name in self.GRANT_TYPES]

    @property
    def redirect_uris(self):
        return self._redirect_uris.split(',')

    @property
    def default_scopes(self):
        return self._default_scopes.split()


class Token(BaseModel):
    user = peewee.ForeignKeyField(User)
    client = peewee.ForeignKeyField(Client)
    token_type = peewee.CharField(max_length=40)
    access_token = peewee.CharField(max_length=255)
    refresh_token = peewee.CharField(max_length=255, default="")
    scope = peewee.CharField(max_length=255, default="")
    expires = peewee.DateTimeField()

    def __init__(self, **kwargs):
        expires_in = kwargs.pop('expires_in', 60 * 60)
        kwargs['expires'] = datetime.now() + timedelta(seconds=expires_in)
        super().__init__(**kwargs)

    @property
    def scopes(self):
        return self.scope.split() if self.scope else None

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.
        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        return datetime.now() >= self.expires

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes
        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)


class Grant(BaseModel):
    user = peewee.ForeignKeyField(User)
    client = peewee.ForeignKeyField(Client)
    code = peewee.CharField(max_length=255, index=True, null=False)
    redirect_uri = peewee.CharField()
    scope = peewee.CharField(null=True)
    expires = peewee.DateTimeField()

    @property
    def scopes(self):
        return self.scope.split() if self.scope else None


auth = OAuthProvider()
application = falcon.API()

models = [Client, User, Token, Grant]


def attach_user(func):

    def attach(kwargs):
        kwargs['headers']['X-User-Id'] = str(User.get().id)

    @wraps(func)
    def inner(*args, **kwargs):
        # Subtly plug in authenticated user.
        if 'client' in kwargs:
            kwargs['client'] = kwargs['client'](before=attach)
        return func(*args, **kwargs)
    return inner


@auth.clientgetter
def clientgetter(client_id):
    return Client.select().where(Client.client_id == client_id).first()


@auth.usergetter
def usergetter(username, password, client, req):
    user = User.select().where(User.username == username).first()
    if user and user.check_password(password):
        return user
    return None


@auth.tokengetter
def tokengetter(access_token=None, refresh_token=None):
    if access_token:
        return Token.select().where(Token.access_token == access_token).first()


@auth.tokensetter
def tokensetter(metadata, req, *args, **kwargs):
    metadata['user'] = req.headers['X-User-Id']
    metadata['client'] = req.client_id
    return Token.create(**metadata)


@auth.grantgetter
def grantgetter(client_id, code):
    return Grant.get(Grant.client == client_id, Grant.code == code)


@auth.grantsetter
def grantsetter(client_id, code, req, *args, **kwargs):
    expires = datetime.utcnow() + timedelta(seconds=100)
    Grant.create(
        client_id=client_id,
        code=code['code'],
        redirect_uri=req.context.get('redirect_uri'),
        scope=' '.join(req.context.get('scopes')),
        user_id=req.context['user'].id,
        expires=expires,
    )


