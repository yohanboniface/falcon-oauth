import pytest
from .base import Client, User, Token, Grant, db, application

models = [Client, User, Token, Grant]


def pytest_configure(config):
    for model in models:
        model.create_table(True)


def pytest_unconfigure(config):
    db.drop_tables(models)


def pytest_runtest_setup(item):
    # Delete in reverse way not to break FK constraints.
    for model in models[::-1]:
        model.delete().execute()
        assert not model.select().count()


@pytest.fixture
def app():
    return application


@pytest.fixture
def user():

    def _(**props):
        props.setdefault('username', 'Jess')
        return User.create(**props)

    return _


@pytest.fixture
def clientmodel(user):

    def _(**props):
        defaults = dict(name="myclient", user=user(), client_id=123456,
                        client_secret="secret", _redirect_uris='/ok')
        defaults.update(props)
        return Client.create(**defaults)

    return _


@pytest.fixture
def token(clientmodel):

    def _(**props):
        client = clientmodel()
        defaults = dict(client=client, user=client.user, access_token="token",
                        token_type="client_credentials")
        defaults.update(props)
        return Token.create(**defaults)

    return _
