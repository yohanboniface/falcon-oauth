# coding: utf-8

import logging
from functools import wraps

import falcon

from oauthlib import oauth2
from oauthlib.oauth2 import Server
from .validator import OAuthValidator
from ...utils import patch_response, extract_params, maybe_args


log = logging.getLogger('falcon_oauth')


class OAuthProvider(object):
    """Provide secure services using OAuth2.

    The server should provide an authorize handler and a token hander,
    But before the handlers are implemented, the server should provide
    some getters for the validation.

    Configure :meth:`tokengetter` and :meth:`tokensetter` to get and
    set tokens. Configure :meth:`grantgetter` and :meth:`grantsetter`
    to get and set grant tokens. Configure :meth:`clientgetter` to
    get the client.

    Configure :meth:`usergetter` if you need password credential
    authorization.

    With everything ready, implement the authorization workflow:

        * :meth:`authorize_handler` for consumer to confirm the grant
        * :meth:`token_handler` for client to exchange access token

    And now you can protect the resource with scopes::

        @app.route('/api/user')
        @oauth.require_oauth('email', 'username')
        def user():
            return jsonify(request.oauth.user)
    """

    def __init__(self, error_uri=None, expires_in=None, validator=None,
                 usergetter=None, clientgetter=None, tokengetter=None,
                 tokensetter=None, grantgetter=None, grantsetter=None,
                 token_generator=None, refresh_token_generator=None,
                 server=None, on_error=None):
        self._error_uri = error_uri
        self._expires_in = expires_in
        self._validator = validator
        self._usergetter = usergetter
        self._clientgetter = clientgetter
        self._tokengetter = tokengetter
        self._tokensetter = tokensetter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter
        self._token_generator = token_generator
        self._refresh_token_generator = refresh_token_generator
        self._server = server
        self._on_error = on_error

    @property
    def error_uri(self):
        """The error page URI.

        When something turns error, it will redirect to this error page.
        """
        if not self._error_uri:
            self._error_uri = '/oauth/error'
        return self._error_uri

    @property
    def server(self):
        """
        All in one endpoints. This property is created automaticaly
        if you have implemented all the getters and setters.

        However, if you are not satisfied with the getter and setter,
        you can create a validator with :class:`OAuth2RequestValidator`::

            class MyValidator(OAuth2RequestValidator):
                def validate_client_id(self, client_id):
                    # do something
                    return True

        And assign the validator for the provider::

            oauth._validator = MyValidator()
        """
        if not self._server:
            if not self._validator:
                accessors = ['_clientgetter', '_tokengetter', '_tokensetter',
                             '_grantgetter', '_grantsetter']
                for accessor in accessors:
                    if not hasattr(self, accessor):
                        raise RuntimeError(
                            'Missing required accessor {}'.format(accessor))

                self._validator = OAuthValidator(
                    clientgetter=self._clientgetter,
                    tokengetter=self._tokengetter,
                    grantgetter=self._grantgetter,
                    usergetter=self._usergetter,
                    tokensetter=self._tokensetter,
                    grantsetter=self._grantsetter,
                )
            self._server = Server(
                self._validator,
                token_expires_in=self._expires_in,
                token_generator=self._token_generator,
                refresh_token_generator=self._refresh_token_generator,
            )
        return self._server

    def clientgetter(self, f):
        """Register a function as the client getter.

        The function accepts one parameter `client_id`, and it returns
        a client object with at least these information:

            - client_id: A random string
            - client_secret: A random string
            - redirect_uris: A list of redirect uris
            - default_redirect_uri: One of the redirect uris
            - default_scopes: Default scopes of the client

        The client may contain more information, which is suggested:

            - allowed_grant_types: A list of grant types
            - allowed_response_types: A list of response types
            - validate_scopes: A function to validate scopes

        Implement the client getter::

            @oauth.clientgetter
            def get_client(client_id):
                client = get_client_model(client_id)
                # Client is an object
                return client
        """
        self._clientgetter = f
        return f

    def usergetter(self, f):
        """Register a function as the user getter.

        This decorator is only required for **password credential**
        authorization::

            @oauth.usergetter
            def get_user(username, password, client, request,
                         *args, **kwargs):
                # client: current request client
                if not client.has_password_credential_permission:
                    return None
                user = User.get_user_by_username(username)
                if not user.validate_password(password):
                    return None

                # parameter `request` is an OAuthlib Request object.
                # maybe you will need it somewhere
                return user
        """
        self._usergetter = f
        return f

    def tokengetter(self, f):
        """Register a function as the token getter.

        The function accepts an `access_token` or `refresh_token` parameters,
        and it returns a token object with at least these information:

            - access_token: A string token
            - refresh_token: A string token
            - client_id: ID of the client
            - scopes: A list of scopes
            - expires: A `datetime.datetime` object
            - user: The user object

        The implementation of tokengetter should accepts two parameters,
        one is access_token the other is refresh_token::

            @oauth.tokengetter
            def bearer_token(access_token=None, refresh_token=None):
                if access_token:
                    return get_token(access_token=access_token)
                if refresh_token:
                    return get_token(refresh_token=refresh_token)
                return None
        """
        self._tokengetter = f
        return f

    def tokensetter(self, f):
        """Register a function to save the bearer token.

        The setter accepts two parameters at least, one is token,
        the other is request::

            @oauth.tokensetter
            def set_token(token, request, *args, **kwargs):
                save_token(token, request.client, request.user)

        The parameter token is a dict, that looks like::

            {
                u'access_token': u'6JwgO77PApxsFCU8Quz0pnL9s23016',
                u'token_type': u'Bearer',
                u'expires_in': 3600,
                u'scope': u'email address'
            }

        The request is an object, that contains an user object and a
        client object.
        """
        self._tokensetter = f
        return f

    def grantgetter(self, f):
        """Register a function as the grant getter.

        The function accepts `client_id`, `code` and more::

            @oauth.grantgetter
            def grant(client_id, code):
                return get_grant(client_id, code)

        It returns a grant object with at least these information:

            - delete: A function to delete itself
        """
        self._grantgetter = f
        return f

    def grantsetter(self, f):
        """Register a function to save the grant code.

        The function accepts `client_id`, `code`, `request` and more::

            @oauth.grantsetter
            def set_grant(client_id, code, request, *args, **kwargs):
                save_grant(client_id, code, request.user, request.scopes)
        """
        self._grantsetter = f
        return f

    def authorize_handler(self, f):
        """Authorization handler decorator.

        This decorator will sort the parameters and headers out, and
        pre validate everything::

            @app.route('/oauth/authorize', methods=['GET', 'POST'])
            @oauth.authorize_handler
            def authorize(*args, **kwargs):
                if request.method == 'GET':
                    # render a page for user to confirm the authorization
                    return render_template('oauthorize.html')

                confirm = request.form.get('confirm', 'no')
                return confirm == 'yes'
        """
        @wraps(f)
        def decorated(req, resp, *args, **kwargs):
            # raise if server not implemented
            server = self.server
            uri, http_method, body, headers = extract_params(req)

            redirect_uri = req.params.get('redirect_uri', self.error_uri)
            log.debug('Found redirect_uri %s.', redirect_uri)
            if req.method in ('GET', 'HEAD'):
                try:
                    ret = server.validate_authorization_request(
                        uri, http_method, body, headers
                    )
                    scopes, credentials = ret
                    kwargs['scopes'] = scopes
                    kwargs.update(credentials)
                except oauth2.FatalClientError as e:
                    log.debug('Fatal client error %r', e)
                    resp.status = falcon.HTTP_SEE_OTHER
                    resp.headers['Location'] = redirect_uri
                except oauth2.OAuth2Error as e:
                    log.debug('OAuth2Error: %r', e)
                    resp.status = falcon.HTTP_SEE_OTHER
                    resp.headers['Location'] = redirect_uri
                else:
                    try:
                        rv = f(*args, **kwargs)
                    except oauth2.FatalClientError as e:
                        log.debug('Fatal client error %r', e)
                        resp.status = falcon.HTTP_SEE_OTHER
                        resp.headers['Location'] = redirect_uri
                    except oauth2.OAuth2Error as e:
                        log.debug('OAuth2Error: %r', e)
                        resp.status = falcon.HTTP_SEE_OTHER
                        resp.headers['Location'] = redirect_uri
                    else:
                        if rv:
                            if not isinstance(rv, bool):
                                resp.body = rv
                            else:
                                self.confirm_authorization_request(req, resp)
                        else:
                            # denied by user
                            e = oauth2.AccessDeniedError()
                            log.debug('OAuth2Error: %r', e)
                            resp.status = falcon.HTTP_SEE_OTHER
                            resp.headers['Location'] = redirect_uri
        return decorated

    def confirm_authorization_request(self, req, resp):
        """When consumer confirm the authorization."""
        server = self.server
        scope = req.params.get('scope') or ''
        scopes = scope.split()
        credentials = dict(
            client_id=req.params.get('client_id'),
            redirect_uri=req.params.get('redirect_uri', None),
            response_type=req.params.get('response_type', None),
            state=req.params.get('state', None)
        )
        log.debug('Fetched credentials from request %r.', credentials)
        redirect_uri = credentials.get('redirect_uri')
        log.debug('Found redirect_uri %s.', redirect_uri)

        uri, http_method, body, headers = extract_params(req)
        try:
            headers, body, status = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            log.debug('Authorization successful.')
        except oauth2.FatalClientError as e:
            log.debug('Fatal client error %r', e)
            redirect(e.in_uri(self.error_uri))
        except oauth2.OAuth2Error as e:
            log.debug('OAuth2Error: %r', e)
            redirect(e.in_uri(redirect_uri or self.error_uri))
        else:
            patch_response(resp, headers, body, status)

    def verify_request(self, req, scopes):
        """Verify current request, get the oauth data.

        If you can't use the ``require_oauth`` decorator, you can fetch
        the data in your request body::

            Class YourResource:

                def on_get(self, req, resp):
                    valid, oauth_req = oauth.verify_request(req, ['email'])
                    if valid:
                        return jsonify(user=oauth_req.user)
                    return jsonify(status='error')
        """
        uri, http_method, body, headers = extract_params(req)
        return self.server.verify_request(
            uri, http_method, body, headers, scopes
        )

    def token_endpoint(self, method):
        """Access/refresh token handler decorator.

        The decorated function should return an dictionary or None as
        the extra credentials for creating the token response.

            Class Token:

                @auth.token_endpoint
                def on_get(self, req, resp):
                    return None
            app.add_route('/auth/token', Token())
        """
        @wraps(method)
        def decorated(resource, req, resp, *args, **kwargs):
            server = self.server
            uri, http_method, body, headers = extract_params(req)
            credentials = method(resource, req, resp, *args, **kwargs) or {}
            log.debug('Fetched extra credentials, %r.', credentials)
            headers, body, status = server.create_token_response(
                uri, http_method, body, headers, credentials
            )
            patch_response(resp, headers, body, status)
        return decorated

    def revoke_endpoint(self, method):
        """Access/refresh token revoke decorator.

        Any return value by the decorated function will get discarded as
        defined in [`RFC7009`_].

        As per [`RFC7009`_] it is recommended to only allow
        the `POST` method::

            Class RevokeToken:

                @auth.revoke_endpoint
                def on_get(self, req, resp):
                    pass
            app.add_route('/auth/revoke', RevokeToken())

        .. _`RFC7009`: http://tools.ietf.org/html/rfc7009
        """

        @wraps(method)
        def decorated(resource, req, resp, *args, **kwargs):
            server = self.server

            token = req.params.get('token')
            req.context['token_type_hint'] = req.params.get('token_type_hint')
            if token:
                req.context['token'] = token

            uri, http_method, body, headers = extract_params(req)
            headers, body, status = server.create_revocation_response(
                uri, headers=headers, body=body, http_method=http_method)
            return patch_response(headers, body, status)
        return decorated

    @maybe_args
    def protect(self, method, *scopes):
        """Protect resource with specified scopes."""

        @wraps(method)
        def decorated(resource, req, resp, *args, **kwargs):

            if req.context.get('oauth'):
                return method(resource, req, resp, *args, **kwargs)

            valid, oauth_req = self.verify_request(req, scopes)

            if not valid:
                if self._on_error:
                    return self._on_error(req, resp)
                challenge = 'Bearer realm="{}"'.format(' '.join(scopes) or '*')
                raise falcon.HTTPUnauthorized('Auth required', 'Auth Required',
                                              [challenge])
            req.context['oauth'] = oauth_req
            return method(resource, req, resp, *args, **kwargs)

        return decorated
