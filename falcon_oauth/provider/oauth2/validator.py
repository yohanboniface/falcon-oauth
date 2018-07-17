import logging
import os

from oauthlib.common import to_unicode
from oauthlib.oauth2 import RequestValidator

from ...utils import decode_base64, utcnow

log = logging.getLogger('falcon_oauth')


class OAuthValidator(RequestValidator):
    """Subclass of Request Validator.

    See https://github.com/oauthlib/oauthlib/blob/master/oauthlib/oauth2/rfc6749/request_validator.py  # noqa
    and https://oauthlib.readthedocs.org/en/latest/oauth2/validator.html

    :param clientgetter: a function to get client object
    :param tokengetter: a function to get bearer token
    :param tokensetter: a function to save bearer token
    :param grantgetter: a function to get grant token
    :param grantsetter: a function to save grant token
    """
    def __init__(self, clientgetter, tokengetter, grantgetter,
                 usergetter=None, tokensetter=None, grantsetter=None):
        self._clientgetter = clientgetter
        self._tokengetter = tokengetter
        self._usergetter = usergetter
        self._tokensetter = tokensetter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter

    def client_authentication_required(self, request, *args, **kwargs):
        """Determine if client authentication is required for current request.

        According to the rfc6749, client authentication is required in the
        following cases:
            - Resource Owner Password Credentials Grant, when Client type is
              Confidential or when Client was issued client credentials or
              whenever Client provided client authentication,
              see `Section 4.3.2`_.
            - Authorization Code Grant, when Client type is Confidential or
              when Client was issued client credentials or whenever Client
              provided client authentication, see `Section 4.1.3`_.
            - Refresh Token Grant, when Client type is Confidential or when
              Client was issued client credentials or whenever Client provided
              client authentication, see `Section 6`_

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Refresh Token Grant

        .. _`Section 4.3.2`: http://tools.ietf.org/html/rfc6749#section-4.3.2
        .. _`Section 4.1.3`: http://tools.ietf.org/html/rfc6749#section-4.1.3
        .. _`Section 6`: http://tools.ietf.org/html/rfc6749#section-6
        """
        grant_types = ('password', 'authorization_code', 'refresh_token')
        return request.grant_type in grant_types

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate client through means outside the OAuth 2 spec.

        Means of authentication is negotiated beforehand and may for example
        be `HTTP Basic Authentication Scheme`_ which utilizes the Authorization
        header.

        Headers may be accesses through request.headers and parameters found in
        both body and query can be obtained by direct attribute access, i.e.
        request.client_id for client_id in the URL query.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant (may be disabled)
            - Client Credentials Grant
            - Refresh Token Grant

        .. _`HTTP Basic Authentication Scheme`: http://tools.ietf.org/html/rfc1945#section-11.1  # noqa
        """
        auth = request.headers.get('Authorization', None)
        log.debug('Authenticate client %r', auth)
        if auth:
            try:
                _, s = auth.split(' ')
                client_id, client_secret = decode_base64(s).split(':')
                client_id = to_unicode(client_id, 'utf-8')
                client_secret = to_unicode(client_secret, 'utf-8')
            except Exception as e:
                log.debug('Authenticate client failed with exception: %r', e)
                return False
        else:
            client_id = request.client_id
            client_secret = request.client_secret

        client = self._clientgetter(client_id)
        if not client:
            return False

        if client.client_secret != client_secret:
            log.debug('Authenticate client failed, secret not match.')
            return False

        request.client = client
        log.debug('Authenticate client success.')
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a non-confidential client.

        A non-confidential client is one that is not required to authenticate
        through other means, such as using HTTP Basic.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        log.debug('Authenticate client id %r.', client_id)

        client = self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate failed, client not found.')
            return False

        # attach client on request for convenience
        request.client = client
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             *args, **kwargs):
        """Ensure that the authorization process represented by this authorization
        code began with this 'redirect_uri'.

        If the client specifies a redirect_uri when obtaining code then that
        redirect URI must be bound to the code and verified equal in this
        method, according to RFC 6749 section 4.1.3.  Do not compare against
        the client's allowed redirect URIs, but against the URI used when the
        code was saved.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization_code.
        :param redirect_uri: Unicode absolute URI
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (during token request)
        """
        client = client or self._clientgetter(client_id)
        log.debug('Confirm redirect uri for client %r and code %r.',
                  client.client_id, code)
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)
        log.debug('Compare redirect uri for grant %r and %r.',
                  grant.redirect_uri, redirect_uri)

        testing = 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ
        if testing and redirect_uri is None:
            # For testing
            return True

        return grant.redirect_uri == redirect_uri

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        :param refresh_token: Unicode refresh token
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of scopes.

        Method is used by:
            - Refresh token grant
        """
        log.debug('Obtaining scope of refreshed token.')
        tok = self._tokengetter(refresh_token=refresh_token)
        return tok.scopes

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Get the default redirect URI for the client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        request.client = request.client or self._clientgetter(client_id)
        redirect_uri = request.client.default_redirect_uri
        log.debug('Found default redirect uri %r', redirect_uri)
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Get the default scopes for the client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of default scopes

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials grant
        """
        request.client = request.client or self._clientgetter(client_id)
        scopes = request.client.default_scopes
        log.debug('Found default scopes %r', scopes)
        return scopes

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        """Invalidate an authorization code after use.

        :param client_id: Unicode client identifier
        :param code: The authorization code grant (request.code).
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Authorization Code Grant
        """
        log.debug('Destroy grant token for client %r, %r', client_id, code)
        grant = self._grantgetter(client_id=client_id, code=code)
        if grant:
            grant.delete()

    def save_authorization_code(self, client_id, code, request,
                                *args, **kwargs):
        """Persist the authorization_code.

        The code should at minimum be stored with:
            - the client_id (client_id)
            - the redirect URI used (request.redirect_uri)
            - a resource owner / user (request.user)
            - the authorized scopes (request.scopes)
            - the client state, if given (code.get('state'))

        The 'code' argument is actually a dictionary, containing at least a
        'code' key with the actual authorization code:

            {'code': 'sdf345jsdf0934f'}

        It may also have a 'state' key containing a nonce for the client, if it
        chose to send one.  That value should be saved and used in
        'validate_code'.

        :param client_id: Unicode client identifier
        :param code: A dict of the authorization code grant and, optionally,
                     state.
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Authorization Code Grant
        """
        log.debug(
            'Persist authorization code %r for client %r',
            code, client_id
        )
        request.client = request.client or self._clientgetter(client_id)
        self._grantsetter(client_id, code, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token.

        The Bearer token should at minimum be associated with:
            - a client and it's client_id, if available
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)
            - an expiration time
            - a refresh token, if issued

        The Bearer token dict may hold a number of items::

            {
                'token_type': 'Bearer',
                'access_token': 'askfjh234as9sd8',
                'expires_in': 3600,
                'scope': 'string of space separated authorized scopes',
                'refresh_token': '23sdf876234',  # if issued
                'state': 'given_by_client',  # if supplied by client
            }

        Note that while "scope" is a string-separated list of authorized
        scopes, the original list is still available in request.scopes

        :param client_id: Unicode client identifier
        :param token: A Bearer token dict
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by all core grant types issuing Bearer tokens:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant (might not associate a
              client)
            - Client Credentials grant
        """
        log.debug('Save bearer token %r', token)
        self._tokensetter(token, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        """Ensure the Bearer token is valid and authorized access to scopes.

        :param token: A string of random characters.
        :param scopes: A list of scopes associated with the protected resource.
        :param request: The HTTP Request (oauthlib.common.Request)

        A key to OAuth 2 security and restricting impact of leaked tokens is
        the short expiration time of tokens, *always ensure the token has not
        expired!*.

        Two different approaches to scope validation:

            1) all(scopes). The token must be authorized access to all scopes
                            associated with the resource. For example, the
                            token has access to ``read-only`` and ``images``,
                            thus the client can view images but not upload new.
                            Allows for fine grained access control through
                            combining various scopes.

            2) any(scopes). The token must be authorized access to one of the
                            scopes associated with the resource. For example,
                            token has access to ``read-only-images``.
                            Allows for fine grained, although arguably less
                            convenient, access control.

        A powerful way to use scopes would mimic UNIX ACLs and see a scope
        as a group with certain privileges. For a restful API these might
        map to HTTP verbs instead of read, write and execute.

        Note, the request.user attribute can be set to the resource owner
        associated with this token. Similarly the request.client and
        request.scopes attribute can be set to associated client object
        and authorized scopes. If you then use a decorator such as the
        one provided for django these attributes will be made available
        in all protected views as keyword arguments.

        :param token: Unicode Bearer token
        :param scopes: List of scopes (defined by you)
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is indirectly used by all core Bearer token issuing grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        log.debug('Validate bearer token %r', token)
        tok = self._tokengetter(access_token=token)
        if not tok:
            msg = 'Bearer token not found.'
            request.error_message = msg
            log.debug(msg)
            return False

        # validate expires
        if utcnow() > tok.expires:
            msg = 'Bearer token is expired.'
            request.error_message = msg
            log.debug(msg)
            return False

        # validate scopes
        if scopes and not set(tok.scopes) & set(scopes):
            msg = 'Bearer token scope not valid.'
            request.error_message = msg
            log.debug(msg)
            return False

        request.access_token = tok
        request.user = tok.user
        request.scopes = scopes

        if hasattr(tok, 'client'):
            request.client = tok.client
        elif hasattr(tok, 'client_id'):
            request.client = self._clientgetter(tok.client_id)
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        log.debug('Validate client %r', client_id)
        client = request.client or self._clientgetter(client_id)
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Verify that the authorization_code is valid and assigned to the given
        client.

        Before returning true, set the following based on the information
        stored with the code in 'save_authorization_code':

            - request.user
            - request.state (if given)
            - request.scopes
        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes
        must also be set.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization code
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        client = client or self._clientgetter(client_id)
        log.debug(
            'Validate code for client %r and code %r', client.client_id, code
        )
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'expires') and \
           utcnow() > grant.expires:
            log.debug('Grant is expired.')
            return False

        request.state = kwargs.get('state')
        request.user = grant.user
        request.scopes = grant.scopes
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        """Ensure client is authorized to use the grant_type requested.

        :param client_id: Unicode client identifier
        :param grant_type: Unicode grant type, i.e. authorization_code,
                           password.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
            - Refresh Token Grant
        """
        if self._usergetter is None and grant_type == 'password':
            log.debug('Password credential authorization is disabled.')
            return False

        default_grant_types = (
            'authorization_code', 'password',
            'client_credentials', 'refresh_token',
        )

        if grant_type not in default_grant_types:
            return False

        if hasattr(client, 'allowed_grant_types') and \
           grant_type not in client.allowed_grant_types:
            return False

        if grant_type == 'client_credentials':
            if not hasattr(client, 'user'):
                log.debug('Client should have a user property')
                return False
            request.user = client.user

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri requested.

        All clients should register the absolute URIs of all URIs they intend
        to redirect to. The registration is outside of the scope of oauthlib.

        :param client_id: Unicode client identifier
        :param redirect_uri: Unicode absolute URI
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        request.client = request.client or self._clientgetter(client_id)
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        """Ensure the Bearer token is valid and authorized access to scopes.

        OBS! The request.user attribute should be set to the resource owner
        associated with this refresh token.

        :param refresh_token: Unicode refresh token
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (indirectly by issuing refresh tokens)
            - Resource Owner Password Credentials Grant (also indirectly)
            - Refresh Token Grant
        """
        token = self._tokengetter(refresh_token=refresh_token)

        if token and token.client_id == client.client_id:
            # Make sure the request object contains user and client_id
            request.client_id = token.client_id
            request.user = token.user
            return True
        return False

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """Ensure client is authorized to use the response_type requested.

        :param client_id: Unicode client identifier
        :param response_type: Unicode response type, i.e. code, token.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        if response_type not in ('code', 'token'):
            return False

        if hasattr(client, 'allowed_response_types'):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        """Ensure the client is authorized access to requested scopes.

        :param client_id: Unicode client identifier
        :param scopes: List of scopes (defined by you)
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return set(client.default_scopes).issuperset(set(scopes))

    def validate_user(self, username, password, client, request,
                      *args, **kwargs):
        """Ensure the username and password is valid.

        OBS! The validation should also set the user attribute of the request
        to a valid resource owner, i.e. request.user = username or similar. If
        not set you will be unable to associate a token with a user in the
        persistance method used (commonly, save_bearer_token).

        :param username: Unicode username
        :param password: Unicode password
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Resource Owner Password Credentials Grant
        """
        log.debug('Validating username %r and its password', username)
        if self._usergetter is not None:
            user = self._usergetter(
                username, password, client, request, *args, **kwargs
            )
            if user:
                request.user = user
                return True
            return False
        log.debug('Password credential authorization is disabled.')
        return False

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Revoke an access or refresh token.

        :param token: The token string.
        :param token_type_hint: access_token or refresh_token.
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Revocation Endpoint
        """
        if token_type_hint:
            tok = self._tokengetter(**{token_type_hint: token})
        else:
            tok = self._tokengetter(access_token=token)
            if not tok:
                tok = self._tokengetter(refresh_token=token)

        if tok and tok.client_id == request.client.client_id:
            request.client_id = tok.client_id
            request.user = tok.user
            tok.delete()
            return True

        msg = 'Invalid token supplied.'
        log.debug(msg)
        request.error_message = msg
        return False
