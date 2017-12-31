import os

from pprint import pformat

from oic import rndstr
from oic.oic import Client as OIDCClient
from oic.oic.message import AuthorizationResponse, RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

__author__ = 'regu0004'


class Client(object):
    # DONE specify the correct path
    ROOT_PATH = "../../"
    # DONE specify the correct URL
    ISSUER = "http://localhost"

    def __init__(self, client_metadata):
        self.client = OIDCClient(client_authn_method=CLIENT_AUTHN_METHOD)

        # DONE get the provider configuration information
        provider_info = self.client.provider_config('https://op1.test.inacademia.org')

        # Uncomment for signed userinfo
        # client_metadata.update({"userinfo_signed_response_alg": "RS256"})

        # DONE register with the provider using the client_metadata
        # Uncomment for dynamic registration
        self.client.register(provider_info["registration_endpoint"], **client_metadata)

        # Uncomment for static registration (Use code flow)
        # client_metadata.update({"client_id": "dpLXCIQRjADs",
        #                         "client_secret": "33c50b922fe04eaa86625f784e609c3908007c179473f0dc504732b3"})
        # client_reg = RegistrationResponse(**client_metadata)
        # self.client.store_registration_info(client_reg)


    def authenticate(self, session):
        # Use the session object to store state between requests

        # DONE make authentication request
        session["state"] = rndstr()
        session["nonce"] = rndstr()
        args = {
            "client_id": self.client.client_id,

            # Uncomment these two to use CODE flow
            "response_type": "code",
            "redirect_uri": self.client.registration_response["redirect_uris"][0],

            # Uncomment these two to use IMPLICIT flow
            # "response_type": ["id_token", "token"],
            # "redirect_uri": self.client.registration_response["redirect_uris"][1],

            # Uncomment these two to use HYBRID flow
            # "response_type": ["code", "id_token"],
            # "redirect_uri": self.client.registration_response["redirect_uris"][1],

            "scope": ["email openid offline_access"],
            "nonce": session["nonce"],
            "state": session["state"],
            "prompt": "consent",

            # Uncomment to request claims
            # "claims": {
            #     "userinfo": {
            #         "given_name": {
            #             "essential": True,
            #         },
            #         "family_name": {
            #             "essential": True,
            #         },
            #         "nickname": None
            #     },
            #     "id_token": {
            #         "email": {
            #             "essential": True,
            #         },
            #         "phone_number": None,
            #     }
            # },
        }

        self.client.authz_req = auth_req = self.client.construct_AuthorizationRequest(request_args=args)

        # DONE insert the redirect URL
        login_url = auth_req.request(self.client.authorization_endpoint)

        return login_url

    def code_flow_callback(self, auth_response, session):
        # DONE parse the authentication response
        aresp = self.client.parse_response(AuthorizationResponse, info=auth_response, sformat="urlencoded")

        # DONE validate the 'state' parameter
        assert aresp['state'] == session['state']

        # DONE make token request
        args = {"code": aresp["code"]}

        resp = self.client.do_access_token_request(state=aresp["state"], request_args=args,
                                                   authn_method="client_secret_basic")

        # DONE? validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)
        assert (session['nonce'] == resp['id_token']['nonce'])
        self.client.verify_id_token(resp['id_token'], self.client.authz_req)

        # DONE make userinfo request
        userinfo = self.client.do_user_info_request(state=aresp["state"])

        # DONE set the appropriate values
        access_code = aresp['code']
        access_token = resp['access_token']
        id_token_claims = resp['id_token']
        userinfo = userinfo

        return success_page(access_code, access_token, id_token_claims, userinfo)

    def implicit_flow_callback(self, auth_response, session):
        # DONE parse the authentication response
        aresp = self.client.parse_response(AuthorizationResponse, info=auth_response, sformat="urlencoded")

        # DONE validate the 'state' parameter
        assert aresp['state'] == session['state']

        # DONE? validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)
        assert (session['nonce'] == aresp['id_token']['nonce'])

        # DONE set the appropriate values
        # This is require for the hybrid flow
        if aresp.get('code'):
            args = {"code": aresp["code"]}
            resp = self.client.do_access_token_request(state=aresp["state"], request_args=args,
                                                       authn_method="client_secret_basic")

        userinfo = self.client.do_user_info_request(state=aresp["state"])

        access_code = aresp.get('code')
        access_token = aresp.get('access_token') or resp.get('access_token')
        id_token_claims = aresp['id_token']
        userinfo = userinfo

        return success_page(access_code, access_token, id_token_claims, userinfo)


def success_page(auth_code, access_token, id_token_claims, userinfo):
    html_page = read_from_file("success_page.html")
    return html_page.format(auth_code, access_token, pformat(id_token_claims.to_dict()), pformat(userinfo.to_dict()))


def read_from_file(path):
    full_path = os.path.join(Client.ROOT_PATH, path)
    with open(full_path, "r") as f:
        return f.read()
