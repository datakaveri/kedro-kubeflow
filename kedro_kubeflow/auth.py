import html
import logging
import os
import re
from urllib.parse import urlsplit, urlunsplit

import requests

IAP_CLIENT_ID = "IAP_CLIENT_ID"
DEX_USERNAME = "DEX_USERNAME"
DEX_PASSWORD = "DEX_PASSWORD"


class AuthHandler(object):

    log = logging.getLogger(__name__)

    def obtain_id_token(self):
        from google.auth.exceptions import DefaultCredentialsError
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token

        client_id = os.environ.get(IAP_CLIENT_ID, None)

        jwt_token = None

        if not client_id:
            self.log.debug(
                "No IAP_CLIENT_ID provided, skipping custom IAP authentication"
            )
            return jwt_token

        try:
            self.log.debug("Attempt to get IAP token for %s." + client_id)
            jwt_token = id_token.fetch_id_token(Request(), client_id)
            self.log.info("Obtained JWT token for IAP proxy authentication.")
        except DefaultCredentialsError as ex:
            self.log.warning(
                str(ex)
                + (
                    " Note that this authentication method does not work with default"
                    " credentials obtained via 'gcloud auth application-default login'"
                    " command. Refer to documentation on how to configure service account"
                    " locally"
                    " (https://cloud.google.com/docs/authentication/production#manually)"
                )
            )
        except Exception as e:
            self.log.error("Failed to obtain IAP access token. " + str(e))
        finally:
            return jwt_token

    # DEX supports Resource Owner Password Credentials Grant only for LDAP connectors.
    # And it doesn't work for Open ID Connect, e.g. Google (Moreover,
    # Google doesn't support such a flow at all).
    # Here is a hacky workaround - we imitate a web browser to navigate to the login page and
    # proceed with 'Log in with Email'. It does work,
    # but it is prone to errors if anything substantial changes in the way DEX handles login screens.
    def obtain_dex_authservice_session(self, username, password, kfp_api):
        if not username or not password:
            raise RuntimeError(
                    f"Login credentials were not found - "
                    f"No redirect after POST to: {auth_session['dex_login_url']}"
                )
        auth_session = {
            "endpoint_url": kfp_api,    # KF endpoint URL
            "redirect_url": None,   # KF redirect URL, if applicable
            "dex_login_url": None,  # Dex login URL (for POST of credentials)
            "is_secured": None,     # True if KF endpoint is secured
            "session_cookie": None  # Resulting session cookies in the form "key1=value1; key2=value2"
        }

        # use a persistent session (for cookies)
        with requests.Session() as s:

            ################
            # Determine if Endpoint is Secured
            ################
            resp = s.get(kfp_api, allow_redirects=True)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"HTTP status code '{resp.status_code}' for GET against: {kfp_api}"
                )

            auth_session["redirect_url"] = resp.url

            # if we were NOT redirected, then the endpoint is UNSECURED
            if len(resp.history) == 0:
                auth_session["is_secured"] = False
                return auth_session
            else:
                auth_session["is_secured"] = True

            ################
            # Get Dex Login URL
            ################
            redirect_url_obj = urlsplit(auth_session["redirect_url"])

            # if we are at `/auth?=xxxx` path, we need to select an auth type
            if re.search(r"/auth$", redirect_url_obj.path): 
                
                #######
                # TIP: choose the default auth type by including ONE of the following
                #######
                
                # OPTION 1: set "staticPasswords" as default auth type
                redirect_url_obj = redirect_url_obj._replace(
                    path=re.sub(r"/auth$", "/auth/local", redirect_url_obj.path)
                )
                # OPTION 2: set "ldap" as default auth type 
                # redirect_url_obj = redirect_url_obj._replace(
                #     path=re.sub(r"/auth$", "/auth/ldap", redirect_url_obj.path)
                # )
                
            # if we are at `/auth/xxxx/login` path, then no further action is needed (we can use it for login POST)
            if re.search(r"/auth/.*/login$", redirect_url_obj.path):
                auth_session["dex_login_url"] = redirect_url_obj.geturl()

            # else, we need to be redirected to the actual login page
            else:
                # this GET should redirect us to the `/auth/xxxx/login` path
                resp = s.get(redirect_url_obj.geturl(), allow_redirects=True)
                if resp.status_code != 200:
                    raise RuntimeError(
                        f"HTTP status code '{resp.status_code}' for GET against: {redirect_url_obj.geturl()}"
                    )

                # set the login url
                auth_session["dex_login_url"] = resp.url

            ################
            # Attempt Dex Login
            ################
            data = {
                "login": username,
                "password": password,
            }
            resp = s.post(
                auth_session["dex_login_url"],
                data=data,
                allow_redirects=True
            )
            if len(resp.history) == 0:
                raise RuntimeError(
                    f"Login credentials were probably invalid - "
                    f"No redirect after POST to: {auth_session['dex_login_url']}"
                )
        
            return s.cookies.get_dict()["authservice_session"]
