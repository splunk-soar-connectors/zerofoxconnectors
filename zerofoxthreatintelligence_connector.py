# File: zerofoxthreatintelligence_connector.py
#
# Copyright (c) ZeroFox, 2024,
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import json

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from zerofoxthreatintelligence_consts import ZEROFOX_API_URL


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ZerofoxThreatIntelligenceConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super(ZerofoxThreatIntelligenceConnector, self).__init__()

        self._state = None

        self._base_url = ZEROFOX_API_URL
        self._access_token = None

    def _get_cti_headers(self):
        access_token = self._handle_get_token()

        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "zf-source": "splunk"
        }

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Unable to parse JSON response. Error: {e}",
                ),
                None,
            )

        if 200 <= r.status_code < 399:
            self.debug_print("RETURNING JSON")
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        self.debug_print("RETURNING ERROR")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately
        if "json" in r.headers.get("Content-Type", ""):
            self.debug_print("processing json")
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            self.debug_print("processing html")
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            self.debug_print("processing empty")
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        """
        **kwargs can be any additional parameters that requests.request accepts
        """

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Invalid method: {method}"
                ),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        self.debug_print(f"URL={url}")

        try:
            r = request_func(
                url, verify=config.get("verify_server_cert", False), **kwargs
            )

            self.debug_print(f"r={r}")

        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error Connecting to server. Details: {e}",
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.debug_print("Testing Access Token...")
        self.debug_print(f"username={self._username}")
        self.debug_print(f"password={self._password}")

        params = {"username": self._username, "password": self._password}

        endpoint = "/auth/token/"

        url = ZEROFOX_API_URL + endpoint

        self.save_progress("Connecting to endpoint")

        self.debug_print(f"url={url}")

        ret_val, _ = self._make_rest_call(
            "/auth/token/", action_result, method="post", json=params, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_token(self):
        """
        Checks if the provided ZeroFOX API token is valid

        :return: bool
        """

        self.debug_print("Fetching Access Token...")
        self.debug_print(f"username={self._username}")
        self.debug_print(f"password={self._password}")

        headers = None

        params = {"username": self._username, "password": self._password}

        endpoint = "/auth/token/"

        url = ZEROFOX_API_URL + endpoint
        response = requests.post(url, headers=headers, json=params)

        self.debug_print(f"url={url}")

        self.debug_print(f"response: {response}")
        self.debug_print(f"validate_api_token status: {response.status_code}")

        if response.status_code == 200:
            json_data = response.json()
            self._access_token = json_data["access"]
            self.debug_print(f"token: {json_data['access']}")
            return json_data["access"]

        else:
            return None

    def _handle_lookup_domain(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain_name = param["domain"]
        headers = self._get_cti_headers()

        domain_endpoints = ["c2-domains", "phishing"]
        total_results = 0
        for ep in domain_endpoints:
            if ep == "c2-domains":
                endpoint = f"/cti/c2-domains/?domain={domain_name}"
            elif ep == "phishing":
                endpoint = f"/cti/phishing/?domain={domain_name}"
            else:
                continue

            ret_val, response = self._make_rest_call(
                endpoint, action_result, params=None, headers=headers
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self.debug_print(
                "-------------------------------------------------------------"
            )
            self.debug_print(f"response: {response}")
            self.debug_print(f"len: {len(response['results'])}")
            self.debug_print(
                "-------------------------------------------------------------"
            )

            total_results = total_results + len(response["results"])
            matches = response.get("results", [])

            for match in matches:
                if ep == "c2-domains":
                    match["created_at"] = match.pop("listed_at")
                    match["details"] = match.pop("tags")
                    match["ip"] = match["ip_addresses"][0]

                elif ep == "phishing":
                    match["created_at"] = match.pop("scanned")
                    match["ip"] = match["host"]["ip"]
                    match["details"] = match.pop("cert")

                action_result.add_data(match)

        summary = action_result.update_summary({})
        summary["total_objects"] = total_results
        summary["status"] = "success"
        summary["message"] = f"{total_results} results found"

        action_result.update_summary(summary)
        self.save_progress("success")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_email(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        email_address = param["email_address"]
        headers = self._get_cti_headers()

        email_endpoints = ["email-addresses", "compromised-credentials"]
        total_results = 0
        for ep in email_endpoints:
            if ep == "email-addresses":
                endpoint = f"/cti/email-addresses/?email={email_address}"
            elif ep == "compromised-credentials":
                endpoint = f"/cti/compromised-credentials/?email={email_address}"
            else:
                continue

            ret_val, response = self._make_rest_call(
                endpoint, action_result, params=None, headers=headers
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self.debug_print(
                "-------------------------------------------------------------"
            )
            self.debug_print(f"response: {response}")
            self.debug_print(f"len: {len(response['results'])}")
            self.debug_print(
                "-------------------------------------------------------------"
            )

            total_results = total_results + len(response["results"])
            matches = response.get("results", [])

            for match in matches:
                self.debug_print(f"match: {len(match)}")
                action_result.add_data(match)

        summary = action_result.update_summary({})
        summary["total_objects"] = total_results
        summary["status"] = "success"
        summary["message"] = f"{total_results} results found"
        action_result.update_summary(summary)

        self.save_progress("success")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip_address = param["ip"]
        headers = self._get_cti_headers()

        ip_endpoints = ["botnet", "disruption", "phishing"]
        total_results = 0
        for ep in ip_endpoints:
            if ep == "botnet":
                endpoint = f"/cti/botnet/?ip_address={ip_address}"
            elif ep == "disruption":
                endpoint = f"/cti/disruption/?ip={ip_address}"
            elif ep == "phishing":
                endpoint = f"/cti/phishing/?host_ip={ip_address}"
            else:
                continue

            ret_val, response = self._make_rest_call(
                endpoint, action_result, params=None, headers=headers
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self.debug_print(
                "-------------------------------------------------------------"
            )
            self.debug_print(f"response: {response}")
            self.debug_print(f"len: {len(response['results'])}")
            self.debug_print(
                "-------------------------------------------------------------"
            )

            total_results = total_results + len(response["results"])

            matches = response.get("results", [])

            for match in matches:
                self.debug_print(f"match: {len(match)}")
                self.debug_print(f"type match: {type(match)}")

                if ep == "botnet":
                    match["created_at"] = match.pop("listed_at")
                    match["threat_type"] = "botnet"

                elif ep == "phishing":
                    match["created_at"] = match.pop("scanned")
                    match["threat_type"] = "phishing"

                action_result.add_data(match)

        summary = action_result.update_summary({})
        summary["total_objects"] = total_results
        summary["status"] = "success"
        summary["message"] = f"{total_results} results found"
        action_result.update_summary(summary)

        self.save_progress("success")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_hash(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        the_hash = param["hash"]

        if len(the_hash) == 32:
            hash_type = "md5"
        elif len(the_hash) == 40:
            hash_type = "sha1"
        elif len(the_hash) == 64:
            hash_type = "sha256"
        elif len(the_hash) == 128:
            hash_type = "sha512"
        else:
            self.save_progress("Unrecognized hash length")
            return action_result.set_status(
                phantom.APP_ERROR, "Unrecognized hash length"
            )

        headers = self._get_cti_headers()

        endpoint = f"/cti/malware/?{hash_type}={the_hash}"

        ret_val, response = self._make_rest_call(
            endpoint, action_result, params=None, headers=headers
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        matches = response.get("results", [])

        for match in matches:
            action_result.add_data(match)

        self.debug_print(
            "-------------------------------------------------------------"
        )
        self.debug_print(f"response: {response}")
        self.debug_print(f"len: {len(response['results'])}")
        self.debug_print(
            "-------------------------------------------------------------"
        )
        summary = action_result.update_summary({})

        summary["total_objects"] = len(response["results"])
        summary["status"] = "success"
        summary["message"] = f"{len(response['results'])} results found"

        action_result.update_summary(summary)

        self.save_progress("success")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_exploit(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        the_cve = param["cve"]

        headers = self._get_cti_headers()

        endpoint = f"/cti/exploits/?cve={the_cve}"

        ret_val, response = self._make_rest_call(
            endpoint, action_result, params=None, headers=headers
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        matches = response.get("results", [])

        for match in matches:
            action_result.add_data(match)

        self.debug_print(
            "-------------------------------------------------------------"
        )
        self.debug_print(f"response: {response}")
        self.debug_print(f"len: {len(response['results'])}")
        self.debug_print(
            "-------------------------------------------------------------"
        )

        summary = action_result.update_summary({})
        summary["total_objects"] = len(response["results"])
        summary["status"] = "success"
        summary["message"] = f"{len(response['results'])} results found"

        action_result.update_summary(summary)

        self.save_progress("success")

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())
        self.debug_print(f"Ingesting handle action in: {param}")
        action = {
            "test_connectivity": self._handle_test_connectivity,
            "lookup_email": self._handle_lookup_email,
            "lookup_ip": self._handle_lookup_ip,
            "lookup_hash": self._handle_lookup_hash,
            "lookup_domain": self._handle_lookup_domain,
            "lookup_exploit": self._handle_lookup_exploit,
        }.get(action_id, None)

        ret_val = action(param=param) if action else phantom.APP_SUCCESS

        return ret_val

    def initialize(self):
        self._state = self.load_state()

        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = ZEROFOX_API_URL

        self._username = config.get("zerofox_username")
        self._password = config.get("zerofox_password")

        self.debug_print("INITIALIZE")
        self.debug_print(f"username={self._username}")
        self.debug_print(f"password={self._password}")

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = (
                f"{ZerofoxThreatIntelligenceConnector._get_phantom_base_url()}/login"
            )

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print(f"Unable to get session id from the platform. Error: {e}")
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ZerofoxThreatIntelligenceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
