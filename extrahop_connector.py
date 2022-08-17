# File: extrahop_connector.py
#
# Copyright (c) 2018-2022 Splunk Inc.
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

import ipaddress
import json
import time

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from extrahop_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ExtrahopConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ExtrahopConnector, self).__init__()

        self._state = None

        self._base_url = None
        # TODO find better way to return response headers
        self._response_headers = None

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = EXTRAHOP_ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as e:
            self.debug_print("Error occurred while fetching exception information. Details: {}".format(str(e)))

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, EXTRAHOP_VALID_INT_MSG.format(param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, EXTRAHOP_VALID_INT_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, EXTRAHOP_NON_NEG_INT_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, EXTRAHOP_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _parse_extrahop_location_header(self, location, action_result):

        # Parse the object id from the location header
        if location:
            last_slash_index = location.rindex('/') + 1
            location_id = location[last_slash_index:]
            if location_id.isdigit():
                return RetVal(phantom.APP_SUCCESS, int(location_id))
        # return error in any other case
        return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse ExtraHop location header"), location)

    def _get_extrahop_api_device_id(self, param, action_result):

        eh_api_id = param.get('eh_api_id')
        if eh_api_id:
            ret_val, eh_api_id = self._validate_integer(action_result, eh_api_id, EXTRAHOP_EH_API_ID_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
            return RetVal(phantom.APP_SUCCESS, eh_api_id)

        ip_address = param.get('ip')
        if not ip_address:
            return action_result.set_status(
                phantom.APP_ERROR, "Please provide at least one of 'ip' and 'eh_api_id' parameters"
            ), None

        params = {
            "limit": "1",
            "search_type": "ip address",
            "value": ip_address
        }

        self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(EXTRAHOP_DEVICES_ENDPOINT))

        # make rest call to get the device
        ret_val, get_devices_response = self._make_rest_call(EXTRAHOP_DEVICES_ENDPOINT, action_result, params=params)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, reassemble RetVal and return
            return RetVal(ret_val, None)

        # Grab device ID from response
        # TODO how to handle more than one device being returned (currently will just take the first)
        if get_devices_response and get_devices_response[0] and 'id' in get_devices_response[0]:
            ret_val, eh_api_id = self._validate_integer(action_result, get_devices_response[0]['id'], EXTRAHOP_EH_API_ID_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
            return RetVal(phantom.APP_SUCCESS, eh_api_id)
        else:
            # Handle device not being found
            return action_result.set_status(phantom.APP_ERROR, "ExtraHop device not found with IP {}".format(ip_address)), None

    def _process_empty_response(self, response, action_result):

        if response.status_code in [200, 201, 204, 207]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(
            phantom.APP_ERROR, "Status code: {}. Empty response and no information in the header".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()

            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = 'Error occurred while connecting to the ExtraHop server'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        # For the valid 201 response, we are getting application/json in the header and empty json response in the body
        try:
            resp_json = r.json() if r.text else {}
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(err_msg)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        # Add ExtraHop headers to each request
        if not headers:
            headers = {}

        headers['Accept'] = 'application/json'
        headers['Authorization'] = 'ExtraHop apikey={}'.format(config['api_key'])

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                json=data,
                headers=headers,
                verify=config.get('verify_server_cert', True),
                params=params,
                timeout=EXTRAHOP_DEFAULT_TIMEOUT
            )
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(err_msg)), resp_json)

        # TODO find better way to return response headers
        self._response_headers = r.headers

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to ExtraHop")
        # make rest call to get basic extrahop details
        ret_val, _ = self._make_rest_call(EXTRAHOP_BASIC_DETAILS_ENDPOINT, action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity to ExtraHop Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity to ExtraHop Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        ip_addresses = [x.strip() for x in param['ip'].split(',')]
        ip_addresses = list(filter(None, ip_addresses))

        # Remove duplicate IPs from the list
        ip_addresses = list(set(ip_addresses))

        parameters = {
            "search_type": "ip address",
            "value": None
        }

        for ip in ip_addresses:

            parameters['value'] = ip

            self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(EXTRAHOP_DEVICES_ENDPOINT))

            # make rest call to get list of devices
            ret_val, get_devices_response = self._paginator(EXTRAHOP_DEVICES_ENDPOINT, action_result, parameter=parameters)

            if phantom.is_fail(ret_val):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            # Now post process the data
            # Add the response into the data section
            for device_obj in get_devices_response:
                action_result.add_data(self._sanitize_object(device_obj))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["device_count"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_peers(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, minutes = self._validate_integer(action_result, param.get('minutes', 30), EXTRAHOP_MINUTES_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        peer_role = param.get('peer_role', "any")
        if peer_role not in EXTRAHOP_PEER_ROLE_LIST:
            return action_result.set_status(
                phantom.APP_ERROR, EXTRAHOP_INVALID_SELECTION.format("peer_role", ", ".join(EXTRAHOP_PEER_ROLE_LIST)))
        protocol = param.get('protocol', "any")

        # get extrahop api device id by ip address
        ret_val, eh_api_id = self._get_extrahop_api_device_id(param, action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        body = {
            "from": "-{}m".format(minutes),
            "walks": [{
                "origins": [{
                    "object_id": eh_api_id,
                    "object_type": "device"
                }],
                "steps": [{
                    "relationships": [{
                        "protocol": protocol,
                        "role": peer_role
                    }]
                }]
            }]
        }

        self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(EXTRAHOP_ACTIVITY_MAP_ENDPOINT))

        # make rest call to get live activity map conversation data
        ret_val, get_activitymap_response = self._make_rest_call(EXTRAHOP_ACTIVITY_MAP_ENDPOINT, action_result, data=body, method="post")

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data
        # Initialize peer sets
        unique_client_ids = set()
        unique_server_ids = set()
        # Determine the peers
        for edge in get_activitymap_response['edges']:
            if edge["to"] == eh_api_id:
                unique_client_ids.add(edge["from"])
            elif edge["from"] == eh_api_id:
                unique_server_ids.add(edge["to"])

        # By peer role filter
        if peer_role.lower() == "client":
            unique_peer_ids = unique_client_ids
        elif peer_role.lower() == "server":
            unique_peer_ids = unique_server_ids
        else:
            unique_peer_ids = unique_client_ids.union(unique_server_ids)

        # Lookup each EH device id
        for peer_id in unique_peer_ids:

            device_uri = EXTRAHOP_DEVICE_WITH_ID_ENDPOINT.format(peer_id)

            self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(device_uri))

            # make rest call to get the device
            ret_val, get_device_response = self._make_rest_call(device_uri, action_result)

            if phantom.is_fail(ret_val):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            # Add device object to the results list
            if get_device_response:
                # Add the peer into the data section
                action_result.add_data(self._sanitize_object(get_device_response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["peer_count"] = len(unique_peer_ids)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_protocols(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly

        ret_val, minutes = self._validate_integer(action_result, param.get('minutes', 30), EXTRAHOP_MINUTES_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # get extrahop api device id by ip address
        ret_val, eh_api_id = self._get_extrahop_api_device_id(param, action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        body = {
            "edge_annotations": ["protocols"],
            "from": "-{}m".format(minutes),
            "walks": [{
                "origins": [{
                    "object_id": eh_api_id,
                    "object_type": "device"
                }],
                "steps": [{}]
            }]
        }

        self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(EXTRAHOP_ACTIVITY_MAP_ENDPOINT))

        # make rest call to get live activity map protocol data
        ret_val, get_activitymap_response = self._make_rest_call(EXTRAHOP_ACTIVITY_MAP_ENDPOINT, action_result, data=body, method="post")

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data
        # Initialize protocol sets
        unique_client_protocols = set()
        unique_server_protocols = set()
        # Determine the sets of active protocols
        for edge in get_activitymap_response['edges']:
            if 'annotations' in edge and 'protocols' in edge['annotations']:
                for protocol_list in edge['annotations']['protocols']:
                    if edge["from"] == eh_api_id:
                        unique_client_protocols.update(protocol_list['protocol'])
                    elif edge["to"] == eh_api_id:
                        unique_server_protocols.update(protocol_list['protocol'])

        # Clean up sets for presentation
        # TODO remove OTHER? does it have value?
        unique_client_protocols.discard('OTHER')
        unique_client_protocols_str = ', '.join(sorted(unique_client_protocols))
        unique_server_protocols.discard('OTHER')
        unique_server_protocols_str = ', '.join(sorted(unique_server_protocols))

        # Add the protocols into the data section
        action_result.add_data({
            "client_protocols": unique_client_protocols_str if unique_client_protocols_str else None,
            "server_protocols": unique_server_protocols_str if unique_server_protocols_str else None
        })

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["client_protocol_count"] = len(unique_client_protocols)
        summary["server_protocol_count"] = len(unique_server_protocols)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginator(self, endpoint, action_result, parameter=None, offset=0, limit=1000):

        records_list = []

        if not parameter:
            parameter = {}

        parameter["limit"] = min(EXTRAHOP_DEFAULT_LIMIT, limit)
        parameter["offset"] = offset

        while True:
            self.debug_print(f"Fetching {parameter['limit']} records from offset {parameter['offset']}")
            ret_val, response = self._make_rest_call(endpoint, action_result, params=parameter)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            records_list.extend(response)

            if len(response) < EXTRAHOP_DEFAULT_LIMIT:
                self.debug_print("Got all the available records, break the loop")
                break

            if len(records_list) >= limit:
                self.debug_print("Got the required count, returning the result")
                return phantom.APP_SUCCESS, records_list[:limit]

            parameter["offset"] += EXTRAHOP_DEFAULT_LIMIT

        return phantom.APP_SUCCESS, records_list

    def _sanitize_object(self, object):
        """
        Recursively remove empty lists, empty dicts, or None elements from a dictionary.
        :param d: Input dictionary.
        :type d: dict
        :return: Dictionary with all empty lists, and empty dictionaries removed.
        :rtype: dict
        """

        def empty(x):
            return x is None or x == {} or x == [] or x == ""

        if isinstance(object, list):
            return [v for v in (self._sanitize_object(v) for v in object) if not empty(v)]
        if isinstance(object, dict):
            return {k: v for k, v in ((k, self._sanitize_object(v)) for k, v in object.items()) if not empty(v)}
        return object

    def _handle_detect_devices(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        activity_type = param['activity_type']
        if activity_type not in EXTRAHOP_ACTIVITY_TYPE_LIST:
            return action_result.set_status(
                phantom.APP_ERROR, EXTRAHOP_INVALID_SELECTION.format("activity_type", ", ".join(EXTRAHOP_ACTIVITY_TYPE_LIST)))

        ret_val, minutes = self._validate_integer(action_result, param.get('minutes', 30), EXTRAHOP_MINUTES_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, offset = self._validate_integer(action_result, param.get('offset', 0), EXTRAHOP_OFFSET_KEY, allow_zero=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, limit = self._validate_integer(action_result, param.get('limit', 1000), EXTRAHOP_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        seconds = minutes * 60
        time_now = time.time()
        new_device_cutoff_time_ms = int((time_now - seconds) * 1000)
        new_devices_count = 0

        parameter = {
            "active_from": new_device_cutoff_time_ms,
            "search_type": activity_type
        }

        self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(EXTRAHOP_DEVICES_ENDPOINT))

        # make rest call to get devices
        ret_val, get_devices_response = self._paginator(
            EXTRAHOP_DEVICES_ENDPOINT, action_result, parameter=parameter, offset=offset, limit=limit)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data
        # Find devices discovered only in the last N minutes
        for device_obj in get_devices_response:
            if 'discover_time' in device_obj:
                device_obj = self._sanitize_object(device_obj)
                discover_time_ms = device_obj['discover_time']
                # Add the response into the data section if the device is new
                if discover_time_ms >= new_device_cutoff_time_ms:
                    action_result.add_data(device_obj)
                    new_devices_count += 1

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["new_devices_count"] = new_devices_count

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_device(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        ip_address = param['ip']

        # Optional values should use the .get() function
        # Custom device definition
        name = param.get('name', "Phantom-{}".format(ip_address))
        author = param.get('author', 'Phantom')
        description = param.get('description', 'Device created by Phantom integration for endpoint inspection')
        cidr = param.get('cidr')

        # Create the new [device]
        custom_device_body = {
            "name": name,
            "author": author,
            "description": description,
            "disabled": False,
            "criteria": [{
                "ipaddr": ip_address + cidr if cidr else ip_address,
            }]
        }

        self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(EXTRAHOP_CUSTOM_DEVICES_ENDPOINT))

        # make rest call to create the custom device
        ret_val, _ = self._make_rest_call(
            EXTRAHOP_CUSTOM_DEVICES_ENDPOINT, action_result, data=custom_device_body, method="post")

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Add the response into the data section
        data = {
            'name': name
        }
        if cidr:
            data['cidr'] = cidr
        action_result.add_data(data)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['name'] = name

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_tag_device(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        tag = param['tag']

        ret_val, eh_api_id = self._get_extrahop_api_device_id(param, action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(EXTRAHOP_TAGS_ENDPOINT))

        # make rest call to get all tags
        ret_val, get_tags_response = self._make_rest_call(EXTRAHOP_TAGS_ENDPOINT, action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Search for tag in tags
        for tag_obj in get_tags_response:
            # if tag names match (case-insensitive) then grab the tag id
            if tag_obj['name'] == tag:
                tag_id = tag_obj['id']
                break
        else:
            # If tag doesn't exist then create it
            tag_body = {
                "name": tag
            }

            self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(EXTRAHOP_TAGS_ENDPOINT))

            # make rest call to create the tag
            ret_val, _ = self._make_rest_call(EXTRAHOP_TAGS_ENDPOINT, action_result, data=tag_body, method="post")

            if phantom.is_fail(ret_val):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            returned_location = self._response_headers.get('location')
            ret_val, tag_id = self._parse_extrahop_location_header(returned_location, action_result)

            if phantom.is_fail(ret_val):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

        assign_tag_body = {
            "assign": [eh_api_id]
        }

        tag_assign_uri = EXTRAHOP_TAG_TO_DEVICE_ENDPOINT.format(tag_id)

        self.save_progress(EXTRAHOP_DEBUG_REST_ENDPOINT.format(tag_assign_uri))

        # make rest call to assign the tag to the device
        ret_val, _ = self._make_rest_call(tag_assign_uri, action_result, data=assign_tag_body, method="post")

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data({
            'tag_id': tag_id
        })

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["tag"] = tag
        summary["extrahop_device_id"] = eh_api_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_device':
            ret_val = self._handle_get_device(param)

        elif action_id == 'get_peers':
            ret_val = self._handle_get_peers(param)

        elif action_id == 'get_protocols':
            ret_val = self._handle_get_protocols(param)

        elif action_id == 'detect_devices':
            ret_val = self._handle_detect_devices(param)

        elif action_id == 'create_device':
            ret_val = self._handle_create_device(param)

        elif action_id == 'tag_device':
            ret_val = self._handle_tag_device(param)

        return ret_val

    def _validate_ip(self, input_data):
        ip_addresses = [x.strip() for x in input_data.split(',')]
        ip_addresses = list(filter(None, ip_addresses))

        for ip in ip_addresses:
            try:
                ipaddress.ip_address(ip.strip())
            except Exception:
                return False

        return True

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print(EXTRAHOP_STATE_FILE_CORRUPT_ERR)
            self._state = {"app_version": self.get_app_json().get("app_version")}

        # get the asset config
        config = self.get_config()

        self._base_url = 'https://{}'.format(config['base_url'])

        self.set_validator('ip', self._validate_ip)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
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
            login_url = "{}login".format(BaseConnector._get_phantom_base_url())
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=EXTRAHOP_DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=EXTRAHOP_DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ExtrahopConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
