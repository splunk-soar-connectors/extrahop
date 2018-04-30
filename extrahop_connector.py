# Description: ExtraHop Networks App for Phantom Cyber Automation
# Author(s): Dan Tucholski and ExtraHop Networks

###############################################################################
#  This file is part of an ExtraHop Supported Bundle.  Make NO MODIFICATIONS  #
###############################################################################

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from extrahop_consts import *
import requests
import json
from bs4 import BeautifulSoup
import time


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ExtrahopConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ExtrahopConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        # TODO find better way to return response headers
        self._response_headers = None

    def _parse_extrahop_location_header(self, location):

        # Parse the object id from the location header
        if location:
            last_slash_index = location.rindex('/') + 1
            location_id = location[last_slash_index:]
            if location_id.isdigit():
                return int(location_id)
        # return error in any other case
        return

    def _process_empty_reponse(self, response, action_result):

        # if response.status_code == 200:
        if response.status_code in [200, 201, 204, 207]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

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

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

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
        headers['Authorization'] = 'ExtraHop apikey=' + config['api_key']

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                json=data,
                headers=headers,
                verify=config.get('verify_server_cert', False),
                params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        # TODO find better way to return response headers
        self._response_headers = r.headers

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to ExtraHop")
        # make rest call to get basic extrahop details
        ret_val, get_extrahop_response = self._make_rest_call('/api/v1/extrahop', action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity to ExtraHop Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity to ExtraHop Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_devices(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        ip_addresses = param['ip'].split(',')

        for ip in ip_addresses:

            device_uri = "/api/v1/devices?limit=100&search_type=ip%20address&value=" + ip

            self.save_progress("Making REST call to {}".format(device_uri))

            # make rest call to get list of devices
            ret_val, get_devices_response = self._make_rest_call(device_uri, action_result)

            if (phantom.is_fail(ret_val)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            # Now post process the data
            # Add the response into the data section
            for device_obj in get_devices_response:
                action_result.add_data(device_obj)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_peers(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        ip_address = param['ip']
        minutes = param['minutes']

        # Optional values should use the .get() function
        peer_role = param.get('peer_role', "any")
        protocol = param.get('protocol', "any")
        eh_api_id = param.get('eh_api_id', None)

        # Grab EH device ID
        if not eh_api_id:

            device_uri = "/api/v1/devices?limit=100&search_type=ip%20address&value=" + ip_address

            self.save_progress("Making REST call to {}".format(device_uri))

            # make rest call to get the device
            ret_val, get_devices_response = self._make_rest_call(device_uri, action_result)

            if (phantom.is_fail(ret_val)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            # Grab device ID from response
            # TODO how to handle more than one device being returned (currently will just take the first)
            if get_devices_response and get_devices_response[0] and 'id' in get_devices_response[0]:
                eh_api_id = get_devices_response[0]['id']
            else:
                # Handle device not being found
                return RetVal(action_result.set_status(phantom.APP_ERROR, "ExtraHop device not found with IP = {}".format(ip_address)), get_devices_response)

        # Convert device ID to int
        eh_api_id = int(eh_api_id)

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

        self.save_progress("Making REST call to /api/v1/activitymaps/query")

        # make rest call to get live activity map conversation data
        ret_val, get_activitymap_response = self._make_rest_call("/api/v1/activitymaps/query", action_result, data=body, method="post")

        if (phantom.is_fail(ret_val)):
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

            device_uri = "/api/v1/devices/" + str(peer_id)

            self.save_progress("Making REST call to {}".format(device_uri))

            # make rest call to get the device
            ret_val, get_device_response = self._make_rest_call(device_uri, action_result)

            if (phantom.is_fail(ret_val)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            # Add device object to the results list
            if get_device_response:
                # Add the peer into the data section
                action_result.add_data(get_device_response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_protocols(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        ip_address = param['ip']
        minutes = param['minutes']

        # Optional values should use the .get() function
        eh_api_id = param.get('eh_api_id', None)

        # Grab EH device ID
        if not eh_api_id:

            device_uri = "/api/v1/devices?limit=100&search_type=ip%20address&value=" + ip_address

            self.save_progress("Making REST call to {}".format(device_uri))

            # make rest call to get the device
            ret_val, get_devices_response = self._make_rest_call(device_uri, action_result)

            if (phantom.is_fail(ret_val)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            # Grab device ID from response
            # TODO how to handle more than one device being returned (currently will just take the first)
            if get_devices_response and get_devices_response[0] and 'id' in get_devices_response[0]:
                eh_api_id = get_devices_response[0]['id']
            else:
                # Handle device not being found
                return RetVal(action_result.set_status(phantom.APP_ERROR, "ExtraHop device not found with IP = {}".format(ip_address)), get_devices_response)

        # Convert device ID to int
        eh_api_id = int(eh_api_id)

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

        self.save_progress("Making REST call to /api/v1/activitymaps/query")

        # make rest call to get live activity map protocol data
        ret_val, get_activitymap_response = self._make_rest_call("/api/v1/activitymaps/query", action_result, data=body, method="post")

        if (phantom.is_fail(ret_val)):
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
        unique_client_protocols = ', '.join(sorted(unique_client_protocols))
        unique_server_protocols.discard('OTHER')
        unique_server_protocols = ', '.join(sorted(unique_server_protocols))

        # Add the protocols into the data section
        action_result.add_data({"client_protocols": unique_client_protocols,
                                "server_protocols": unique_server_protocols})

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_discover_new_devices(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        activity_type = param['activity_type']
        minutes = param['minutes']
        seconds = int(minutes) * 60
        time_now = time.time()
        new_device_cutoff_time_ms = int((time_now - seconds) * 1000)

        if activity_type.lower() in ('gateway', 'node', 'remote'):
            # TODO what should device limit be?
            device_search_uri = "/api/v1/devices?active_from={}&limit=-1&search_type=type&value={}".format(new_device_cutoff_time_ms, activity_type)
        else:
            # TODO what should device limit be?
            device_search_uri = "/api/v1/devices?active_from={}&limit=-1&search_type=activity&value=extrahop.device.{}".format(new_device_cutoff_time_ms, activity_type)

        self.save_progress("Making REST call to {}".format(device_search_uri))

        # make rest call to get devices
        ret_val, get_devices_response = self._make_rest_call(device_search_uri, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data
        # Find devices discovered only in the last N minutes
        for device_obj in get_devices_response:
            if 'discover_time' in device_obj:
                discover_time_ms = device_obj['discover_time']
                # Add the response into the data section if the device is new
                if discover_time_ms >= new_device_cutoff_time_ms:
                    action_result.add_data(device_obj)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_custom_device(self, param):

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
        extrahop_id = param.get('extrahop_id', "PH-{}".format(ip_address))
        cidr = param.get('cidr', '/32')

        # Create the new [device]
        custom_device_body = {
            "name": name,
            "author": author,
            "description": description,
            "disabled": False,
            "extrahop_id": extrahop_id
        }

        self.save_progress("Making REST call to /api/v1/customdevices")

        # make rest call to create the custom device
        ret_val, create_customdevice_response = self._make_rest_call('/api/v1/customdevices', action_result, data=custom_device_body, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data
        # Retrieve the custom device id in the location response header
        # TODO find better way to return response headers
        returned_location = self._response_headers.get('location')
        custom_device_id = self._parse_extrahop_location_header(returned_location)

        # Handle tag location being unparsable
        if not custom_device_id:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                "Unable to parse ExtraHop location header of custom device with extrahop_id = {}".format(extrahop_id)), returned_location)

        criteria = {
            "custom_device_id": extrahop_id,
            "ipaddr": ip_address + cidr,
        }

        custom_device_criteria_uri = returned_location + '/criteria'

        self.save_progress("Making REST call to {}".format(custom_device_criteria_uri))

        # make rest call set the custom device criteria
        ret_val, set_criteria_response = self._make_rest_call(custom_device_criteria_uri, action_result, data=criteria, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data({
            'name': name,
            'custom_device_id': extrahop_id
        })

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['name'] = name
        summary['extrahop id'] = extrahop_id

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_tag_device(self, param):

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        ip_address = param['ip']
        tag = param['tag']

        # Optional values should use the .get() function
        eh_api_id = param.get('eh_api_id', None)

        # Grab EH device ID
        if not eh_api_id:

            device_uri = "/api/v1/devices?limit=100&search_type=ip%20address&value=" + ip_address

            self.save_progress("Making REST call to {}".format(device_uri))

            # make rest call to get devices
            ret_val, get_devices_response = self._make_rest_call(device_uri, action_result)

            if (phantom.is_fail(ret_val)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            # Grab device ID from response
            # TODO how to handle more than one device being returned (currently will just take the first)
            if get_devices_response and get_devices_response[0] and 'id' in get_devices_response[0]:
                eh_api_id = get_devices_response[0]['id']
            else:
                # Handle device not being found
                return RetVal(action_result.set_status(phantom.APP_ERROR, "ExtraHop device not found with IP = {}".format(ip_address)), get_devices_response)

        # Convert device ID to int
        eh_api_id = int(eh_api_id)

        self.save_progress("Making REST call to /api/v1/tags")

        # make rest call to get all tags
        ret_val, get_tags_response = self._make_rest_call('/api/v1/tags', action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Search for tag in tags
        for tag_obj in get_tags_response:
            # if tag names match (case-insensitive) then grab the tag id
            if tag_obj['name'].lower() == tag.lower():
                tag_id = tag_obj['id']
                break
        else:
            # If tag doesn't exist then create it
            tag_body = {
                "name": tag
            }

            self.save_progress("Making REST call to /api/v1/tags")

            # make rest call to create the tag
            ret_val, create_tag_response = self._make_rest_call('/api/v1/tags', action_result, data=tag_body, method="post")

            if (phantom.is_fail(ret_val)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()

            returned_location = self._response_headers.get('location')
            tag_id = self._parse_extrahop_location_header(returned_location)

            # Handle tag location being unparsable
            if not tag_id:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse ExtraHop location header of tag with name = {}".format(tag)), returned_location)

        assign_tag_body = {
            "assign": [eh_api_id]
        }

        tag_assign_uri = '/api/v1/tags/{}/devices'.format(tag_id)

        self.save_progress("Making REST call to {}".format(tag_assign_uri))

        # make rest call to assign the tag to the device
        ret_val, assign_tag_response = self._make_rest_call(tag_assign_uri, action_result, data=assign_tag_body, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data({
            'tag_id': tag_id
        })

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_devices':
            ret_val = self._handle_get_devices(param)

        elif action_id == 'get_peers':
            ret_val = self._handle_get_peers(param)

        elif action_id == 'get_protocols':
            ret_val = self._handle_get_protocols(param)

        elif action_id == 'discover_new_devices':
            ret_val = self._handle_discover_new_devices(param)

        elif action_id == 'create_custom_device':
            ret_val = self._handle_create_custom_device(param)

        elif action_id == 'tag_device':
            ret_val = self._handle_tag_device(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = 'https://' + config['base_url']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ExtrahopConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
