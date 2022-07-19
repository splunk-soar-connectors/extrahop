# File: extrahop_consts.py
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

# Error and status messages
EXTRAHOP_ERR_MSG_UNAVAILABLE = 'Error message unavailable. Please check the asset configuration and|or action parameters'
EXTRAHOP_DEBUG_REST_ENDPOINT = "Making REST call to {}"
EXTRAHOP_STATE_FILE_CORRUPT_ERR = "Error occurred while loading the state file due to its unexpected format. " \
    "Resetting the state file with the default format."

# Endpoints
EXTRAHOP_DEVICES_ENDPOINT = '/api/v1/devices'
EXTRAHOP_DEVICE_WITH_ID_ENDPOINT = '/api/v1/devices/{}'
EXTRAHOP_BASIC_DETAILS_ENDPOINT = '/api/v1/extrahop'
EXTRAHOP_ACTIVITY_MAP_ENDPOINT = '/api/v1/activitymaps/query'
EXTRAHOP_CUSTOM_DEVICES_ENDPOINT = '/api/v1/customdevices'
EXTRAHOP_TAGS_ENDPOINT = '/api/v1/tags'
EXTRAHOP_TAG_TO_DEVICE_ENDPOINT = '/api/v1/tags/{}/devices'

# Default values
EXTRAHOP_DEFAULT_TIMEOUT = 30
EXTRAHOP_DEFAULT_LIMIT = 500

# Validation for value_list
EXTRAHOP_PEER_ROLE_LIST = ["client", "server", "any"]
EXTRAHOP_ACTIVITY_TYPE_LIST = ["any", "name", "discovery_id", "ip address", "mac address", "vendor",
                               "type", "tag", "activity", "node", "vlan", "discover time"]
EXTRAHOP_INVALID_SELECTION = "Invalid '{0}' selected. Must be one of: {1}."

# Constants relating to 'validate_integer'
EXTRAHOP_VALID_INT_MSG = "Please provide a valid integer value in the '{param}' parameter"
EXTRAHOP_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in '{param}' parameter"
EXTRAHOP_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the '{param}' parameter"

EXTRAHOP_EH_API_ID_KEY = "'eh_api_id' action parameter"
EXTRAHOP_MINUTES_KEY = "'minutes' action parameter"
EXTRAHOP_OFFSET_KEY = "'offset' action parameter"
EXTRAHOP_LIMIT_KEY = "'limit' action parameter"
