# ExtraHop Reveal(x)

Publisher: ExtraHop \
Connector Version: 3.1.1 \
Product Vendor: ExtraHop Networks \
Product Name: ExtraHop Reveal(x) \
Minimum Product Version: 6.0.0

This app integrates with your ExtraHop system to gain insight into devices, traffic, and detections in your environment

### Configuration variables

This table lists the configuration variables required to operate ExtraHop Reveal(x). These variables are specified when configuring a ExtraHop Reveal(x) asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**instance_type** | required | string | Type of asset |
**base_url** | required | string | IP address or hostname |
**platform_url** | optional | string | Extrahop platform URL (https://companyname.cloud.extrahop.com/) |
**api_key** | optional | password | REST API key (Reveal(x) Enterprise only) |
**verify_server_cert** | optional | boolean | Verify server certificate |
**client_id** | optional | string | Client ID (Reveal(x) 360 only) |
**client_secret** | optional | password | Client secret (Reveal(x) 360 only) |
**ingestion_type** | optional | string | Type of data to retrieve and ingest |
**json_object** | optional | string | JSON object for on poll action |
**detection_category** | optional | string | Category of detections to retrieve. (Default detection category: 'sec.attack') |
**detection_status** | optional | string | Status of detections to retrieve. (Comma-delimited; leave blank to retrieve detections of any status) |
**metric_cycle_length** | optional | string | Aggregation time interval for retrieved metrics |
**object_type** | optional | string | Object type associated with the API IDs to poll for metrics |
**object_id** | optional | string | API IDs for the objects to poll for metrics (Comma-delimited) |
**metric_category** | optional | string | Category of metrics to retrieve. (See REST API Parameters in the ExtraHop Metric Catalog to find categories) |
**metric_name** | optional | string | Names of metrics to retrieve. (Comma-delimited; see REST API Parameters in the ExtraHop Metric Catalog to find metric names) |
**bpf** | optional | string | Berkeley Packet Filter (BPF) syntax for packet retrieval |
**limit_bytes** | optional | string | Maximum number of return bytes for packet retrieval |
**limit_search_duration** | optional | string | Maximum runtime for packet retrieval. The default unit is milliseconds, but other units can be specified with a unit suffix. |
**ip1** | optional | string | Retrieve packets sent to or received by this IP address |
**ip2** | optional | string | Retrieve packets sent to or received by this additional IP address |
**port1** | optional | numeric | Retrieve packets sent to or received by this port number |
**port2** | optional | numeric | Retrieve packets sent to or received by this additional port number |

### Supported Actions

[test connectivity](#action-test-connectivity) - Initiate a connection to the ExtraHop system to validate the asset configuration \
[get device info](#action-get-device-info) - Retrieve details and properties for a device \
[get peers](#action-get-peers) - Retrieve a list of peers that communicated with a device \
[get protocols](#action-get-protocols) - Retrieve a list of protocols observed on a device \
[get devices](#action-get-devices) - Retrieve a list of devices based on specified search criteria \
[create device](#action-create-device) - Create a custom device (Reveal(x) Enterprise only) \
[tag device](#action-tag-device) - Tag an existing device \
[get metrics](#action-get-metrics) - Retrieve the metrics data \
[get packets](#action-get-packets) - Retrieve the packets data \
[on poll](#action-on-poll) - Retrieve and ingest of data from the ExtraHop system

## action: 'test connectivity'

Initiate a connection to the ExtraHop system to validate the asset configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get device info'

Retrieve details and properties for a device

Type: **investigate** \
Read only: **True**

This action retrieves details about a specified device on the ExtraHop network such as MAC address, DHCP name, discovery time, device role, and device group membership. Learn more about <a href='https://docs.extrahop.com/current/rest-search-for-device/' target='_blank'>retrieving device information through the ExtraHop REST API</a>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | Comma-delimited list of device IP addresses to retrieve details and properties | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` | 208.14.6.61 |
action_result.data.\*.analysis | string | | advanced |
action_result.data.\*.analysis_level | numeric | | 1 |
action_result.data.\*.auto_role | string | | other |
action_result.data.\*.cdp_name | string | | |
action_result.data.\*.cloud_account | string | | |
action_result.data.\*.cloud_instance_description | string | | |
action_result.data.\*.cloud_instance_id | string | | |
action_result.data.\*.cloud_instance_name | string | | |
action_result.data.\*.cloud_instance_type | string | | |
action_result.data.\*.critical | boolean | | True False |
action_result.data.\*.custom_criticality | string | | |
action_result.data.\*.custom_make | string | | |
action_result.data.\*.custom_model | string | | |
action_result.data.\*.custom_name | string | | |
action_result.data.\*.custom_type | string | | |
action_result.data.\*.default_name | string | | VMware 208.14.6.61 |
action_result.data.\*.description | string | | |
action_result.data.\*.device_class | string | | node |
action_result.data.\*.dhcp_name | string | `host name` | networksec.example.com |
action_result.data.\*.discover_time | numeric | | 1522964970000 |
action_result.data.\*.discovery_id | string | | fff45b060a0a0000 |
action_result.data.\*.display_name | string | | networksec.example.com |
action_result.data.\*.dns_name | string | `host name` | networksec.example.com |
action_result.data.\*.extrahop_id | string | | fff45b060a0a0000 |
action_result.data.\*.id | numeric | `extrahop api id` | 1458 |
action_result.data.\*.ipaddr4 | string | `ip` | 208.14.6.61 |
action_result.data.\*.ipaddr6 | string | `ip` | FE80::0202:B3FF:FE1E:8329 |
action_result.data.\*.is_l3 | boolean | | False True |
action_result.data.\*.last_seen_time | numeric | | 1657260540000 |
action_result.data.\*.macaddr | string | `mac address` | 0E:6F:28:A4:2B:62 |
action_result.data.\*.mod_time | numeric | | 1525963038299 |
action_result.data.\*.model | string | | vmware_vm |
action_result.data.\*.model_override | string | | |
action_result.data.\*.netbios_name | string | | |
action_result.data.\*.node_id | numeric | | |
action_result.data.\*.on_watchlist | boolean | | False True |
action_result.data.\*.parent_id | numeric | | 491 |
action_result.data.\*.role | string | | other |
action_result.data.\*.subnet_id | string | | |
action_result.data.\*.user_mod_time | numeric | | 1525212324713 |
action_result.data.\*.vendor | string | | VMware |
action_result.data.\*.vlanid | numeric | | 0 |
action_result.data.\*.vpc_id | string | | |
action_result.summary.device_count | numeric | | 1 |
action_result.message | string | | Device count: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get peers'

Retrieve a list of peers that communicated with a device

Type: **investigate** \
Read only: **True**

This action retrieves a list of all peers that communicated with a specified device within the last N minutes. The peers can be filtered by role and protocols. Specify the device through either the 'ip' or 'eh_api_id' parameter. If both parameters are provided, 'eh_api_id' is the default.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | optional | IP address of the device from which to search for peers | string | `ip` |
**minutes** | optional | Amount of lookback data in minutes (default is 30 mins) | numeric | |
**peer_role** | optional | Role to search for on peers | string | |
**protocol** | optional | Protocol to search for on peers | string | |
**eh_api_id** | optional | REST API ID of the device (default value if 'ip' is also specified) | numeric | `extrahop api id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.eh_api_id | numeric | `extrahop api id` | 565 |
action_result.parameter.ip | string | `ip` | 208.14.6.61 |
action_result.parameter.minutes | numeric | | 30 |
action_result.parameter.peer_role | string | | any |
action_result.parameter.protocol | string | | any |
action_result.data.\*.analysis | string | | standard |
action_result.data.\*.analysis_level | numeric | | 0 |
action_result.data.\*.cdp_name | string | | |
action_result.data.\*.custom_name | string | | |
action_result.data.\*.custom_type | string | | |
action_result.data.\*.default_name | string | | TestVendor 208.14.12.23 |
action_result.data.\*.description | string | | |
action_result.data.\*.device_class | string | | node |
action_result.data.\*.dhcp_name | string | `host name` | app-perf03.example.com |
action_result.data.\*.discover_time | numeric | | 1522967820000 |
action_result.data.\*.discovery_id | string | | fff4cc0a140a0000 |
action_result.data.\*.display_name | string | | app-perf03.example.com |
action_result.data.\*.dns_name | string | `host name` | app-perf03.example.com |
action_result.data.\*.extrahop_id | string | | fff4cc0a140a0000 |
action_result.data.\*.id | numeric | `extrahop api id` | 2850 |
action_result.data.\*.ipaddr4 | string | `ip` | 208.14.12.23 |
action_result.data.\*.ipaddr6 | string | `ip` | FE80::0202:B3FF:FE1E:8329 |
action_result.data.\*.is_l3 | boolean | | False True |
action_result.data.\*.macaddr | string | `mac address` | A4:52:B7:E6:15:EB |
action_result.data.\*.mod_time | numeric | | 1525965708165 |
action_result.data.\*.netbios_name | string | | |
action_result.data.\*.node_id | numeric | | |
action_result.data.\*.on_watchlist | boolean | | False True |
action_result.data.\*.parent_id | numeric | | 438 |
action_result.data.\*.user_mod_time | numeric | | 1522967940018 |
action_result.data.\*.vendor | string | | TestVendor |
action_result.data.\*.vlanid | numeric | | 0 |
action_result.summary.peer_count | numeric | | 8 |
action_result.message | string | | Peer count: 8 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get protocols'

Retrieve a list of protocols observed on a device

Type: **investigate** \
Read only: **True**

This action retrieves a list of all protocols that were observed to have communicated on a specified device within the last N minutes. Specify the device through either the 'ip' or 'eh_api_id' parameter. If both parameters are provided, 'eh_api_id' is the default.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | optional | IP address of the device on which to search for protocols | string | `ip` |
**minutes** | optional | Amount of lookback data in minutes (default is 30 mins) | numeric | |
**eh_api_id** | optional | REST API ID of the device (default value if 'ip' is also specified) | numeric | `extrahop api id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.eh_api_id | numeric | `extrahop api id` | 565 |
action_result.parameter.ip | string | `ip` | 208.14.6.61 |
action_result.parameter.minutes | numeric | | 30 |
action_result.data.\*.client_protocols | string | | DNS, IPv4, LDAP, NTP, SSL, TCP, UDP |
action_result.data.\*.server_protocols | string | | DB, IPv4, SSL, TCP |
action_result.summary.client_protocol_count | numeric | | 7 |
action_result.summary.server_protocol_count | numeric | | 4 |
action_result.message | string | | Server protocol count: 4, Client protocol count: 7 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get devices'

Retrieve a list of devices based on specified search criteria

Type: **investigate** \
Read only: **True**

This action retrieves a list of active devices that were discovered on the ExtraHop network within the last N minutes. The 'filter' parameter is applicable only if the value for 'field_type' is set to 'custom_filter'. Learn more about <a href='https://docs.extrahop.com/current/rest-extract-devices/' target='_blank'>extracting a device list through the ExtraHop REST API</a>. If 'json_object' parameter is provided, it will be prioritized and rest of the parameters will be ignored.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**json_object** | optional | Json object for get device | string | |
**field_type** | optional | Type of search criteria | string | |
**minutes** | optional | Amount of lookback data in minutes (default is 30 mins) | numeric | |
**offset** | optional | Starting count for the set of results (default is 0) | numeric | |
**limit** | optional | Maximum number of results that can be retrieved | numeric | |
**filter** | optional | JSON query of device search criteria | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.field_type | string | | ipaddr |
action_result.parameter.filter | string | | { "operator": "and", "rules": [ { "field": "activity", "operand": "dhcp_client", "operator": "=" }, { "field": "name", "operand": "Cisco Meraki", "operator": "~" } ] } |
action_result.parameter.json_object | string | | { "active_from": 1663141553000, "active_until": 0, "filter": { "field": "activity", "operand": "dhcp_client", "operator": "=" }, "limit": 10, "offset": 0 } |
action_result.parameter.limit | numeric | | 1000 |
action_result.parameter.minutes | numeric | | 30 |
action_result.parameter.offset | numeric | | 0 |
action_result.data.\*.analysis | string | | standard |
action_result.data.\*.analysis_level | numeric | | 0 |
action_result.data.\*.auto_role | string | | other |
action_result.data.\*.cdp_name | string | | |
action_result.data.\*.cloud_account | string | | |
action_result.data.\*.cloud_instance_description | string | | |
action_result.data.\*.cloud_instance_id | string | | |
action_result.data.\*.cloud_instance_name | string | | |
action_result.data.\*.cloud_instance_type | string | | |
action_result.data.\*.critical | boolean | | True False |
action_result.data.\*.custom_criticality | string | | |
action_result.data.\*.custom_make | string | | |
action_result.data.\*.custom_model | string | | |
action_result.data.\*.custom_name | string | | |
action_result.data.\*.custom_type | string | | |
action_result.data.\*.default_name | string | | Device 208.14.4.92 |
action_result.data.\*.description | string | | |
action_result.data.\*.device_class | string | | node |
action_result.data.\*.dhcp_name | string | `host name` | log-ingest43 |
action_result.data.\*.discover_time | numeric | | 1523484750000 |
action_result.data.\*.discovery_id | string | | fff41af90a0a0000 |
action_result.data.\*.display_name | string | | log-ingest43 |
action_result.data.\*.dns_name | string | `host name` | log-ingest43.example.com |
action_result.data.\*.extrahop_id | string | | fff41af90a0a0000 |
action_result.data.\*.id | numeric | `extrahop api id` | 3785 |
action_result.data.\*.ipaddr4 | string | `ip` | 208.14.4.92 |
action_result.data.\*.ipaddr6 | string | `ip` | FE80::0202:B3FF:FE1E:8329 |
action_result.data.\*.is_l3 | boolean | | False True |
action_result.data.\*.last_seen_time | numeric | | 1657260540000 |
action_result.data.\*.macaddr | string | `mac address` | 5B:6A:32:00:32:FE |
action_result.data.\*.mod_time | numeric | | 1525975638514 |
action_result.data.\*.model | string | | vmware_vm |
action_result.data.\*.model_override | string | | |
action_result.data.\*.netbios_name | string | | |
action_result.data.\*.node_id | numeric | | |
action_result.data.\*.on_watchlist | boolean | | False True |
action_result.data.\*.parent_id | numeric | | 3784 |
action_result.data.\*.role | string | | other |
action_result.data.\*.subnet_id | string | | |
action_result.data.\*.user_mod_time | numeric | | 1523484816110 |
action_result.data.\*.vendor | string | | |
action_result.data.\*.vlanid | numeric | | 0 |
action_result.data.\*.vpc_id | string | | |
action_result.summary.active_devices_count | numeric | | 47 |
action_result.message | string | | Active devices count: 47 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create device'

Create a custom device (Reveal(x) Enterprise only)

Type: **generic** \
Read only: **False**

This action creates a new custom device on the ExtraHop system from a specified IP address and CIDR block. Learn more about <a href='https://docs.extrahop.com/current/rest-create-custom-devices/' target='_blank'>creating a custom device through the ExtraHop REST API</a>. If 'json_object' parameter is provided, it will be prioritized and rest of the parameters will be ignored.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**json_object** | optional | Json object for creating a custom device | string | |
**ip** | optional | IP address for the custom device | string | `ip` |
**name** | optional | Unique name for the custom device | string | |
**author** | optional | User that created the custom device | string | |
**description** | optional | Description details for the custom device | string | |
**cidr** | optional | CIDR block for the custom device | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.author | string | | DevOps-team |
action_result.parameter.cidr | string | | /24 |
action_result.parameter.description | string | | Created using IP |
action_result.parameter.ip | string | `ip` | 208.14.6.61 |
action_result.parameter.json_object | string | | { "author": "test_author", "criteria": [ { "ipaddr": "10.40.2.3", "ipaddr_direction": "any", "src_port_max": 443, "src_port_min": 10, "dst_port_max": 443, "dst_port_min": 10, "vlan_max": 10, "vlan_min": 1 } ], "name": "test_device", "description": "test_desc", "extrahop_id": "test_eid" } |
action_result.parameter.name | string | | Custom IP |
action_result.data.\*.cidr | string | | /32 |
action_result.data.\*.name | string | | Custom IP |
action_result.summary.name | string | | Custom IP |
action_result.message | string | | Name: Custom IP |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'tag device'

Tag an existing device

Type: **generic** \
Read only: **False**

This action assigns tags to a device on the ExtraHop system. Specify the device through either the 'ip' or 'eh_api_id' parameter. If both parameters are provided, 'eh_api_id' is the default.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | optional | IP address of the device to tag | string | `ip` |
**tag** | required | Name of the tag | string | |
**eh_api_id** | optional | REST API ID of the device (default value if 'ip' is also specified | numeric | `extrahop api id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.eh_api_id | numeric | `extrahop api id` | 565 |
action_result.parameter.ip | string | `ip` | 208.14.6.61 |
action_result.parameter.tag | string | | suspicious_endpoint |
action_result.data.\*.tag_id | numeric | | 4 |
action_result.summary.extrahop_device_id | numeric | | 1458 |
action_result.summary.tag | string | | suspicious_endpoint |
action_result.message | string | | Extrahop device id: 1458, Tag: suspicious_endpoint |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get metrics'

Retrieve the metrics data

Type: **investigate** \
Read only: **True**

This action will retrieve the details of the metric based on the given inputs. If 'json_object' parameter is provided, it will be prioritized and rest of the parameters will be ignored.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**json_object** | optional | JSON object for get metrics action | string | |
**minutes** | optional | Amount of lookback data in minutes (default is 30 mins) | numeric | |
**metric_cycle_length** | optional | Aggregation time interval for retrieved metrics | string | |
**object_type** | optional | Object type associated with the API IDs | string | |
**object_id** | optional | API IDs for the objects (Comma-delimited) | string | `extrahop api id` |
**metric_category** | optional | Category of metrics to retrieve. (See REST API Parameters in the ExtraHop Metric Catalog to find categories) | string | |
**metric_name** | optional | Names of metrics to retrieve. (Comma-delimited; see REST API Parameters in the ExtraHop Metric Catalog to find metric names) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.json_object | string | | {"cycle": "30sec", "from": 1661624490000, "until": 1661628090000, "metric_category": "tcp_detail", "metric_specs": [{"name": "established"}], "object_ids": [1994], "object_type": "device"} |
action_result.parameter.metric_category | string | | tcp_detail |
action_result.parameter.metric_cycle_length | string | | 30sec |
action_result.parameter.metric_name | string | | established |
action_result.parameter.minutes | numeric | | 30 |
action_result.parameter.object_id | string | `extrahop api id` | 1994 |
action_result.parameter.object_type | string | | Device |
action_result.data.\*.cycle | string | | 30sec |
action_result.data.\*.detail | string | | 10.10.10.10 |
action_result.data.\*.metric_category | string | | tcp_detail |
action_result.data.\*.object_type | string | | Device |
action_result.data.\*.oid | string | `extrahop api id` | 1994 |
action_result.data.\*.time | numeric | | 1664736060 |
action_result.summary | string | | |
action_result.message | string | | Successfully received metrics data |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get packets'

Retrieve the packets data

Type: **investigate** \
Read only: **True**

This action will retrieve the packets in the form of a pcap file and stored it into the vault. If 'json_object' parameter is provided, it will be prioritized and rest of the parameters will be ignored.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**json_object** | optional | JSON object for get packets action | string | |
**minutes** | optional | Amount of lookback data in minutes (default is 30 mins) | numeric | |
**bpf** | optional | Berkeley Packet Filter (BPF) syntax for packet retrieval | string | |
**limit_bytes** | optional | Maximum number of return bytes for packet retrieval | string | |
**limit_search_duration** | optional | Maximum runtime for packet retrieval. The default unit is milliseconds, but other units can be specified with a unit suffix. | string | |
**ip1** | optional | Retrieve packets sent to or received by this IP address | string | `ip` |
**ip2** | optional | Retrieve packets sent to or received by this additional IP address | string | `ip` |
**port1** | optional | Retrieve packets sent to or received by this port number | numeric | |
**port2** | optional | Retrieve packets sent to or received by this additional port number | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.bpf | string | | src host 10.10.10.10 and dst port 443 |
action_result.parameter.ip1 | string | `ip` | 10.10.10.10 |
action_result.parameter.ip2 | string | `ip` | 10.10.10.11 |
action_result.parameter.json_object | string | | { "from": 1654340066000, "limit_bytes": "200MB", "bpf": "src host 10.10.10.10 and dst port 443", "ip1": "10.10.10.11", "port1": 22 } |
action_result.parameter.limit_bytes | string | | 100MB |
action_result.parameter.limit_search_duration | string | | 5m |
action_result.parameter.minutes | numeric | | 30 |
action_result.parameter.port1 | numeric | | 443 |
action_result.parameter.port2 | numeric | | 443 |
action_result.data.\*.file_name | string | | extrahop 2022-09-30 11.13.16 to 11.18.16 IST.pcap |
action_result.data.\*.vault_id | string | `vault id` | b0a83ea208b4cd125e5296cfb06053d740a5f444 |
action_result.summary | string | | |
action_result.message | string | | Successfully added packets |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

Retrieve and ingest of data from the ExtraHop system

Type: **ingest** \
Read only: **True**

This action ingests detections, metrics, or PCAP data from the ExtraHop system as specified by the asset configuration.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_count** | optional | Maximum number of containers to ingest | numeric | |
**start_time** | optional | Parameter ignored in this app | numeric | |
**end_time** | optional | Parameter ignored in this app | numeric | |
**artifact_count** | optional | Parameter ignored in this app | numeric | |

#### Action Output

No Output

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
