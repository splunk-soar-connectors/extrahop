[comment]: # "Auto-generated SOAR connector documentation"
# ExtraHop

Publisher: Splunk  
Connector Version: 2\.0\.0  
Product Vendor: ExtraHop Networks  
Product Name: ExtraHop  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

This app integrates with the ExtraHop platform to perform investigative actions based on real\-time network data

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2018-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
### ExtraHop Installation

For ExtraHop installation and configuration instructions visit
[bundles.extrahop.com](https://www.extrahop.com/customers/community/bundles/extrahop-created/) .

The Splunk SOAR integration for ExtraHop enables you to automate and orchestrate rapid security
investigation, response, and remediation workflows. ExtraHop Reveal(x) provides a uniquely rich,
real-time data source by turning unstructured packets into structured wire data and analyzing it in
real-time. Based on this data, you can confidently configure Splunk SOAR to automate security
workflows and investigations and orchestrate precise, rapid responses to security threats more
effectively than ever before.

Extrahop and Splunk SOAR connect through simple, powerful REST APIs, making it easy to build and
iterate new use cases to get the most value for the least effort, a vital capability for thinly
stretched enterprise security teams.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ExtraHop asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | IP Address or Hostname
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**api\_key** |  required  | password | REST API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get device info](#action-get-device-info) - Get device details from ExtraHop  
[get peers](#action-get-peers) - Get a list of peers that a device communicated with within the last N minutes  
[get protocols](#action-get-protocols) - Get a list of protocols that a device communicated in the last N minutes  
[get devices](#action-get-devices) - Get a list of newly discovered devices  
[create device](#action-create-device) - Create a new custom device on the ExtraHop  
[tag device](#action-tag-device) - Tag an existing device on the ExtraHop  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get device info'
Get device details from ExtraHop

Type: **investigate**  
Read only: **True**

This action will get more details about a device given its IP address\. Details include MAC address, dhcp name, first discovered time, device type, and more\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | Comma\-separated IP addresses | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.analysis | string | 
action\_result\.data\.\*\.analysis\_level | numeric | 
action\_result\.data\.\*\.auto\_role | string | 
action\_result\.data\.\*\.cdp\_name | string | 
action\_result\.data\.\*\.cloud\_account | string | 
action\_result\.data\.\*\.cloud\_instance\_description | string | 
action\_result\.data\.\*\.cloud\_instance\_id | string | 
action\_result\.data\.\*\.cloud\_instance\_name | string | 
action\_result\.data\.\*\.cloud\_instance\_type | string | 
action\_result\.data\.\*\.critical | boolean | 
action\_result\.data\.\*\.custom\_criticality | string | 
action\_result\.data\.\*\.custom\_make | string | 
action\_result\.data\.\*\.custom\_model | string | 
action\_result\.data\.\*\.custom\_name | string | 
action\_result\.data\.\*\.custom\_type | string | 
action\_result\.data\.\*\.default\_name | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.device\_class | string | 
action\_result\.data\.\*\.dhcp\_name | string |  `host name` 
action\_result\.data\.\*\.discover\_time | numeric | 
action\_result\.data\.\*\.discovery\_id | string | 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.dns\_name | string |  `host name` 
action\_result\.data\.\*\.extrahop\_id | string | 
action\_result\.data\.\*\.id | numeric |  `extrahop api id` 
action\_result\.data\.\*\.ipaddr4 | string |  `ip` 
action\_result\.data\.\*\.ipaddr6 | string |  `ip` 
action\_result\.data\.\*\.is\_l3 | boolean | 
action\_result\.data\.\*\.last\_seen\_time | numeric | 
action\_result\.data\.\*\.macaddr | string |  `mac address` 
action\_result\.data\.\*\.mod\_time | numeric | 
action\_result\.data\.\*\.model | string | 
action\_result\.data\.\*\.model\_override | string | 
action\_result\.data\.\*\.netbios\_name | string | 
action\_result\.data\.\*\.node\_id | string | 
action\_result\.data\.\*\.on\_watchlist | boolean | 
action\_result\.data\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.role | string | 
action\_result\.data\.\*\.subnet\_id | string | 
action\_result\.data\.\*\.user\_mod\_time | numeric | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.vlanid | numeric | 
action\_result\.data\.\*\.vpc\_id | string | 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get peers'
Get a list of peers that a device communicated with within the last N minutes

Type: **investigate**  
Read only: **True**

This action retrieves a list of all of the peers that a device communicated with within the last N minutes, optionally filtered by role and/or protocol\. Either 'ip' or 'eh\_api\_id' parameter is required\. If both the parameters are provided, 'eh\_api\_id' will be considered\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  optional  | IP address of device | string |  `ip` 
**minutes** |  optional  | Minutes to look back \(default 30\) | numeric | 
**peer\_role** |  optional  | Filter by peer role | string | 
**protocol** |  optional  | Filter by protocol | string | 
**eh\_api\_id** |  optional  | ExtraHop API id | numeric |  `extrahop api id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.eh\_api\_id | numeric |  `extrahop api id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.minutes | numeric | 
action\_result\.parameter\.peer\_role | string | 
action\_result\.parameter\.protocol | string | 
action\_result\.data\.\*\.analysis | string | 
action\_result\.data\.\*\.analysis\_level | numeric | 
action\_result\.data\.\*\.cdp\_name | string | 
action\_result\.data\.\*\.custom\_name | string | 
action\_result\.data\.\*\.custom\_type | string | 
action\_result\.data\.\*\.default\_name | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.device\_class | string | 
action\_result\.data\.\*\.dhcp\_name | string |  `host name` 
action\_result\.data\.\*\.discover\_time | numeric | 
action\_result\.data\.\*\.discovery\_id | string | 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.dns\_name | string |  `host name` 
action\_result\.data\.\*\.extrahop\_id | string | 
action\_result\.data\.\*\.id | numeric |  `extrahop api id` 
action\_result\.data\.\*\.ipaddr4 | string |  `ip` 
action\_result\.data\.\*\.ipaddr6 | string |  `ip` 
action\_result\.data\.\*\.is\_l3 | boolean | 
action\_result\.data\.\*\.macaddr | string |  `mac address` 
action\_result\.data\.\*\.mod\_time | numeric | 
action\_result\.data\.\*\.netbios\_name | string | 
action\_result\.data\.\*\.node\_id | string | 
action\_result\.data\.\*\.on\_watchlist | boolean | 
action\_result\.data\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.user\_mod\_time | numeric | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.vlanid | numeric | 
action\_result\.summary\.peer\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get protocols'
Get a list of protocols that a device communicated in the last N minutes

Type: **investigate**  
Read only: **True**

This action retrieves a list of all of the protocols that a device communicated over the last N minutes, optionally filtered by role\. Either 'ip' or 'eh\_api\_id' parameter is required\. If both the parameters are provided, 'eh\_api\_id' will be considered\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  optional  | IP address of device | string |  `ip` 
**minutes** |  optional  | Minutes to look back \(default 30\) | numeric | 
**eh\_api\_id** |  optional  | ExtraHop API id | numeric |  `extrahop api id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.eh\_api\_id | numeric |  `extrahop api id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.minutes | numeric | 
action\_result\.data\.\*\.client\_protocols | string | 
action\_result\.data\.\*\.server\_protocols | string | 
action\_result\.summary\.client\_protocol\_count | numeric | 
action\_result\.summary\.server\_protocol\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get devices'
Get a list of newly discovered devices

Type: **investigate**  
Read only: **True**

This action retrieves a list of newly discovered devices classified in a particular activity group that first communicated on your network in the last N minutes\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**activity\_type** |  required  | Activity type | string | 
**minutes** |  optional  | Minutes of look back \(default 30\) | numeric | 
**offset** |  optional  | Starting index of overall result set \(default 0\) | numeric | 
**limit** |  optional  | Numbers of records to fetch \(default 1000\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.activity\_type | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.minutes | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.data\.\*\.analysis | string | 
action\_result\.data\.\*\.analysis\_level | numeric | 
action\_result\.data\.\*\.auto\_role | string | 
action\_result\.data\.\*\.cdp\_name | string | 
action\_result\.data\.\*\.cloud\_account | string | 
action\_result\.data\.\*\.cloud\_instance\_description | string | 
action\_result\.data\.\*\.cloud\_instance\_id | string | 
action\_result\.data\.\*\.cloud\_instance\_name | string | 
action\_result\.data\.\*\.cloud\_instance\_type | string | 
action\_result\.data\.\*\.critical | boolean | 
action\_result\.data\.\*\.custom\_criticality | string | 
action\_result\.data\.\*\.custom\_make | string | 
action\_result\.data\.\*\.custom\_model | string | 
action\_result\.data\.\*\.custom\_name | string | 
action\_result\.data\.\*\.custom\_type | string | 
action\_result\.data\.\*\.default\_name | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.device\_class | string | 
action\_result\.data\.\*\.dhcp\_name | string |  `host name` 
action\_result\.data\.\*\.discover\_time | numeric | 
action\_result\.data\.\*\.discovery\_id | string | 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.dns\_name | string |  `host name` 
action\_result\.data\.\*\.extrahop\_id | string | 
action\_result\.data\.\*\.id | numeric |  `extrahop api id` 
action\_result\.data\.\*\.ipaddr4 | string |  `ip` 
action\_result\.data\.\*\.ipaddr6 | string |  `ip` 
action\_result\.data\.\*\.is\_l3 | boolean | 
action\_result\.data\.\*\.last\_seen\_time | numeric | 
action\_result\.data\.\*\.macaddr | string |  `mac address` 
action\_result\.data\.\*\.mod\_time | numeric | 
action\_result\.data\.\*\.model | string | 
action\_result\.data\.\*\.model\_override | string | 
action\_result\.data\.\*\.netbios\_name | string | 
action\_result\.data\.\*\.node\_id | string | 
action\_result\.data\.\*\.on\_watchlist | boolean | 
action\_result\.data\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.role | string | 
action\_result\.data\.\*\.subnet\_id | string | 
action\_result\.data\.\*\.user\_mod\_time | numeric | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.vlanid | numeric | 
action\_result\.data\.\*\.vpc\_id | string | 
action\_result\.summary\.new\_devices\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create device'
Create a new custom device on the ExtraHop

Type: **generic**  
Read only: **False**

This action will create a new custom device on the ExtraHop appliance with a single IP address\. This action is expected to be used with endpoints, which are not typically tracked individually with full analysis\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address | string |  `ip` 
**name** |  optional  | The friendly name for the custom device | string | 
**author** |  optional  | The name of the custom device creator | string | 
**description** |  optional  | An optional description of the custom device | string | 
**cidr** |  optional  | CIDR block | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.author | string | 
action\_result\.parameter\.cidr | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.name | string | 
action\_result\.data\.\*\.cidr | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.summary\.name | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'tag device'
Tag an existing device on the ExtraHop

Type: **generic**  
Read only: **False**

This action will tag a device on the ExtraHop appliance\. Normally tags are used to control device membership in dynamic groups\. Either 'ip' or 'eh\_api\_id' parameter is required\. If both the parameters are provided, 'eh\_api\_id' will be considered\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  optional  | IP address | string |  `ip` 
**tag** |  required  | Tag name | string | 
**eh\_api\_id** |  optional  | ExtraHop device API ID | numeric |  `extrahop api id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.eh\_api\_id | numeric |  `extrahop api id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.tag | string | 
action\_result\.data\.\*\.tag\_id | numeric | 
action\_result\.summary\.extrahop\_device\_id | numeric | 
action\_result\.summary\.tag | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 