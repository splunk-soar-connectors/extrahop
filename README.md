[comment]: # "Auto-generated SOAR connector documentation"
# ExtraHop

Publisher: ExtraHop  
Connector Version: 1\.0\.4  
Product Vendor: ExtraHop Networks  
Product Name: ExtraHop  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.5\.180  

This app integrates with the ExtraHop platform to perform investigative actions based on real\-time network data


### ExtraHop Installation

For further ExtraHop installation and configuration instructions visit
[bundles.extrahop.com](https://www.extrahop.com/customers/community/bundles/extrahop-created/) .

The Phantom integration for ExtraHop enables you to automate and orchestrate rapid security
investigation, response, and remediation workflows. ExtraHop Reveal(x) provides a uniquely rich,
real-time data source by turning unstructured packets into structured wire data and analyzing it in
real-time. Based on this data, you can confidently configure Phantom to automate security workflows
and investigations and orchestrate precise, rapid responses to security threats more effectively
than ever before.

Extrahop and Phantom connect through simple, powerful REST APIs, making it easy to build and iterate
new use cases to get the most value for the least effort, a vital capability for thinly stretched
enterprise security teams.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ExtraHop asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | IP Address or Hostname
**verify\_server\_cert** |  required  | boolean | Verify server certificate
**api\_key** |  required  | password | REST API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get device info](#action-get-device-info) - Get device details from ExtraHop  
[get peers](#action-get-peers) - Get a list of peers that a device communicated with in the last N minutes  
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
**ip** |  required  | IP Address | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.ipaddr4 | string |  `ip` 
action\_result\.data\.\*\.macaddr | string |  `mac address` 
action\_result\.data\.\*\.dhcp\_name | string |  `host name` 
action\_result\.data\.\*\.dns\_name | string |  `host name` 
action\_result\.data\.\*\.device\_class | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.is\_l3 | boolean | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.discover\_time | numeric | 
action\_result\.data\.\*\.ipaddr6 | string |  `ip` 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.custom\_type | string | 
action\_result\.data\.\*\.netbios\_name | string | 
action\_result\.data\.\*\.user\_mod\_time | numeric | 
action\_result\.data\.\*\.cdp\_name | string | 
action\_result\.data\.\*\.vlanid | numeric | 
action\_result\.data\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.node\_id | string | 
action\_result\.data\.\*\.mod\_time | numeric | 
action\_result\.data\.\*\.extrahop\_id | string | 
action\_result\.data\.\*\.custom\_name | string | 
action\_result\.data\.\*\.default\_name | string | 
action\_result\.data\.\*\.analysis\_level | numeric | 
action\_result\.data\.\*\.analysis | string | 
action\_result\.data\.\*\.on\_watchlist | boolean | 
action\_result\.summary | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.discovery\_id | string | 
action\_result\.summary\.device\_count | numeric |   

## action: 'get peers'
Get a list of peers that a device communicated with in the last N minutes

Type: **investigate**  
Read only: **True**

This action retrieves a list of all of the peers that a device communicated with in the last N minutes, optionally filtered by role and/or protocol\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address of device | string |  `ip` 
**minutes** |  required  | Minutes to look back | numeric | 
**peer\_role** |  optional  | Filter by peer role | string | 
**protocol** |  optional  | Filter by protocol | string | 
**eh\_api\_id** |  optional  | ExtraHop API id | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.ipaddr4 | string |  `ip` 
action\_result\.data\.\*\.macaddr | string |  `mac address` 
action\_result\.data\.\*\.dhcp\_name | string |  `host name` 
action\_result\.data\.\*\.dns\_name | string |  `host name` 
action\_result\.data\.\*\.device\_class | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.is\_l3 | boolean | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.discover\_time | numeric | 
action\_result\.data\.\*\.ipaddr6 | string |  `ip` 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.custom\_type | string | 
action\_result\.data\.\*\.netbios\_name | string | 
action\_result\.data\.\*\.user\_mod\_time | numeric | 
action\_result\.data\.\*\.cdp\_name | string | 
action\_result\.data\.\*\.vlanid | numeric | 
action\_result\.data\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.node\_id | string | 
action\_result\.data\.\*\.mod\_time | numeric | 
action\_result\.data\.\*\.extrahop\_id | string | 
action\_result\.data\.\*\.custom\_name | string | 
action\_result\.data\.\*\.default\_name | string | 
action\_result\.data\.\*\.analysis\_level | numeric | 
action\_result\.data\.\*\.analysis | string | 
action\_result\.data\.\*\.on\_watchlist | boolean | 
action\_result\.summary | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.minutes | numeric | 
action\_result\.parameter\.peer\_role | string | 
action\_result\.parameter\.protocol | string | 
action\_result\.parameter\.eh\_api\_id | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.discovery\_id | string | 
action\_result\.summary\.peer\_count | numeric |   

## action: 'get protocols'
Get a list of protocols that a device communicated in the last N minutes

Type: **investigate**  
Read only: **True**

This action retrieves a list of all of the protocols that a device communicated over the last N minutes, optionally filtered by role\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address of device | string |  `ip` 
**minutes** |  required  | Minutes to look back | numeric | 
**eh\_api\_id** |  optional  | ExtraHop API id | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.client\_protocols | string | 
action\_result\.data\.\*\.server\_protocols | string | 
action\_result\.summary | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.minutes | numeric | 
action\_result\.parameter\.eh\_api\_id | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.summary\.server\_protocol\_count | numeric | 
action\_result\.summary\.client\_protocol\_count | numeric |   

## action: 'get devices'
Get a list of newly discovered devices

Type: **investigate**  
Read only: **True**

This action retrieves a list of newly discovered devices classified in a particular activity group that first communicated on your network in the last N minutes\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**activity\_type** |  required  | Activity type | string | 
**minutes** |  required  | Minutes of look back | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.ipaddr4 | string |  `ip` 
action\_result\.data\.\*\.macaddr | string |  `mac address` 
action\_result\.data\.\*\.dhcp\_name | string |  `host name` 
action\_result\.data\.\*\.dns\_name | string |  `host name` 
action\_result\.data\.\*\.discover\_time | numeric | 
action\_result\.data\.\*\.device\_class | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.is\_l3 | boolean | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.ipaddr6 | string |  `ip` 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.custom\_type | string | 
action\_result\.data\.\*\.netbios\_name | string | 
action\_result\.data\.\*\.user\_mod\_time | numeric | 
action\_result\.data\.\*\.cdp\_name | string | 
action\_result\.data\.\*\.vlanid | numeric | 
action\_result\.data\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.node\_id | string | 
action\_result\.data\.\*\.mod\_time | numeric | 
action\_result\.data\.\*\.extrahop\_id | string | 
action\_result\.data\.\*\.custom\_name | string | 
action\_result\.data\.\*\.default\_name | string | 
action\_result\.data\.\*\.analysis\_level | numeric | 
action\_result\.data\.\*\.analysis | string | 
action\_result\.data\.\*\.on\_watchlist | boolean | 
action\_result\.summary | string | 
action\_result\.parameter\.activity\_type | string | 
action\_result\.parameter\.minutes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.summary\.new\_devices\_count | numeric | 
action\_result\.data\.\*\.discovery\_id | string |   

## action: 'create device'
Create a new custom device on the ExtraHop

Type: **generic**  
Read only: **False**

This action will create a new custom device on the ExtraHop appliance with a single IP address\. This action is expected to be used with endpoints, which are not typically tracked individually with full analysis\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address | string |  `ip` 
**name** |  optional  | The friendly name for the custom device | string | 
**author** |  optional  | The name of the custom device creator | string | 
**description** |  optional  | An optional description of the custom device | string | 
**cidr** |  optional  | CIDR block | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.custom\_device\_id | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.cidr | string | 
action\_result\.summary | string | 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.author | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.cidr | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.summary\.name | string | 
action\_result\.summary\.extrahop id | string |   

## action: 'tag device'
Tag an existing device on the ExtraHop

Type: **investigate**  
Read only: **False**

This action will tag a device on the ExtraHop appliance\. Normally tags are used to control device membership in dynamic groups\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address | string |  `ip` 
**tag** |  required  | Tag Name | string | 
**eh\_api\_id** |  optional  | ExtraHop Device API ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.tag | string | 
action\_result\.data\.\*\.tag\_id | string | 
action\_result\.summary | string | 
action\_result\.parameter\.eh\_api\_id | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.summary\.extrahop\_device\_id | numeric | 
action\_result\.summary\.tag | string | 