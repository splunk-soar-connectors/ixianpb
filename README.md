[comment]: # "Auto-generated SOAR connector documentation"
# Ixia Network Packet Broker

Publisher: Splunk  
Connector Version: 1\.0\.0  
Product Vendor: Ixia  
Product Name: Network Packet Broker  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This ixia NPB App supports a variety of actions on the network packet broker platform\. This App has been tested with Vision One

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2022 Splunk Inc."
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
**Notes**

-   Delete Filter

      

    -   The first priority while deleting a filter is given to the name. If a filter is having name
        "51" and another filter having ID 51 then the filter with the name "51" will be deleted

      

-   Update Filter IP

      

    -   For type Source, the input is expected in the source_ip parameter
    -   For type Destination, the input is expected in the destination_ip parameter
    -   For type Source or Destination, the input is expected in the source_or_destination_ip
        parameter
    -   For type Unidirectional Flow and Bidirectional Flow, the input is expected in both source_ip
        and destination_ip parameters
    -   The input should be in JSON (list of the list) format. Eg.
        (\[\["X.X.X.X"\],\["X.X.X.X/X.X.X.X"\],\["X.X.X.X/Y"\]\]) where X = 0-255 and Y = 1-32

      

-   Update Filter MAC

      

    -   For type Source, the input is expected in the 'source_mac' or in 'administration'. First
        preference is given to the 'source_mac' parameter
    -   For type Destination, the input is expected in the 'destination_mac' or in 'administration'
        and 'destination_address' parameters. First preference is given to the 'destination_mac'
        parameter
    -   For type Source or Destination, the input is expected in the source_or_destination_mac
        parameter
    -   For type Unidirectional Flow and Bidirectional Flow, the input is expected in both
        source_mac and destination_mac parameters
    -   The input should be in JSON (list of the list) format. Eg.
        (\[\["X-X-X-X-X-X"\],\["Y-Y-Y-Y-Y-Y"\]\]) where X = 00-FF and Y = 00-FF

      

-   Update Filter Port

      

    -   For type Source, the input is expected in the source_port parameter
    -   For type Destination, the input is expected in the destination_port parameter
    -   For type Source or Destination, the input is expected in the source_or_destination_port
        parameter
    -   For type Unidirectional Flow and Bidirectional Flow, the input is expected in both
        source_port and destination_port parameters
    -   The input should be in JSON (list of the list) format. Eg. (\[\["X"\],\["Y"\]\]) where X =
        1-65535 and Y = 1-65535


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Network Packet Broker asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**endpoint** |  required  | string | Endpoint \(e\.g\. https\://10\.1\.16\.31\:8000\)
**username** |  required  | string | Username
**password** |  required  | password | Password
**verify\_cert** |  optional  | boolean | Verify Server SSL certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration parameters  
[delete filter](#action-delete-filter) - Remove a filter from the instance  
[update mode](#action-update-mode) - Update the mode of a filter  
[update operator](#action-update-operator) - Update the operator of a filter  
[update mac](#action-update-mac) - Update the mac address criteria for a filter  
[update port](#action-update-port) - Update the port criteria of a filter  
[update ip](#action-update-ip) - Update the IP address criteria of a filter  
[update vlan replacement](#action-update-vlan-replacement) - Updates the vlan replacement settings of a filter  
[create filter](#action-create-filter) - Creates a new filter on the instance  
[list filters](#action-list-filters) - Fetch a list of the filters from the instance  
[describe filter](#action-describe-filter) - Fetches the details of a specified filter  
[restart](#action-restart) - Restarts Ixia vision one instance  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration parameters

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'delete filter'
Remove a filter from the instance

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_id\_or\_name** |  required  | Filter identifier | string |  `ixianpb filter id or name` 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.filter\_id\_or\_name | string |  `ixianpb filter id or name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update mode'
Update the mode of a filter

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_id\_or\_name** |  required  | Filter identifier | string |  `ixianpb filter id or name` 
**mode** |  required  | Mode of a filter | string | 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.filter\_id\_or\_name | string |  `ixianpb filter id or name` 
action\_result\.parameter\.mode | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update operator'
Update the operator of a filter

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_id\_or\_name** |  required  | Filter identifier | string |  `ixianpb filter id or name` 
**operator** |  required  | Operator of a filter | string | 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.filter\_id\_or\_name | string |  `ixianpb filter id or name` 
action\_result\.parameter\.operator | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update mac'
Update the mac address criteria for a filter

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_id\_or\_name** |  required  | Filter identifier | string |  `ixianpb filter id or name` 
**type** |  required  | Type of MAC address criteria | string | 
**administration** |  optional  | Admin type | string | 
**destination\_address** |  optional  | Destination address | string | 
**source\_mac** |  optional  | Source MAC addresses to be added | string | 
**destination\_mac** |  optional  | Destination MAC addresses to be added | string | 
**source\_or\_destination\_mac** |  optional  | Source or destination IP addresses to be added | string | 
**overwrite** |  optional  | Overwrites all the MAC related rules in the filter with the specified rule in the action run | boolean | 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.administration | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.destination\_address | string | 
action\_result\.parameter\.destination\_mac | string | 
action\_result\.parameter\.filter\_id\_or\_name | string |  `ixianpb filter id or name` 
action\_result\.parameter\.overwrite | boolean | 
action\_result\.parameter\.source\_mac | string | 
action\_result\.parameter\.source\_or\_destination\_mac | string | 
action\_result\.parameter\.type | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update port'
Update the port criteria of a filter

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_id\_or\_name** |  required  | Filter identifier | string |  `ixianpb filter id or name` 
**type** |  required  | Type of port criteria | string | 
**source\_port** |  optional  | Source IP addresses to be added | string | 
**destination\_port** |  optional  | Destination IP addresses to be added | string | 
**source\_or\_destination\_port** |  optional  | Source or destination IP addresses to be added | string | 
**overwrite** |  optional  | Overwrites all the port related rules in the filter with the specified rule in the action run | boolean | 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.destination\_port | string | 
action\_result\.parameter\.filter\_id\_or\_name | string |  `ixianpb filter id or name` 
action\_result\.parameter\.overwrite | boolean | 
action\_result\.parameter\.source\_or\_destination\_port | string | 
action\_result\.parameter\.source\_port | string | 
action\_result\.parameter\.type | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update ip'
Update the IP address criteria of a filter

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_id\_or\_name** |  required  | Filter identifier | string |  `ixianpb filter id or name` 
**type** |  required  | Type of IP address criteria | string | 
**source\_ip** |  optional  | Source IP addresses to be added | string | 
**destination\_ip** |  optional  | Destination IP addresses to be added | string | 
**source\_or\_destination\_ip** |  optional  | Source or destination IP addresses to be added | string | 
**overwrite** |  optional  | Overwrites all the IP related rules in the filter with the specified rule in the action run | boolean | 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.destination\_ip | string | 
action\_result\.parameter\.filter\_id\_or\_name | string |  `ixianpb filter id or name` 
action\_result\.parameter\.overwrite | boolean | 
action\_result\.parameter\.source\_ip | string | 
action\_result\.parameter\.source\_or\_destination\_ip | string | 
action\_result\.parameter\.type | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update vlan replacement'
Updates the vlan replacement settings of a filter

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_id\_or\_name** |  required  | Filter identifier | string |  `ixianpb filter id or name` 
**vlan\_id** |  required  | VLAN identifier | numeric | 
**enable** |  optional  | Enables the VLAN replacement | boolean | 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.enable | boolean | 
action\_result\.parameter\.filter\_id\_or\_name | string |  `ixianpb filter id or name` 
action\_result\.parameter\.vlan\_id | numeric | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create filter'
Creates a new filter on the instance

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_name** |  optional  | Name of the filter | string | 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.filter\_name | string |  `ixianpb filter id or name` 
action\_result\.data\.\*\.id | numeric |  `ixianpb filter id or name` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list filters'
Fetch a list of the filters from the instance

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.data\.\*\.id | numeric |  `ixianpb filter id or name` 
action\_result\.data\.\*\.name | string |  `ixianpb filter id or name` 
action\_result\.summary\.num\_filters | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'describe filter'
Fetches the details of a specified filter

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_id\_or\_name** |  required  | Filter identifier | string |  `ixianpb filter id or name` 
**allow\_temporary\_data\_loss** |  optional  | Allow temporary data loss | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_temporary\_data\_loss | boolean | 
action\_result\.parameter\.filter\_id\_or\_name | string |  `ixianpb filter id or name` 
action\_result\.data | string | 
action\_result\.data\.\*\.connect\_in\_access\_settings\.policy | string | 
action\_result\.data\.\*\.connect\_out\_access\_settings\.policy | string | 
action\_result\.data\.\*\.created\.caused\_by | string | 
action\_result\.data\.\*\.created\.details | string | 
action\_result\.data\.\*\.created\.time | numeric | 
action\_result\.data\.\*\.created\.type | string | 
action\_result\.data\.\*\.criteria\.ipv4\_dst\.addr | string | 
action\_result\.data\.\*\.criteria\.ipv4\_flow\.\*\.address\_sets\.\*\.addr\_a | string | 
action\_result\.data\.\*\.criteria\.ipv4\_flow\.\*\.address\_sets\.\*\.addr\_b | string | 
action\_result\.data\.\*\.criteria\.ipv4\_flow\.\*\.flow\_type | string | 
action\_result\.data\.\*\.criteria\.ipv4\_src\.addr | string | 
action\_result\.data\.\*\.criteria\.layer4\_dst\_port\.\*\.port | string | 
action\_result\.data\.\*\.criteria\.logical\_operation | string | 
action\_result\.data\.\*\.default\_name | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.dest\_port\_group\_list | numeric | 
action\_result\.data\.\*\.dynamic\_filter\_type | string | 
action\_result\.data\.\*\.history\.\*\.caused\_by | string | 
action\_result\.data\.\*\.history\.\*\.details | string | 
action\_result\.data\.\*\.history\.\*\.props | string | 
action\_result\.data\.\*\.history\.\*\.time | numeric | 
action\_result\.data\.\*\.history\.\*\.type | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.match\_count\_unit | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_IN\_ACCESS\_SETTINGS\.access\_settings\.policy | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_IN\_ACCESS\_SETTINGS\.current\_value | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_IN\_ACCESS\_SETTINGS\.expression\_text | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_IN\_ACCESS\_SETTINGS\.operation\_name | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_IN\_ACCESS\_SETTINGS\.operation\_phrase | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_IN\_ACCESS\_SETTINGS\.user\_names | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_IN\_ACCESS\_SETTINGS\.users\_statement | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_OUT\_ACCESS\_SETTINGS\.access\_settings\.policy | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_OUT\_ACCESS\_SETTINGS\.current\_value | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_OUT\_ACCESS\_SETTINGS\.expression\_text | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_OUT\_ACCESS\_SETTINGS\.operation\_name | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_OUT\_ACCESS\_SETTINGS\.operation\_phrase | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_OUT\_ACCESS\_SETTINGS\.user\_names | string | 
action\_result\.data\.\*\.misc\.access\_map\.CONNECT\_OUT\_ACCESS\_SETTINGS\.users\_statement | string | 
action\_result\.data\.\*\.misc\.access\_map\.MODIFY\_ACCESS\_SETTINGS\.access\_settings\.policy | string | 
action\_result\.data\.\*\.misc\.access\_map\.MODIFY\_ACCESS\_SETTINGS\.current\_value | string | 
action\_result\.data\.\*\.misc\.access\_map\.MODIFY\_ACCESS\_SETTINGS\.expression\_text | string | 
action\_result\.data\.\*\.misc\.access\_map\.MODIFY\_ACCESS\_SETTINGS\.operation\_name | string | 
action\_result\.data\.\*\.misc\.access\_map\.MODIFY\_ACCESS\_SETTINGS\.operation\_phrase | string | 
action\_result\.data\.\*\.misc\.access\_map\.MODIFY\_ACCESS\_SETTINGS\.user\_names | string | 
action\_result\.data\.\*\.misc\.access\_map\.MODIFY\_ACCESS\_SETTINGS\.users\_statement | string | 
action\_result\.data\.\*\.misc\.access\_map\.RESOURCE\_ACCESS\_SETTINGS\.access\_settings\.policy | string | 
action\_result\.data\.\*\.misc\.access\_map\.RESOURCE\_ACCESS\_SETTINGS\.current\_value | string | 
action\_result\.data\.\*\.misc\.access\_map\.RESOURCE\_ACCESS\_SETTINGS\.expression\_text | string | 
action\_result\.data\.\*\.misc\.access\_map\.RESOURCE\_ACCESS\_SETTINGS\.operation\_name | string | 
action\_result\.data\.\*\.misc\.access\_map\.RESOURCE\_ACCESS\_SETTINGS\.operation\_phrase | string | 
action\_result\.data\.\*\.misc\.access\_map\.RESOURCE\_ACCESS\_SETTINGS\.user\_names | string | 
action\_result\.data\.\*\.misc\.access\_map\.RESOURCE\_ACCESS\_SETTINGS\.users\_statement | string | 
action\_result\.data\.\*\.misc\.access\_map\.VIEW\_ACCESS\_SETTINGS\.access\_settings\.policy | string | 
action\_result\.data\.\*\.misc\.access\_map\.VIEW\_ACCESS\_SETTINGS\.current\_value | string | 
action\_result\.data\.\*\.misc\.access\_map\.VIEW\_ACCESS\_SETTINGS\.expression\_text | string | 
action\_result\.data\.\*\.misc\.access\_map\.VIEW\_ACCESS\_SETTINGS\.operation\_name | string | 
action\_result\.data\.\*\.misc\.access\_map\.VIEW\_ACCESS\_SETTINGS\.operation\_phrase | string | 
action\_result\.data\.\*\.misc\.access\_map\.VIEW\_ACCESS\_SETTINGS\.user\_names | string | 
action\_result\.data\.\*\.misc\.access\_map\.VIEW\_ACCESS\_SETTINGS\.users\_statement | string | 
action\_result\.data\.\*\.misc\.access\_props | string | 
action\_result\.data\.\*\.mod\_count | numeric | 
action\_result\.data\.\*\.mode | string | 
action\_result\.data\.\*\.modify\_access\_settings\.policy | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.port\_group\_list\.destination\_list\.\*\.id | numeric | 
action\_result\.data\.\*\.port\_group\_list\.destination\_list\.\*\.name | string | 
action\_result\.data\.\*\.port\_group\_list\.source\_list\.\*\.id | numeric | 
action\_result\.data\.\*\.port\_group\_list\.source\_list\.\*\.name | string | 
action\_result\.data\.\*\.resource\_access\_settings\.policy | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.burst\_buffer\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.data\_masking\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.dedup\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.erspan\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.etag\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.fabric\_path\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.filter\_criteria | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.filter\_match\_count\_unit | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.filter\_mode | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.filtering\_direction | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.filtering\_options | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.gtp\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.l2gre\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.lisp\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.mpls\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.packet\_fragmentation\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.packet\_length\_trailer\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.port\_mode | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.pppoe\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.resource\_id | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.timestamp\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.trailer\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.trim\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.vntag\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_config\.vxlan\_strip\_settings | string | 
action\_result\.data\.\*\.resource\_attachment\_type | string | 
action\_result\.data\.\*\.snmp\_tag | string | 
action\_result\.data\.\*\.source\_port\_group\_list | numeric | 
action\_result\.data\.\*\.view\_access\_settings\.policy | string | 
action\_result\.data\.\*\.vlan\_replace\_setting\.enabled | boolean | 
action\_result\.data\.\*\.vlan\_replace\_setting\.vlan\_id | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'restart'
Restarts Ixia vision one instance

Type: **generic**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 