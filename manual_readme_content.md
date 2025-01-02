[comment]: # " File: README.md"
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
