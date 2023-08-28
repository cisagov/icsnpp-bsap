# ICSNPP-BSAP

Industrial Control Systems Network Protocol Parsers (ICSNPP) - BSAP over IP.

## Overview

ICSNPP-BSAP is a Zeek plugin for parsing and logging fields within the BSAP (Bristol Standard Asynchronous Protocol).

This plugin was developed to be fully customizable. To drill down into specific BSAP packets and log certain variables, users can add the logging functionality to [scripts/icsnpp/bsap/main.zeek](scripts/icsnpp/bsap/main.zeek). The functions within [scripts/icsnpp/bsap/main.zeek](scripts/icsnpp/bsap/main.zeek) and [src/events.bif](src/events.bif) are good guides for adding new logging functionality.

This parser produces seven log files. These log files are defined in [scripts/icsnpp/bsap/main.zeek](scripts/icsnpp/bsap/main.zeek).
* bsap_ip_header.log
* bsap_ip_rdb.log
* bsap_ip_unknown.log 
* bsap_serial_header.log 
* bsap_serial_rdb.log 
* bsap_serial_rdb_ext.log
* bsap_serial_unknown.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-bsap
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly, users will see `ICSNPP::BSAP`.

If ZKG is configured to load packages (see @load packages in quickstart guide), this plugin and these scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add `icsnpp/bsap` to the command to run this plugin's scripts on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-bsap.git
zeek -Cr icsnpp-bsap/tests/traces/bsap-ip_example.pcap icsnpp/bsap
zeek -Cr icsnpp-bsap/tests/traces/bsap-serial_example.pcapng icsnpp/bsap
```

### Manual Install

To install this package manually, clone this repository and run the configure and make commands as shown below.

```bash
git clone https://github.com/cisagov/icsnpp-bsap.git
cd icsnpp-bsap/
./configure
make
```

If these commands succeed, users will end up with a newly created build directory that contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::BSAP_IP
```

Once users have tested the functionality locally and it appears to have compiled correctly, they can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::BSAP_IP
```

To run this plugin in a site deployment users will need to add the line `@load icsnpp/bsap` to the `site/local.zeek` file to load this plugin's scripts.

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add `icsnpp/bsap` to the command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-bsap/tests/traces/bsap-ip_example.pcap icsnpp/bsap
zeek -Cr icsnpp-bsap/tests/traces/bsap-serial_example.pcapng icsnpp/bsap
```

If users want to deploy this plugin on an already existing Zeek implementation and don't want to build the plugin on the machine, they can extract the ICSNPP_Bsap.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/ICSNPP_Bsap.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### Header Log (bsap_ip_header.log)

#### Overview

This log captures BSAP header information for every BSAP packet converted to ethernet and logs it to **bsap_ip_header.log**.

#### Fields Captured

| Field             | Type      | Description                                                   |
| ----------------- |-----------|---------------------------------------------------------------|
| ts                | time      | Timestamp                                                     |
| uid               | string    | Unique ID for this connection                                 |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig           | bool      | True if the packet is sent from the originator                |
| source_h          | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p          | port      | Source port (see *Source and Destination Fields*)             |
| destination_h     | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p     | port      | Destination port (see *Source and Destination Fields*)        |
| num_msg           | string    | Number of functions per message                               |
| type_name         | count     | Message type                                                  |


### RDB (Remote Database Access) Log (bsap_ip_rdb.log)

#### Overview

This log captures BSAP RDB function information and logs it to **bsap_ip_rdb.log**.

The vast majority of BSAP traffic is RDB function traffic. The RDB access is used to read and write variables between master and slave RTUs.

#### Fields Captured

| Field                 | Type           | Description                                                 |
| --------------------- |----------------|-------------------------------------------------------------|
| ts                    | time           | Timestamp                                                   |
| uid                   | string         | Unique ID for this connection                               |
| id                    | conn_id        | Default Zeek connection info (IP addresses, ports)          |
| is_orig               | bool           | True if the packet is sent from the originator              |
| source_h              | address        | Source IP address (see *Source and Destination Fields*)     |
| source_p              | port           | Source port (see *Source and Destination Fields*)           |
| destination_h         | address        | Destination IP address (see *Source and Destination Fields*)|
| destination_p         | port           | Destination port (see *Source and Destination Fields*)      |
| header_size           | count          | Header length                                               |
| mes_seq               | count          | Message sequence                                            |
| res_seq               | count          | Response sequence                                           |
| data_len              | count          | Length of data                                              |
| sequence              | count          | Function sequence (same as response)                        |
| app_func_code         | string         | Application function                                        |
| node_status           | count          | Node status byte                                            |
| func_code             | string         | Application sub function                                    |
| variable_count        | count          | Variable count in message                                   |
| variables             | vector<string> | Vector of variables in message                              |
| variable_value        | vector<string> | Vector of variable value in message                         |


### Unknown Log (bsap_ip_unknown.log)

#### Overview

This log captures all other zeek_bsap_ip traffic that hasn't been defined and logs it to **bsap_ip_unknown.log**.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|---------------------------------------------------------------|
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this connection                                 |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination port (see *Source and Destination Fields*)        |
| data                  | string    | BSAP_IP unknown data                                          |


### BSAP Header Log (bsap_serial_header.log)

#### Overview

This log captures BSAP header information for every BSAP packet converted to Ethernet and logs it to **bsap_serial_header.log**.

#### Fields Captured

| Field             | Type      | Description                                                   |
| ----------------- |-----------|---------------------------------------------------------------|
| ts                | time      | Timestamp                                                     |
| uid               | string    | Unique ID for this connection                                 |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig           | bool      | True if the packet is sent from the originator                |
| source_h          | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p          | port      | Source port (see *Source and Destination Fields*)             |
| destination_h     | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p     | port      | Destination port (see *Source and Destination Fields*)        |
| ser               | string    | Message serial number                                         |
| dadd              | count     | Destination address                                           |
| sadd              | count     | Source address                                                |
| ctl               | count     | Control byte                                                  |
| dfun              | string    | Destination function                                          |
| seq               | count     | Message sequence                                              |
| sfun              | string    | Source function                                               |
| nsb               | count     | Node status byte                                              |
| type_name         | string    | Local or global header                                        |

### BSAP RDB (Remote Database Access) Log (bsap_serial_rdb.log)

#### Overview

This log captures BSAP RDB function information and logs it to **bsap_serial_rdb.log**.

The vast majority of BSAP traffic is RDB function traffic. The RDB access is used to read and write variables between master and slave RTU's.

#### Fields Captured

| Field                 | Type           | Description                                                 |
| --------------------- |----------------|-------------------------------------------------------------|
| ts                    | time           | Timestamp                                                   |
| uid                   | string         | Unique ID for this connection                               |
| id                    | conn_id        | Default Zeek connection info (IP addresses, ports)          |
| is_orig               | bool           | True if the packet is sent from the originator              |
| source_h              | address        | Source IP address (see *Source and Destination Fields*)     |
| source_p              | port           | Source port (see *Source and Destination Fields*)           |
| destination_h         | address        | Destination IP address (see *Source and Destination Fields*)|
| destination_p         | port           | Destination port (see *Source and Destination Fields*)      |
| func_code             | string         | RDB function being initiated                                |
| variables             | vector<string> | Vector of variables in message                              |
| variable_value        | vector<string> | Vector of variable value in message                         |


### BSAP BSAP_RDB_EXT (Remote Database Access Extended) Log (bsap_serial_rdb_ext.log)

#### Overview

This log captures BSAP RDB Extension function information and logs it to **bsap_serial_rdb_ext.log**.

These Extension functions of RDB contain information from controllers loading date and time, setting clearing diagnostics, and calling system resets. These only pertain to the GFC 3308 controllers.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|---------------------------------------------------------------|
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this connection                                 |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination port (see *Source and Destination Fields*)        |
| dfun                  | string    | Destination function                                          |
| seq                   | count     | Message sequence                                              |
| sfun                  | string    | Source function                                               |
| nsb                   | count     | Node status byte                                              |
| extfun                | string    | RDB extension function                                        |
| data                  | string    | RDB extension function specific data                          |


### BSAP Unknown (bsap_serial_unknown.log)

#### Overview

This log captures all other BSAP traffic that hasn't been defined and logs it to **bsap_serial_unknown.log**.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|---------------------------------------------------------------|
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this connection                                 |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination port (see *Source and Destination Fields*)        |
| data                  | string    | BSAP unknown data                                             |

### Source and Destination Fields

#### Overview

Zeek's typical behavior is to focus on and log packets from the originator and not log packets from the responder. However, most ICS protocols contain useful information in the responses, so the ICSNPP parsers log both originator and responses packets. Zeek's default behavior, defined in its `id` struct, is to never switch these originator/responder roles which leads to inconsistencies and inaccuracies when looking at ICS traffic that logs responses.

The default Zeek `id` struct contains the following logged fields:
* id.orig_h (Original Originator/Source Host)
* id.orig_p (Original Originator/Source Port)
* id.resp_h (Original Responder/Destination Host)
* id.resp_p (Original Responder/Destination Port)

Additionally, the `is_orig` field is a boolean field that is set to T (True) when the id_orig fields are the true originators/source and F (False) when the id_resp fields are the true originators/source.

To not break existing platforms that utilize the default `id` struct and `is_orig` field functionality, the ICSNPP team has added four new fields to each log file instead of changing Zeek's default behavior. These four new fields provide the accurate information regarding source and destination IP addresses and ports:
* source_h (True Originator/Source Host)
* source_p (True Originator/Source Port)
* destination_h (True Responder/Destination Host)
* destination_p (True Responder/Destination Port)

The pseudocode below shows the relationship between the `id` struct, `is_orig` field, and the new `source` and `destination` fields.

```
if is_orig == True
    source_h == id.orig_h
    source_p == id.orig_p
    destination_h == id.resp_h
    destination_p == id.resp_p
if is_orig == False
    source_h == id.resp_h
    source_p == id.resp_p
    destination_h == id.orig_h
    destination_p == id.orig_p
```

#### Example

The table below shows an example of these fields in the log files. The first log in the table represents a Modbus request from 192.168.1.10 -> 192.168.1.200 and the second log represents a Modbus reply from 192.168.1.200 -> 192.168.1.10. As shown in the table below, the `id` structure lists both packets as having the same originator and responder, but the `source` and `destination` fields reflect the true source and destination of these packets.

| id.orig_h    | id.orig_p | id.resp_h     | id.resp_p | is_orig | source_h      | source_p | destination_h | destination_p |
| ------------ | --------- |---------------|-----------|---------|---------------|----------|---------------|-------------- |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | T       | 192.168.1.10  | 47785    | 192.168.1.200 | 502           |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | F       | 192.168.1.200 | 502      | 192.168.1.10  | 47785         |

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/icsnpp-bsap)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a national research facility with a focus on development of software and toolchains to improve the security of criticial infrastructure environments around the world. Please review our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2023 Battelle Energy Alliance, LLC

Licensed under the 3-Clause BSD License (the "License");
this file cannot be used except in compliance with the License.
A copy of the License can be obtained at:

  https://opensource.org/licenses/BSD-3-Clause

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Licensing
-----
This software is licensed under the terms found in the file named "LICENSE" in this directory.
