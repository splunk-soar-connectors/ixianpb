# File: ixianetworkpacketbroker_consts.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
IXIA_GET_FILTERS_ENDPOINT = '/api/filters'
TOKEN_URL = '/api/actions/get_login_info'
MODE_MAP = {
    "Pass All": "PASS_ALL",
    "Pass By Criteria": "PASS_BY_CRITERIA",
    "PBC Unmatched": "PBC_UNMATCHED",
    "Disable": "DISABLE",
    "Deny By Criteria": "DENY_BY_CRITERIA",
    "DBC Matched": "DBC_MATCHED"
}
IP_TYPE_MAP = {
    "Source": ["ipv4_src", "source_ip"],
    "Destination": ["ipv4_dst", "destination_ip"],
    "Source or Destination": ["ipv4_src_or_dst", "source_or_destination_ip"],
    "Unidirectional Flow": ["ipv4_flow", "UNI"],
    "Bidirectional Flow": ["ipv4_flow", "BIDI"]
}
PORT_TYPE_MAP = {
    "Source": ["ipv4_src", "source_ip"],
    "Destination": ["ipv4_dst", "destination_ip"],
    "Source or Destination": ["ipv4_src_or_dst", "source_or_destination_ip"],
    "Unidirectional Flow": ["ipv4_flow", "UNI"],
    "Bidirectional Flow": ["ipv4_flow", "BIDI"]
}
MAC_TYPE_MAP = {
    "Source": ["layer4_src_port", "source_port"],
    "Destination": ["layer4_dst_port", "destination_port"],
    "Source or Destination": ["layer4_src_or_dst_port", "source_or_destination_port"],
    "Unidirectional Flow": ["layer4_port_flow", "UNI"],
    "Bidirectional Flow": ["layer4_port_flow", "BIDI"]
}
