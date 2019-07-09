# File: ixianetworkpacketbroker_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from ixianetworkpacketbroker_consts import *

# Usage of the consts file is recommended
# from ixianetworkpacketbroker_consts import *
import requests
import json
import base64
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class IxiaNetworkPacketBrokerConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(IxiaNetworkPacketBrokerConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._username = None
        self._password = None
        self._verify = None
        self._res_headers = None
        self._oauth_access_token = None
        self._proxy = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
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

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            if r.status_code == 404:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error: {0}".format(str(r.text))), None)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        if r.status_code == 401:
            message = "Error from server. Status Code: {}. Reason: {}. Description: {}".format(r.status_code, resp_json.get('reasonPhrase'), resp_json.get('description'))
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

    def _make_rest_call_oauth2(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(endpoint, json=json, data=data, proxies=self._proxy, headers=headers, verify=verify, params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}"
                                                   .format(str(e))), resp_json)

        self._res_headers = r.headers
        return self._process_response(r, action_result)

    def _make_rest_call_helper_oauth2(self, action_result, endpoint, verify=True, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that helps setting REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        url = "{0}{1}".format(self._base_url, endpoint)
        if (headers is None):
            headers = {}

        token = self._state.get('access_token', {})

        if not token:
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
        headers.update({
                'Authentication': self._oauth_access_token,
                'Content-Type': 'application/json'
            })

        ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, verify=verify, headers=headers, params=params, data=data, json=json, method=method)

        # If token is expired, generate a new token
        msg = action_result.get_message()
        # if msg and 'token is invalid' in msg or 'token has expired' in msg or 'ExpiredAuthenticationToken' in msg or 'authentication failed' in msg or 'access denied ' in msg:
        if msg and "Unauthorized" in msg:
            self.save_progress("bad token")
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({ 'Authentication': self._oauth_access_token})

            ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, verify, headers, params, data, json, method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _get_token(self, action_result, from_action=False):
        """ This function is used to get a token via REST Call.

        :param action_result: Object of action result
        :param from_action: Boolean object of from_action
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        encoded_creds = base64.b64encode("{}:{}".format(self._username, self._password))
        token1 = "Basic {}".format(encoded_creds)

        headers = {
            'Authorization': token1
        }

        ret_val, resp_json = self._make_rest_call_oauth2("{}{}".format(self._base_url, TOKEN_URL), action_result, verify=self._verify, headers=headers, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self._state['access_token'] = self._res_headers.get('X-Auth-Token')
        self._oauth_access_token = self._res_headers.get('X-Auth-Token')
        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        # new token
        ret_val = self._get_token(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        # make rest call
        ret_val, response = self._make_rest_call_helper_oauth2(action_result, IXIA_GET_FILTERS_ENDPOINT, verify=self._verify, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def fetch_filter_criteria(self, filter_id, action_result):
        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id)

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status(), None

        if response.get('criteria'):
            return action_result.set_status(phantom.APP_SUCCESS), response.get('criteria')
        else:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No criteria found"), None)

    def check_input(self, inp, inp_name, action_result):
        if isinstance(inp, list):
            for i in inp:
                if not isinstance(i, list):
                    return action_result.set_status(phantom.APP_ERROR, 'The input parameter {} must be in proper JSON (list of list) format.\
                    Example :- [["X","Y"], ["Z"]]'.format(inp_name))

            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, 'The input parameter {} must be in proper JSON (list of list) format.\
            Example :- [["X","Y"], ["Z"]]'.format(inp_name))

    def _handle_update_mac(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        filter_id = param['filter_id_or_name']
        type = param['type']
        overwrite = param['overwrite']

        criteria = dict()
        mac_add_dict = dict()
        params = dict()

        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')
        mac_list = ['mac_src', 'mac_dst', 'mac_src_or_dst', 'mac_flow']

        ret_val, criteria_resp = self.fetch_filter_criteria(filter_id, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if overwrite:
            for item in mac_list:
                try:
                    del criteria_resp[item]
                except:
                    pass

        type_map = MAC_TYPE_MAP[type][0]

        if type_map == "mac_src":

            mac_list = list()
            mac_address_1 = param.get('source_mac')
            admin_type = param.get('administration')

            if mac_address_1:
                try:
                    mac_address_1 = json.loads(mac_address_1)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

                ret_val = self.check_input(mac_address_1, 'source_mac', action_result)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                for item in mac_address_1:
                    data = {}
                    data["addr"] = item
                    mac_list.append(data)
            elif admin_type:
                try:
                    admin_type = json.loads(admin_type)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

                if not isinstance(admin_type, list):
                    return action_result.set_status(phantom.APP_ERROR, "Please provide administration input in a valid JSON format")

                for item in admin_type:
                    data = {}
                    data["admin_type"] = item
                    mac_list.append(data)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Please provide value in source_mac or administration parameter")

            if criteria_resp.get(type_map):
                temp = criteria_resp.get(type_map)
                if isinstance(temp, dict):
                    mac_list.append(temp)
                else:
                    mac_list.extend(temp)

            mac_add_dict[type_map] = mac_list

            criteria_resp.update(mac_add_dict)

        elif type_map == "mac_dst":
            mac_list = list()
            mac_address_1 = param.get('destination_mac')
            admin_type = param.get('administration')
            destination_addr = param.get('destination_address')

            if mac_address_1:
                try:
                    mac_address_1 = json.loads(mac_address_1)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

                ret_val = self.check_input(mac_address_1, 'destination_mac', action_result)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                for item in mac_address_1:
                    data = {}
                    data["addr"] = item
                    mac_list.append(data)
            elif admin_type and destination_addr:
                try:
                    admin_type = json.loads(admin_type)
                    destination_addr = json.loads(destination_addr)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

                if not isinstance(admin_type, list) or not isinstance(destination_addr, list):
                    return action_result.set_status(phantom.APP_ERROR, "Please provide administration and destination_address input in a valid JSON format")

                if len(admin_type) != len(destination_addr):
                    return action_result.set_status(phantom.APP_ERROR, "Length of admin_type and destination_addr must be same")

                for i, j in enumerate(admin_type):
                    data = {}
                    data['admin_type'] = admin_type[i]
                    data['dest_addr_type'] = destination_addr[i]
                    mac_list.append(data)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Please provide value in destination_mac or in adminstration and destination_addr parameter(s)")

            if criteria_resp.get(type_map):
                temp = criteria_resp.get(type_map)
                if isinstance(temp, dict):
                    mac_list.append(temp)
                else:
                    mac_list.extend(temp)

            mac_add_dict[type_map] = mac_list

            criteria_resp.update(mac_add_dict)

        elif type_map == "mac_src_or_dst":
            mac_list = list()
            mac_address_1 = param.get('source_or_destination_mac')

            if mac_address_1:
                try:
                    mac_address_1 = json.loads(mac_address_1)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

                ret_val = self.check_input(mac_address_1, 'source_or_destination_mac', action_result)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                for item in mac_address_1:
                    data = {}
                    data["addr"] = item
                    mac_list.append(data)

            else:
                return action_result.set_status(phantom.APP_ERROR, "Please provide value in source_or_destination_mac parameter")

            if criteria_resp.get(type_map):
                temp = criteria_resp.get(type_map)
                if isinstance(temp, dict):
                    mac_list.append(temp)
                else:
                    mac_list.extend(temp)

            mac_add_dict[type_map] = mac_list

            criteria_resp.update(mac_add_dict)

        else:
            flow_type = MAC_TYPE_MAP[type][1]
            flow = dict()
            address_set = list()
            flow_list = list()
            try:
                mac_address_1 = json.loads(param.get('source_mac'))
                mac_address_2 = json.loads(param.get('destination_mac'))
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

            ret_val = self.check_input(mac_address_1, 'source_mac', action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            ret_val = self.check_input(mac_address_2, 'destination_mac', action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if len(mac_address_1) != len(mac_address_2):
                return action_result.set_status(phantom.APP_ERROR, "Lenght of source and destination must be same")

            for i, j in enumerate(mac_address_1):
                data = {}
                data['addr_a'] = mac_address_1[i]
                data['addr_b'] = mac_address_2[i]
                address_set.append(data)

            flow['address_sets'] = address_set
            flow['flow_type'] = flow_type

            if criteria_resp.get(type_map):
                temp = criteria_resp.get(type_map)
                if isinstance(temp, dict):
                    flow_list.append(temp)
                else:
                    flow_list.extend(temp)

            flow_list.append(flow)

            criteria_resp.update({"mac_flow": flow_list})

        criteria['criteria'] = criteria_resp
        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id)

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params, headers=None, json=criteria, method="put")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Updated the MAC address criteria for a filter successfully")

    def _handle_update_port(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        filter_id = param['filter_id_or_name']
        type = param['type']
        overwrite = param['overwrite']

        criteria = dict()
        port_dict = dict()
        params = dict()

        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')
        port_list = ['layer4_dst_port', 'layer4_src_port', 'layer4_src_or_dst_port', 'layer4_port_flow']

        ret_val, criteria_resp = self.fetch_filter_criteria(filter_id, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if overwrite:
            for item in port_list:
                try:
                    del criteria_resp[item]
                except:
                    pass

        type_map = PORT_TYPE_MAP[type][0]

        if type_map != "layer4_port_flow":

            port_list = list()
            port_1 = param.get(PORT_TYPE_MAP[type][1])

            if not port_1:
                return action_result.set_status(phantom.APP_ERROR, "Please provide value in {} parameter".format(PORT_TYPE_MAP[type][1]))
            try:
                port_1 = json.loads(port_1)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

            ret_val = self.check_input(port_1, PORT_TYPE_MAP[type][1], action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # if not isinstance(port_1, list):
                # return action_result.set_status(phantom.APP_ERROR, "Please provide {} input in a valid format".format(PORT_TYPE_MAP[type][1]))

            for item in port_1:
                data = {}
                data["port"] = ','.join(item)
                port_list.append(data)

            if criteria_resp.get(type_map):
                temp = criteria_resp.get(type_map)
                if isinstance(temp, dict):
                    port_list.append(temp)
                else:
                    port_list.extend(temp)

            port_dict[type_map] = port_list

            criteria_resp.update(port_dict)

        elif not param.get('source_port') or not param.get('destination_port'):
            return action_result.set_status(phantom.APP_ERROR, "Please provide value in both source_port and destination_port parameters")

        else:
            flow_type = PORT_TYPE_MAP[type][1]
            flow = dict()
            port_set = list()
            flow_list = list()
            try:
                port_1 = json.loads(param.get('source_port'))
                port_2 = json.loads(param.get('destination_port'))
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

            ret_val = self.check_input(port_1, 'source_port', action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            ret_val = self.check_input(port_2, 'destination_port', action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not isinstance(port_1, list) or not isinstance(port_2, list):
                return action_result.set_status(phantom.APP_ERROR, "Please provide source_port and destination_port input in a valid format")

            if len(port_1) != len(port_2):
                return action_result.set_status(phantom.APP_ERROR, "Lenght of source and destination must be same")

            for i, j in enumerate(port_1):
                data = {}
                data['port_a'] = ','.join(port_1[i])
                data['port_b'] = ','.join(port_2[i])
                port_set.append(data)

            flow['port_sets'] = port_set
            flow['flow_type'] = flow_type

            if criteria_resp.get(type_map):
                temp = criteria_resp.get(type_map)
                if isinstance(temp, dict):
                    flow_list.append(temp)
                else:
                    flow_list.extend(temp)

            flow_list.append(flow)

            criteria_resp.update({"layer4_port_flow": flow_list})

        criteria['criteria'] = criteria_resp
        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id)

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params, headers=None, json=criteria, method="put")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Updated the port criteria for a filter successfully")

    def _handle_update_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        filter_id = param['filter_id_or_name']
        type = param['type']
        overwrite = param['overwrite']

        criteria = dict()
        ip_add_dict = dict()
        params = dict()

        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')
        ipv4_list = ['ipv4_src', 'ipv4_dst', 'ipv4_src_or_dst', 'ipv4_flow']

        ret_val, criteria_resp = self.fetch_filter_criteria(filter_id, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if overwrite:
            for item in ipv4_list:
                try:
                    del criteria_resp[item]
                except:
                    pass

        type_map = IP_TYPE_MAP[type][0]

        if type_map != "ipv4_flow":

            ip_list = list()
            ip_address_1 = param.get(IP_TYPE_MAP[type][1])

            if not ip_address_1:
                return action_result.set_status(phantom.APP_ERROR, "Please provide value in {} parameter".format(IP_TYPE_MAP[type][1]))

            try:
                ip_address_1 = json.loads(ip_address_1)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

            ret_val = self.check_input(ip_address_1, IP_TYPE_MAP[type][1], action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # if not isinstance(ip_address_1, list):
                # return action_result.set_status(phantom.APP_ERROR, "Please provide {} input in a valid format".format(IP_TYPE_MAP[type][1]))

            for item in ip_address_1:
                data = {}
                data["addr"] = item
                ip_list.append(data)

            if criteria_resp.get(type_map):
                temp = criteria_resp.get(type_map)
                if isinstance(temp, dict):
                    ip_list.append(temp)
                else:
                    ip_list.extend(temp)

            ip_add_dict[type_map] = ip_list

            criteria_resp.update(ip_add_dict)

        elif not param.get('source_ip') or not param.get('destination_ip'):
            return action_result.set_status(phantom.APP_ERROR, "Please provide value in both source_id and destination_id parameters")

        else:
            flow_type = IP_TYPE_MAP[type][1]
            flow = dict()
            address_set = list()
            flow_list = list()
            try:
                ip_address_1 = json.loads(param.get('source_ip'))
                ip_address_2 = json.loads(param.get('destination_ip'))
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error while parsing into JSON. Error: {}".format(str(e)))

            ret_val = self.check_input(ip_address_1, 'source_ip', action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            ret_val = self.check_input(ip_address_2, 'destination_ip', action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # if not isinstance(ip_address_1, list) or not isinstance(ip_address_2, list):
                # return action_result.set_status(phantom.APP_ERROR, "Please provide source_ip and destination_ip input in a valid format")

            if len(ip_address_1) != len(ip_address_2):
                return action_result.set_status(phantom.APP_ERROR, "Lenght of source and destination must be same")

            for i, j in enumerate(ip_address_1):
                data = {}
                data['addr_a'] = ip_address_1[i]
                data['addr_b'] = ip_address_2[i]
                address_set.append(data)

            flow['address_sets'] = address_set
            flow['flow_type'] = flow_type

            if criteria_resp.get(type_map):
                temp = criteria_resp.get(type_map)
                if isinstance(temp, dict):
                    flow_list.append(temp)
                else:
                    flow_list.extend(temp)

            flow_list.append(flow)

            criteria_resp.update({"ipv4_flow": flow_list})

        criteria['criteria'] = criteria_resp
        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id)

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params, headers=None, json=criteria, method="put")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Updated the IP address criteria for a filter successfully")

    def _handle_update_operator(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        filter_id = param['filter_id_or_name']
        operator = param['operator']

        criteria = dict()
        params = dict()

        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')

        ret_val, criteria_resp = self.fetch_filter_criteria(filter_id, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        criteria_resp.update({'logical_operation': operator})

        criteria['criteria'] = criteria_resp
        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id)

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params, headers=None, json=criteria, method="put")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Filter operator updated successfully")

    def _handle_update_mode(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        filter_id = param['filter_id_or_name']
        mode = param['mode']

        params = dict()
        data = dict()

        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')
        data['mode'] = MODE_MAP.get(mode, '')

        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id)

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params, headers=None, json=data, method="put")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = "Filter mode updated successfully"

        return action_result.set_status(phantom.APP_SUCCESS, "Filter mode updated successfully")

    def _handle_update_vlan_replacement(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        filter_id = param['filter_id_or_name']
        vlan_id = param['vlan_id']
        enables = param['enable']

        params = dict()
        data = dict()
        vlan_setting = dict()

        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')

        vlan_setting['enabled'] = enables
        vlan_setting['vlan_id'] = vlan_id

        data['vlan_replace_setting'] = vlan_setting

        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id)

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params, headers=None, json=data, method="put")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = "VLAN replacement settings updated successfully"

        return action_result.set_status(phantom.APP_SUCCESS, "Filter VLAN replacement settings updated successfully")

    def _handle_delete_filter(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        filter_id = param['filter_id_or_name']

        params = {}
        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')

        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id)
        # make rest call
        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params, headers=None, method="delete")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = "One item deleted succussfully"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_SUCCESS, "Deleted filter successfully")

    def _handle_create_filter(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        allowtemporarydataloss = param.get('allowtemporarydataloss')
        filter_name = param.get('filter_name')

        data = None
        if filter_name:
            data = dict()
            data['name'] = filter_name

        params = {}
        params['allowtemporarydataloss'] = allowtemporarydataloss

        endpoint = IXIA_GET_FILTERS_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params, headers=None, json=data, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Created filter successfully")

    def _handle_describe_filter(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        filter_id_or_name = param.get('filter_id_or_name')
        params = dict()
        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')

        endpoint = "{}/{}".format(IXIA_GET_FILTERS_ENDPOINT, filter_id_or_name)

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        src_port_grp_list = response.get('source_port_group_list')
        dst_port_grp_list = response.get('dest_port_group_list')
        src_port_list = response.get('source_port_list')
        dst_port_list = response.get('dest_port_list')
        resp_port_grp_dict = dict()

        if src_port_grp_list or dst_port_grp_list:

            ret_val, resp = self._make_rest_call_helper_oauth2(action_result, '/api/port_groups', verify=self._verify, params=params)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            for item in resp:
                resp_port_grp_dict[item.get('id')] = item.get('name')

            source_list = list()
            destination_list = list()

            for i in src_port_grp_list:
                if i in resp_port_grp_dict:
                    port_grp_detail = dict()
                    port_grp_detail['id'] = i
                    port_grp_detail['name'] = resp_port_grp_dict[i]
                    source_list.append(port_grp_detail)

            for i in dst_port_grp_list:
                if i in resp_port_grp_dict:
                    port_grp_detail = dict()
                    port_grp_detail['id'] = i
                    port_grp_detail['name'] = resp_port_grp_dict[i]
                    destination_list.append(port_grp_detail)

            group_dic = dict()
            group_dic['source_list'] = source_list
            group_dic['destination_list'] = destination_list

            response['port_group_list'] = group_dic

        if src_port_list or dst_port_list:

            ret_val, resp = self._make_rest_call_helper_oauth2(action_result, '/api/ports', verify=self._verify, params=params)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            for item in resp:
                resp_port_grp_dict[item.get('id')] = item.get('name')

            source_list = list()
            destination_list = list()

            for i in src_port_list:
                if i in resp_port_grp_dict:
                    port_grp_detail = dict()
                    port_grp_detail[i] = src_port_list[i]
                    source_list.append(port_grp_detail)

            for i in dst_port_list:
                if i in resp_port_grp_dict:
                    port_grp_detail = dict()
                    port_grp_detail['id'] = i
                    port_grp_detail['name'] = dst_port_list[i]
                    destination_list.append(port_grp_detail)

            group_dic = dict()
            group_dic['source_list'] = source_list
            group_dic['destination_list'] = destination_list

            response['port_list'] = group_dic

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved filter information")

    def _handle_list_filters(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = dict()
        params['allowtemporarydataloss'] = param.get('allowtemporarydataloss')

        endpoint = IXIA_GET_FILTERS_ENDPOINT

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, params=params)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        for item in response:
            action_result.add_data(item)

        summary = action_result.update_summary({})
        summary['num_filters'] = len(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restart(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        endpoint = IXIA_RESTART_ENDPOINT

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, verify=self._verify, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "System restart request sent sucessfully")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'delete_filter':
            ret_val = self._handle_delete_filter(param)

        elif action_id == 'update_vlan_replacement':
            ret_val = self._handle_update_vlan_replacement(param)

        elif action_id == 'update_mode':
            ret_val = self._handle_update_mode(param)

        elif action_id == 'update_operator':
            ret_val = self._handle_update_operator(param)

        elif action_id == 'update_ip':
            ret_val = self._handle_update_ip(param)

        elif action_id == 'update_port':
            ret_val = self._handle_update_port(param)

        elif action_id == 'update_mac':
            ret_val = self._handle_update_mac(param)

        elif action_id == 'create_filter':
            ret_val = self._handle_create_filter(param)

        elif action_id == 'list_filters':
            ret_val = self._handle_list_filters(param)

        elif action_id == 'describe_filter':
            ret_val = self._handle_describe_filter(param)

        elif action_id == 'restart':
            ret_val = self._handle_restart(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._username = config['username']
        self._password = config['password']
        self._verify = config['verify_cert']

        self._base_url = config['endpoint']

        self._oauth_access_token = self._state.get('access_token', {})

        self._proxy = {}
        env_vars = config.get('_reserved_environment_variables', {})

        if 'HTTP_PROXY' in env_vars:
            self._proxy['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._proxy['https'] = env_vars['HTTPS_PROXY']['value']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
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
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = IxiaNetworkPacketBrokerConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
