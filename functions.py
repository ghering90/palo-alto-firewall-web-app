import requests
import json
import xmltodict as xmltodict
import pandas as pd
import time
import os


class LogClass:
    def __init__(self):
        self.API_KEY_PALO = os.environ.get('NEW_TEST_PALO_API_KEY')

    def xml_api_call(self, fw, cmd):
        headers = {
            'Accept': 'application/json',
            'X-PAN-KEY': self.API_KEY_PALO,
        }
        palo_job_url = f"https://{fw}/api/?type=op&cmd={cmd}"
        job_response = requests.get(url=palo_job_url, headers=headers, verify=False)
        return xmltodict.parse(job_response.content)

    def get_fw_data(self, fw, log_num, query):
        paloURL = f"https://{fw}/api/?type=log&log-type=traffic&nlogs={log_num}&query=({query})"
        headers = {
            'Accept': 'application/json',
            'X-PAN-KEY': self.API_KEY_PALO,
        }
        try:
            response = requests.get(url=paloURL, headers=headers, verify=False)
        except requests.exceptions.InvalidURL:
            return 'wrong input'
        except requests.exceptions.ConnectionError:
            return 'wrong input'
        else:
            print(response.status_code)
            # makes a dictonary from the xml and grabs the job id
            dict_data = xmltodict.parse(response.content)
            job_id = dict_data['response']['result']['job']

            # takes the job id from the dict and runs command to query for it
            waiting = True
            while waiting:
                time.sleep(5)
                palo_job_url = f"https://{fw}/api/?type=op&cmd=<show><query><result><id>{job_id}</id></result></query></show>"
                job_response = requests.get(url=palo_job_url, headers=headers, verify=False)
                dict_result = xmltodict.parse(job_response.content)
                json_object = json.dumps(dict_result, indent=4)
                progress = json.loads(json_object)['response']['result']['log']['logs']['@progress']
                if progress == '100':
                    print(f'progress {progress}%')
                    with open("sample.json", "w") as outfile:
                        outfile.write(json_object)
                    return json.loads(json_object)
                else:
                    print(f'progress {progress}%')

    def pull_logs(self, log_data, fw):
        try:
            loop = log_data['response']['result']['log']['logs']['entry']
            return pd.DataFrame(loop)
            # df.to_excel(f'{fw}_logs.xlsx')
            # for n in range(0, len(loop)):
            #     if loop[n]['action'] == 'allow':
            #         print(
            #             f"source ip {loop[n]['src']} to destination ip {loop[n]['dst']} traffic is allowed through the firewall via this rule {loop[n]['rule']} last time hit {loop[n]['time_generated']}"
            #             f" no issue to report")
            #     else:
            #         print(f"your traffic is being denied by {loop[n]['rule']}")
        except KeyError:
            print(f"timeout")

    def log_input(self, data):

        query_list = []

        device = data['device']
        ha_device = ''
        amount_logs = 10
        if int(amount_logs) > 100:
            amount_logs = '100'

        src_ip = data['src_ip']
        if src_ip != '':
            query_list.append(f'and ( addr.src in {src_ip})')
        dst_ip = data['dst_ip']
        if dst_ip != '':
            query_list.append(f'and ( addr.dst in {dst_ip})')
        port = data['port']
        if port != '':
            query_list.append(f'and ( port.dst eq {port})')
        time_start = data['time_start']
        if time_start != '':
            query_list.append(f"and ( receive_time geq '{time_start}')")
        time_end = data['time_stop']
        if time_end != '':
            query_list.append(f"and ( receive_time leq '{time_end}')")
        try:
            query_list[0] = query_list[0][4:]
        except IndexError:
            return 'wrong input'
        else:
            query_string = ' '.join(query_list)

            if ha_device == '':
                primary_device = self.get_fw_data(device, amount_logs, query_string)
                if primary_device == 'wrong input':
                    return primary_device
                else:
                    self.pull_logs(primary_device, device)
                # self.pull_logs(primary_device, device)
            else:
                primary_device = self.get_fw_data(device, amount_logs, query_string)
                secondary_device = self.get_fw_data(ha_device, amount_logs, query_string)
                self.pull_logs(primary_device, device)
                self.pull_logs(secondary_device, ha_device)
            df = self.pull_logs(primary_device, device)
            return df[['time_generated', 'from', 'src', 'to', 'dst', 'rule', 'app', 'dport', 'captive-portal', 'action',
                      'device_name', 'bytes_sent', 'bytes_received', 'packets', 'session_end_reason']]

    def get_ha_info(self, data):
        response = self.xml_api_call(fw=data['device'], cmd='<show><high-availability><all/></high-availability></show>')
        return response['response']['result']['group']['local-info']['state']

    def get_mgmt_uptime_info(self, data):
        response = self.xml_api_call(fw=data['device'],
                                     cmd='<show><system><resources/></system></show>')
        return response['response']['result'][15:33]

    def get_data_uptime_info(self, data):
        response = self.xml_api_call(fw=data['device'],
                                     cmd='<show><system><info/></system></show>')
        return response['response']['result']['system']['uptime']

    def get_ha_info(self, data):
        response = self.xml_api_call(fw=data['device'],
                                     cmd='<show><high-availability><all/></high-availability></show>')
        return [response['response']['result']['group']['mode'], response['response']['result']['group']['local-info']['state']]

    def get_panorama_status(self, data):
        response = self.xml_api_call(fw=data['device'],
                                     cmd='<show><panorama-status></panorama-status></show>')
        return [response['response']['result'][:80], response['response']['result'][80:]]
    def get_interface(self, data):
        response = self.xml_api_call(fw=data['device'],
                                     cmd='<show><interface>all interface</interface></show>')
        json_object = json.dumps(response, indent=4)
        json_object = json.loads(json_object)['response']['result']['hw']['entry']
        return pd.DataFrame(json_object)


