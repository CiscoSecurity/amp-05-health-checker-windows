'''
The data module does the majority of the grunt work for the program.
'''
import os
import re
from string import Template
from collections import Counter
import time
import xml.etree.ElementTree as ET
import winreg
import json
import platform
import logging
import ssl
import socket
import sys
import subprocess
import struct
import shutil
import psutil
import requests
import PySimpleGUI as sg
from dotenv import load_dotenv
from nam_urls import NAMADDRESSLIST
from eu_urls import EUADDRESSLIST
from apjc_urls import APJCADDRESSLIST
from temp_maintained_exclusions import TEMP_MAINTAINED_EXCLUSIONS
# try:
#     import apiCreds # pylint: disable=import-error
# except ModuleNotFoundError:
apiCreds = False

class Data:
    '''
    The data class is the instance containing most of the data for the health check.
    '''

    def __init__(self):
        logging.debug("Initializing Data...")
        self.check_for_amp()
        self.last_log_line = ""
        self.every_folder = []
        self.root_path = "C:/Program Files/Cisco/AMP"
        self.version = self.get_version()
        self.build = self.get_build()
        self.path_includes_build = self.does_path_include_build()
        self.path_prelude = ""
        if self.path_includes_build:
            self.sfc_path = "{}/{}.{}/sfc.exe.log".format(self.root_path, self.version, self.build)
            self.path_prelude = "{}/{}.{}".format(self.root_path, self.version, self.build)
        else:
            self.sfc_path = "{}/{}/sfc.exe.log".format(self.root_path, self.version)
            self.path_prelude = "{}/{}".format(self.root_path, self.version)
        self.regex_1 = r"\w\w\w \d\d \d\d:\d\d:\d\d.*\\\\\?\\.*\\\\\?\\.*\\\\\?\\.*"
        self.regex_2 = r"(\w\w\w \d\d \d\d:\d\d:\d\d).*\\\\\?\\(.*)\(\\\\\?\\.*\\\\\?\\(.*)"
        self.data = []
        self.cpu_list = [(time.ctime(), self.get_cpu_usage())]
        self.current_cpu = self.cpu_list[-1][1]
        self.spero_count = 0
        self.ethos_count = 0
        self.quarantine_count = 0
        self.cloud_lookup_count = 0
        self.tetra_scan_count = 0
        self.excluded_count = 0
        self.cache_hit_count = 0
        self.malicious_hit_count = 0
        self.inner_file_count = 0
        self.tetra_latest = 0
        self.internal_health_check = 0
        self.api_cred_valid = False
        self.auth = False
        if apiCreds:
            logging.debug("Found apiCreds")
            self.client_id = apiCreds.client_id
            self.api_key = apiCreds.api_key
            self.auth = (self.client_id, self.api_key)
            self.verify_api_creds()
        else:
            load_dotenv()
            self.load_dotenv_data()
            self.verify_api_creds()
        self.business_uuid = self.dig_thru_xml("janus", "business", "uuid", root=self.get_root("C:/Program Files/Cisco/AMP/local.xml"), tag="")
        self.local_uuid = self.dig_thru_xml("agent", "uuid", root=self.get_root("C:/Program Files/Cisco/AMP/local.xml"), tag="")
        self.parse_xml()
        self.debug_check()
        self.local_uuid = self.dig_thru_xml("agent", "uuid", \
            root=self.get_root("C:/Program Files/Cisco/AMP/local.xml"), tag="")
        self.policy_color = 'Yellow'
        self.diag_failed = False
        self.ip_list = []
        self.excluded_list = []
        
        if self.auth:
            logging.debug("Found self.auth")
            self.policy_serial_compare(self.policy_dict['policy_uuid'], \
                self.policy_dict['policy_sn'])
        try:
            self.tetra_version = self.dig_thru_xml("agent", "engine", "tetra", \
                "defversions", root=self.get_root("C:/Program Files/Cisco/AMP/local.xml"), \
                    tag="").split(':')[1]
            self.tetra_version_display = str(self.tetra_version)
        except IndexError:
            logging.error("tetra_version or tetra_version_display IndexError")
            self.tetra_version = 0
            self.tetra_version_display = str(self.tetra_version)
        #self.tetra_def_compare() #removing from init, on-demand only
        self.isolation_check()
        self.conn_test_results = {}
        logging.info('Data imports completed')

    def load_dotenv_data(self):
        logging.debug("Loading credentials from .env")
        self.client_id = os.getenv('CLIENT_ID')
        self.api_key = os.getenv('API_KEY')
        self.region = os.getenv('REGION')
        self.set_region_urls()
        self.sx_client_id = os.getenv('SX_CLIENT_ID')
        self.sx_api_key = os.getenv('SX_API_KEY')
        self.org_name = os.getenv('ORG_NAME')
        self.auth = (self.client_id, self.api_key)
        if self.org_name == None:
            logging.info(f"Organization name not found in .env file. Check .env file for proper ORG_NAME.")
            sg.popup(f"Organization name not found in .env file. Check .env file for proper ORG_NAME.")
            sys.exit()

    def get_list_of_folders(self, file_path):
        r"""
        Takes a file path and returns list of folders involved
        Input: "C:\Users\bmacer\Desktop\file.txt"
        Output: ["C:\Users", "C:\Users\bmacer", "C:\Users\bmacer\Desktop",
        "C:\Users\bmacer\Desktop\file.txt"]
        """
        logging.debug("Starting get_list_of_folders")
        list_of_folders = []
        split_it = file_path.split("\\")
        for i in range(1, len(split_it)):
            list_of_folders.append("\\".join(split_it[0:i+1]))
        return list_of_folders

    def __repr__(self):
        to_return = ""
        to_return += "Cloud Lookup Count: {}\n".format(self.cloud_lookup_count)
        to_return += "TETRA Scan Count: {}\n".format(self.tetra_scan_count)
        to_return += "Excluded Count: {}\n".format(self.excluded_count)
        to_return += "Cache Hit Count: {}\n".format(self.cache_hit_count)
        to_return += "Malicious Hit Count: {}\n".format(self.malicious_hit_count)
        to_return += "Inner File Count: {}\n".format(self.inner_file_count)

        return to_return

    def get_top_folders(self, n_count=None):
        """
        Takes list of all possible folder exclusions,
        returns curated, ordered list of tuples:
        [(path, count), (path, count)]
        """
        logging.debug("Starting get_top_folders")
        c_count = Counter(self.every_folder)
        common = c_count.most_common()
        filtered_list = []
        for i in range(len(common)-2):
            if common[i][0] not in common[i+1][0]:
                filtered_list.append(common[i])
        return "\n".join(["{:<5} | {}".format(i[1], i[0]) for i in filtered_list[:n_count]])

    def get_cpu_usage(self):
        '''
        Determine the CPU usage by AMP on the local system.
        '''
        logging.debug("Starting get_cpu_usage")
        cpu = 0
        processors = psutil.cpu_count()
        for proc in psutil.process_iter():
            try:
                if proc.name() == "sfc.exe":
                    logging.debug("Found proc: %s", proc)
                    try:
                        cpu += proc.cpu_percent()
                        logging.debug("sfc cpu: %s", cpu)
                        start_time = psutil.Process(proc.pid).create_time()
                        uptime = int(time.time() - start_time)
                        self.convert_uptime(uptime)
                    except psutil.NoSuchProcess:
                        cpu = '0'
                        logging.debug('sfc.exe process not found.  setting cpu to 0')
            except psutil.NoSuchProcess:
                logging.warning("Error: psutil.NoSuchProcess")
        final_cpu = cpu / processors
        return float(final_cpu)
    
    def get_build(self):
        '''
        Determine build version of the AMP connector installed
        '''
        logging.debug("Starting get_build")
        path = r"C:/Program Files/Cisco/AMP"
        directory = os.listdir(path)
        reg_version = r'\d{1,2}\.\d{1,2}\.\d{1,2}.\d{1,5}'
        reg = re.compile(reg_version)
        build_list = list(filter(reg.match, directory))
        if len(build_list) > 0:
            logging.debug(f"Found matching directories {build_list}")
        else:
            return ""
        highest_build = 0
        for entry in build_list:
            if f"{self.version}." in entry:
                if int(entry.split('.')[-1]) > highest_build:
                    highest_build = int(entry.split('.')[-1])
                    logging.debug(f"New highest build: {highest_build}")
        return highest_build

    def does_path_include_build(self):
        logging.debug("running does_path_include_build")
        sp = self.version.split(".")
        val = int(sp[-1]) + 100*int(sp[-2]) + 10000*int(sp[-3])
        if val >= 70400:
            logging.debug("newer than 7.4, path includes build")
            return True
        logging.debug("older than 7.4, path does not include build")
        return False

    def get_version(self):
        '''
        Determine version of the AMP connector installed.
        '''
        logging.debug("Starting get_version")
        path = r"C:/Program Files/Cisco/AMP"
        directory = os.listdir(path)
        max_version = [0, 0, 0]
        reg_version = r'\d{1,2}\.\d{1,2}\.\d{1,2}'
        for entry in directory:
            logging.debug("entry: %s", entry)
            reg = re.findall(reg_version, entry)
            if reg:
                logging.debug("found match")
                if list(map(lambda x: int(x), reg[0].split("."))) > max_version:
                    max_version = list(map(lambda x: int(x), reg[0].split(".")))
        return ".".join(list(map(lambda x: str(x), max_version)))

    def convert_line(self, line):
        '''
        Conversion function.
        '''
        logging.debug("Starting convert_line")
        time, path, process = None, None, None
        reg = re.findall(self.regex_2, line)
        if reg:
            time, path, process = reg[0]
            logging.debug("time: %s", time)
            logging.debug("path: %s", path)
            logging.debug("process: %s", process)
        return {
            "time": time,
            "path": path,
            "process": process
        }

    def reset_data(self):
        '''
        Reset data counters.
        '''
        logging.debug("Starting reset_data")

        self.policy_serial_compare(self.policy_dict['policy_uuid'], self.policy_dict['policy_sn'])
        self.data = []
        self.spero_count = 0
        self.quarantine_count = 0
        self.cloud_lookup_count = 0
        self.tetra_scan_count = 0
        self.excluded_count = 0
        self.cache_hit_count = 0
        self.ethos_count = 0
        self.inner_file_count = 0
        self.malicious_hit_count = 0
        self.isolation_check()

    def update(self):
        '''
        Update GUI with latest data counters.
        '''
        logging.debug("Starting update")
        if self.region == 'NAM':
            self.connectivity_urls = NAMADDRESSLIST
        elif self.region == 'EU':
            self.connectivity_urls = EUADDRESSLIST
        elif self.region == 'APJC':
            self.connectivity_urls = APJCADDRESSLIST
        self.cpu_list.append((time.ctime(), self.get_cpu_usage()))
        self.current_cpu = self.cpu_list[-1][1]
        with open(self.sfc_path, errors="ignore") as file_1:
            file_read = file_1.readlines()
        if self.last_log_line in file_read:
            start_index = file_read.index(self.last_log_line)
            logging.debug("start_index: %s", start_index)
        else:
            start_index = -1
        self.last_log_line = file_read[-2]
        for line in file_read[start_index:]:
            if "AMP_Health_Checker" in line:
                self.internal_health_check += 1
                continue
            elif "main_page.py" in line:
                self.internal_health_check += 1
                continue
            elif "iptray.exe" in line:
                self.internal_health_check += 1
                continue
            if "Event::Handle" in line:
                logging.debug("Found Event::Handle")
                reg = re.findall(self.regex_1, line)
                if reg:
                    converted = self.convert_line(reg[0])
                    logging.debug("converted: %s", converted)
                    self.data.append(converted)
                    to_add = self.get_list_of_folders(self.convert_line(reg[0])["path"])[:-1]
                    logging.debug("Extending self.every_folder with: %s", to_add)
                    self.every_folder.extend(to_add)
                if "EVENT_INNER_FILE_SCAN start" in line:
                    self.inner_file_count += 1
            elif "GetSperoHash SPERO fingerprint: status: 1" in line:
                self.spero_count += 1
                logging.debug("found SPERO: %s", self.spero_count)
            elif "imn::CEventManager::PublishEvent: publishing type=553648143" in line:
                self.quarantine_count += 1
                logging.debug("found Quarantine: %s", self.quarantine_count)
            elif "Query::LookupExecute: attempting lookup with cloud" in line:
                self.cloud_lookup_count += 1
                logging.debug("found lookup cloud: true: %s", self.cloud_lookup_count)
            elif "lock acquired" in line:
                self.tetra_r = r"TetraEngineInterface::ScanFile\[\d{3,5}\] lock acquired"
                logging.debug("found lock acquired")
                reg = re.findall(self.tetra_r, line)
                if reg:
                    self.tetra_scan_count += 1
                    logging.debug("found Tetra ScanFile lock: %s", self.tetra_scan_count)
            elif "ExclusionCheck: responding: is excluded" in line:
                self.excluded_count += 1
                logging.debug("found is excluded: %s", self.excluded_count)
            elif "ExclusionCheck:" in line:
                reg = re.findall(r'ExclusionCheck: \\\\\?\\.* is excluded', line)
                if reg:
                    self.excluded_list.append(line.split(" ")[8])
                    self.excluded_count += 1
            elif "Exclusion::IsExcluded: result: 1 for" in line:
                self.excluded_list.append(line.split(" ")[11].split(",")[0])
                self.excluded_count += 1
            elif "Exclusion::IsExcluded: result: 1 from cache" in line:
                self.excluded_list.append(line.split(" ")[13])
                self.excluded_count += 1
            elif "Cache::Get: age" in line:
                self.cache_hit_count += 1
                logging.debug("found Cache::Get: age %s", self.cache_hit_count)
            elif "calculating ETHOS hash" in line:
                self.ethos_count += 1
                logging.debug("found ETHOS hash %s", self.ethos_count)
            elif "NFMMemCache::Get rip" in line:
                reg = re.findall(r'NFMMemCache::Get rip: ([\d]*)', line)
                if reg:
                    converted = socket.inet_ntoa(struct.pack('!L', int(reg[0])))
                    self.ip_list.append(".".join(reversed(converted.split("."))))
            if "disp 3" in line:
                self.malicious_hit_count += 1
                logging.debug("found disp 3 %s", self.malicious_hit_count)

    def __len__(self):
        return len(self.data)

    def get_top_exclusions(self, n_count=None):
        '''
        Get count of top exclusions hit.
        '''
        logging.debug("Starting get_top_exclusions")
        cnt = Counter()
        for i in self.excluded_list:
            cnt[i] += 1
        c_count = Counter(cnt.most_common(n_count))
        return "\n".join(["{:<5} | {}".format(i[1], i[0]) for i in c_count])

    def get_processes(self):
        '''
        Get list of processes.
        '''
        logging.debug("Starting get_processes")
        return list(map(lambda i: i["process"], self.data))

    def get_paths(self):
        '''
        Get list of paths.
        '''
        logging.debug("Starting get_paths")
        return list(map(lambda i: i["path"], self.data))

    def convert_to_layout(self, temp="$time || $process || $path\n"):
        '''
        Convert layout to proper format.
        '''
        logging.debug("Starting convert_to_layout")
        template = Template(temp)
        b_w = [template.substitute(time=i["time"], process=i["process"], \
            path=i["path"]) for i in self.data]
        b_w.reverse()
        return "\n".join(b_w)

    def get_top_processes(self, n_count=None):
        '''
        Get a list of the top system processes in terms of CPU usage.
        '''
        logging.debug("Starting get_top_processes")
        c_count = Counter(self.get_processes()).most_common(n_count)
        return "\n".join(["{:<5} | {}".format(i[1], i[0]) for i in c_count])

    def get_top_extensions(self, n_count=None):
        '''
        Get a list of the top extensions scanned by AMP.
        '''
        logging.debug("Starting get_top_extensions")
        extensions = []
        for i in self.data:
            if "." in i["path"]:
                ext = i["path"].split(".")[-1]
                if len(ext) < 25:
                    extensions.append("." + ext)
                else:
                    extensions.append("." + ext[:25] + " (truncated)")
            else:
                extensions.append("[no period in file path]")
        c_count = Counter(extensions).most_common(n_count)
        return "\n".join(["{:<5} | {}".format(i[1], i[0]) for i in c_count])

    def get_top_paths(self, n_count=None):
        '''
        Get a list of the top paths scanned by AMP.
        '''
        logging.debug("Starting get_top_paths")
        c_count = Counter(self.get_paths()).most_common(n_count)
        return "\n".join(["{:<5} | {}".format(i[1], i[0]) for i in c_count])

    def dig_thru_xml(self, *args, root, tag="{http://www.w3.org/2000/09/xmldsig#}", \
        is_list=False):
        '''
        Pull all information from the policy.xml file.
        '''
        logging.debug("Starting dig_thru_xml")
        for arg in args[:-1]:
            query = "{}{}".format(tag, arg)
            logging.debug("query: %s", query)
            root = root.findall(query)
            if root:
                root = root[0]
                logging.debug("root: %s", root)
            else:
                logging.debug("no root found")
                return None
        root = root.findall("{}{}".format(tag, args[-1]))
        logging.debug("searching root for %s", root)
        if root:
            if is_list:
                logging.debug("returning %s", root)
                return [i.text for i in root]
            else:
                logging.debug("returning %s", root[0].text)
                return root[0].text
        return None

    def get_root(self, path):
        '''
        Determine the root path of the XML.
        '''
        logging.debug("Starting get_root")
        
        with open(path) as f:
            tree = ET.parse(f)
            root = tree.getroot()
            logging.debug("root: %s", root)
        return root

    def parse_xml(self, path=r"C:/Program Files/Cisco/AMP/policy.xml"):
        """
        takes policy key's and their route-to-values, returns dictionary of the key-value pairs
        """
        logging.debug("Starting parse_xml")

        policy_key = {
            "business_uuid": ("Object", "config", "janus", "business", "uuid"),
            "policy_sn": ("Object", "config", "janus", "policy", "serial_number"),
            "policy_uuid": ("Object", "config", "janus", "policy", "uuid"),
            "policy_name": ("Object", "config", "janus", "policy", "name"),
            "identity_sync": ("Object", "config", "janus", "agent_guid_sync_type"),
            "cache_ttl_unknown": ("Object", "config", "agent", "cloud", "cache", "ttl", "unknown"),
            "cache_ttl_clean": ("Object", "config", "agent", "cloud", "cache", "ttl", "clean"),
            "cache_ttl_malicious": ("Object", "config", "agent", "cloud", "cache", "ttl", \
                "malicious"),
            "cache_ttl_unseen": ("Object", "config", "agent", "cloud", "cache", "ttl", "unseen"),
            "cache_ttl_block": ("Object", "config", "agent", "cloud", "cache", "ttl", "block"),
            "qaction": ("Object", "config", "agent", "driver", "protmode", "qaction"), \
                # qaction 0=audit, 1=quarantine
            "monitor_file": ("Object", "config", "agent", "driver", "protmode", "file"), \
                # monitor file copy/move
            "process": ("Object", "config", "agent", "driver", "protmode", "process"), \
                # monitor file executes
            "spp": ("Object", "config", "agent", "driver", "selfprotect", "spp"), # SPP enabled?
            "spp_qaction": ("Object", "config", "agent", "driver", "selfprotect", "spp_qaction"), \
                # SPP quarantine action
            "exprev_enable": ("Object", "config", "agent", "exprev", "enable"), # Exprev enabled?
            "ethos_file": ("Object", "config", "agent", "scansettings", "ethos", "file"), \
                # ETHOS on file copy/move
            "ethos": ("Object", "config", "agent", "scansettings", "ethos", "enable"),
            "ethos_max_filesize": ("Object", "config", "agent", "scansettings", "ethos", \
                "maxfilesize"),
            "max_archive_filesize": ("Object", "config", "agent", "scansettings", \
                "maxarchivefilesize"),
            "max_filesize": ("Object", "config", "agent", "scansettings", "maxfilesize"),
            "scheduled_scan": ("Object", "config", "agent", "scansettings", "scheduled"),
            "spero": ("Object", "config", "agent", "scansettings", "spero", "enable"),
            "tetra_scan_archives": ("Object", "config", "agent", "scansettings", "tetra", \
                "options", "ondemand", "scanarchives"),
            "tetra_deep_scan": ("Object", "config", "agent", "scansettings", "tetra", "options", \
                "ondemand", "deepscan"),
            "tetra_scan_packed": ("Object", "config", "agent", "scansettings", "tetra", "options", \
                "ondemand", "scanpacked"),
            "tetra_automatic_update": ("Object", "config", "agent", "scansettings", "tetra", \
                "updater", "enable"),
            "tetra_update_server": ("Object", "config", "agent", "scansettings", "tetra", \
                "updater", "server"),
            "tetra_update_interval": ("Object", "config", "agent", "scansettings", "tetra", \
                "updater", "interval"),
            "tetra": ("Object", "config", "agent", "scansettings", "tetra", "enable"),
            "urlscanner": ("Object", "config", "agent", "urlscanner", "enable"),
            "orbital": ("Object", "config", "orbital", "enablemsi"),
            "endpoint_isolation": ("Object", "config", "agent", "endpointisolation", "enable"),
            "connector_protection": ("Object", "config", "agent", "control", "serviceex"),
            "uninstall_password": ("Object", "config", "agent", "control", "uninstallex"),
            "DFC_qaction": ("Object", "config", "agent", "nfm", "settings", "qaction"),
            "DFC_mode": ("Object", "config", "agent", "nfm", "settings", "mode"), \
                # 0=Audit, 1=Passive (allow until disposition received), 2=Active \
                # (block until disposition received)
            "DFC": ("Object", "config", "agent", "nfm", "enable"),
            "heartbeat": ("Object", "config", "agent", "hb", "interval"),
            "log_level": ("Object", "config", "agent", "log", "level"), # Default=0
            "cmd_line_log": ("Object", "config", "agent", "log", "showcmdline"),
            "cmd_line": ("Object", "config", "agent", "cmdlinecapture", "enable"),
            "verbose_history": ("Object", "config", "agent", "history", "verbose"),
            "update_server": ("Object", "config", "updater", "server"),
            "cloud_notification": ("Object", "config", "ui", "notification", "cloud"),
            "hide_ioc_toast": ("Object", "config", "ui", "notification", "hide_ioc_toast"),
            "hide_file_toast": ("Object", "config", "ui", "notification", "hide_file_toast"),
            "hide_nfm_toast": ("Object", "config", "ui", "notification", "hide_nfm_toast"),
            "hide_exprev_toast": ("Object", "config", "ui", "notification", \
                "hide_exprev_toast"),
            "hide_detection_toast": ("Object", "config", "ui", "notification", \
                "hide_detection_toast"),
            "tray_log_level": ("Object", "config", "ui", "log", "level"),
            "connector_log_level": ("Object", "config", "monitor", "log", "level"),
            "ip_tray": ("Object", "config", "ui", "enable"),
            "send_user_info": ("Object", "config", "janus", "senduserinfo"),
            "proxy_authtype": ("Object", "config", "proxy", "authtype"),
            "proxy_server": ("Object", "config", "proxy", "server"),
            "proxy_nolocalresolvehost": ("Object", "config", "proxy", "nolocalresolvehost"),
            "proxy_pac_url": ("Object", "config", "proxy", "pacloc"),
            "proxy_password": ("Object", "config", "proxy", "password"),
            "proxy_port": ("Object", "config", "proxy", "port"),
            "proxy_type": ("Object", "config", "proxy", "type"),
            "proxy_username": ("Object", "config", "proxy", "username"),
            "device_control": ("Object", "config", "agent", "dc", "enabled")
        }

        policy_dict = {}
        try:
            root = self.get_root(path)
            self.policy_xml_root = root
        except OSError as e:
            if self.api_cred_valid == False:
                logging.info("Unable to pull policy due to invalid Secure Endpoint API credentials.")
                sg.popup("Unable to pull policy due to invalid Secure Endpoint API credentials.")
                sys.exit()
            self.pull_policy_from_sx()
            root = self.policy_xml_root

        policy_dict["path_exclusions"] = self.dig_thru_xml("Object", "config", "exclusions", \
            "info", "item", root=root, is_list=True)
        logging.debug("path exclusions: %s", policy_dict['path_exclusions'])
        policy_dict["process_exclusions"] = self.dig_thru_xml("Object", "config", "exclusions", \
            "process", "item", root=root, is_list=True)
        logging.debug("process exclusions: %s", policy_dict['process_exclusions'])

        for i in policy_key.items():
            logging.debug("digging thru xml for %s", i[1])
            policy_dict[i[0]] = self.dig_thru_xml(*i[1], root=root)
        self.policy_dict = policy_dict

    def isolation_check(self):
        '''
        Check to see if the endpoint is isolated.
        '''
        logging.info("Running isolation_check")
        self.isolated = 'Not Isolated'
        self.unlock_code = ''
        try:
            aReg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            logging.debug("aReg: %s", aReg)
            aKey = winreg.OpenKey(aReg, r"SOFTWARE\\Immunet Protect", 0, \
                (winreg.KEY_WOW64_64KEY+winreg.KEY_READ))
            logging.debug("aKey: %s", aKey)
            i = 0
            while 1:
                name, value, typ = winreg.EnumValue(aKey, i)
                logging.debug("name: %s", name)
                logging.debug("value: %s", value)
                logging.debug("type: %s", typ)
                if name == 'unlock_code':
                    logging.debug("name == unlock_code")
                    unlock_code = value
                    logging.debug("unlock_code: %s", unlock_code)
                    self.isolated = 'Isolated'
                    break
                i += 1
        except WindowsError:
            logging.warning("WindowsError")
            self.isolated = 'Not Isolated'
        if self.isolated == 'Isolated':
            logging.debug("isolated")
            self.isolation_code(self.local_uuid)

    def isolation_code(self, local_uuid):
        '''
        Pull the isolation code if the endpoint is isolated.
        '''
        logging.debug("Checking isolation for %s", local_uuid)
        self.unlock_code = ''
        if self.region == 'NAM':
            url = "https://api.amp.cisco.com/v1/computers/{}/isolation".format(local_uuid)
        elif self.region == 'EU':
            url = "https://api.eu.amp.cisco.com/v1/computers/{}/isolation".format(local_uuid)
        elif self.region == 'APJC':
            url = "https://api.apjc.amp.cisco.com/v1/computers/{}/isolation".format(local_uuid)
        try:
            r = requests.get(url, auth=self.auth)
            j = json.loads(r.content)
            self.unlock_code = "Unlock Code: {}".format(j['data']['unlock_code'])
        except requests.exceptions.ConnectionError:
            logging.warning("requests.exceptions.ConnectionError")
            self.unlock_code = ''
        except KeyError:
            logging.warning("KeyError")
            self.unlock_code = ''

    def policy_serial_compare(self, policy_uuid, policy_xml_serial):
        '''
        Check to see if the policy is up to date.
        '''
        if self.region == 'NAM':
            url = "http://api.amp.cisco.com/v1/policies/{}".format(policy_uuid)
        elif self.region == 'EU':
            url = "http://api.eu.amp.cisco.com/v1/policies/{}".format(policy_uuid)
        elif self.region == 'APJC':
            url = "http://api.apjc.amp.cisco.com/v1/policies/{}".format(policy_uuid)
        logging.debug("requesting %s", url)
        try:
            r = requests.get(url, auth=self.auth)
            j = json.loads(r.content)
            logging.debug(f"SELF.POLICY_SERIAL_RESPONSE: {j}")
            
            self.policy_serial = j['data'].get('serial_number')
            logging.debug(f"SELF.POLICY_SERIAL: {self.policy_serial}")
            if self.policy_serial:
                logging.debug("self.policy_serial: %s", self.policy_serial)
                logging.debug("policy_xml_serial: %s", policy_xml_serial)
                if int(self.policy_serial) == int(policy_xml_serial):   # Policy is up to date
                    self.policy_color = 'Green'
                else:   # Policy is not up to date
                    self.policy_color = 'Red'
            else:
                self.policy_color = 'Red'
        except:
            logging.debug("Unknown Exception.  Network issue?")
            self.policy_color = 'Yellow'

    def tetra_def_compare(self):
        '''
        Check to see if the TETRA definitions are up to date.
        '''
        if platform.machine().endswith('64'):
            url = "http://update.amp.cisco.com/av64bit/versions.id"
        else:
            url = "http://udpate.amp.cisco.com/av32bit/versions.id"
        logging.debug("requesting %s", url)
        try:
            r = requests.get(url)
            j = r.text
            self.tetra_latest = j.split('value="')[1].split('"')[0]
            logging.debug("tetra_latest: %s", self.tetra_latest)
            logging.debug("data.tetra_version: %s", self.tetra_version)
            if (int(self.tetra_latest) - int(self.tetra_version)) <= 5: # Within 5 versions \
                # is still relatively up to date since 4-5 versions come out a day
                self.tetra_color = "green"
                self.tetra_version_display = str(self.tetra_version)
            elif self.tetra_version == 0 and self.policy_dict['tetra'] == "1": \
                # TETRA defs are still downloading
                self.tetra_color = "yellow"
                self.tetra_version_display = str(self.tetra_version)
            elif self.tetra_version == 0 and self.policy_dict['tetra'] == "0": \
                # TETRA is not enabled
                self.tetra_color = "red"
                self.tetra_version_display = "DISABLED"
            else:    #TETRA definitions are not up to date
                self.tetra_color = "yellow"
                self.tetra_version_display = str(self.tetra_version)
        except requests.exceptions.ConnectionError:
            logging.warning("requests.exceptions.ConnectionError")
            self.tetra_color = "yellow"
        except IndexError:
            self.tetra_color = "yellow"

    def update_api_calls(self):
        '''
        Update the information pulled via the API.
        '''
        logging.info("Running update_api_calls")
        self.policy_dict['policy_sn'] = self.dig_thru_xml("Object", "config", "janus", "policy", \
            "serial_number", root=self.policy_xml_root)
        self.policy_serial_compare(self.policy_dict['policy_uuid'], self.policy_dict['policy_sn'])
        try:
            self.tetra_version = self.dig_thru_xml("agent", "engine", "tetra", "defversions", \
                root=self.get_root("C:/Program Files/Cisco/AMP/local.xml"), tag="").split(':')[1]
        except IndexError:
            logging.warning("IndexError in digging through xml")
            self.tetra_version = 0
        self.tetra_def_compare()

    def verify_api_creds(self):
        '''
        Check for API credential validity.
        '''
        if self.region == 'NAM':
            url = "https://api.amp.cisco.com/v1/version"
        elif self.region == 'EU':
            url = "https://api.eu.amp.cisco.com/v1/version"
        elif self.region == 'APJC':
            url = "https://api.apjc.amp.cisco.com/v1/version"
        try:
            logging.debug("Requesting {}".format(url))
            r = requests.get(url, auth=(self.client_id, self.api_key))
            if r.status_code == 200:
                logging.debug("200 response from %s", url)
                self.api_cred_valid = True
                logging.debug('Valid API creds for Client ID: %s', self.client_id)
                # Set display for API Creds to Valid
            else:
                logging.debug("%s response from %s", r.status_code, url)
                self.api_cred_valid = False
        except requests.exceptions.ConnectionError:
            self.api_cred_valid = False
        except AttributeError:
            self.api_cred_valid = False
        except UnboundLocalError:
            logging.info("Region not found in .env file.  Refer to the README to fix this issue, and try running the program again.")
            sg.popup("Region not found in .env file.  Refer to the README to fix this issue, and try running the program again.")
            sys.exit()

    def connectivity_check(self, window=None):
        '''
        Check connectivity to the required URLs for proper AMP operation.
        '''
        logging.debug("Running connectivity check.")
        for url in self.connectivity_urls:
            logging.debug("Trying cert for %s", url)
            try:
                cert = ssl.get_server_certificate((url, 443))
                logging.debug("Cert is %s", cert)
                self.conn_test_results[url] = 'Green'
                logging.debug("Found cert for %s", url)
            except TimeoutError:
                logging.warning("Connection timed out for %s", url)
                self.conn_test_results[url] = 'Red'
            except socket.gaierror:
                logging.warning("Cert error for %s", url)
                self.conn_test_results[url] = 'Red'
            except ConnectionRefusedError:
                logging.warning("ConnectionRefusedError for %s", url)
                self.conn_test_results[url] = 'Red'
            except WindowsError:
                logging.warning("WinError for %s", url)
                self.conn_test_results[url] = 'Red'
            window.find_element(url).Update(background_color=self.conn_test_results[url])
            logging.debug("conn for %s complete: %s", url, self.conn_test_results[url])
            window.Refresh()

    def check_for_amp(self):
        '''
        Ensure AMP is installed on the system.
        '''
        logging.debug("data.check_for_amp: Running data.check_for_amp")
        amp_installed = False
        for proc in psutil.process_iter():
            try:
                if proc.name() == "sfc.exe":
                    logging.debug("found sfc.exe")
                    amp_installed = True
                    if proc.is_running():
                        logging.debug("proc.is_running() == True")
                        amp_running = True
            except psutil.NoSuchProcess:
                logging.warning("Error: psutil.NoSuchProcess in check_for_amp")
        if amp_installed == False or amp_running == False:
            logging.warning("amp_installed or amp_running == False")
            sg.popup("Ensure AMP is installed and runnning and try again.", title="AMP not found")
            sys.exit()

    def debug_check(self):
        '''
        Check to see if AMP logging is set to debug. If not set, set temporarily.
        '''
        if self.policy_dict['log_level'] == "549755813887":
            logging.info("Debug Logging already enabled")
            self.enabled_debug = False
        elif self.policy_dict['log_level'] == '0':
            logging.info('Enabling debug logging.')
            try:
                logging.debug(f"Attempting to run {self.path_prelude}/sfc.exe")
                subprocess.Popen(["{}/sfc.exe".format(self.path_prelude), '-l', 'start'])
            except OSError:
                sg.popup("Changing log level requires running AMP Health Checker as Admin. Please try again as Admin.", title="Admin required")
                sys.exit()
            logging.info('Debug logging enabled.')
            self.enabled_debug = True
        else:
            logging.info("Log level was set to %s", self.policy_dict['log_level'])
            self.enabled_debug = False

    def disable_debug(self):
        '''
        Disable AMP debug logging if set temporarily.
        '''
        logging.info('Disabling debug logging.')
        subprocess.Popen(["{}/sfc.exe".format(self.path_prelude), '-l', 'stop'])
        logging.info('Debug logging disabled.')
        self.enabled_debug = False

    def convert_uptime(self, uptime, granularity=4):
        '''
        Convert the pulled uptime into a readable format.
        '''
        intervals = (
            ('weeks', 604800),
            ('days', 86400),
            ('hours', 3600),
            ('mins', 60),
            ('secs', 1),
        )

        result = []
        for name, count in intervals:
            value = uptime // count
            if value:
                uptime -= value * count
                if value == 1:
                    name = name.rstrip('s')
                result.append("{} {}".format(value, name))
        self.converted_uptime = ', '.join(result[:granularity])

    def get_top_ips(self, ip_list, n=10):
        '''
        Get a list of the top IPs seen by AMP.
        '''
        c = Counter(ip_list)
        to_return = []
        for i in c.most_common(n):
            to_return.append("{:5}: {:<}".format(i[1], i[0]))
        return "\n".join(to_return)

    def generate_diagnostic(self):
        '''
        Generate an AMP diagnostic file.
        '''
        src = os.path.join(os.getcwd(), 'amp_health_checker_log.log')
        dst = os.path.join(os.environ['HOMEPATH'], 'Desktop')
        try:
            shutil.copy(src, dst)
        except FileNotFoundError:
            logging.error("FileNotFoundError: Source: %s | Dest: %s", src, dst)
            self.diag_failed = True

        try:
            subprocess.Popen("{}/ipsupporttool.exe".format(self.path_prelude))
            logging.info("Diagnostic generated.")
        except OSError as e:
            logging.error(e)
            self.diag_failed = True

    def pull_policy_from_sx(self):
        '''
        Authenticate to SecureX and pull the policy.xml file, then return the root xml for parsing
        '''
        root = ''
        # Pull the policy uuid
        url = f"{self.base_secure_endpoint_url}/v1/computers/{self.local_uuid}"
        try:
            r = requests.get(url, auth=self.auth)
            j = json.loads(r.content)
            logging.debug(j)
            self.policy_uuid = j['data']['policy']['guid']
        except requests.exceptions.ConnectionError:
            logging.warning("requests.exceptions.ConnectionError")
            sys.exit("Unable to pull the policy guid due to requests.exceptions.ConnectionError")
        except KeyError:
            logging.warning("KeyError")
            sg.popup("Unable to pull the policy guid due to KeyError")
            sys.exit()
            
        se_access_token = self.get_se_access_token()

        org_id_url = f"{self.base_secure_endpoint_url}/v3/organizations?size=100"
        headers = {'Authorization': f'Bearer {se_access_token}'}
        org_response = requests.get(org_id_url, headers=headers)
        for org in org_response.json()['data']:
            if org['name'] == self.org_name:
                self.org_id = org['organizationIdentifier']
        if not hasattr(self, 'org_id'):
            logging.info("Organization name in .env file not found in authorized SecureX Orgs. Check .env file information for accuracy.")
            sg.popup("Organization name in .env file not found in authorized SecureX Orgs. Check .env file information for accuracy.")
            sys.exit()
        policy_xml_url = f"{self.base_secure_endpoint_url}/v3/organizations/{self.org_id}/policies/{self.policy_uuid}/xml"
        policy_response = requests.get(policy_xml_url, headers=headers)
        if policy_response.status_code == 404:
            logging.debug("Policy call retured 404, check your SecureX Org ID to ensure it matches the org containing this policy.")
        self.policy_xml = policy_response.text
        tree = ET.ElementTree(ET.fromstring(self.policy_xml))
        self.policy_xml_root = tree.getroot()
        
        return self.policy_xml_root

    def set_region_urls(self):
        if self.region == "NAM":
            self.base_securex_url = "https://visibility.amp.cisco.com"
            self.base_secure_endpoint_url = "https://api.amp.cisco.com"
        elif self.region == "EU":
            self.base_securex_url = "https://visibility.eu.amp.cisco.com"
            self.base_secure_endpoint_url = "https://api.eu.amp.cisco.com"
        elif self.region == "APJC":
            self.base_securex_url = "https://visibility.apjc.amp.cisco.com"
            self.base_secure_endpoint_url = "https://api.apjc.amp.cisco.com"

    def get_se_access_token(self):
        """
        Authenticate with SecureX and Secure Endpoints to get a token.  
        :return Secure Endpoints access token
        """
        
        auth = (self.sx_client_id, self.sx_api_key)
        securex_url = f"{self.base_securex_url}/iroh/oauth2/token"
        data = {"grant_type": "client_credentials"}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
        
        # Authenticate with SecureX and get an access_token
        sx_response = requests.post(securex_url, headers=headers, data=data, auth=auth)
        if sx_response.status_code == 400:
            logging.info("Please check your .env file for proper SecureX credentials and try again.")
            sg.popup("Please check your .env file for proper SecureX credentials and try again.")
            sys.exit()
        sx_access_token = (sx_response.json().get("access_token"))

        # Get Secure Endpoints access_token
        secure_endpoint_url = f"{self.base_secure_endpoint_url}/v3/access_tokens"
        headers = {
            'Authorization': f'Bearer {sx_access_token}'
        }
        se_response = requests.post(secure_endpoint_url, headers=headers)
        se_access_token = se_response.json().get("access_token")
        logging.debug(f"SE ACCESS TOKEN: {se_access_token}")
        return se_access_token

    def recommend_exclusions(self):
        '''        
        Loop through the processes seen on the endpoint and compare them with Cisco Maintained Exclusions.
        If any matches are found, return them.
        TODO - Once an API call is implemented to pull details for the Cisco Maintained Exclusions, use that call instead of this hard coded json 
        '''
        recommendations = {"Microsoft Windows Default": ["Always Recommended"]}

        for proc in psutil.process_iter():
            try:
                process = proc.name().lower()
                for program in TEMP_MAINTAINED_EXCLUSIONS:
                    if process in TEMP_MAINTAINED_EXCLUSIONS[program]:
                        if program in recommendations:
                            if not process in recommendations[program]:
                                recommendations[program].append(process)
                        else:
                            recommendations[program] = [process]
            except psutil.NoSuchProcess:
                logging.warning("Error: psutil.NoSuchProcess")

        return recommendations

def main():
    '''
    Process Data class.
    '''
    d = Data()
    d.update()
    d.generate_diagnostic()

if __name__ == "__main__":
    main()
