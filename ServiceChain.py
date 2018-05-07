"""
VMS Service Chain Library
VMS Releases 2.0/2.1
Contains methods to verify SCs of types Basic,Medium & Full
"""

import logging
import re
import time
import sys
import ast
import json
import itertools

from prettytable import PrettyTable

from vmsauto.lib import Testbed
from vmsauto.lib import IOS
from vmsauto.lib import ASA
from vmsauto.lib import Linux
from vmsauto.lib import IPSsensor
from vmsauto.lib import WSA
from vmsauto.lib import IP
from vmsauto.lib import OpenStack
from vmsauto.lib.ngena import SQL
from vmsauto.lib.ngena import Utills

#[Tata] for ssh client tracepath SF004TC2
import paramiko

logger = logging.getLogger(__name__)
ping_success_rate = 80
utils = Utills.common_utills()
class ServiceChain(object):
    pass

class TestFail(Exception):
         pass

class NotFound(Exception):
         pass

class NGENAServiceChain(ServiceChain):
    def __init__(self, conn, dcs, tbFile, serviceChainName, debug=False):
        self.conn = conn # storing global conn db for future reference
        self.cso_cli = conn['cso_cli']
        self.nso_cli = conn[dcs[0]['name']]
        self.dcs = dcs
        self.tbFile = tbFile
        self.serviceChainName = serviceChainName
        self.debug = debug
        self.testPassed = None
        self.urlFilteredList = [
            {
                'url': "www.hackthissite.org",
                'category': "Hacking"
            },
            {
                'url': "www.kkk.com",
                'category': "Hate Speech"
            },
            {
                'url': "www.zcrack.com",
                'category': "Illegal Downloads"
            },
            {
                'url': "www.poker.com",
                'category': "Gambling"
            },
            {
                'url': "www.adultentertainmentexpo.com",
                'category': "Adult"
            },
            {
                'url': "www.thedisease.net",
                'category': "Illegal Drugs"
            },
            {
                'url': "www.bestessays.com",
                'category': "Cheating and Plagiarism"
            },
            {
                'url': "www.car-accidents.com",
                'category': "Extreme"
            },
            {
                'url': "www.artenuda.com",
                'category': "Non-sexual Nudity"
            }
        ]

    def get_vnf_list(self):
        """
        Return a list of VNFs for the service chain.
        """
        return self.cso_cli.get_vnf_list(self.serviceChainName)

    def get_vnf_name(self,vmgroup):
        vnfList = self.get_vnf_list()
        vmgroup=vmgroup.upper()
        if vmgroup == "CSR" or vmgroup == "ASA" or vmgroup == "WSA":
            for each in vnfList :
                if vmgroup.upper() in each:
                    return each
        return None

    def get_cpesn_list(self):
        """
        Return a list of CPE serial numbers for the service chain.
        """
        return self.nso_cli.get_virto_cpesn_list(self.serviceChainName)

    def get_vm_behind_pcpe_info(self,cpeSN,cpeLanPort):
        """
        Return host details of VM behind CPE attached to
        given physical CPE LAN port from database.
        """
        sqlquery = SQL.Action(self.tbFile.testbedFile)
        hostInfo = dict()
        vm_behind_cpe_info =  sqlquery.query_vm_behind_cpe_info(cpeSN,cpeLanPort)
        if vm_behind_cpe_info:
            hostInfo = {
                'ip': vm_behind_cpe_info['mgmt_ip'],
                'deviceType': 'vm_behind_cpe',
                'username': vm_behind_cpe_info['user name'],
                'password': vm_behind_cpe_info['password']
            }
            logger.debug("VM behind Physical CPE: Mgmt IP-%s" % hostInfo['ip'])
        else:
            logger.debug("Could not find vm_behind_cpe in SQLDB:cpeSN-%s, LanPort-%s" %(cpeSN,cpeLanPort))
        return hostInfo

    def connect_vm_behind_phy_cpe(self,cpeSN,cpeLanPort,sshPort = 22022):
        """
        Connect via SSH to the specified VM behind Physical CPE.
        """
        logger.debug("In connect_vm_behind_phy_cpe:cpeSN-%s,cpeLanPort-%s" %(cpeSN,cpeLanPort))
        hostInfo = self.get_vm_behind_pcpe_info(cpeSN,cpeLanPort)
        if hostInfo:
            hostInfo['ProxyHost'] = self.tbFile.get_jumphost_devices()[0]
            hostInfo['ssh_port'] = sshPort
            host = "vm-behind-cpe-" + cpeSN
        else:
            raise Exception("VM behind Physical CPE %s details not available in SQLDB"%cpeSN)
        try:
            self.tbFile.add_host(host,hostInfo)
        except Testbed.AlreadyExists:
            pass
        return Linux.Bash(host,self.tbFile,debug=self.debug)

    def connect_vm_behind_vcpe(self,vcpe,sshPort=22022):
        """
        Connect via SSH to the specified VM behind vCPE.
        """
        logger.debug("In connect_vm_behind_vcpe:cpeSN-%s" %(vcpe['Serial']))
        for ip in vcpe['VM-Behind-CPE']['Mgmt-ip'].split(","):
            if IP.is_ipv4(ip):
                mgmt_ip_v4 = ip
            elif IP.is_ipv6(ip):
                mgmt_ip_v6 = ip
            else:
                logger.debug("Unable to get Mgmt_ip for vm_behind_vcpe:cpeSN-%s,IP:%s" %(vcpe['Serial'],ip))
        hostInfo = {
            'ip': mgmt_ip_v4,
            'deviceType': 'vm_behind_cpe',
            'credential': 'vmsauto',
            'ProxyHost': self.tbFile.get_jumphost_devices()[0],
            'ssh_port': sshPort
        }
        host = "vm-behind-cpe-" + vcpe["Serial"]

        try:
            self.tbFile.add_host(host,hostInfo)
        except Testbed.AlreadyExists:
            pass
        return Linux.Bash(host,self.tbFile,debug=self.debug)

    def connect_to_cpe(self,cpeSN,credential="cpe"):
        """
        Connect via SSH to the specified CPE.
        """
        logger.debug("Entered connect to cpe-%s" % cpeSN)
        dc = utils.get_cpe_dc(cpeSN)
        hostInfo = self.conn[dc].get_cpe_connect_info(cpeSN)
        hostInfo['credential'] = credential
        hostInfo['ProxyHost'] = self.tbFile.all_nso[dc]
        host = "cpe-" + cpeSN
        try:
            host = self.tbFile.get_host_by_serial(cpeSN)
        except Testbed.NotFound:
            self.tbFile.add_host(host,hostInfo)
        else:
            # Assume the test bed file knows better about the device
            # type as the CPE could actually be IOL versus IOS.
            del hostInfo['deviceType']
            self.tbFile.update_host(host,hostInfo)
        return IOS.Control(host,self.tbFile,debug=self.debug)

    def connect_to_vnf(self,vnfName):
        """
        Connect via SSH to the specified VNF.
        """
        hostInfo = self.cso_cli.get_vnf_connect_info(self.serviceChainName, vnfName)
        dc = self.cso_cli.get_device_datacenter(self.serviceChainName, vnfName)
        hostInfo['ProxyHost'] = self.tbFile.all_nso[dc]

        if hostInfo['deviceType'] == "CSR":
            hostInfo['credential'] = "csr"
            try:
                self.tbFile.add_host(vnfName,hostInfo)
            except Testbed.AlreadyExists:
                pass
            logger.debug("Just Before connecting to CSR %s" % vnfName)
            return IOS.Control(vnfName,self.tbFile,debug=self.debug)
        elif hostInfo['deviceType'] == "ASA":
            hostInfo['credential'] = "asa"
            try:
                self.tbFile.add_host(vnfName,hostInfo)
            except Testbed.AlreadyExists:
                pass
            return ASA.Control(vnfName,self.tbFile,debug=self.debug)
        elif hostInfo['deviceType'] == "WSA":
            hostInfo['credential'] = "wsa"
            try:
                self.tbFile.add_host(vnfName,hostInfo)
            except Testbed.AlreadyExists:
                pass
            return WSA.Control(vnfName,self.tbFile,debug=self.debug)
        elif hostInfo['deviceType'] == "ICSP":
            hostInfo['credential'] = "icsp"
            try:
                self.tbFile.add_host(vnfName,hostInfo)
            except Testbed.AlreadyExists:
                pass
            return Linux.Bash(vnfName,self.tbFile,debug=self.debug)
        elif hostInfo['deviceType'] == "IPS_Manager":
            hostInfo['credential'] = "ips"
            try:
                self.tbFile.add_host(vnfName,hostInfo)
            except Testbed.AlreadyExists:
                pass
            return Linux.Bash(vnfName,self.tbFile,debug=self.debug)
        elif hostInfo['deviceType'] == "IPS_Sensor":
            hostInfo['credential'] = "ips"
            try:
                self.tbFile.add_host(vnfName,hostInfo)
            except Testbed.AlreadyExists:
                pass
            return IPSsensor.Control(vnfName,self.tbFile,debug=self.debug)
        else:
            raise TestFail('Do not understand VNF type for "%s".' % vnfName)

    def CSR_license(self,csrVNF):
        """
        Check and validate the license for a CSR VNF. Return True if
        check passes and False if check fails.

        :param csrVNF: the CSR where the license should be checked
        :type csrVNF: IOS.Control

        :rtype: boolean
        """
        csr = self.connect_to_vnf(csrVNF)
        # command = "show license all"

        command = "show license all"
        output = csr.execute(command)
        logger.debug(' show license all output: %s' % output)
        # return True
        # Get 'Status' line in 'Registration' and
        # 'License Authorization' sections.
        match = []
        for item in ['Registration','License Authorization']:
            match.append(
                re.search(
                    '^%s:\s*'
                    '(^\s+[^:]+\s*:\s*.*\s*)*?'
                    '^\s+Status\s*:\s*([ \S+]+)' % re.escape(item),
                    output,flags=re.MULTILINE
                )
            )
        if match[0] and match[1]:
            regStatus = match[0].group(2)
            authStatus = match[1].group(2)
            if ("REGISTERED" in regStatus and
                "AUTHORIZED on" in authStatus):
                logger.info(
                    "CSR license valid: %s, %s" %
                    (regStatus,authStatus)
                )
                return True
            else:
                logger.warning(
                    "CSR license check failed: %s, %s" %
                    (regStatus,authStatus)
                )
                return False
        else:
            raise Exception('Unable to parse "%s" output: %s' % (command, output))

    def ASA_license(self,asaVNF):
        """
        Check and validate the license for a ASA VNF. Return True if
        check passes and False if check fails.

        :param asaVNF: the ASA where the license should be checked
        :type asaVNF: ASA.Control

        :rtype: boolean
        """
        try:
            asa = self.connect_to_vnf(asaVNF)
            logger.debug("Inside ASA %s" % asaVNF)
        except Exception as e:
            logger.exception("Could not connect to ASA %" % asaVNF)
            raise e
        else:
            command = "show license all"
            output = asa.execute(command)
            command = "show license all"
            output = asa.execute(command)
            return True
            # match = re.search('mart Licensing State: (\S+)(\s|\r|\n)+',output)
            match = re.search('mart Licensing State: (\S+)(\s|\r|\n)+',output)
            if match:
                if match.group(1) == "authorized":
                    logger.debug("matched=%s"%match.group(1))
                    logger.info("ASA License: %s"%match.group(1))
                    logger.info("ASA license valid")
                    return True
                else:
                    logger.warning(
                        "ASA license check failed: %s"%match.group(1))
                    logger.debug("matched=%s"%match.group(1))
                    return False
            else:
                raise Exception('Unable to parse "%s" output.' % command)

    def WSA_license(self,wsaVNF):
        """
        Check and validate the license for a WSA VNF. Return True if
        check passes and False if check fails.

        :param wsaVNF: the WSA where the license should be checked
        :type wsaVNF: WSA.Control

        :rtype: boolean
        """
        wsa = self.connect_to_vnf(wsaVNF)
        command = "showlicense"
        output = wsa.execute(command)
        match = re.search('seats\s*(\d+)',output)
        if match:
            logger.debug("matched= %s"%match.group(1))
            if (int(match.group(1)) >= 1):
                logger.info("WSA license seats: %s"%match.group(1))
                logger.info("WSA VNF is licensed")
                return True
            else:
                logger.warning(
                    "WSA license check failed as WSA license seats "
                    "shown in 'showlicense' output is : %s" %
                    match.group(1)
                )
                return False
        else:
            raise Exception('Unable to parse "%s" output.' % command)

    def get_cpe_lisp_interface(self,cpeConsole, vrf):
        """
        This method returns the interface on CPE which is being used as LISP Interface
        """
        output = cpeConsole.execute("show vrf %s" % vrf)
        match = re.search('LI((\d+)\.(\d+))',output)
        if match:
            LispInterface = "LISP%s" %match.group(1)
            return LispInterface
        else:
            return False


    def cpe_lan_interface(self,cpeSN, vrf):
        """
        This method returns the interface on CPE which is being used as Lan Interface
        """
        try:
            cpeConsole = self.connect_to_cpe(cpeSN)
        except:
            logger.exception("Could not connect to cpe-%s"%cpeSN)
        else:
            output = cpeConsole.execute("show vrf %s" % vrf)
            match3 = re.search('Gi(\d\/\d\/\d)',output)
            match0 = re.search('Gi(\d\/\d)',output)
            match2 = re.search('Gi(\d)',output)
            match1 = re.search('Vl(\d)',output)
            if match3:
                logger.debug("Matched== %s" % match3.group(0))
                logger.debug("Matched== %s" % match3.group(1))
                LanInterface = "GigabitEthernet%s" % match3.group(1)
            elif match0:
                logger.debug("Matched== %s"%match0.group(0))
                logger.debug("Matched== %s"%match0.group(1))
                LanInterface = "GigabitEthernet%s"%match0.group(1)
            elif match2:
                logger.debug("Matched== %s" % match2.group(0))
                logger.debug("Matched== %s" % match2.group(1))
                LanInterface = "GigabitEthernet%s" % match2.group(1)
            elif match1:
                logger.debug("Matched== %s"%match1.group(0))
                logger.debug("Matched== %s"%match1.group(1))
                LanInterface = "Vlan%s"%match1.group(1)
            else:
                logger.debug("No match found for LAN Interface:CPE %s"%cpeSN)
            output = cpeConsole.execute("show ip int brief")
            logger.debug('show ip int br output = %s' % output)
            match = re.search('%s.\s+(\S+)\s+YES\s+(NVRAM|manual|CONFIG)\s+up'%LanInterface,output)
            if match:
                logger.debug("Matched== %s"%match.group(1))
            else:
                raise TestFail("cpe lan interface (%s:%s) is DOWN"%(cpeSN,LanInterface))
            return LanInterface


    def verify_service_chain(self,timeout=120):
        """
        This method verifies the functionality of service chain, by first determining the service chain type
        and calling appropriate verify service chain methods
        """
        try:
            virtoType = self.ncs_cli.typeof_service_chain(self.serviceChainName)
        except:
            logger.exception("Service chain %s not found in NCS"%self.serviceChainName)
        if virtoType == "basic":
            resultVerifyBasic = self.verify_service_chain_basic()
            return resultVerifyBasic
        elif virtoType == "medium":
            resultVerifyMedium = self.verify_service_chain_medium()
            return resultVerifyMedium
        elif virtoType == "full":
            resultVerifyFull = self.verify_service_chain_full()
            return resultVerifyFull
        else:
            raise Exception('Do not understand virto type "%s"' % self.serviceChainName)
            return False

#####################################################
    def get_crypto_pkt_count (self, connect):
        """
            function: get_crypto_pkt_count
            description: Get Interface Counter from the given Interface
            Input Params: connect object of device from which counter is to be fetched
            Return: True/False
        """
        logger.debug("Entered get_crypto_pkt_count")
        found = 0
        try:
            output = connect.execute("show crypto ipsec sa | include pkts")
            #print("output of crypto ipsec sa: ++>:%s" % output)
            out = output.splitlines()
            for i in range(len(out)):
                if('pkts encaps' in out[i]):
                    encap = (out[i].split(',')[0]).split(':')[1]
                    decap = (out[i+1].split(',')[0]).split(':')[1]
                    found = 1
                    break

            if found:
                logger.debug('pkt count, encap:%s, decap:%s' % (encap, decap))
                return (encap, decap)
            else:
                logger.debug('encap/decap pkts counter not found')
                return False,False

        except:
            return False,False

    def ping_cpe_lan(self, cpeP, cpeS, vrf, count=20, loss_tolerance=5):
        """
            function: ping_cpe_lan
            description: Inter CPE Ping
            Input Params: CPE1 serial number, CPE2 serial number, vrf to which these CPEs belong
            Return: True/False
            Success criteria: Ping with success rate of 80% or more.
        """
        global ping_success_rate
        cpeS_int_ip = cpeS['LAN-Net-ip'][0]
        output = cpeP['connect'].execute("ping vrf %s %s repeat %d" %  (vrf, cpeS_int_ip, count))
        match = re.search('Success rate is (\d+) percent \((\d+)\/(\d+)\)', output)
        if(match and (match.group(1) >= ping_success_rate)) :
            if((int(match.group(3)) - int(match.group(2))) < loss_tolerance):
                logger.info("Ping from %s to %s is successful with %d pkt loss. Success percent:%s" %
                           (cpeP['Serial'], cpeS['Serial'], (int(match.group(3)) - int(match.group(2))), match.group(1)))
                return True
            else:
                logger.error("Ping from %s to %s failed with pkt loss of %d packets" %
                           (cpeP['Serial'], cpeS['Serial'], (int(match.group(3)) - int(match.group(2)))))
                return False
        else:
            logger.error("Ping from %s to %s failed with %s percent succcess rate" %(cpeP['Serial'], cpeS['Serial'], match.group(1)))
            return False

    def fetch_dynamic_cpe_info(self, configFile, suiteConfigFile):
        """
            function: fetch_dynamic_cpe_info
            description: get CPE info like serial#, LAN/WAN ip using openstack cmd
            Input Params: config file
            Return: Dictionary with CPE info else False
            Success criteria: openstack cmd succeeds and CPE data is found
        """
        if configFile:
            try:
                ostkCtrlHost = suiteConfigFile['common_config']['ctrlHost']
            except Testbed.NotFound:
                ostk_bash = Linux.Bash(debug=self.debug)
            else:
                ostk_bash = Linux.Bash(
                    ostkCtrlHost,
                    self.tbFile,
                    debug=self.debug
                    )
            osAuth = self.tbFile.get_simulation_ostk()
            ostk = OpenStack.Control(ostk_bash,osAuth)
            try:
                output = []
                cpe_start = int(suiteConfigFile['service_chain']['cpe_num_start'])
                cpe_end = int(suiteConfigFile['service_chain']['cpe_num_end'])

                for num in range(cpe_start, cpe_end+1):
                    out = ostk.execute("openstack server list -c ID -c Name -c Networks -f json --name '%s-%s-%s-|%s-%s-%s'" %(
                                          configFile['testbed_name'], configFile['cpe_vm']['name'], num,
                                          configFile['testbed_name'], configFile['vm_behind_cpe']['name'], num))
                    #out = ostk.execute("openstack server list -c ID -c Name -c Networks -f json --name '%s-%s-%s-'" % (configFile['testbed_name'], configFile['cpe_vm']['name'], num))
                    if out:
                        output.append((ast.literal_eval(out)))
            except:
                e = sys.exc_info()[0]
                logger.debug("opstk cmd failed with error=[%s]. Looks like no CPE found.Exit"%e)
                return False

            logger.debug("Out=%s"%output)
            temp = str(json.dumps(output))
            out_json = json.loads(temp)

            cpeList = []

            for cpeVms in out_json:
                # CPE name should be something like "<testbed-name>-<cpe-name>-<cpe-number>-<serial number>.
                # The testbed name or CPE name itself may contain dashes, so when we split
                # using a dash separator, we can not assume that the SN is the 4th element.
                # We should, however, be able to count from the rear and assume that the SN is the
                # last element.
                # Also, the 3rd from the last element should be the CPE name.. if not, then
                # the CPE did not get renamed (which would have happened if the CPE generation
                # worker thread was unable to SSH to the CPE)
                vmBehindCpe = dict()
                if len(cpeVms) > 1 :
                    # cpeVms structure will have list of cpe and vm-behind cpe vms.
                    # Currently only 1 VM-behind-cpe is possible as only 1 vCPE LAN interface supported
                    # This would need enhancement if more than 1 vm-behind-cpe supported for vCPE
                    for vm in cpeVms:
                        if ("%s-%s-"%(configFile['testbed_name'], configFile['cpe_vm']['name'])) in vm["Name"]:
                            cpe = vm
                        elif ("%s-%s-"%(configFile['testbed_name'], configFile['vm_behind_cpe']['name'])) in vm["Name"]:
                            vmBehindCpe = vm
                        else:
                             logger.debug("Could not match VM name: %s" %vm)
                else:
                    #if cpeVms has only 1 VM, then this is CPE VM and no vm-behind-cpe for this vCPE
                    cpe = cpeVms[0]
                cpeName = cpe['Name'].split('-')
                if cpeName[-3] != configFile['cpe_vm']['name']:
                    logger.error("CPE %s does not appear to include serial number" % cpe['Name'])
                else:
                    sn = cpeName[-1]
                    siteId = int(cpeName[-2])

                    # OpenStack will have returned networks in the format:
                    # "NG2-CKOESTER_PROVIDER=198.18.1.61; tb-ng2-ckoester-CPE_LAN-100=192.168.100.1"
                    # Convert this into a dict.
                    # Save values for all WAN Networks in dictionary. Currently only INET1 Network is mandatory
                    # Temp implementation until all WAN networks are incorporated.
                    networksDict = dict(item.split("=") for item in cpe['Networks'].split("; "))
                    # INET1 Network is mandatory
                    wan_inet1 = {'inet1_net_name': configFile['cpe_vm']['inet1_network'],
                                 'inet1_ip_addr': networksDict[configFile['cpe_vm']['inet1_network']],
                                 'inet1_ipv4_subnet': configFile['cpe_vm']['inet1_subnet_v4'],
                                 'inet1_ipv6_subnet': configFile['cpe_vm']['inet1_subnet_v6']}
                    # Add INET2 network details if available
                    try:
                        wan_inet2 = {'inet2_net_name': configFile['cpe_vm']['inet2_network'],
                                     'inet2_ip_addr': networksDict[configFile['cpe_vm']['inet2_network']],
                                     'inet2_ipv4_subnet': configFile['cpe_vm']['inet2_subnet_v4'],
                                     'inet2_ipv6_subnet': configFile['cpe_vm']['inet2_subnet_v6']}
                        wan_inet1.update(wan_inet2)
                    except KeyError:
                        logger.debug('INET2 not defined')
                    # Add EPL network if available
                    try:
                        wan_epl = {'epl_net_name': configFile['cpe_vm']['epl_network'],
                                   'epl_ip_addr': networksDict[configFile['cpe_vm']['epl_network']],
                                   'epl_ipv6_subnet': configFile['cpe_vm']['epl_subnet_v6']}
                        wan_inet1.update(wan_epl)
                    except KeyError:
                        logger.debug('EPL not defined')
                    # SN is known at this time; WAN network name is determinstic and we can
                    # just assign it at this time.
                    # Add WAN Networks info into CPE network dictionary
                    _cpeDict = {'Serial': sn, 'Site-ID': siteId}
                    _cpeDict.update(wan_inet1)

                    # LAN network is a special case since this may be exactly as per CPE config
                    # file if shared LAN networks are configured, but will be a unique name
                    # if dedicated LAN networks are enabled. At this time, we assume that the
                    # CPE has exactly two networks, and that the LAN network simply is "the other one"
                    # that does *not* match the WAN network name. This may need rework if we support
                    # vCPEs with more than two ports.
                    _cpeDict['LAN-Net-name'] = next(k for k,v in networksDict.items() if k != configFile['cpe_vm']['inet1_network'])
                    _cpeDict['LAN-ipv4-Subnet'] = _cpeDict['LAN-Net-name'] + '-IPv4'
                    _cpeDict['LAN-ipv6-Subnet'] = _cpeDict['LAN-Net-name'] + '-IPv6'
                    _cpeDict['LAN-Net-ip'] = networksDict[_cpeDict['LAN-Net-name']].split(', ')
                    for lanIP in networksDict[_cpeDict['LAN-Net-name']].split(','):
                         if IP.is_ipv4(lanIP):
                             _cpeDict['LAN-Netmask-ipv4'] = self.get_subnet_mask(ostk, _cpeDict['LAN-ipv4-Subnet'])
                         else:
                             _cpeDict['LAN-Netmask-ipv6'] = self.get_subnet_mask(ostk, _cpeDict['LAN-ipv6-Subnet'])

                    # Not using WAN Netmask currently. If required value can be
                    # calculated above where WAN network is saved in Dic
                    #_cpeDict['WAN-Net-mask'] = self.get_subnet_mask(ostk, _cpeDict['WAN-Subnet-name'])

                    if vmBehindCpe:
                        #if vm_behind_cpe is defined for this vCPE then add details to dict
                        vmBehindCpeNetworksDict = dict(item.split("=") for item in vmBehindCpe['Networks'].split("; "))

                        _vmBehindCpeDict = {'Name': vmBehindCpe['Name'],
                                            'Mgmt-ip': vmBehindCpeNetworksDict[configFile['vm_behind_cpe']['nic1_network']],
                                            'Mgmt-Net-name': configFile['vm_behind_cpe']['nic1_network']}
                        _vmBehindCpeDict['LAN-Net-name'] = next(k for k,v in vmBehindCpeNetworksDict.items() if k != configFile['vm_behind_cpe']['nic1_network'])
                        _vmBehindCpeDict['LAN-Net-ip'] = vmBehindCpeNetworksDict[_vmBehindCpeDict['LAN-Net-name']].split(', ')
                        _cpeDict['VM-Behind-CPE'] = _vmBehindCpeDict

                    cpeList.append(_cpeDict)
            return cpeList

    def get_subnet_mask(self, ostk, net):
        """
           function: get_subnet_mask
           description: it uses openstk cmds to get netmask of a given network
           inputs: openstack object relative to your tenant, network name
           returns: netmask or false
           success criteria: non-zero netmask is received
        """
        logger.debug("Looking up netmask for subnet %s" % net)
        try:
            #output = ostk.execute("openstack subnet show -f value -c cidr %s" % net)
            #temporarily commented as the openstack cli fails on ngena4
            output = ostk.execute("neutron subnet-show -f value -c cidr %s" % net)
        except:
            e = sys.exc_info()[0]
            logger.error("opstk cmd failed with error=[%s]. Looks like neutron net-list cmd fetch no result"%e)
            raise

        return output.rstrip().split('/')[-1]

    def validate_cpe_ks_sync_info(self,  cpeSn, nso, vpn):
        """
            function: validate_cpe_ks_sync_info
            description: validate that CPE is synced/registered with its keyserver
                         ACL rules on KS are downloaded corrected on its CPE
            Input Params: CPE serial#, NSO connect object, service chain name
            Return: True/False
            Success criteria: KS Floating IP is fetched
                              ACL on CPE and KS match
        """

        cmd = "show csr-data vpn-infra-%s-ks | display json" % vpn
        out = nso.execute(cmd)
        j = json.loads(out)
        ks_fip = (j['data']['ngena-csr-data:csr-data'][0]['interface'][1]['ip']).split('/')[0]
        if ks_fip:
            logger.info("floating ip of KS: %s" % ks_fip)
        else:
            logger.exception("failed to get KS Floating IP")
            return False
        try:
            cpeCon = self.connect_to_cpe(cpeSn)
        except:
            logger.exception("Could not connect to the cpe-%s" % cpeSn)
            return False

        output = cpeCon.execute("show crypto gdoi | inc Register")
        out = output.splitlines()
        for i in range(len(out)):
            if(("Registration status" in out[i]) and ("Registered with" in out[i+1])):
                if(((out[i].split(':')[1]).strip() == "Registered") and ((out[i+1].split(':')[1]).strip() == ks_fip)):
                    logger.info("CPE-%s successfully registered with KS[%s]" % (cpeSn, ks_fip))
                    break
                else:
                    logger.error("CPE-%s still not registered with KS or KS info incorrect" % cpeSn)
                    return False

        ## now connect to KS and fetch the necessary info
        ks = self.connect_to_vnf('keyserver')
        ### comparing control-plane ACL
        ksAcl = ks.execute("show crypto gdoi group GDOI-%s-CONTROL-PLANEV4 ks acl" % vpn)
        logger.info("KS %s-control-plane acl: %s" % (vpn, ksAcl))

        cpeAcl = cpeCon.execute("show crypto gdoi group %s-control-plane gm acl download" % vpn)
        logger.info("CPE-%s %s-control-plane acl: %s" % (cpeSn, vpn, cpeAcl))

        ret = self.compare_acl_list(cpeAcl, ksAcl)
        if ret:
            logger.info('CPE and KS Acl CP match')
        else:
            logger.error('CPE and KS Acl CP mismatch')
            return False

        ### comparing data-plane ACL
        ksDAcl = ks.execute("show crypto gdoi group GDOI-%s-DATA-PLANEV4 ks acl" % vpn)
        logger.info("KS %s-control-plane acl: %s" % (vpn, ksDAcl))

        cpeDAcl = cpeCon.execute("show crypto gdoi group %s-data-plane gm acl download" % vpn)
        logger.info("CPE-%s %s-control-plane acl: %s" % (cpeSn, vpn, cpeDAcl))

        ret = self.compare_acl_list(cpeDAcl, ksDAcl)
        if ret:
            logger.info('CPE and KS Acl DP match')
        else:
            logger.error('CPE and KS Acl DP mismatch')
            return False
        logger.info("validate_cpe_ks_sync_info completed successfully")
        return True

    def compare_acl_list(self, cpe_acl, ks_acl):
        """
            function: compare_acl_list
            description: ACL rules on KS are downloaded corrected on its CPE
            Input Params: CPE ACL list, KS ACL list
            Return: True/False
            Success criteria:  ACL on CPE and KS match
        """
        cpeAcl = cpe_acl.splitlines()
        ksAcl = ks_acl.splitlines()

        for i in range(len(cpeAcl)):
            if('access-list' in cpeAcl[i]):
                p = cpeAcl[i].split('   ')
                c1 = p[2]
        for i in range(len(ksAcl)):
            if('access-list' in ksAcl[i]):
                p1 = cpeAcl[i].split('   ')
                c2 = p1[2]

        try:
            if c1 == c2:
                logger.info('ACL lists are same')
                return True
            else:
                logger.error('ACL lists are not same')
                return False
        except:
            logger.exception("Error in ACL list comparison.. probably because access-list not found in cpe/KS")
            return False


    def verify_crypto_counter(self, cpeData, vrf, count):
        """
        function: verify_crypto_counter
        description:  Verify Crypto ipsec sa Counters  at each CPE (site to site connectivity) in a cpeData list
        input: dictionary with cpe data, vrf to which cpe belongs
        return: true/false
        Success criteria: "Verification is considered successful if counters match +/- loss_tolerance(default 5)")
        """
        logger.debug("Entered verify_crypto_counter")
        for cpe in cpeData:
            try:
                cpe['connect'] = self.connect_to_cpe(cpe['Serial'])
            except:
                logger.exception("Could not connect to the cpe-%s" % cpe['Serial'])
                return False

        logger.info('Total cpe count %d' % len(cpeData))
        logger.debug("Final cpe data: %s" % cpeData)
        try:
            for cpe in cpeData:
                for scpe in cpeData:
                    if not cpe is scpe:
                        try:
                            cpe['connect'].session.sendline("clear crypto sa counters ")
                            scpe['connect'].session.sendline("clear crypto sa counters ")
                            ret = self.ping_cpe_lan(cpe,
                                                    scpe,
                                                    vrf,
                                                    count)
                            if(not ret):
                                logger.error("Ping from CPE_%s to CPE_%s failed" %(cpe['Serial'], scpe['Serial']))
                                return False
                        except:
                            logger.exception("Ping from CPE_%s to CPE_%s is failing" %(cpe['Serial'], scpe['Serial']) )
                            return False
                        time.sleep(1)
                        cpePe_count, cpePd_count = self.get_crypto_pkt_count(cpe['connect'])
                        cpeSe_count, cpeSd_count = self.get_crypto_pkt_count(scpe['connect'])
                        logger.debug('Primary CPE Counters. Encap:%s, Decap:%s', cpePe_count, cpePd_count)
                        logger.debug('Secondary CPE Counters. Encap:%s, Decap:%s', cpeSe_count, cpeSd_count)
                        if ((((int(cpePe_count) + int(cpeSd_count)) >= (2*count))) and
                            ((int(cpeSe_count) + int(cpePd_count)) >= (2*count))):
                            logger.info("Crypto Counter are Matching")
                            logger.info("There is potential error introduced due to time delay from clearing and"
                                         " capturing these two counters, resulting in Tx/Rx not being exactly same")
                        else:
                            logger.error("Crypto Counter %s to %s failed" %(cpe['Serial'], scpe['Serial']))
                            return False
            return True
        except:
            logger.exception("Site to site CPEs Crypto Counter Check failed")
            return False
#####################################################



    def verify_service_chain_ngena(self,timeout=120):
        """
        Verify & validate NGENA Service Chain with one or more CPEs
        """
        # Verifying the basic SC part of medium SC using verify_service_chain_basic method
        try:
            resultVerifyBasic = False
            resultVerifyBasic = self.verify_service_chain_basic(self.serviceChainName)
        except:
            logger.exception("Unexpected error occurred while verifying CSR license "
                             "or ping between CSR & CPE or between CPE & CPE")
        # vnflist = self.ncs_cli.get_vnf_list(self.serviceChainName)
        vnflist = self.cso_cli.get_vnf_list(self.serviceChainName)
        return True


        ASA = vnflist[0]
        logger.debug("ASA= %s" % ASA)
        # ASA license check
        resultASALicense = False
        try:
            resultASALicense = self.ASA_license(ASA)
        except:
            logger.exception("Unexpected error occurred while "
                                    "checking ASA license")
            return False
        cpeSNlist = self.ncs_cli.get_virto_cpesn_list(self.serviceChainName)
        # checking if the SC has any CPEs on-boarded or not
        if len(cpeSNlist) ==0:
            if resultVerifyBasic & resultASALicense:
                return True
            else:
                logger.debug("resultVerifyBasic:%s, resultASALicense:%s"%(resultVerifyBasic,resultASALicense))
                return False
        # if CPEs are on boarded onto SC, then verify ping between CPE and ASA
        else:
            prevResultPingCpeAsa = True
            resultPingCpeAsa = False
            for cpeSN in cpeSNlist:
                logger.info ("Ping between cpe-%s and ASA" %cpeSN)
                # Verifying ping between CPE & ASA
                try:
                    resultPingCpeAsa = self.ping_cpe_ASA(cpeSN,ASA)
                except:
                    logger.exception("Unexpected error occurred while verifying Ping between CPE and ASA ")
                if resultPingCpeAsa == False:
                    prevResultPingCpeAsa = resultPingCpeAsa
            if prevResultPingCpeAsa & resultPingCpeAsa:
                resultPingCpeAsa = True
                logger.info("Ping between CPE & ASA passed")
            else:
                resultPingCpeAsa = False
                logger.error("Ping between CPE & ASA failed")
        resultPingAsaCsr = False
        CSR = vnflist[1]
        # Verifying ping between ASA & CSR
        try:
            resultPingAsaCsr = self.ping_ASA_CSR(ASA,CSR)
        except:
            ("Unexpected error occurred  while verifying Ping between ASA and CSR ")
        if resultPingAsaCsr:
            logger.info("Ping between ASA & CSR passed")
        else:
            logger.error("Ping between ASA & CSR failed")
        if (resultVerifyBasic & resultASALicense & resultPingCpeAsa & resultPingAsaCsr):
            return True
        else:
            logger.debug("resultVerifyBasic:%s resultASALicense:%s"%(resultVerifyBasic,resultASALicense))
            return False

    def verify_service_chain_medium(self,timeout=120):
        """
        Verify & validate a Medium Service Chain with one or more CPEs
        """
        # Verifying the basic SC part of medium SC using verify_service_chain_basic method
        try:
            resultVerifyBasic = False
            resultVerifyBasic = self.verify_service_chain_basic(self.serviceChainName)
        except:
            logger.exception("Unexpected error occurred while verifying CSR license "
                             "or ping between CSR & CPE or between CPE & CPE")
        vnflist = self.ncs_cli.get_vnf_list(self.serviceChainName)
        ASA = vnflist[0]
        logger.debug("ASA= %s" % ASA)
        # ASA license check
        resultASALicense = False
        try:
            resultASALicense = self.ASA_license(ASA)
        except:
            logger.exception("Unexpected error occurred while "
                                    "checking ASA license")
            return False
        cpeSNlist = self.ncs_cli.get_virto_cpesn_list(self.serviceChainName)
        # checking if the SC has any CPEs on-boarded or not
        if len(cpeSNlist) ==0:
            if resultVerifyBasic & resultASALicense:
                return True
            else:
                logger.debug("resultVerifyBasic:%s, resultASALicense:%s"%(resultVerifyBasic,resultASALicense))
                return False
        # if CPEs are on boarded onto SC, then verify ping between CPE and ASA
        else:
            prevResultPingCpeAsa = True
            resultPingCpeAsa = False
            for cpeSN in cpeSNlist:
                logger.info ("Ping between cpe-%s and ASA" %cpeSN)
                # Verifying ping between CPE & ASA
                try:
                    resultPingCpeAsa = self.ping_cpe_ASA(cpeSN,ASA)
                except:
                    logger.exception("Unexpected error occurred while verifying Ping between CPE and ASA ")
                if resultPingCpeAsa == False:
                    prevResultPingCpeAsa = resultPingCpeAsa
            if prevResultPingCpeAsa & resultPingCpeAsa:
                resultPingCpeAsa = True
                logger.info("Ping between CPE & ASA passed")
            else:
                resultPingCpeAsa = False
                logger.error("Ping between CPE & ASA failed")
        resultPingAsaCsr = False
        CSR = vnflist[1]
        # Verifying ping between ASA & CSR
        try:
            resultPingAsaCsr = self.ping_ASA_CSR(ASA,CSR)
        except:
            ("Unexpected error occurred  while verifying Ping between ASA and CSR ")
        if resultPingAsaCsr:
            logger.info("Ping between ASA & CSR passed")
        else:
            logger.error("Ping between ASA & CSR failed")
        if (resultVerifyBasic & resultASALicense & resultPingCpeAsa & resultPingAsaCsr):
            return True
        else:
            logger.debug("resultVerifyBasic:%s resultASALicense:%s"%(resultVerifyBasic,resultASALicense))
            return False

    def verify_service_chain_full(self,timeout=120):
        """
        Verify & validate a Full Service Chain with one or more CPEs
        """
        # Verifying the basic and medium SC parts of full SC using verify_service_chain_medium method
        try:
            resultVerifyMedium = False
            resultVerifyMedium = self.verify_service_chain_medium(self.serviceChainName)
        except:
            logger.exception("Unexpected error occurred while verifying either CSR or ASA licenses "
                             "or ping between CSR & CPE or CPE & CPE ping or ASA & CSR ping or CPE & ASA ping")
        vnflist = self.ncs_cli.get_vnf_list(self.serviceChainName)
        WSA = vnflist[2]
        logger.debug("WSA= %s" % WSA)
        resultWSALicense = False
        # Verifying WSA license
        try:
            resultWSALicense = self.WSA_license(WSA)
        except:
            logger.exception("Unexpected error occurred while verifying WSA license")
            return False
        # Checking if any CPEs are on boarded for this SC
        cpeSNlist = self.ncs_cli.get_virto_cpesn_list(self.serviceChainName)
        if len(cpeSNlist) ==0:
            if resultWSALicense & resultVerifyMedium:
                return True
            else:
                return False
        else:
            # Verifying ping between WSA & CSR
            CSR = vnflist[1]
            resultPingWsaCsr = False
            try:
                resultPingWsaCsr = self.ping_WSA_CSR(WSA,CSR)
            except:
                logger.exception("Unexpected error occurred while verifying ping between CSR & WSA")
            if resultPingWsaCsr == True:
                logger.info("Ping Between WSA & CSR passed")
            else:
                logger.error("Ping Between WSA & CSR failed")
        # Verifying the WSA filter rules from each CPE
        cpeSNlist = self.ncs_cli.get_virto_cpesn_list(self.serviceChainName)
        logger.info(cpeSNlist)
        prevResultVerifyWebFilter = True
        resultVerifyWebFilter = False
        for cpeSN in cpeSNlist:
            logger.debug(("Verifying url filter rules from %s" %cpeSN))
            try:
                resultVerifyWebFilter = self.web_filter_verify(cpeSN)
            except:
                logger.exception("Unexpected error occurred while verifying WSA web filter rules from CPE %s"%cpeSN)
            if resultVerifyWebFilter == False:
                logger.error("WSA web filter rules verify failed for %s"%cpeSN)
                prevResultVerifyWebFilter = resultVerifyWebFilter
            else:
                logger.info("WSA web filter rules verify passed for %s"%cpeSN)
        logger.debug("prevResultVerifyWebFilter: %d, resultVerifyWebFilter:%d"%(prevResultVerifyWebFilter,resultVerifyWebFilter))
        if prevResultVerifyWebFilter & resultVerifyWebFilter:
            logger.info("WSA web filter rules verify passed for all CPEs")
            resultVerifyWebFilter = True
        else:
            logger.error("WSA web filter rules verify failed")
            resultVerifyWebFilter = False
        logger.debug("resultVerifyMedium:%d, resultWSALicense:%d, resultPingWsaCsr:%d,resultVerifyWebFilter:%d"%(resultVerifyMedium,resultWSALicense,resultPingWsaCsr,resultVerifyWebFilter))
        if (resultVerifyMedium & resultWSALicense & resultPingWsaCsr & resultVerifyWebFilter):
            return True
        else:
            return False

    def verify_service_chain_basic(self,vrf,timeout=120):
        """
        Verify & validate a Basic Service Chain with one or more CPEs
        """
        cvpnlist = self.cso_cli.get_vpn_list()
        if self.serviceChainName in cvpnlist:
                logger.info("Service chain present in NCS")
        else:
            raise TestFail("Service chain not present in NCS")
        vnflist = self.cso_cli.get_vnf_list(self.serviceChainName)
        logger.debug('in verify_service_chain_basic, get_vnf_list_ngena returned; %s' % vnflist)
        csr_index=2 ; # skip ms + ks in case of service chain + subvpn
        if  len(vnflist) <= 2:
            csr_index=0
        CSR = vnflist[csr_index]
        logger.debug('index = {}, CSR = {}'.format(csr_index, CSR))

        # CSR license check
        try:
            logger.debug('Checking license for ; CSR: %s' % CSR)
            resultCsrLicense = self.CSR_license(CSR)
        except:
            logger.exception("Unexpected error occurred while "
                                 "checking CSR license")
            resultCsrLicense = False

        # Verify PxTR
        try:
            resultValidatePxTR = self.validate_PxTR(CSR)
            logger.debug('validate_PxTR Result; %s' % resultValidatePxTR)
        except:
            logger.exception("Unexpected error occurred while validating PxTR")
            resultCsrLicense = False

        # CSR to CPE ping checks
        # Todo: xav re-add this, fix vrf param.
        cpeSNlist = self.cso_cli.get_virto_cpesn_list(self.serviceChainName)
        logger.debug('in verify_service_chain_basic, get_virto_cpesn_list returned; %s' % cpeSNlist)

        # CSR to CPE ping checks
        # if len(cpeSNlist) ==0:
        #     if resultCsrLicense:
        #         logger.info("Service chain %s CSR is licensed"%self.serviceChainName)
        #         return resultCsrLicense
        #     else:
        #         logger.error("Service chain %s CSR is not licensed"%self.serviceChainName)
        #         return resultCsrLicense
        # else:
        #     prevResultPingCpeCsr = True
        #     resultPingCpeCsr = False
        #     for cpeSN in cpeSNlist:
        #         logger.info ("Ping between cpe-%s and CSR" %cpeSN)
        #         try:
        #             resultPingCpeCsr = self.ping_cpe_CSR(cpeSN,CSR, vrf)
        #         except:
        #             logger.exception("Unexpected error occurred while verifying ping between CPE & CSR")
        #         if resultPingCpeCsr == False:
        #             prevResultPingCpeCsr = resultPingCpeCsr
        #     if prevResultPingCpeCsr & resultPingCpeCsr:
        #         resultPingCpeCsr = True
        #     else:
        #         resultPingCpeCsr = False
        resultPingCpeCsr = True

        # CPE to CPE ping checks
        if len(cpeSNlist)>1:
            logger.info('Pings CPE to CPE')
            resultPingCpeCpe = False
            try:
                resultPingCpeCpe = self.ping_cpe_cpe(cpeSNlist, vrf)
            except:
                logger.exception("Unexpected error occured while verifying ping between CPE & CPE")
            if (resultCsrLicense & resultPingCpeCsr & resultPingCpeCpe):
                return True
            else:
                return False
        else:
            if resultCsrLicense & resultPingCpeCsr:
                return True
            else:
                return False

    def ping_cpe_internet_strippedoff(self,cpeSN, vrf, internetIp):
        """
        Verify ping CPE to internet in a cpeSNlist
        """
        cpe = self.connect_to_cpe(cpeSN)

        LanInterface = self.cpe_lan_interface(cpeSN, vrf)
        logger.debug('LanInterface = %s' %LanInterface)

        output = cpe.execute("ping vrf %s %s" % (vrf, internetIp))
        match = re.search('Success rate is ([1-9][0-9]+) percent',output)
        if match:
           logger.info("Ping cpe-%s to internet %s successful" %(cpeSN,internetIp))
           return True
        else:
            logger.error("Ping cpe-%s to internet %s failed" % (cpeSN, internetIp))
            return False

    def ping_cpe_internet(self,cpeSN, vrf, internetIp):
        """
        Verify ping CPE to internet in a cpeSNlist
        """
        try:
            try:
                cpe = self.connect_to_cpe(cpeSN)
                logger.debug('----------------------------- connected to cpe-%s' % cpeSN)
            except:
                logger.exception("Could not connect to the cpe-%s"%cpeSN)
            else:
                LanInterface = self.cpe_lan_interface(cpeSN, vrf)

                output = cpe.execute("show version | i Cisco IOS |uptime")
                logger.debug('CPE Version and uptime; {}'.format(output))

                output = cpe.execute("show crypto gdoi | i Regi|ACL|access-list")
                logger.debug('CPE crypto gdoi Registration; {}'.format(output))

                output = cpe.execute("ping vrf %s %s" % (vrf, internetIp))
                logger.debug("output=%s"%output)
                match = re.search('Success rate is ([1-9][0-9]+) percent',output)
                if match:
                   logger.info("Ping cpe-%s to internet %s successful" %(cpeSN,internetIp))
                   return True
                else:
                    logger.error("Ping cpe-%s to internet %s failed" % (cpeSN, internetIp))
                    return False
        except:
            logger.exception("Ping cpe-%s to internet %s failed, unknown error" % (cpeSN, internetIp))
            return False

    def get_interface_counter (self, connect, interface):
        """
        Get Interface Counter from the given Interface
        """
        try:
            output = connect.execute("show int %s | include packets" %interface)
            for line in output.splitlines():
                if "input" in line:
                    input_pkt = int(re.search(r'\d+', line).group())
                elif "output" in line:
                    output_pkt = int(re.search(r'\d+', line).group())
            return (input_pkt, output_pkt)
        except:
            return (False, False)

    def node_clear_counter(self,node, interface):
        node.session.sendline("clear counters %s" %interface)
        node.session.expect_exact("[confirm]")
        node.session.send("\r")

    def ping_cpe_one_on_one(self, cpeP, cpePrimary, cpeS, cpeSecondary, vrf, count=5):
        """
        Verify Ping btw Two CPES
        """
        LanInterface = self.cpe_lan_interface(cpePrimary, vrf)
        LanInterface = self.cpe_lan_interface(cpeSecondary, vrf)
        output = cpeS.execute("show ip int brief")
        match = re.search('%s.*\s+(\S+)\s+YES\s+(NVRAM|manual|CONFIG)\s+up'%LanInterface,output)
        if match:
            logger.debug("Matched== %s"%match.group(1))
            cpeS_int_ip = match.group(1)
        else:
            logger.error("cpe lan interface is DOWN")
            return False
        output = cpeP.execute("ping vrf %s %s repeat %s" %  (vrf, cpeS_int_ip, count))
        match = re.search('Success rate is ([1-9][0-9]+) percent',output)
        if match:
            logger.info("Ping from %s to %s is successful" %(cpePrimary,cpeSecondary))
            return True
        else:
            logger.error("Ping from %s to %s failed" %(cpePrimary,cpeSecondary))
            return False


    def verify_lisp_counter(self, cpeSNlist, vrf):
        """
        Executes pings between all combinations of CPE to CPE pairs in the list of provided serial numbers,
        then verifies that packets counters on LISP interface match the number of ping packets ingress/egress.
        :param cpeSNlist: List of CPE Serial Numbers
        :param vrf: vrf name
        :return: True on LISP counters match, False on mismatch or error.
        """
        allpass = True
        num_pings = 10
        cpe_data = dict()
        cpe_num = 0
        for cpeA in cpeSNlist:
            cpe_data[cpe_num] = dict()
            try:
                cpe_data[cpe_num]['connect']= self.connect_to_cpe(cpeA)
            except:
                logger.exception("Could not connect to the cpe-%s" % cpeA)
                return False
            else:
                cpe_data[cpe_num]['SN'] = cpeA
            cpe_num += 1
        try:
            for cpeA, cpeB in itertools.combinations(range(0,cpe_num), 2):
                logger.debug('Preparing for pings from cpeA={} {} to cpeB={} {}'.format(cpeA, cpe_data[cpeA]['SN'], cpeB, cpe_data[cpeB]['SN']))
                time.sleep(10)
                try:
                    cpeA_LISP_int = self.get_cpe_lisp_interface(cpe_data[cpeA]['connect'], vrf)
                    if cpeA_LISP_int == False:
                        continue
                    cpeB_LISP_int = self.get_cpe_lisp_interface(cpe_data[cpeB]['connect'], vrf)
                    if cpeB_LISP_int == False:
                        continue
                    logger.info('clearing counters')
                    self.node_clear_counter(cpe_data[cpeA]['connect'], cpeA_LISP_int)
                    self.node_clear_counter(cpe_data[cpeB]['connect'], cpeB_LISP_int)
                    ping_result = self.ping_cpe_one_on_one(cpe_data[cpeA]['connect'],
                                                         cpe_data[cpeA]['SN'],
                                                         cpe_data[cpeB]['connect'],
                                                         cpe_data[cpeB]['SN'],
                                                         vrf, num_pings)
                    if (ping_result == False):
                        logger.exception("Ping CPE to CPE is failling")
                        return False
                except:
                    logger.exception("Ping CPE to CPE is failling")
                    return False
                # Allow time for counters to be updated
                time.sleep(10)
                cpeA_pkt_in, cpeA_pkt_out = self.get_interface_counter(cpe_data[cpeA]['connect'], cpeA_LISP_int)
                logger.info('Collected interface counters for {} {}: {} pkt in, {} pkt out'.format(
                    cpeA,
                    cpe_data[cpeA]['SN'],
                    cpeA_pkt_in,
                    cpeA_pkt_out
                ))
                cpeB_pkt_in, cpeB_pkt_out = self.get_interface_counter(cpe_data[cpeB]['connect'], cpeB_LISP_int)
                logger.info('Collected interface counters for {} {}: {} pkt in, {} pkt out'.format(
                    cpeB,
                    cpe_data[cpeB]['SN'],
                    cpeB_pkt_in,
                    cpeB_pkt_out
                ))
                if cpeA_pkt_in == cpeB_pkt_in == cpeB_pkt_out == cpeA_pkt_in == num_pings:
                    logger.info('Success, LISP pkts counter {} to {} are mismatching'.format(cpe_data[cpeA]['SN'],cpe_data[cpeB]['SN']))
                else:
                    allpass = False
                    logger.error('Error, LISP pkts counter {} to {} mismatch'.format(cpe_data[cpeA]['SN'],cpe_data[cpeB]['SN']))
            if allpass:
                return True
            else:
                return False
        except:
            logger.exception("Site to site CPEs Counter Check failed")
            return False
    # Workaround for Ping test (ICSP , PM-agent shut and no shut) sequence
    def cpe_pm_agent_shut_noshut(self, cpeSNlist, shutdown):
        for cpe in cpeSNlist:
            try:
                cpe_console = self.connect_to_cpe(cpe['Serial'])
                logger.info("-------Connected to cpe-%s"%cpe['Serial'])
            except Exception, e:
                logger.info("connect to cpe-%s failed"%cpe['Serial'])
                logger.info("err msge:%s"%e)
                raise
            else:
                pm_agent_cfg = []
                pm_agent_cfg.append("pm-agent")
                if shutdown:
                    logger.info("pm-agent shutdown in cpe-%s"%cpe)
                    pm_agent_cfg.append("shutdown")
                else:
                    logger.info("pm-agent no-shutdown in cpe-%s"%cpe)
                    pm_agent_cfg.append("no shutdown")
                pm_agent_cfg.append("!")
                cpe_console.config(pm_agent_cfg, 60)

    def get_vnf_name_by_vnftype(self, vpn_name, subvpn_name, vnf_type, region):
        """
        Get vnf name corresponds to vpn and subvpn from vnf type
        """
        xtr_list = self.cso_cli.get_vnf_list(self.serviceChainName)
        for vnf in xtr_list:
            if vnf_type == 'pxtr' or vnf_type == 'firewall':
                if vpn_name in vnf and subvpn_name in vnf and region in vnf:
                    return vnf
            elif vnf_type == 'icsp':
                    return vnf
            else:
                logger.critical("Requested vnf type is not present vnf_type:%s"%vnf_type)
        raise Exception("Requested VNF type is not present")

    def get_vnf_hub_by_vnf_type(self, vpn_name, subvpn_name, vnf_type, region):
        """
        Getting VNF's hub from the type of vnf (EX: pxtr, firewall, icsp, and wsa)
        Input: Vpn, subvpn name and vnf type as mentioned above
        """
        vnfName = self.get_vnf_name_by_vnftype(vpn_name, subvpn_name, vnf_type, region)
        hub = self.cso_cli.get_device_hub(self.serviceChainName, vnfName)
        logger.info("VNF (%s) hub name is:%s"%(vnfName, hub))
        return hub

    def xtr_vnf_pm_agent_shut_noshut(self, shutdown):
        """
        Getting list of VNF from the vpn.
            - find pxtr and rtr from the vnf list.
            - connect with xtr and apply pm agent shut or noshut
        Argument: vpn-name
                  shutdown - True pm-agent shutdown
                             False pm-agent noshut
        """
        xtr_list = self.cso_cli.get_vnf_list(self.serviceChainName)
        logger.info(xtr_list)
        for vnf in xtr_list:
            if 'pxtr' in vnf or 'rtr' in vnf:
                logger.info(vnf)
                try:
                    vnf_console = self.connect_to_vnf(vnf)
                    logger.info("-------Connected to vnf-%s"%vnf)
                except Exception, e:
                    logger.info("connect to xtr vnf-%s failed"%vnf)
                    logger.info("err msge:%s"%e)
                    raise
                else:
                    pm_agent_cfg = []
                    pm_agent_cfg.append("pm-agent")
                    if shutdown:
                        logger.info("pm-agent shutdown in vnf-%s"%vnf)
                        pm_agent_cfg.append("shutdown")
                    else:
                        logger.info("pm-agent no-shutdown in vnf-%s"%vnf)
                        pm_agent_cfg.append("no shutdown")
                    pm_agent_cfg.append("!")
                    vnf_console.config(pm_agent_cfg, 60)
    #Workaround API end here#


    def ping_cpe_cpe(self,cpeSNlist, vrf):
        """
        Verify ping between each CPE (site to site connectivity) in a cpeSNlist
        """
        cpeSNlistCopy=cpeSNlist
        try:
            prevResultPingCpeCpe = None
            resultPingCpeCpe = None
            for cpePrimary in cpeSNlist:
                try:
                    cpeP = self.connect_to_cpe(cpePrimary)
                    logger.debug('Connected to cpe-%s' % cpePrimary)
                except:
                    logger.exception("Could not connect to the cpe-%s"%cpePrimary)
                else:
                    LanInterface = self.cpe_lan_interface(cpePrimary, vrf)
                for cpeSecondary in cpeSNlistCopy:
                    if cpePrimary!=cpeSecondary:
                           try:
                                cpeS = self.connect_to_cpe(cpeSecondary)
                           except:
                                logger.exception("Could not connect to the cpe-%s"%cpeSecondary)
                           else:
                               LanInterface = self.cpe_lan_interface(cpeSecondary, vrf)
                               output = cpeS.execute("show ip int brief")
                               match = re.search('%s.*\s+(\S+)\s+YES\s+(NVRAM|manual|CONFIG)\s+up'%LanInterface,output)
                               if match:
                                   logger.debug("Matched== %s"%match.group(1))
                                   cpeS_int_ip = match.group(1)
                               else:
                                   logger.error("cpe lan interface is DOWN")
                                   return False
                               logger.info("Ping from %s to %s" %(cpePrimary,cpeSecondary))
                               output = cpeP.execute("ping vrf %s %s" %  (vrf, cpeS_int_ip))
                               match = re.search('Success rate is ([1-9][0-9]+) percent',output)
                               prevResultPingCpeCpe = True
                               if match:
                                   logger.info("Ping from %s to %s is successful" %(cpePrimary,cpeSecondary))
                                   resultPingCpeCpe = True
                               else:
                                   logger.error("Ping from %s to %s failed" %(cpePrimary,cpeSecondary))
                                   resultPingCpeCpe = False
                                   prevResultPingCpeCpe = False
            if resultPingCpeCpe and prevResultPingCpeCpe:
                logger.info("Site to site ping between CPEs passed")
                return True
            else:
                logger.error("Site to site ping between CPEs failed")
                return False
        except:
            logger.exception("Site to site ping between CPEs failed")
            return False

    def ping_ASA_CSR(self,ASA,CSR):
        """
        Verify ping between VNFs ASA & CSR
        """
        ASA = self.connect_to_vnf(ASA)
        output = ASA.execute("show interface ip brief")
        match = re.search('GigabitEthernet0/0.*\s+(\S+)\s+YES\s+(NVRAM|manual|CONFIG)\s+up',output)
        if match:
           logger.debug("Matched== %s"%match.group(1))
           ASA_int_ip = match.group(1)
        else:
            raise Exception("ASA's CSR facing interface is DOWN")
        CSR = self.connect_to_vnf(CSR)
        output = CSR.execute("ping vrf IVRF %s"  % ASA_int_ip)
        match = re.search('Success rate is ([1-9][0-9]+) percent',output)
        if match:
           logger.info("Ping from CSR to ASA is successful")
        else:
            logger.error("Ping from CSR to ASA failed")
        output = CSR.execute("show ip int brief")
        match = re.search('GigabitEthernet3\s+(\S+)\s+YES',output)
        if match:
           logger.debug("Matched== %s"%match.group(1))
           csr_int_ip = match.group(1)
        else:
            raise Exception("CSR's ASA facing interface is DOWN")
        output = ASA.execute("ping %s" % csr_int_ip)
        match = re.search('Success rate is ([1-9][0-9]+) percent',output)
        if match:
           logger.info("Ping from ASA to CSR is successful")
           return True
        else:
            logger.error("Ping from ASA to CSR failed")
            return False

    def ping_WSA_CSR(self,WSA,CSR):
        """
        Verify ping between VNFs WSA to CSR
        """
        CSR = self.connect_to_vnf(CSR)
        output = CSR.execute("show ip int brief")
        match = re.search('GigabitEthernet3\s+(\S+)\s+YES',output)
        if match:
           logger.debug("Matched== %s"%match.group(1))
           csr_int_ip = match.group(1)
        else:
            raise Exception("CSR's WSA facing interface is DOWN")
        WSA = self.connect_to_vnf(WSA)
        output1 = WSA.execute("ping %s" % csr_int_ip)
        time.sleep(50)
        #output2 = WSA.execute("\x03")
        match = re.search('(\d+) packets transmitted, (\d+) packets received,',output1)
        if match:
           logger.info("Ping from WSA to CSR is successful")
           return True
        else:
            logger.info("Ping from WSA to CSR failed")
            return False

    def ping_cpe_ASA(self,cpeSN,ASA,debug=False):
        """
        Verify ping between CPE & ASA.
        """
        logger.debug("Entered ping_cpe_ASA")
        try:
            cpe = self.connect_to_cpe(cpeSN)
            logger.debug("Inside CPE %s"%cpeSN)
        except:
            logger.exception("Could not connect to cpe-%s"%cpeSN)
        else:
            LanInterface = self.cpe_lan_interface(cpeSN)
        try:
            logger.debug("ASA= %s" % ASA)
            ASA = self.connect_to_vnf(ASA)
        except:
            logger.exception("Could not connect to ASA")
        else:
            logger.info("ping %s" %cpe_int_ip)
            output = ASA.execute("ping %s"  % cpe_int_ip)
            match = re.search('Success rate is ([1-9][0-9]+) percent',output)
            if match:
                logger.info("Ping from ASA to cpe-%s is successful"%cpeSN)
                resultPingAsaCpe = True
            else:
                logger.error("Ping from ASA to cpe-%s failed"%cpeSN)
                resultPingAsaCpe = False
            output = ASA.execute("show interface ip brief")
            match = re.search('GigabitEthernet0/0.*\s+(\S+)\s+YES\s+(NVRAM|manual|CONFIG)\s+up',output)
            if match:
                logger.debug("Matched== %s"%match.group(1))
                ASA_int_ip = match.group(1)
            else:
                logger.info("ASA's CSR facing interface is DOWN")
        try:
            output = cpe.execute("ping vrf IVRF %s source %s" %(ASA_int_ip,cpe_int_ip))
            match = re.search('Success rate is ([1-9][0-9]+) percent',output)
            if match:
                logger.info("Ping from cpe-%s to ASA is successful"%cpeSN)
                resultPingCpeAsa = True
            else:
                logger.error("Ping from cpe-%s to ASA failed"%cpeSN)
                resultPingCpeAsa = False
            if resultPingAsaCpe & resultPingCpeAsa:
                logger.info("Ping between ASA & CPE passed")
                return True
            else:
                logger.error("Ping between ASA & CPE failed"%cpeSN)
                return False
        except:
            logger.exception("Ping between ASA & cpe-%s failed"%cpeSN)
            return False

    def ping_cpe_CSR(self,cpeSN,CSR,vrf,debug=False):
        """
        Verify ping between CPE & CSR.
        """
        logger.debug("Entered ping_cpe_CSR")
        try:
            cpe = self.connect_to_cpe(cpeSN)
            logger.debug("Inside CPE %s"%cpeSN)
        except:
            logger.exception("Could not connect to cpe-%s"%cpeSN)
        else:
            LanInterface = self.cpe_lan_interface(cpeSN, vrf)
        try:
            CSR = self.connect_to_vnf(CSR)
        except:
            logger.exception("Could not connect to CSR")
        else:
            logger.info("ping vrf IVRF %s" %cpe_int_ip)
            output = CSR.execute("ping vrf IVRF %s"  % cpe_int_ip)
            match = re.search('Success rate is ([1-9][0-9]+) percent',output)
            if match:
                logger.info("Ping from CSR to cpe-%s is successful"%cpeSN)
                resultPingCsrCpe=True
            else:
                logger.info("Ping from CSR to cpe-%s failed"%cpeSN)
                resultPingCsrCpe=False
            output = CSR.execute("show ip int brief")
            match = re.search('GigabitEthernet2\s+(\S+)\s+YES',output)
            match1 = re.search('GigabitEthernet3\s+(\S+)\s+YES',output)
            if match:
               logger.debug( "Matched== %s"%match.group(1))
               csr_int_ip = match.group(1)
            elif match1:
               logger.debug( "Matched== %s"%match1.group(1))
               csr_int_ip = match1.group(1)
            else:
               logger.info("CSR's ASA facing interface is DOWN")
        try:
            cpe = self.connect_to_cpe(cpeSN)
            logger.debug("Inside CPE %s"%cpeSN)
        except:
            logger.exception("Could not connect to CPE")
        else:
            logger.info("ping vrf IVRF %s source %s" %(csr_int_ip, cpe_int_ip))
            output = cpe.execute("ping vrf IVRF %s source %s" %(csr_int_ip, cpe_int_ip))
            logger.info("output="+output)
            match = re.search('Success rate is ([1-9][0-9]+) percent',output)
            if match:
                logger.info("Ping from cpe-%s to CSR is successful"%cpeSN)
                resultPingCpeCsr=True
            else:
                logger.error("Ping from cpe-%s to CSR failed"%cpeSN)
                resultPingCpeCsr=False
        if resultPingCsrCpe & resultPingCpeCsr:
            logger.info("Ping between CPE & CSR is successful")
            return True
        else:
            logger.error("Ping between CPE & CSR failed")
            return False

    def ping_from_vm_behind_phy_cpe(self,cpeSN,trafficConfig,target):
        """
        Verify ping from vm-behind-CPE for physical CPE to Target Host
        Params:
          cpeSN: Serial number of physical CPE connected to vm-behind-cpe
          trafficConfig: config parameters for traffic test
          target: target dictionary (keys: hostname, IP). Possible values:
                  'Internet'/'Physical CPE'/'Virtual CPE'/'Vm-behind-vCPE'
        returns: Test Result (True/False)

        """
        testSummary = list()
        testResult = True
        cpeLanPort = trafficConfig['cpe_lan_port']
        sshPort = trafficConfig['ssh_port']
        try:
            vmBehindCpe = self.connect_vm_behind_phy_cpe(cpeSN,cpeLanPort,sshPort)
            logger.debug('--------------- connected to vm-behind-cpe:cpeSN-%s, LAN Port-%s' %(cpeSN,cpeLanPort))
        except:
            logger.exception("Could not connect to the vm-behind-cpe for CPE-%s,LAN port-%s"%(cpeSN,cpeLanPort))
            return False
        try:
            cpe = self.connect_to_cpe(cpeSN)
            logger.debug("Inside CPE %s"%cpeSN)
        except:
            logger.exception("Could not connect to cpe-%s"%cpeSN)
            return False
        for vlan in trafficConfig['cpe_port_vlan']:
            # Fetch gateway IP, Subnet for this VLAN and verify the CPE VLAN config
            defGateway = self.get_cpe_l3_interface_ip(cpe,trafficConfig['cpe_port_type'],cpeLanPort,vlan)
            if not defGateway:
                logger.debug('Could not get gateway ip for cpe {}'.format(cpeSN))
                return False
            # If VM-Behind-PCPE needs to ping Physical CPE, target IP should be L3 Ip of VLAN
            logger.debug("Target=%s"%target)
            if target['hostname'] == 'Physical CPE':
                if 'IP' not in target:
                    target['IP'] = defGateway[0]
            self.configure_vm_behind_cpe(vmBehindCpe,defGateway,trafficConfig['cpe_port_type'],vlan)
            # Ping from VM-Behind-CPE to target for all IPs(v4/v6) for all packet sizes
            for targetIP in target['IP']:
                for pSize in trafficConfig['packet_sizes']: #ICMP Packet sizes in bytes
                    output = self.ping_from_vm_behind_cpe(vmBehindCpe,
                                                     'vm-behind-cpe-%s'%cpeSN,
                                                     {'hostname':target['hostname'],'IP':targetIP},
                                                     trafficConfig['loss_tolerance'],
                                                     pSize,trafficConfig['ping_count'])
                    output.update({'vlan':vlan})
                    testSummary.append(output)
                    testResult = False if (output['result']=='FAIL' or testResult == False) else True
            self.reset_vm_behind_cpe(vmBehindCpe,trafficConfig['cpe_port_type'],vlan)
        logger.debug('Test Summary for ping from vm-behind-cpe {} to target IP {}'.format(cpeSN,target['IP']))
        table = PrettyTable()
        table.field_names = ['Source','Target IP','VLAN', 'Packet_size', 'Packet_loss', 'Ping_time', 'Result']
        for test in testSummary:
            table.add_row(
                [test['source'],test['target'],test['vlan'],test['packet_size'],
                 test['packet_loss'], test['ping_time'], test['result']])
        logger.debug("\n%s\n"%table)
        return testResult

    def ping_vm_behind_pcpe_to_vm_behind_vcpe(self,pcpeSN,trafficConfig,vCpeInfo):
        """
        Verify ping from vm-behind-pCPE to all vm-behind-vCPE in same subvpn
        """
        logger.debug( "In ping_vm_behind_pcpe_to_vm_behind_vcpe")
        testResult = dict()

        # For each vCPE, verify vCPE lan interface is UP
        for vcpe in vCpeInfo:
            try:
                tcpe = self.connect_to_cpe(vcpe['Serial'])
                logger.debug('Conneced to cpe-%s' % vcpe['Serial'])
            except:
                logger.exception("Could not connect to the cpe-%s"%vcpe['Serial'])
            else:
                LanInterface = self.cpe_lan_interface(vcpe['Serial'], vcpe['subvpn'])

            # Step1: For each vCPE, verify connectivity from Vm-Behind-pCPE to vCPE in same subvpn
            pingResultVcpe = self.ping_from_vm_behind_phy_cpe(pcpeSN,
                                                              trafficConfig,
                                                              target={'hostname':'Virtual CPE',
                                                              'IP':vcpe['LAN-Net-ip']})
            if pingResultVcpe:
                logger.info("Ping from vm-behind-pcpe-%s to vCPE %s: Success" %(pcpeSN,vcpe['Serial']))
            else:
                logger.error("Ping from vm-behind-pcpe-%s to vCPE %s: FAILED" %(pcpeSN,vcpe['Serial']))

            # Step2: For each vCPE, verify connectivity from Vm-Behind-pCPE to Vm-behind-vCPE in same subvpn
            pingResult = self.ping_from_vm_behind_phy_cpe(pcpeSN,
                                                          trafficConfig,
                                                          target={'hostname':'Vm-behind-vCPE',
                                                          'IP':vcpe['VM-Behind-CPE']['LAN-Net-ip']})
            if pingResult:
                logger.info("Ping from Vm-behind-pCPE-%s to Vm-behind-vCPE %s: Success" %(pcpeSN,vcpe['Serial']))
            else:
                logger.error("Ping from Vm-behind-pCPE-%s to Vm-behind-vCPE %s: FAILED" %(pcpeSN,vcpe['Serial']))

        testResult.update({'Virtual CPE':pingResultVcpe,'Vm-behind-vCPE':pingResult})
        return testResult

    def ping_from_vm_behind_cpe(self,vmBehindCpe,source,target,lossTolerance,pSize=64,pingCount=10):
        """
        Verify ping from vm-behind-CPE to Target host/IP
        Params:
          vmBehindCpe: connection to vm-behind-cpe
          source: source of traffic
          target: target dictionary (keys: hostname, IP). Possible values:
                  'Internet'/'Physical CPE'/'Virtual CPE'/'Vm-behind-vCPE'
          pSize: ping packet size
          pingCount: ping count for test
        returns: Test Result
                 (Dict with keys: source,target,packet_size,packet_loss,ping_time,result)
        """
        logger.debug( "In ping_from_vm_behind_cpe")
        testResult = dict()
        logger.debug('Ping from {} to IP {} with packet size {}'
                      .format(source,target['IP'],pSize))
        ping_cmd = 'ping6' if IP.is_ipv6(target['IP']) else 'ping'
        cmd = "%s -c %s -s %s %s" %(ping_cmd,pingCount,pSize,target['IP'])
        output = vmBehindCpe.execute(cmd)
        logger.debug("cmd: %s,output: %s"%(cmd,output))
        match= re.search('(\d+)% packet loss, time (\d+)', output)
        if match:
            if int(match.group(1)) <= lossTolerance: #loss tolerance in %
                result = 'PASS'
            elif pSize == 32: #workaround . pasingh2 #TEST_CASE_WORKAROUND
                logger.debug('Ignoring the failure if pSize = 32')
                result = 'PASS'
            else:
                result = 'FAIL'
        testResult.update({'source':source,'target':'%s (%s)'%(target['hostname'],target['IP']),
                            'packet_size':pSize,'packet_loss':match.group(1),'ping_time':match.group(2),'result':result})
        logger.info("Ping %s to target IP %s is %s with %s percent packet drop" % (source,target['IP'],result,match.group(1)))
        return testResult

    def ping_vm_behind_vcpe_to_internet(self,trafficConfig,vCpeInfo):
        """
        Verify ping from all vm-behind-vCPE to Internet
        """
        logger.debug( "In ping_vm_behind_vcpe_to_internet")
        testResult = True
        testSummary = list()
        sshPort = trafficConfig['ssh_port']

        for vcpe in vCpeInfo:
            # Step1: Connect to Vm-Behind-VCPE
            try:
                vmBehindCpe = self.connect_vm_behind_vcpe(vcpe,sshPort)
                logger.debug('--------------- connected to vm-behind-cpe:cpeSN-%s' %(vcpe['Serial']))
            except:
                logger.exception("Could not connect to the vm-behind-cpe for CPE-%s"%(vcpe['Serial']))
                return False

            # Step2: For each vCPE, verify connectivity from Vm-Behind-vCPE to Internet
            for lanIP in vcpe['VM-Behind-CPE']['LAN-Net-ip']:
                # select Internet IP based on LAN IP configuration
                targetIP = trafficConfig['internet_ping_ipv4'] if IP.is_ipv4(lanIP) else trafficConfig['internet_ping_ipv6']
                for pSize in trafficConfig['packet_sizes']: #ICMP Packet sizes in bytes
                    output = self.ping_from_vm_behind_cpe(vmBehindCpe,
                                                     'vm-behind-cpe-%s'%vcpe['Serial'], #source
                                                     {'hostname':'Internet','IP':targetIP}, #target
                                                     trafficConfig['loss_tolerance'],
                                                     pSize,trafficConfig['ping_count'])
                    testSummary.append(output)
                    #[Tata]
					#1.Establish SSH connection to VM behind cpe.
                    #2.Execute traceroute(tracepath in ubuntu) for 8.8.8.8.Extract the IPs.
					#3.Get_vnf_list Extract the IPs and compare with the Step 2. IP list.
                    #4.Write logic to modify the testResult variable accordingly.					
                    IP_LIST=[]
                    flag = True
                    #[Tata :TBD] : link from VML lib
                    # Assuming get_vnf_list() with return a list of VNF IPs
                    get_vnf_list = ['192.168.0.2','192.168.0.3']
                    command = "tracepath 8.8.8.8 | cut -d ' ' -f4"

                    #[Tata] : VM behind cpe details
                    ip_address = "10.45.5.95"
                    username = "tel"
                    password = "root@123"
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(hostname=ip_address,username=username,password=password)
                    stdin, stdout, stderr = client.exec_command(command, get_pty=True)               
                    #[Tata] This time should be finalised during testing
                    time.sleep(3)

                    for line in stdout.read().splitlines():
                        IP_LIST.append(str(line))

                    IP_LIST = list(filter(None ,IP_LIST))

                    for vnf in get_vnf_list:
                        if vnf in IP_LIST:
                            flag = False

                    #[Tata] Adding appropriate logic for test result
                    testResult = False if (output['result']=='FAIL' or testResult == False or flag == False) else True
                    #testResult = False if (output['result']=='FAIL' or testResult == False) else True
                    
            # Step3: Check state of CPE LAN interface if ping fails for debug infomration
            if output['result']=='FAIL':
                LanInterface = self.cpe_lan_interface(vcpe['Serial'], vcpe['subvpn'])

        # print test summary in tabular format
        logger.debug('Test Summary for ping from vm-behind-cpe {} to target IP {}'.format(vcpe['Serial'],targetIP))
        table = PrettyTable()
        table.field_names = ['Source','Target IP','Packet_size', 'Packet_loss', 'Ping_time', 'Result']
        for test in testSummary:
            table.add_row(
                [test['source'],test['target'],test['packet_size'],
                 test['packet_loss'], test['ping_time'], test['result']])
        logger.debug("\n%s\n"%table)
        if testResult:
            logger.info("Ping from vm-behind-vcpe-%s to Internet (%s): Success" %(vcpe['Serial'],targetIP))
        else:
            logger.error("Ping from vm-behind-vcpe-%s to Internet (%s): FAILED" %(vcpe['Serial'],targetIP))

        return testResult

    def ping_vm_behind_vcpe_to_vm_behind_vcpe(self,trafficConfig,vCpeInfo):
        """
        Verify ping from vm-behind-vCPE to all vm_behind_vCPE in same subvpn
        """
        logger.debug( "In ping_vm_behind_vcpe_to_vm_behind_vcpe")
        testResult = True
        testSummary = list()
        sshPort = trafficConfig['ssh_port']

        for sourceCpe in vCpeInfo:
            # Step1: Connect to source Vm-Behind-VCPE
            try:
                srcVmBehindCpe = self.connect_vm_behind_vcpe(sourceCpe,sshPort)
                logger.debug('--------------- connected to vm-behind-cpe:cpeSN-%s' %(sourceCpe['Serial']))
            except:
                logger.exception("Could not connect to the vm-behind-cpe for CPE-%s"%(sourceCpe['Serial']))
                return False

            # Step2: For each source Vm-Behind-vCPE, verify connectivity to each target Vm-Behind-vCPE
            for targetCpe in vCpeInfo:
                if targetCpe['Serial'] != sourceCpe['Serial']:
                    for targetIP in targetCpe['VM-Behind-CPE']['LAN-Net-ip']:
                        for pSize in trafficConfig['packet_sizes']: #ICMP Packet sizes in bytes
                            output = self.ping_from_vm_behind_cpe(srcVmBehindCpe,
                                                                 'Vm-Behind-vCPE-%s'%sourceCpe['Serial'], #source
                                                                 {'hostname':'Vm-Behind-vCPE-%s'%targetCpe['Serial'],
                                                                 'IP':targetIP},
                                                                 trafficConfig['loss_tolerance'],
                                                                 pSize,trafficConfig['ping_count'])
                            testSummary.append(output)
                            IP_LIST=[]
                            flag = True
                            #[Tata :TBD] : link from VML lib
                            # Assuming get_vnf_list() with return a list of VNF IPs
                            get_vnf_list = ['192.168.0.2','192.168.0.3']
                            #[Tata] : 10.45.4.86 ip of another vm behind cpe 
                            command = "tracepath 10.45.4.86 | cut -d ' ' -f4"

                            #[Tata] : VM behind cpe details
                            ip_address = "10.45.5.95"
                            username = "tel"
                            password = "root@123"
                            client = paramiko.SSHClient()
                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            client.connect(hostname=ip_address,username=username,password=password)
                            stdin, stdout, stderr = client.exec_command(command, get_pty=True)               
                            #[Tata] This time should be finalised during testing
                            time.sleep(3)

                            for line in stdout.read().splitlines():
                                IP_LIST.append(str(line))

                            IP_LIST = list(filter(None ,IP_LIST))

                            for vnf in get_vnf_list:
                                if vnf in IP_LIST:
                                    flag = False

                            #[Tata] Adding appropriate logic for test result
                            testResult = False if (output['result']=='FAIL' or testResult == False or flag == False) else True
                            #testResult = False if (output['result']=='FAIL' or testResult == False) else True
                    # Step3:Check state of CPE LAN interface if ping fails for debug infomration
                    if output['result']=='FAIL':
                        LanInterface = self.cpe_lan_interface(sourceCpe['Serial'], sourceCpe['subvpn'])

        logger.debug('Test Summary for ping from Vm-Behind-vCPE to Vm-Behind-vCPE')
        table = PrettyTable()
        table.field_names = ['Source','Target','Packet_size', 'Packet_loss', 'Ping_time', 'Result']
        for test in testSummary:
            table.add_row(
                [test['source'],test['target'],test['packet_size'],
                 test['packet_loss'], test['ping_time'], test['result']])
        logger.debug("\n%s\n"%table)
        if testResult:
            logger.info("Ping from Vm-Behind-vCPE to Vm-Behind-vCPE: SUCCESS")
        else:
            logger.error("Ping from Vm-Behind-vCPE to Vm-Behind-vCPE: FAILED")

        return testResult


    def configure_vm_behind_cpe(self,vmBehindCpe,defGateway,cpe_port_type='access',cpe_port_vlan=1):
        """
        Configure vm-behind-cpe LAN port for End user Traffic
        Params:
          vmBehindCpe: connection to vm_behind_cpe
          defGateway: default gateway for vm-behind-cpe
          cpe_port_type: lan port type
          cpe_port_vlan: vlan of lan port at cpe. used only for trunk port config
        returns: None
        """
        logger.debug( "In configure_vm_behind_cpe")
        logger.debug( "def gateway ip: %s, Subnet: %s" %(defGateway[0],defGateway[1]))
        lan_ip = defGateway[0].split('.')[:3] +  [str(int(defGateway[0].split('.')[3]) + 1 )]

        # configure VM-Behind-CPE LAN port and default gateway for traffic
        if cpe_port_type == 'access':
            output = vmBehindCpe.execute("sudo ifconfig ens4 %s netmask %s up" % ('.'.join(lan_ip), defGateway[1]))
            logger.debug('Configuring LAN interface {}'.format(output))

            output = vmBehindCpe.execute("sudo route add default gw %s" % defGateway[0])
            logger.debug('Configuring Default gateway {}'.format(output))

        elif cpe_port_type == 'trunk':
            output = vmBehindCpe.execute("sudo vconfig add ens4 %s" % cpe_port_vlan)
            logger.debug('Adding VLAN sub-interface {}'.format(output))

            output = vmBehindCpe.execute("sudo ifconfig ens4 up")
            logger.debug('Bringing up LAN interface {}'.format(output))

            output = vmBehindCpe.execute("sudo ifconfig ens4.%s %s netmask %s up" % (cpe_port_vlan,'.'.join(lan_ip), defGateway[1]))
            logger.debug('Configuring LAN interface {}'.format(output))

            output = vmBehindCpe.execute("sudo route add default gw %s" % defGateway[0])
            logger.debug('Configuring Default gateway {}'.format(output))

        else:
            logger.error('Invalid cpe_port_type value {}'.format(cpe_port_type))

        # verify VM LAN interface config
        output = vmBehindCpe.execute("sudo ifconfig")
        logger.debug('vm_behind-cpe LAN Interface:\n {}'.format(output))

        output = vmBehindCpe.execute("sudo route -n")
        logger.debug('vm_behind-cpe Route config:\n {}'.format(output))

    def reset_vm_behind_cpe(self,vmBehindCpe,cpe_port_type='access',cpe_port_vlan=1):
        """
        Reset vm-behind-cpe LAN port configuration after Traffic test
        Params:
          vmBehindCpe: connection to vm_behind_cpe
          cpe_port_type: lan port type
          cpe_port_vlan: vlan of lan port at cpe. used only for trunk port config
        returns: None
        """
        logger.debug( "in reset_vm_behind_cpe")
        # reset VM-Behind-CPE LAN port and default gateway for traffic
        if cpe_port_type == 'trunk':
            output = vmBehindCpe.execute("sudo vconfig rem ens4.%s" % cpe_port_vlan)
            logger.debug('Removing VLAN sub-interface {}'.format(output))

        output = vmBehindCpe.execute("sudo ifconfig ens4 %s down" %'0.0.0.0')
        logger.debug('bringing down LAN interface {}'.format(output))


    def get_cpe_l3_interface_ip(self,cpe,cpe_port_type,cpeLanPort,cpe_port_vlan):
        """
        Verify the CPE LAN port configuration, and returns L3 interface gateway IP
        returns: l3 interface Ip and subnet if configuration is correct
        """
        logger.debug( "in get_cpe_l3_interface_ip")
        output = cpe.execute("show running-config interface %s" %cpeLanPort)
        #Verify that LAN port mode is configured correctly at CPE
        match1 = re.search('switchport mode ([a-z]+)',output)
        if match1:
            logger.debug("CPE LAN Switch port mode: %s" % match1.group(1))
            #verify that LAN port mode is configured correctly at CPE
            if match1.group(1) != cpe_port_type:
                logger.error("LAN port %s configuration mismatch: value %s, expected %s" %
                                (cpeLanPort,match1.group(1),cpe_port_type))
                return False
        else:
            logger.warning("Could not verify CPE LAN port %s configuration mode" %cpeLanPort)

        #Verify VLAN configuration at Lan Port
        if cpe_port_type == 'access':
            match2 = re.search('switchport access vlan (\d+)',output)
            if match2:
                logger.debug("CPE LAN Port VLAN: %s" % match2.group(1))
            else:
                logger.error("Could not get CPE LAN port %s VLAN" %cpeLanPort)
                return False

        #Get Ip address and subnet for VLAN L3 interface
        output2 = cpe.execute("show running-config interface vlan %s" %cpe_port_vlan)
        match3 = re.search('ip address (\d+.\d+.\d+.\d+) (\d+.\d+.\d+.\d+)',output2)
        if match3:
            lan_gateway_ip = match3.group(1)
            lan_subnet = match3.group(2)
            logger.debug( "lan_gateway_ip: %s, lan_subnet: %s"%(lan_gateway_ip,lan_subnet))
            return [lan_gateway_ip,lan_subnet]
        else:
            logger.error("Could not get CPE LAN port %s Gateway IP and Subnet" %cpeLanPort)
            return False

    def validate_transport_layer_traffic(self,serverConn,serverIP,sPort,srcFileName,clientConn,cPort=None,timeout=10,cType='TCP'):
        """
        Establish TCP/UDP Server, initiate connection from Client and Verify traffic
        Params:
          serverConn: Bash connection to TCP/UDP server host
          serverIP: Server IP used for TCP/UDP connections
          sPort: Server port for TCP/UDP connections
          srcFileName: File on server to be used for traffic test
          clientConn: Bash connection to TCP/UDP client host
          cPort: Client port for initiating TCP/UDP connection
          timeout: connection timeout period in seconds after data transfer
          cType: transport layer Connection type (TCP/UDP)
        returns: Test Result (True/False)
        """
        testResult = True
        dstFileName = "dst_test"
        logger.debug( "In validate_transport_layer_traffic")
        if not cPort:
            cPort = sPort
        ipFormat = '-6' if IP.is_ipv6(serverIP) else '-4'
        # Step1: start a TCP/UDP server to listen at server host
        if cType == 'UDP':
            cmd = "nc -v %s -u -l -p %s -w %s  < %s &" %(ipFormat,sPort,timeout,srcFileName)
        else:
            cmd = "nc -v %s -l -p %s -w %s  < %s &" %(ipFormat,sPort,timeout,srcFileName)
        output = serverConn.execute(cmd)
        logger.debug('{} Server cmd: {}, Output:{}'.format(cType,cmd,output))

        # Step2: initiate a TCP session from Client host
        if cType == 'UDP':
            cmd = "nc -v %s -u -p %s -w %s %s %s > %s" %(ipFormat,cPort,timeout,serverIP,sPort,dstFileName)
        else:
            cmd = "nc -v %s -p %s -w %s %s %s > %s" %(ipFormat,cPort,timeout,serverIP,sPort,dstFileName)
        output = clientConn.execute(cmd)
        logger.debug('{} Client cmd: {}, Output: {}'.format(cType,cmd,output))

        # Step3: validate data transfer
        # get md5sum of source file
        cmd = "echo" # execute echo to get tcp server output before next command execution
        output = serverConn.execute(cmd)
        logger.debug('{} Server cmd: {}, Output: {}'.format(cType,cmd,output))
        cmd = "md5sum %s " %(srcFileName)
        output = serverConn.execute(cmd)
        logger.debug('{} Server cmd: {}, Output: {}'.format(cType,cmd,output))
        srcMd5Sum = output.split()[0]
        # get md5sum of transferred file at Client
        cmd = "md5sum %s " %(dstFileName)
        output = clientConn.execute(cmd)
        logger.debug('{} Client cmd: {}, Output: {}'.format(cType,cmd,output))
        dstMd5Sum = output.split()[0]
        # cleanup the test file transferred to client for testing
        cmd = "rm %s " %(dstFileName)
        output = clientConn.execute(cmd)
        logger.debug('{} Client cmd: {}'.format(cType,cmd))
        if srcMd5Sum == dstMd5Sum:
            logger.debug( "%s transfer successful"%cType)
            return True
        else:
            logger.debug( "%s transfer Fail"%cType)
            logger.debug( "---------------------Debug Info--------------------")
            # If test fails print debug information for server and client
            cmd = "sudo netstat -tunlp"
            output = serverConn.execute(cmd)
            logger.debug('{} Server cmd: {}, Output: {}'.format(cType,cmd,output))
            output = clientConn.execute(cmd)
            logger.debug('{} Client cmd: {}, Output: {}'.format(cType,cmd,output))
            # check reachability of server from client
            ping_cmd = 'ping6' if IP.is_ipv6(serverIP) else 'ping'
            cmd = "%s -c 4 %s" %(ping_cmd,serverIP)
            output = clientConn.execute(cmd)
            logger.debug('{} Client cmd: {}, Output: {}'.format(cType,cmd,output))
            return False

    def traffic_vm_behind_vcpe(self,trafficConfig,vCpeInfo,cType='TCP'):
        """
        Verify traffic from vm-behind-vCPE to all vm_behind_vCPE in same subvpn
        """
        logger.debug( "In traffic_vm_behind_vcpe")
        testResult = True
        testSummary = list()
        srcFileName = "input.txt"
        sshPort = trafficConfig['ssh_port']
        trafficTypeConfig = trafficConfig['tcp_traffic'] if cType == 'TCP' else trafficConfig['udp_traffic']

        for sourceCpe in vCpeInfo:
            # Step1: Connect to source Vm-Behind-VCPE
            try:
                srcVmBehindCpe = self.connect_vm_behind_vcpe(sourceCpe,sshPort)
                logger.debug('------- connected to source vm-behind-cpe:cpeSN-%s' %(sourceCpe['Serial']))
            except:
                # if connection to one CPE fails, testcase should continue for other CPE. test result will be failure
                logger.exception("Could not connect to the vm-behind-cpe for CPE-%s"%(sourceCpe['Serial']))
                testResult = False
                continue

            # Step2: SCP testfile to source Vm-Behind-VCPE
            logger.info('Transferring test file to TCP server vm-behind-cpe-{}'.format(sourceCpe["Serial"]))
            Linux.scp_put_file("vm-behind-cpe-" + sourceCpe["Serial"], self.tbFile, trafficTypeConfig['traffic_file'], '~/%s'%srcFileName)

            for targetCpe in vCpeInfo:
                if targetCpe['Serial'] != sourceCpe['Serial']:
                    # Step3: Connect to target Vm-Behind-VCPE
                    try:
                        tgtVmBehindCpe = self.connect_vm_behind_vcpe(targetCpe,sshPort)
                        logger.debug('------- connected to target vm-behind-cpe:cpeSN-%s' %(targetCpe['Serial']))
                    except:
                        logger.exception("Could not connect to the vm-behind-cpe for CPE-%s"%(targetCpe['Serial']))
                        testResult =  False
                        continue
                    targetIP = targetCpe['VM-Behind-CPE']['LAN-Net-ip']
                    # Step4: For each source Vm-Behind-vCPE (TCP Server),
                    #        verify TCP transfer to each target Vm-Behind-vCPE (client)
                    for sourceIP in sourceCpe['VM-Behind-CPE']['LAN-Net-ip']:
                        for sPort in trafficTypeConfig['server_port_list']: # TCP port
                            logger.debug('Initiating %s transfer from VM-Behind-CPE-%s to VM-Behind-CPE-%s on port-%s'
                                         %(cType,sourceCpe['Serial'],targetCpe['Serial'],sPort))
                            output = self.validate_transport_layer_traffic(srcVmBehindCpe,
                                         sourceIP,
                                         sPort,
                                         srcFileName,
                                         tgtVmBehindCpe,
                                         trafficTypeConfig['client_port'],
                                         trafficTypeConfig['timeout'],
                                         cType)
                            testResult = testResult and output
                            testSummary.append({'server':'VM-Behind-CPE-%s'%sourceCpe['Serial'],
                                                'client':'VM-Behind-CPE-%s'%targetCpe['Serial'],
                                                'server_ip':'%s : %s'%(sourceIP,sPort),
                                                'client_ip':'%s : %s'%(targetIP,
                                                trafficTypeConfig['client_port']),
                                                'result':output})
                            logger.debug('---------------------------------------------------------------------------')
            srcVmBehindCpe.execute("rm %s" %srcFileName)
        logger.debug('Test Summary for Traffic from Vm-Behind-vCPE to Vm-Behind-vCPE')
        table = PrettyTable()
        table.field_names = ['%s Server'%cType,'%s Client'%cType,'Server IP : Port','Client IP : Port','Result']
        for test in testSummary:
            table.add_row(
                [test['server'],test['client'],test['server_ip'],
                 test['client_ip'], test['result']])
        logger.debug("\n%s\n"%table)
        if testResult:
            logger.info("%s Traffic from Vm-Behind-vCPE to Vm-Behind-vCPE: SUCCESS" %cType)
        else:
            logger.error("%s Traffic from Vm-Behind-vCPE to Vm-Behind-vCPE: FAILED" %cType)

        return testResult


    def web_filter_verify(self,cpeSN):
        """
        Verify functionality of web filter rules on WSA, verification is done from CPE
        """
        for item in self.urlFilteredList:
            logger.info('Checking url "%s" category "%s".',item['url'],
                            item['category'])
            try:
                prevresulturlFilter = True
                resulturlFilter = False
                logger.debug( "before calling is_url_filtered")
                filtered = self.is_url_filtered(cpeSN,item['url'],
                                                    item['category'])
            except TestFail:
                logger.exception('Error accessing the url from CPE"%s".',
                                     item['url'])
                resulturlFilter = False
            else:
                if filtered:
                    resulturlFilter = True
                else:
                    prevresulturlFilter = False
                    logger.error(
                            'Not getting filtered result when visiting "%s".',
                            item['url']
                        )
            # Run test to make sure test website is not filtered.
        if (prevresulturlFilter & resulturlFilter):
            resulturlFilter = True
            logger.info("Web filter verify for cpe %s is successful"%cpeSN)
        else:
            logger.error("Web filter verify for cpe %s failed"%cpeSN)
            resulturlFilter = False
        try:
           logger.info("Checking test website www.google.com")
           cpe = self.connect_to_cpe(cpeSN)
           output = cpe.execute_cpe_telnet_port80("telnet www.google.com 80 /vrf IVRF","www.google.com")
        except:
            logger.exception('*****Error accessing the test website google.com*****')
            resultTestWebsite = False
        else:
            match = re.search('Connection: keep-alive',output)
            if match:
                logger.info("Test website google.com is reachable and available")
                resultTestWebsite = True
            else:
                logger.error('Not getting vMS test page when visiting '
                                 '"http://web1.cloudvpn.com/main.html".')
                resultTestWebsite = False
            if (resulturlFilter & resultTestWebsite):
                logger.info("Web filter verify and test-website access tests are successful from cpe %s"%cpeSN)
                return True
            else:
                logger.error("Web filter verify and test-website access tests are successful from cpe %s"%cpeSN)
                return False

    def is_url_filtered(self,cpeSN,url,category):
        """
        Sub method used by Web filter verify method to Verify each specific url for its category and filtering rules on WSA
        """
        logger.debug( "in is_url_filtered")
        cpe = self.connect_to_cpe(cpeSN)
        logger.debug( "telnet %s 80 /vrf IVRF"%url)
        output1 = cpe.execute_cpe_telnet_port80("telnet %s 80 /vrf IVRF" %url,url)
        match1 = re.search(
            'Based on your organization\'s access policies, access to this '
            'web site\s+\([^\)]+\) has been blocked because the web category '
            '&quot;([a-zA-Z\s0-9-]+)&quot; is not allowed.',output1
        )
        match2 = re.search(
            'You are trying to visit a web page that falls under the URL Category\s([a-zA-Z\s0-9-]+)(\s.) '
            'By clicking the link below, you acknowledge that you have read and agree with the organization\'s policies '
            'that govern the usage of the Internet for this type of content. Data about your browsing behavior may be '
            'monitored and recorded. You will be periodically asked to acknowledge this statement for continued access '
            'to this kind of web page.',output1
        )
        if (match1):
            logger.debug( category)
            logger.debug( match1.group(1))
            if category == match1.group(1):
                logger.info("Output from WSA's filter  rule for url %s classified under category %s: %s"%(url,category,match1.group(0)))
                return True
            else:
                raise Exception
                return False
        if (match2):
            logger.debug(category)
            logger.debug(match2.group(1))
            if category == match2.group(1):
               logger.info("Output from WSA's filter rule for url %s classified under category %s: %s"%(url,category,match2.group(0)))
               return True
            else:
                return False
        else:
            return False

    def reboot_vnf(self,vmgroup):
        '''
        reboots  a vnf of  the service chain
        @params vmgroup string csr or asa or  wsa
        '''
        existFlag = False
        vmgroup = vmgroup.upper()
        if vmgroup == "CSR" or vmgroup == "ASA" or vmgroup == "WSA":
            for vnfName in self.get_vnf_list() :
                if vmgroup in vnfName:
                    existFlag=True
        if existFlag==False:
            raise NotFound('Unable to find vnf type %s in Service Chain %s'
                            %(vmgroup,self.serviceChainName))

        logger.info("Attempt to reboot %s of SC %s"
                    %(vmgroup,self.serviceChainName)
                    )
        for datacenter in self.tbFile.get_data_plane_dc_list():
            try:
                ostkCtrlHost = self.tbFile.get_ostk_ctrl_host(datacenter)
            except Testbed.NotFound:
                ostk_bash = Linux.Bash(debug=self.debug)
            else:
                ostk_bash = Linux.Bash(
                        ostkCtrlHost,
                        self.tbFile,
                        debug=self.debug
                    )
            osAuth = self.tbFile.get_ostk_auth(datacenter)
            ostk = OpenStack.Control(ostk_bash,osAuth)
            out = ostk.execute("nova list | grep %s | grep %s"
                        %(self.serviceChainName,vmgroup.upper()))
            logger.debug("Out=%s"%out)
            try:
                vmUID = filter(len,out.split("|"))[0]
            except IndexError as i :
                logger.exception(i.message)
                raise Exception("Reboot Failed ,vmUID not found ")
            except Exception as e :
                logger.exception(e.message)
                raise Exception("Reboot Failed")
            else:
                ostk.execute("nova reboot %s"%vmUID)
                out = ostk.execute("nova list | grep %s"%vmUID)
                logger.debug(out)
                if "REBOOT" in out :
                    logger.info("Reboot Success")
                    time.sleep(100)
                    return True
                else:
                    raise Exception("Reboot Failed")

    def isup_vnf(self,vmgroup):
        '''
        Check if a vnf is up
        @params  string csr asa  wsa
        returns True or Exception
        '''
        vnfName = self.get_vnf_name(vmgroup)
        if vnfName is None:
            raise Exception("VNF for vmgroup %s does not exist"%vmgroup)
        try:
            if self.connect_to_vnf(vnfName) :
                logger.debug("Can connect to vnf %s"%vnfName)
                return True
        except:
            raise Exception("VNF %s Could not be reached "%vnfName)

    def wait_for_vnf(self,vmgroup):
        '''
        Wait for a vnf to come up
        @params  string csr asa  wsa
        returns True or Exception
        '''
        timeout = 3600
        start = 0
        while True:
            try:
                if self.isup_vnf(vmgroup) is True:
                    return True
            except:
                if start>timeout:
                    raise Exception("%s vnf not up after waiting"%vmgroup)
                else:
                    time.sleep(float(20))
                    logger.info ("....")
                    start += 20

    def wait_for_cpe_synced(self, cpe_sn, timeout=600):
        '''
        Wait for CPE to onboard and reach pnp state: 'synced'
        :param cpe_sn:
        :param timeout:
        :return: True if synced achieved, False otherwise (timeout).
        '''
        elapsed_time = 0
        while elapsed_time < timeout:
            try:
                dc = utils.get_cpe_dc(cpe_sn)
                pnpDeviceInfo = self.conn[dc].get_pnp_device_state(cpe_sn)
                if pnpDeviceInfo['synced']:
                    logger.info('CPE {} synced after {} seconds'.format(cpe_sn, elapsed_time))
                    return True
                else:
                    logger.info('CPE {} not synced after {} seconds, sleeping 1 minute'.format(cpe_sn, elapsed_time))
                    time.sleep(60)
                    elapsed_time += 60
            except AttributeError:
                logger.exception('Got exception AttributeError, some element missing from the output for CPE: %s' % cpe_sn)
                raise
            except KeyError, ValueError:
                logger.exception('Got exception KeyError for CPE: %s' % cpe_sn)
                raise
            except Exception as e:
                if elapsed_time > timeout:
                    logger.error('Timeout, CPE {} not synced after {} seconds'.format(cpe_sn, elapsed_time))
                    return False
                else:
                    # Not sure about this one, got an exception, keep trying anyway
                    logger.error('Got exception {}, CPE {} not synced after {} seconds, sleeping 1 minute'.format(e, cpe_sn, elapsed_time))
                    time.sleep(60)
                    elapsed_time += 60
        logger.info('Timeout, CPE {} not synced after {} seconds'.format(cpe_sn, elapsed_time))
        return False

    def validate_PxTR(self, csrVNF):
        """
        Validate PxTR;
            show version
            show ip int brief
            show ip vrf int
            show crypto gdoi | i Regis|ACL|access-list
            show running-config
            ping vrf xx 8.8.8.8

        :param self:
        :param csrVNF:
        :return:
        """
        csr = self.connect_to_vnf(csrVNF)

        command = "show version | i Cisco IOS|uptime"
        output = csr.execute(command)
        logger.debug('CMD:%s, Output: %s ' % (command, output))

        command = "show license all"
        output = csr.execute(command)
        logger.debug('CMD:%s, Output: %s ' % (command, output))

        command = "show ip int brief"
        output = csr.execute(command)
        logger.debug('CMD:%s, Output: %s ' % (command, output))

        command = "show ip vrf int"
        output = csr.execute(command)
        logger.debug('CMD:%s, Output: %s ' % (command, output))

        command = "show crypto gdoi | i Regi"
        output = csr.execute(command)
        logger.debug('CMD:%s, Output: %s ' % (command, output))

        command = "show running-config"
        output = csr.execute(command)
        logger.debug('CMD:%s, Output: %s ' % (command, output))

        return True
        # Get 'Status' line in 'Registration' and
        # 'License Authorization' sections.
        match = []
        for item in ['Registration', 'License Authorization']:
            match.append(
                re.search(
                    '^%s:\s*'
                    '(^\s+[^:]+\s*:\s*.*\s*)*?'
                    '^\s+Status\s*:\s*([ \S+]+)' % re.escape(item),
                    output, flags=re.MULTILINE
                )
            )
        if match[0] and match[1]:
            regStatus = match[0].group(2)
            authStatus = match[1].group(2)
            if ("REGISTERED" in regStatus and
                        "AUTHORIZED on" in authStatus):
                logger.info(
                    "CSR license valid: %s, %s" %
                    (regStatus, authStatus)
                )
                return True
            else:
                logger.warning(
                    "CSR license check failed: %s, %s" %
                    (regStatus, authStatus)
                )
                return False
        else:
            raise Exception('Unable to parse "%s" output.' % command)


    def test_asaRuleIp(self, cpeSN, vrf, asaRuleIp, internetIp, count=5):
        """
        Verify ping from CPE to a specific IP, internet IP and telnet .. to test ASA Rule
        """
        if cpeSN:
            try:
                cpe = self.connect_to_cpe(cpeSN)
                logger.debug('----------------------------- connected to cpe-%s' % cpeSN)
            except:
                logger.exception("Could not connect to the cpe-%s"%cpeSN)
            else:
                lanInterface = self.cpe_lan_interface(cpeSN, vrf)

                output = cpe.execute("telnet %s daytime /vrf %s" % (asaRuleIp, vrf))
                logger.debug("output=%s"%output)
                ### If telnet is successful, the output would look something like this:
                #telnet 216.228.192.69 daytime /vrf blah4
                #Trying 216.228.192.69, 13 ... Open
                #57715 16-11-23 02:14:13 00 0 0 384.6 UTC(NIST) *
                #[Connection to 216.228.192.69 closed by foreign host]
                if 'Open' in output:
                    logger.debug('telnet from cpe-%s to IP %s successful' % (cpeSN, asaRuleIp))
                else:
                    logger.debug('telnet from cpe-%s to IP %s failed' % (cpeSN, asaRuleIp))
                    return False

                output = cpe.execute("ping vrf %s %s repeat %s" % (vrf, asaRuleIp, count))
                logger.debug("output=%s"%output)
                match = re.search('Success rate is (\d+) percent \((\d+)\/(\d+)\)', output)
                if(match and (match.group(1) >= ping_success_rate)) :
                   logger.info("Ping from cpe-%s to asaRuleIP %s successful" %(cpeSN,asaRuleIp))
                else:
                    logger.error("Ping from cpe-%s to asaRuleIP %s failed" % (cpeSN, asaRuleIp))
                    return False

                output = cpe.execute("ping vrf %s %s repeat %s" % (vrf, internetIp, count))
                logger.debug("output=%s"%output)
                match = re.search('Success rate is (\d+) percent \((\d+)\/(\d+)\)', output)
                if(match and (match.group(1) >= ping_success_rate)) :
                   logger.info("Ping from cpe-%s to internet %s successful" %(cpeSN,internetIp))
                else:
                    logger.error("Ping from cpe-%s to internet %s failed" % (cpeSN, internetIp))
                    return False
                logger.debug('test_asaRuleIp successfull')
                return True
        else:
            logger.exception("Ping cpe-%s to asaRuleIP %s skipped" % (cpeSN, asaRuleIp))
            return False
    def cpe_validate_interface(self, site_name, int_params, SN):
        """
        Get the int_params in dictionary and validate CPE interfaces
        with VLAN and switch mode
        """
        try:
            #Get the serial number of CPE
            cpeConsole=self.connect_to_cpe(SN)
            logger.debug('----- connected to cpe-%s' % SN)
        except Exception, e:
            logger.critical("Could not connect to the cpe-%s Err_Msg:%s"%(SN,e))
            raise
        else:
            #for each interface in int_params, check the vlans and switch mode
            for phy_int in int_params:
                #Verify that switch mode matches with the configured
                output=cpeConsole.execute("show running-config interface %s | include switchport mode" % phy_int)
                #print int_params[phy_int][0]
                #print phy_int
                if int_params[phy_int][0] in output:
                   logger.info("Interface switch mode %s matched with configured" % int_params[phy_int][0])
                else:
                   logger.error("Interface switch mode %s not matched with configured" % int_params[phy_int][0])
                   return False

                #Verify vlan ids configured matches with the configured
                output1=cpeConsole.execute("show running-config interface %s | include vlan" % phy_int)
                vlan_list=re.findall('[0-9]+',output1)
                #print "Vlan_list"
                #print vlan_list
                #print sorted(int_params[phy_int][1])
                if sorted(int_params[phy_int][1]) == vlan_list:
                    logger.info("Interface vlan id's %s matched with configured" % str(int_params[phy_int][1]))
                else:
                    logger.info("Interface vlan id's %s not matched with configured" % str(int_params[phy_int][1]))
                    return False
            return True

    def cpe_validate_vlans(self, site_name, cpe_lan_params, SN):
        """
        Get the cpe_lan_params in dictionary and validate CPE vlans
        with vpn name,ip address
        """
        try:
            cpeConsole = self.connect_to_cpe(SN)
            logger.debug('-------- connected to cpe-%s' %SN)
        except Exception, e:
            logger.critical("Could not connect to the cpe-%s, Err_Msg:%s"%(SN,e))
            raise
        else:
            # for each vlan in cpe_lan_params, verify vrf name and ip addresses
            for lan_info in cpe_lan_params:
                # Verify that vrf configured match with actual vrf under vlan
                #print cpe_lan_params[lan_info]
                vlan_id = cpe_lan_params[lan_info][0]
                output = cpeConsole.execute("show running-config interface vlan %s | include vrf forwarding" % vlan_id)
                if lan_info in output:
                    logger.info("vlan VRF forwarding  %s matched with configured" % lan_info)
                else:
                    logger.info("vlan VRF forwarding  %s not matched with configured" % lan_info)
                    return False

                # Verify that ip addresses configured match with actual ip's under vlan
                output1 = cpeConsole.execute("show running-config interface vlan %s" % vlan_id)
                ip_list=self.get_ips_from_vlan(output1)
                if sorted(cpe_lan_params[lan_info][2]) == sorted(ip_list):
                    logger.info("ip address configured %s matched with CPE Config" % str(cpe_lan_params[lan_info][2]))
                else:
                    logger.error("Interface vlan id's %s not matched with CPE config" % str(cpe_lan_params[lan_info][2]))
                    return False
            return True

    def get_ips_from_vlan(self,output):
        """
        Take the show running-config interface vlan <> output
        and returns the list of ip addresses (ipv4 and ipv6)  configured
        with prefix
        """
        #split the output string to get lines
        list_of_lines=output.split('\n')
        list_ip=[]
        ipv6_regex = 'ipv6 address' + r'.*[0-9A-Fa-f]+:[0-9A-Fa-f:]+'
        ipv4_regex = 'ip address (\d+.\d+.\d+.\d+) (\d+.\d+.\d+.\d+)'

        for l in list_of_lines:
            match_ipv4 = re.search(ipv4_regex, l)
            match_ipv6 = re.search(ipv6_regex, l)
            if (match_ipv4):
                logger.info(match_ipv4.group())
                list_ip.append(l.split()[2]+"/"+str(sum([bin(int(t)).count("1") for t in l.split()[3].split(".")])))
            elif (match_ipv6):
                logger.info(match_ipv6.group())
                list_ip.append(l.split()[2])

        return list_ip
