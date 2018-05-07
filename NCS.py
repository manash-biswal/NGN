"""
NCS automation library

Provides an interface for interacting with the NCS.
"""

import logging
from vmsauto.lib import Linux
from vmsauto.lib import Testbed
import re
import os
import sys
import pexpect
import copy
import traceback
import vmsauto.lib.ngena.Netconf
import vmsauto.lib.ngena.ServiceChain
import time
import traceback
import json
import xml.etree.ElementTree as xmlET
import xml.dom.minidom
from netaddr import IPNetwork, IPAddress

logger = logging.getLogger(__name__)

libDir = os.path.dirname(os.path.realpath(__file__))
subDir="cso_xml_templates/"
subDirConfig="cso_config_templates/"
ns = {'config': "http://tail-f.com/ns/config/1.0",
      'ncs': "http://tail-f.com/ns/ncs",
      'pnp': "http://tail-f.com/ned/cisco/pnp",
      'vpn': "http://ngena.com/yang/cfs/ngena-vpn",
      'sub-vpns': "http://ngena.com/yang/cfs/ngena-sub-vpns",
      'ad': "http://ngena.com/yang/cfs/ngena-access-design"
}

class ParseFail(Exception):
    pass
class NotFound(Exception):
    pass
class Timeout(Exception):
    pass
class CLI_Reset(Exception):
    pass

class Control(object):
    """
    Provides a class for interacting with the NCS CLI.
    """
    def __init__(self,bash,user="admin",vmsModel="old"):
        """
        Create a session to the NCS command line interface.  The 'bash'
        argument is a Linux.Bash object which has access to the NCS CLI.
        """
        self.bash = bash
        self.vmsModel = vmsModel
        self.session = bash.session
        self.session.sendline("ncs_cli -C -u %s" % user)
        # self.session.sendline("ncs_cli -u %s" % user)
        self.session.expect('#')
        # self.session.expect('>')
        self.__init_cli()
    def __init_cli(self):
        """
        Optimize the CLI for automated input.
        """
        self.prompt = "NCS-PROMPT:"
        self.execute("prompt1 NCS-PROMPT:")
        self.execute("paginate false")
        self.execute("screen-width 0")

    def execute(self,command,timeout=120):
        """
        Execute a command on the NCS CLI. This method has logic to
        detect a reset of the NCS CLI due to internal errors.  Upon
        this condition the CLI will be reinitialized and a CLI_Reset
        Exception will be raised.
        """
        logger.debug('NCS.py cmd = %s' % command)
        self.session.sendline(command)
        # Wait until command is echo'ed back on TTY. If for whatever
        # reason the command is not echo'ed back, then eventually the
        # expect statement for "\r\n" will run through the buffer
        # and timeout.
        done = False
        while not done:
            # Wait until the end of a line.
            self.session.expect_exact("\r\n")
            # Remove any backspaces from the buffer.
            before = re.sub('.\b',"",self.session.before)
            # Check to see if the command has been echo'ed back.
            if before.find(command) != -1:
                done = True
        index = self.session.expect_exact(
            [
                self.prompt,
                "Internal error: Restarting CLI..."
            ],
            timeout
        )
        if index == 0:
            if re.search('-+\^\r\nsyntax error: unknown argument\r\n',
                         self.session.before):
                raise SyntaxError(
                    'Syntax error: unknown argument when executing command "%s"' % command
                )
            elif re.search('-+\^\r\nsyntax error: element does not exist\r\n',
                         self.session.before):
                raise SyntaxError(
                    'Syntax error: element does not exist when executing command "%s"' % command
                )
            elif re.search('-+\^\r\nsyntax error: \r\n',
                         self.session.before):
                raise SyntaxError(
                    'Syntax error: when executing command "%s"' % command
                )
            else:
                return self.session.before
        elif index == 1:
            self.__init_cli()
            raise CLI_Reset(
                "NCS CLI was reset due to internal error with NCS."
            )


    def exist_service_chain(self,chain_name):
        """
        Return True if  Service Chain exists and False  otherwise
        @param   string  chain_name
        @return  bool True or  False or Exception
        """
        try:
            # First try to execute the command to list the cloud vpn
            # output = self.execute("show cloudvpn-data %s device-list" % chain_name,120)
            output = self.execute("show vpn %s vpn-state" % chain_name,timeout=120)
            #logger.debug( " output = %s"% output)
            # TODO: xav fix this, should be run on NSO maybe, or find a more meaningful cmd
            if "n1" in output :
                return True
            else :
                logger.debug("output=%s"%output)
                return False
        except SyntaxError:
            # Command has failed with expected failure, return False
            return  False

    def exist_service_chain_wa1(self,chain_name):
        """
        Return True if  Service Chain exists and False  otherwise
        @param   string  chain_name
        @return  bool True or  False or Exception
        """
        try:
            # First try to execute the command to list the cloud vpn
            # output = self.execute("show cloudvpn-data %s device-list" % chain_name,120)
            # output = self.execute("show vpn %s vpn-state | display xml" % chain_name,timeout=120)
            output = self.execute("show vpn %s vpn-state" % chain_name,timeout=120)
            # TODO: xav fix this, should be run on NSO maybe, or find a more meaningful cmd
            # print '+++ xav1 output= %s' % output

            if chain_name in output :
                logger.debug('found {}, return true'.format(chain_name))
                return True
            else :
                logger.debug('{} not found, return false'.format(chain_name))
                logger.debug("output=%s"%output)
                return False
        except SyntaxError:
            # Command has failed with expected failure, return False
            return  False


    def get_esc_state(self):
        '''
        Returns the esc state
        '''
        try:
            output = self.execute("show running-config infrastructure datacenter is-active")
            if "is-active true" in  output:
                return True
            else:
                return False
        except:
            raise NotFound(
                'Unable to Find the ESC Active State')

    def is_esc_active(self):
        '''
        Returns True if esc is active
        '''
        if self.get_esc_state():
            return True
        else:
            return False


    def typeof_service_chain(self,chain_name):
        """
        Returns the  type of service chain
        @param   string  chain_name
        @return  string  basic or  medium or full
        """
        #print '>>> xav1 func typeof_service_chain ; ', chain_name
        #print '   +++ xav1 typeof_service_chain ; returning static medium for now'
        # todo: xav remove all this for now, adapt later'
        return 'medium'

        vnfcount={}
        vnfcount['ASA'] = 0
        vnfcount['CSR'] = 0
        vnfcount['WSA'] = 0

        try:
             vnflist = self.get_vnf_list(chain_name)
             vnflen = len(vnflist)
        except Exception as e :
            # Command has failed , return False
            logger.exception('Unable to find the type of service chain:%s'%e.message)
            raise NotFound(
                'Unable to find the type of service chain "%s".' % chain_name)
        for each in  vnflist:
           if '-ASA-' in each :
               vnfcount['ASA']+=1
           elif '-WSA-' in each :
               vnfcount['WSA']+=1
           elif '-CSR-' in each :
               vnfcount['CSR']+=1
        if (vnflen == 3 and
               vnfcount ['ASA'] == 1 and
               vnfcount['WSA'] == 1 and
               vnfcount['CSR']== 1):
           return 'full'
        elif (vnflen == 2 and
               vnfcount ['ASA'] == 1 and
               vnfcount['CSR']== 1):
           return 'medium'
        elif (vnflen == 1 and
               vnfcount['CSR']== 1):
           return 'basic'
        else:
            raise NotFound(
                'Unable to find the type of service chain "%s".' % chain_name)

    def get_pnp_device_state(self,serial):
        """
        Return dictionary containing the PNP device state for a given
        CPE serial. The dictionary will be returned in this form:
        {
            'serial': CPE_SERIAL,
            'username': CPE_USERNAME,
            'password': CPE_PASSWORD,
            'sec-password': CPE_ENABLE_PASS,
            'ip-address': CPE_IP,
            'configured': BOOL,
            'added': BOOL,
            'synced': BOOL
        }
        """
        logger.debug('func get_pnp_device_state for CPE# %s '% serial)
        try:
            # First try to address the device specifically in the command.
            output = self.execute("show pnp list")
            output = self.execute("show pnp-state device %s | display xml" % serial)

        except SyntaxError:
            # If this doesn't work, then just get the entire output.
            # Most likely the device doesn't exist.
            output = self.execute("show pnp-state device | display xml")
        except :
            # for other exceptions like timeout
            output = self.execute("show pnp-state device | display xml")
        root = xmlET.fromstring(output)
        pnpState = root.find('pnp:pnp-state',ns)
        # Loop through all the devices in the output until we find one
        # that matches the provided serial number.
        for device in pnpState.findall('pnp:device',ns):
            serialElement = device.find('pnp:serial',ns)
            if serialElement.text == serial:
                pnpDeviceInfo = {'serial': serialElement.text}
                for item in ['username','password','sec-password','ip-address']:
                    pnpDeviceInfo[item] = device.find('pnp:' + item,ns).text
                for item in ['configured','added','synced']:
                    pnpDeviceInfo[item] = self.__parse_true_false(
                        device.find('pnp:' + item,ns).text
                    )
                return pnpDeviceInfo
        # If a device with the given serial number cannot be found,
        # then raise a NotFound exception.
        raise NotFound(
            'Unable to find pnp state info for device "%s".' % serial
        )


    def get_pnp_cred(self,serial):
        """
        Return the username and password of a given CPE by serial
        number. If the username or password are not available then the
        values will be set to None. The credential is returned as a
        Python dictionary in this form:
        {
            'username': USERNAME,
            'password': PASSWORD
        }
        """
        state = self.get_pnp_device_state(serial)
        return {'username': state['username'], 'password': state['password']}

    def compare_alarm_info(self, alarm_prev, alarm_cur):
        """
        Compare two alarm info Before and after TC execution
        """
        alarm_list = ["indeterminates", "criticals","majors","minors","warnings",]
        alarm_raised = False
        #for current in range(len(alarm_list)):
        try:
            for alarm in alarm_list:
                #alarm = alarm_list[current]
                if alarm_prev[alarm] != alarm_cur[alarm]:
                    logger.warning ('New Alarm raised Alarm:%s, Prev_cnt:%d, Current_cnt:%d'
                                    %(alarm ,alarm_prev[alarm], alarm_cur[alarm]))
                    alarm_raised = True
        except:
            logger.info("Exception in Parsing alarm info")
            alarm_raise = False

        return alarm_raised

    def get_alarm_info(self):
        """
        Return Alarm Info
        """
        # First try to address the device specifically in the command.
        output = self.execute("show alarms summary")

        alarm_info = {}
        for line in output.splitlines():
            alarm = re.split(' ', line)
            cnt = int(alarm[-1])
            alarm_name = alarm[2]
            alarm_info[alarm_name] = cnt
        return alarm_info

    def get_vpn_list(self):
        """
        NGENA 111 Return a list of vpn that are present in NCS.
        """
        vpnList = []
        cmd = "show running-config vpn | display xml"
        out = self.execute(cmd)
        root = xmlET.fromstring(out)
        for vpn in root:
            name = vpn.find('vpn:name', ns)
            vpnList.append(name.text)
        logger.debug('Returning list of existing vpns:%s' % vpnList)
        return vpnList

    # [Tata]: Add get access design list
    def get_access_design_list(self):
        """
        NGENA 111 Return a list of vpn that are present in NCS.
        """
        accessDesign = []
        cmd = "show running-config access-design | display xml"
        out = self.execute(cmd)
        root = xmlET.fromstring(out)
        for ad in root:
            name = ad.find('ad:name', ns)
            accessDesign.append(name.text)
        logger.debug('Returning list of existing access-designs:%s' % accessDesign)
        return accessDesign


    def get_subvpn_list(self, vpn):
        """
        NGENA Return a list of subvpn that are present in CSO.
        """
        subvpnList = []
        cmd = "show running-config sub-vpns %s | display xml" % vpn
        out = self.execute(cmd)
        root = xmlET.fromstring(out)

        for sub in root.findall('sub-vpns:sub-vpns/sub-vpns:sub-vpn/sub-vpns:name', ns):
            subvpnList.append(sub.text)
        logger.debug('Returning list of existing vpns:%s' % subvpnList)
        return subvpnList


    def get_virto_name(self,shortName):
        '''
        Return a list of virtos matching a shortName
        @params string shortName
        @return list  fullNames
        '''
        fullNames=[]
        for virto in self.get_virto_list():
            string = shortName+"-"
            if string in virto :
                fullNames.append(virto)
        if fullNames==[]:
            raise  NotFound("could not find any matching short names %s"%shortName)
        else:
            return fullNames
    def wait_for_virto_creation(self,shortName,timeout=300):
        """
        Wait for virto to appear on NCS. Returns the full name of
        the virto given the short name.

        :param shortName: the short name that was used to create the
                          service chain in the portal
        :type shortName: string
        :param timeout: the maximum of time to wait for virto to appear
                        on NCS
        :type timeout: integer
        :rtype: string
        """
        endTime = time.time() + timeout
        done = False
        while time.time() < endTime:
            try:
                virtoList = self.get_virto_name(shortName)
            except NotFound:
                time.sleep(30)
                continue
            else:
                return virtoList[0]
        raise Timeout("Timeout exceeded while waiting for "
                      "virto to appear on NCS.")
    def get_cpe_list(self,virto):
        """
        Return a list of CPEs for a given virto.
        """
        if self.vmsModel == "old":
            raise NotImplementedError("You should have implemented this!")
        elif self.vmsModel == "simple":
            cpeList = []
            cmd = "show running-config vpn %s | display xml" % virto
            out = self.execute(cmd)
            root = xmlET.fromstring(out)
            for vpn in root:
                name = vpn.find('subvpn:name',ns)
                if name.text == virto:
                    for cpe in vpn.findall('subvpn:cpe',ns):
                        cpeID = cpe.find('cvpn:id',ns)
                        cpeList.append(cpeID.text)
                    return cpeList
            raise NotFound('Unable to find CPE device names for virto "%s".' %
                           virto)
        else:
            raise Exception(
                'Do not understand vMS model "%s".' %
                self.vmsModel
            )

    def get_vnf_list(self, virto):
        """
        Return a list of VNFs for a given vpn on NGENA.
        """
        vnfList = []
        cmd = "show vpn %s vpn-state | display xml" % virto
        root = xmlET.fromstring(self.execute(cmd))
        for vpn in root:
            vpnName = vpn.find('vpn:name',ns)
            if vpnName.text == virto:
                for device in vpn.findall('vpn:vpn-state/vpn:device',ns):
                    deviceName = device.find('vpn:name',ns)
                    vnfList.append(deviceName.text)
                logger.debug('returning vnfList: %s' % vnfList)
                return vnfList
        raise NotFound('Unable to find NFV device names for virto "%s".' % virto)


    def get_device_hub(self, vpnName, deviceName):
        """
        Return the device's hub.
        """
        if self.vmsModel == "old":
            raise NotImplementedError("You should have implemented this!")
        elif self.vmsModel == "simple":
            # cmd = ("show running-config devices device %s "
            #        "address | display xml" % device)
            cmd = ("show vpn %s vpn-state | display xml" % vpnName)
            out1 = self.execute(cmd)
            root = xmlET.fromstring(out1)
            hub = root.findall('vpn:vpn[vpn:name="{}"]/vpn:vpn-state/vpn:device[vpn:name="{}"]/vpn:hub'\
                              .format(vpnName, deviceName), ns)
            if hub == None:
                hub = 'misssing'
            else:
                hub_text = hub[0].text
            logger.debug('For {} deviceName: {} found hub, returning ={}'.format(vpnName, deviceName, hub_text))
            return hub_text
        else:
            raise Exception(
                'Do not understand vMS model "%s".' %
                self.vmsModel
            )

    def get_device_datacenter(self, vpnName, deviceName):
        """
        Return the device's datacenter.
        """
        if self.vmsModel == "old":
            raise NotImplementedError("You should have implemented this!")
        elif self.vmsModel == "simple":
            # cmd = ("show running-config devices device %s "
            #        "address | display xml" % device)
            cmd = ("show vpn %s vpn-state | display xml" % vpnName)
            out1 = self.execute(cmd)
            root = xmlET.fromstring(out1)
            data_center = root.findall('vpn:vpn[vpn:name="{}"]/vpn:vpn-state/vpn:device[vpn:name="{}"]/vpn:data-center'\
                              .format(vpnName, deviceName), ns)
            if data_center == None:
                data_center = 'misssing'
            else:
                data_center_text = data_center[0].text
            logger.debug('For {} deviceName: {} found datacenter, returning ={}'.format(vpnName, deviceName, data_center_text))
            return data_center_text
        else:
            raise Exception(
                'Do not understand vMS model "%s".' %
                self.vmsModel
            )

    def get_device_address(self,vpnName, deviceName):
        """
        Return the IP address of a device.
        """
        if self.vmsModel == "old":
            raise NotImplementedError("You should have implemented this!")
        elif self.vmsModel == "simple":
            # cmd = ("show running-config devices device %s "
            #        "address | display xml" % device)
            cmd = ("show vpn %s vpn-state | display xml" % vpnName)
            out1 = self.execute(cmd)
            root = xmlET.fromstring(out1)
            ip = root.findall('vpn:vpn[vpn:name="{}"]/vpn:vpn-state/vpn:device[vpn:name="{}"]/vpn:management-ip'\
                              .format(vpnName, deviceName), ns)
            if ip == None:
                ip = 'misssing'
            else:
                ip_text = ip[0].text
            logger.debug('For {} deviceName: {} found ip, returning ={}'.format(vpnName, deviceName, ip_text))
            return ip_text


            for deviceNode in devices.findall('ncs:device',ns):
                if deviceNode.find('ncs:name',ns).text == device:
                    return deviceNode.find('ncs:address',ns).text
            raise NotFound('Unable to find IP address for device "%s".' %
                           device)
        else:
            raise Exception(
                'Do not understand vMS model "%s".' %
                self.vmsModel
            )


    def get_device_address_nso(self,device):
        """
        Return the IP address of a device.
        """
        cmd = ("show running-config devices device %s address | display xml" % device)
        root = xmlET.fromstring(self.execute(cmd))
        devices = root.find('ncs:devices',ns)
        for deviceNode in devices.findall('ncs:device',ns):
            if deviceNode.find('ncs:name',ns).text == device:
                return deviceNode.find('ncs:address',ns).text
        raise NotFound('Unable to find IP address for device "%s".' %
                       device)


    def get_vpn_state_ngena(self,vpn):
        """
        Return a dictionary of devices in a given virto where the key
        is the device name and the contents is another dictionary with
        the ready and provisioned state of that device.

        **** for NGENA;   could use CSO; ****

            cloud@cso> show vpn ivpn221657 vpn-state | display xml
            <config xmlns="http://tail-f.com/ns/config/1.0">
              <vpn xmlns="http://ngena.com/yang/cfs/ngena-vpn">
                <name>ivpn221657</name>
                  <vpn-state>
                    <access>
                      <name>SITE221657</name>
                      <data-center>dc1</data-center>
                      <hub>n1</hub>
                      <status>done</status>
                    </access>
                    <device>
                      <name>mapserver</name>
                      <type>map-server</type>
                      <data-center>dc1</data-center>
                      <hub>n1</hub>
                      <status>done</status>
                      <management-ip>10.0.2.52</management-ip>
                    </device>
                    <device>
                      <name>keyserver</name>
                      <type>key-server</type>
                      <data-center>dc1</data-center>
                      <hub>n1</hub>
                      <status>done</status>
                      <management-ip>10.0.2.51</management-ip>
                    </device>
                    <device>
                      <name>pxtr/ivpn221657-sales</name>
                      <type>pxtr</type>
                      <data-center>dc1</data-center>
                      <hub>n1</hub>
                      <status>done</status>
                      <management-ip>10.0.2.53</management-ip>
                    </device>
                    <device>
                      <name>fw/ivpn221657-sales</name>
                      <type>firewall</type>
                      <data-center>dc1</data-center>
                      <hub>n1</hub>
                      <status>done</status>
                      <management-ip>10.0.2.54</management-ip>
                    </device>
                    <device>
                      <name>SITE221657-cpe1</name>
                      <type>cpe</type>
                      <data-center>dc1</data-center>
                      <hub>n1</hub>
                      <status>done</status>
                      <management-ip>192.168.252.124</management-ip>
                    </device>
                  </vpn-state>
              </vpn>
            </config>
            [ok][2016-07-21 21:01:02]
        """
        vpnState = {}
        cmd = "show vpn %s vpn-state | display xml" % vpn
        output = self.execute(cmd)
        root = xmlET.fromstring(output)
        for device in root.findall('vpn:vpn[vpn:name="{}"]/vpn:vpn-state/vpn:device'.format(vpn), ns):
            deviceName = device.find('vpn:name', ns)
            type = device.find('vpn:type', ns)
            status = device.find('vpn:status', ns)
            if status == None:
                status_text = 'missing'
            else:
                status_text = status.text
            mgmtip = device.find('vpn:management-ip', ns)
            if mgmtip == None:
                mgmtip_text = 'missing'
            else:
                mgmtip_text = mgmtip.text

            vpnState[deviceName.text] = {
                'type': type.text,
                'status': status_text,
                'mgmtip': mgmtip_text
            }
        logger.debug('get_vpn_state_ngena, returning vpnState: %s' % vpnState)
        return vpnState



    def get_device_status(self,virto):
        """
        Return a dictionary of devices in a given virto where the key
        is the device name and the contents is another dictionary with
        the ready and provisioned state of that device.

        Example:
        {
            'DEVICE1_NAME': {
                'ready': READYSTATE,
                'provisioned': PROVISIONEDSTATE
            },
            'DEVICE2_NAME': {
                'ready': READYSTATE,
                'provisioned': PROVISIONEDSTATE
            }
        }

        **** for NGENA;   could use CSO; ****
        admin@cso> show vpn ivpn20160713T1039 vpn-state    + | display xml
                                        DATA                  MANAGEMENT
        NAME                TYPE        CENTER  HUB  STATUS   IP
        ------------------------------------------------------------------
        mapserver           map-server  dc1     n1   done     10.0.1.84
        keyserver           key-server  dc1     n1   done     10.0.1.83
        pxtr/apple-finance  pxtr        dc1     n1   unknown  -
        fw/apple-finance    firewall    dc1     n1   unknown  -
        pxtr/apple-support  pxtr        dc1     n1   done     10.0.1.85
        fw/apple-support    firewall    dc1     n1   done     10.0.1.86
        CA-cpe1             cpe         dc1     n1   done     -


        admin@cso> show vpn ivpn20160713T1039 vpn-state | display xml
        <config xmlns="http://tail-f.com/ns/config/1.0">
          <vpn xmlns="http://ngena.com/yang/cfs/ngena-vpn">
            <name>ivpn20160713T1039</name>Error: vpn ivpn20160713T1039 vpn-state access: Exception in callback:
        Trace : [java.lang.NullPointerException]
        [error][2016-07-13 10:03:45]
        admin@cso>

        *** or NSO ***
        admin@rtp> show vpn-infra bmw device-list | display xml
        <config xmlns="http://tail-f.com/ns/config/1.0">
          <vpn-infra xmlns="http://tailf-f.com/yang/rfs/ngena-vpn-infra">
            <id>bmw</id>
              <device-list>p-3-services_csr-vpn-infra-bmw-ks_CSR_esc0</device-list>
              <device-list>p-3-services_csr-vpn-infra-bmw-ms_CSR_esc0</device-list>
          </vpn-infra>
        </config>
        """
        if self.vmsModel == "old":
            raise NotImplementedError("You should have implemented this!")
        elif self.vmsModel == "simple":
            vnfStatus = {}

            cmd = "show vpn %s vpn-state" % virto
            output = self.execute(cmd)
            logger.debug('show vpn output:%s' % output)

            # cmd = "show vpn %s device-list | display xml" % virto
            cmd = "show vpn %s vpn-state | display xml" % virto
            if self.exist_service_chain_wa1(virto) is False:
                raise NotFound('Unable to find Service Chain  "%s".' % virto)
            output = self.execute(cmd)
            root = xmlET.fromstring(output)
            for device in root.findall('vpn:vpn[vpn:name="{}"]/vpn:vpn-state/vpn:device'.format(virto), ns):
                deviceName = device.find('vpn:name', ns)
                type = device.find('vpn:type', ns)
                status = device.find('vpn:status', ns)
                dc = device.find('vpn:data-center', ns)
                hub = device.find('vpn:hub', ns)
                host = device.find('vpn:hostname', ns)
                # Hostname is None when creating service chain, assigned once
                # service chain is up and used in testcase to find hostname
                # of a device.
                if host is None:
                    hostnm = '-'
                else:
                    hostnm = host.text
                # special case for cpe, status may not be unavailable
                if status == None:
                    status_text = 'missing'
                else:
                    status_text = status.text
                vnfStatus[deviceName.text] = {
                    'type': type.text,
                    'status': status_text,
                    'dc': dc.text,
                    'hub':hub.text,
                    'hostname': hostnm
                }
            logger.debug('get_device_status returning vnfStatus: %s' % vnfStatus)
            return vnfStatus
            raise NotFound('Unable to find NFV status for virto "%s".' % virto)
        else:
            raise Exception(
                'Do not understand vMS model "%s".' %
                self.vmsModel
            )



    def get_virto_devices(self,virto):
        """
        Return a list of devices for a virto.
        """
        if self.vmsModel == "old":
            cmd = "show virto %s device-list" % virto
            output = self.execute(cmd)
            match = re.search('device-list\s+\[\s+([^\]]+)\s+\]',output)
            if match:
                deviceList = match.group(1).split(' ')
            else:
                raise ParseFail('Unable to parse "%s" output.' % cmd)
            return deviceList
        elif self.vmsModel == "simple":
            raise NotImplementedError("You should have implemented this!")
        else:
            raise Exception(
                'Do not understand vMS model "%s".' %
                self.vmsModel
            )
    @staticmethod
    def __parse_true_false(value):
        """
        Internal method used to parse a True/False string into a
        True/False Python value.
        """
        value = value.lower()
        if value == 'true':
            return True
        elif value == 'false':
            return False
        else:
            raise ParseFail('Expected "true" or "false" but got "%s".' % value)
    def get_cpesn_list(self):
        """
        Return list of CPE serial numbers that are in the PNP server.
        """
        serialList = []
        root = xmlET.fromstring(self.execute("show pnp | display xml"))
        pnp = root.find('pnp:pnp',ns)
        for mapElement in pnp.findall('pnp:map',ns):
            idElement = mapElement.find('pnp:id',ns)
            serialList.append(idElement.text)
        for unclaimed in pnp.findall('pnp:unclaimed',ns):
            idElement = unclaimed.find('pnp:id',ns)
            serialList.append(idElement.text)
        return serialList


    def get_virto_cpesn_list(self,virto):
        """
        Return list of CPE serial numbers that are configured in a virto.
        """
        if self.vmsModel == "old":
            raise NotImplementedError("You should have implemented this!")
        elif self.vmsModel == "simple":
            cpeSNList = []
            cmd = "show running-config access-design vpn-name %s | display xml" % virto
            output = self.execute(cmd)
            root = xmlET.fromstring(output)
            for site in root:
                siteName = site.find('ad:name', ns).text
                cpes = site.findall('ad:cpe', ns)
                for cpe in cpes:
                    cpeName = cpe.find('ad:name', ns)
                    cpeSN = cpe.find('ad:serial-number', ns)
                    logger.debug('  -> {:15} {:10} {:10}, cpeSN = {:12}'.format(virto, siteName, cpeName.text, cpeSN.text))
                    cpeSNList.append(cpeSN.text)
            logger.debug( 'get_virto_cpesn_list Returning cpeSNList: %s' % cpeSNList)
            return cpeSNList
        else:
            raise Exception(
                'Do not understand vMS model "%s".' % self.vmsModel)

    def get_icsp_device_name(self, vpn_name):
        """
        Returning Icsp device name in NSO.
        """
        # Execute 'show device list' from NCS server
        output = self.execute('show devices list', timeout=10)
        logger.info(output)
        device = ('services_%s_NGENA-ICSP_ICSP'%vpn_name)
        for line in output.splitlines():
            fieldList = re.split(' ', line)
            if device in fieldList[0]:
                return fieldList[0]
        return False

    def get_pnp_list(self):
        """
        Return a List of PNP devices
        :return: List of Dict {'serial', 'ip_address', 'configured', 'added', 'synced', 'last_contact'}
        """
        pnpList = []
        # Execute "show pnp list" from NCS server
        output = self.execute('show pnp list', timeout=10)
        cnt = 1
        for line in output.splitlines():
            if cnt > 2:
                # Skip first two lines, Header line and Horizontal row line
                fieldList = re.split(r'\s{2,}', line)         # Split on 2 or more white spaces
                if len(fieldList) >= 5:
                    # Only process lines that have more then one field element, this should skip the last blank line
                    pnpList.append({'serial': fieldList[0],
                                    'ip_address': fieldList[1],
                                    'configured': fieldList[2],
                                    'added': fieldList[3],
                                    'synced': fieldList[4],
                                    'last_contact': fieldList[5]})
            cnt += 1
        return pnpList
    def get_free_cpe_list(self, ip_address=None, quantity=None):
        """
        Get a List of free CPE's with the most current ones first

        :param str ip_address:   This will filter by IP/Mask, ie '192.168.13.23/24' mask is optional
        :param int quantity:     This will limit the number of CPE's returned in the List
        :return: List of CPE Serial Numbers
        :rtype: list of strings
        """
        cnt = 0
        cpeList = []
        try:
            pnpList = self.get_pnp_list()
        except:
            logger.exception("Failed to get PNP List")
            return None
        else:
            # Sort the list by Last Contact time to ensure the CPE is functional
            # CPE's with the most current Last Contact time will be returned first
            pnpListSorted = sorted(pnpList, key=lambda k: k['last_contact'], reverse=True)
            for cpe in pnpListSorted:
                # Only add CPE's that have there status as false, false, false
                # and (ip_address is None or CPE IP is in ip_address/mask
                if (ip_address is None or (IPAddress(cpe['ip_address']) in IPNetwork(ip_address))) and \
                        cpe['configured'] == 'false' and \
                        cpe['added'] == 'false' and \
                        cpe['synced'] == 'false':
                    cpeList.append(cpe['serial'])
                    cnt += 1
                    if quantity is not None and cnt >= quantity:
                        break                   # Break if the quantity of CPE's has been reached
            # If no records Match this IP then return empty List
            return cpeList
    def get_pnp_imap(self,cpe_model):
        """
        Return the pnp interface-map WAN interface for a given CPE model
        """
        if cpe_model[0:2] == "C8" or cpe_model == "Unix":
            cmd = "show running-config pnp interface-map %s wan | display xml" % cpe_model
        elif cpe_model[0:3] == "C19":
            cmd = "show running-config pnp interface-map (C19[0-9][0-9])\|(CISCO19[0-9][0-9]) wan | display xml"
        elif cpe_model[0:3] == "C29":
            cmd = "show running-config pnp interface-map (C29[0-9][0-9])\|(CISCO29[0-9][0-9]) wan | display xml"
        elif cpe_model[0:3] == "C39":
            cmd = "show running-config pnp interface-map (C39[0-9][0-9])\|(CISCO39[0-9][0-9]) wan | display xml"

        root = xmlET.fromstring(self.execute(cmd))

        pnp = root.find('pnp:pnp',ns)
        interface = pnp.find('pnp:interface-map',ns)
        cpe_wan = interface.find('pnp:wan',ns).text

        return cpe_wan
    def get_esc_device_name(self,virto):
        """
        Return the ESC device name for a given virto.
        """
        if self.vmsModel == "old":
            raise NotImplementedError("You should have implemented this!")
        elif self.vmsModel == "simple":

            cmd = ("show cloudvpn-oper %s escList | display xml" %virto)
            root = xmlET.fromstring(self.execute(cmd))

            for cloudvpn in root:
                cv=root.find("cvpndata:cloudvpn-oper",ns)
                virtoname = cv.find("cvpndata:name",ns)
                if virtoname.text ==virto:
                    escList = cv.find("cvpndata:escList",ns)
                    escName = escList.find("cvpndata:esc",ns)
                    return escName.text
            raise NotFound('Unable to find esc device name for virto "%s".' %
                           virto)
        else:
            raise Exception(
                'Do not understand vMS model "%s".' %
                self.vmsModel
            )

    def wait_for_service_deploy_ngena(self, virto, breakoutSubvpnCount=1, interSubvpnCount=1, dcList=['dc1'], virtoType=None, cpeList=[],
                                        vips=False, timeout=2700):
        """
        Function: Wait for Ngena Service Shain deployment, waiting for each vnf to reach ready state.
        params: 'virtoType' parameter should be set "basic", "chain", "medium", or "full".
                'dcList' maps to a list of all data-centers that the chain is part of, eg: dcList = ['dc1', 'dc2']
                 If no CPEs are expected then the list can be empty.
                'vips' parameter should be set to True if vIPS is deployed with the service chain.
                'breakoutSubvpnCount' maps to number of breakout subvpns part of the chain
                'cpeList' parameter should be a list of the device names for all of the CPEs in the virto.
                'timeout' for max-timeout to wait for chain to be ready.
                'interSubvpnCount' this value represents how many subvpns are present across multi region.
        """
        logger.debug('wait_for_service_deploy_ngena; vpn: %s, vpnType: %s, dcList: %s, subvpnCount: %s'
                                                          %(virto, virtoType, dcList, breakoutSubvpnCount))
        NUM_VNF_PER_MEDIUM_SC = 4 #This could be 4 if it is enable with redundancy
        NUM_VNF_PER_FULL_SC   = 6 #This could be 6 if it is enable with redundancy
        if virtoType is None:
            virtoType = 'medium'
        if virtoType == "basic":
            vnfTypes = ['pxtr', 'cpe']
            vnfCount = 1
        elif virtoType == "icsp":
            vnfTypes = ['icsp']
            vnfCount = 1
        elif virtoType == "medium":
            if len(dcList) > 1:
                vnfTypes = ['icsp', 'pxtr', 'firewall', 'rtr']
                vnfCount = 1 + (NUM_VNF_PER_MEDIUM_SC * breakoutSubvpnCount)+ (((NUM_VNF_PER_MEDIUM_SC * len(dcList))- NUM_VNF_PER_MEDIUM_SC) * interSubvpnCount) + len(dcList)
                # maps to 1 icsp + pair of ASA/PxTR(2 vnfs) * no. of subvpns + pair of vnfs( 2) * no. of dc list - pari of vnfs(2) * multi region subvpn count + no. of DCs (ie.e., 1 RTR per DC)
            else:
                vnfTypes = ['icsp', 'pxtr', 'firewall']
                vnfCount = 1 + (NUM_VNF_PER_MEDIUM_SC * len(dcList) * breakoutSubvpnCount)
                # maps to 1 icsp + (a pair of ASA/PxTR (2 vnfs) * no. of DCs * no. of subvpns)
        elif virtoType == "full":
            if len(dcList) > 1:
                vnfTypes = ['icsp', 'pxtr','firewall','wsa', 'rtr']
                vnfCount = 1 + (NUM_VNF_PER_FULL_SC * breakoutSubvpnCount)+(((NUM_VNF_PER_FULL_SC *len(dcList))- NUM_VNF_PER_FULL_SC) * interSubvpnCount) + len(dcList)
                # maps to 1 icsp + pair of ASA/PxTR/WSA (3 vnfs) * no. of subvpns + pair of vnfs(3) * no. of dc list - pair of vnfs(3) * multi region subvpn count + no. of DCs (ie.e., 1 RTR per DC)
            else:
                vnfTypes = ['icsp', 'pxtr','firewall','wsa']
                vnfCount = 1 + (NUM_VNF_PER_FULL_SC * len(dcList) * breakoutSubvpnCount)
                # maps to 1 icsp + (a pair of ASA/PxTR/WSA (3 vnfs) * no. of DCs * no. of subvpns)
        else:
            raise Exception('Do not understand virto type "%s".' % virtoType)
        if vips:
            vnfTypes.append("IPS_Manager")
            vnfTypes.append("IPS_Sensor")
        startTime = time.time()
        endTime = time.time() + timeout
        done = False

        while not done:
            if time.time() > endTime:
                raise Timeout(
                    'Timeout of %d secs exceeded while waiting for deployment '
                    'of service chain "%s".' %(timeout,virto)
                )
            vnfDone = {}
            cpeDone = {}
            try:
                device_info = self.get_device_status(virto)
                logger.debug('wait_for_service_deploy_ngena get_device_status: %s' % device_info)

                for deviceName, info in device_info.iteritems():
                    logger.debug('wait_for_service_deploy_ngena;deviceName:%s, info: %s, cpeList: %s:' %(deviceName, info, cpeList))
                    if(deviceName.split('/')[0].split('-')[1] in cpeList and info['status'] == 'ready'):
                            if info['dc'] in cpeDone:
                                cpeDone[info['dc']] += 1
                            else:
                                cpeDone[info['dc']] = 1

                    for vnfType in vnfTypes:
                        if info['type'] == vnfType and info['status'] == 'ready':
                            if info['dc'] in vnfDone:
                                vnfDone[info['dc']] += 1
                            else:
                                vnfDone[info['dc']] = 1

                logger.debug('Counting VNF status; vnfDone={}, vnfCount={}, cpeDone={}, len(cpeList)={}'.format(vnfDone, vnfCount, cpeDone, len(cpeList)))

                if cpeList and sum(vnfDone.values()) >= vnfCount and sum(cpeDone.values()) >= len(cpeList) \
                    and len(vnfDone) == len(dcList) and len(cpeDone) == len(dcList):
                    done = True
                elif not cpeList and sum(vnfDone.values()) >= vnfCount and len(vnfDone) == len(dcList):
                    done = True
                else:
                    done = False
                    duration = round((time.time() - startTime) / 60)
                    logger.info("Service chain %s not ready after %s min, sleeping 60 sec" % (virto, duration))
                    time.sleep(60)
            except NotFound as n:
                # This may be a false exception,waiting till the timeout ends
                logger.debug( 'sleep 30 sec')
                time.sleep(30)
                continue


    def wait_for_vpn_infra_chain_deploy(self, vpn, vpnType=None, sub=None, cpeList=[],
                                        vips=False, timeout=2700):
        """
        Inputs: virtoType infra or chain
        Wait for vpn infra deployment (only KS + MSMR)
        wait + return True when done, or False if timed out.
        """
        logger.debug('Control.wait_for_service_deploy_ngena; vpn:%s , vpnType:%s, sub:%s ' \
                                                     % (vpn, vpnType, str(sub)))
        # Todo: add case without internet-breakout
        # Todo: fix for case multiple subs
        if vpnType == "infra":
            vnfTypes = ['key-server', 'map-server']
            wait_num_vnf = 2
        elif vpnType == "chain":
            vnfTypes = ['pxtr', 'firewall']
            wait_num_vnf = 2
        elif vpnType == "chainfull":
            vnfTypes = ['key-server', 'map-server', 'pxtr', 'firewall', 'WSA', 'cpe']
            wait_num_vnf = 3
        else:
            raise Exception('Do not understand virto type "%s".' % vpnType)
        startTime = time.time()
        endTime = time.time() + timeout
        done = False
        time.sleep(30)
        while not done:
            if time.time() > endTime:
                raise Timeout(
                    'Timeout of %d secs exceeded while waiting for deployment '
                    'of service chain "%s".' % (timeout, vpn)
                )
            vnfDone = 0
            cpeDone = 0
            try:
                device_info = self.get_device_status(vpn)
                #print 'device_info =', device_info
                for deviceName, info in device_info.iteritems():
                    if deviceName in cpeList:
                        if info['ready']:
                            cpeDone += 1
                    for vnfType in vnfTypes:
                        if info['type'] == vnfType:
                            if info['status'] == 'ready':
                                vnfDone += 1
                logger.debug('   +++ xav1 Counting VNF status; Type: {} vnfDone = {} , len(vnfTypes) = {}'.format(vpnType, vnfDone,
                                                                                                           len(vnfTypes)))

                # if vnfDone >= len(vnfTypes) and cpeDone >= len(cpeList):
                if vnfDone >= wait_num_vnf:
                    done = True
                else:
                    done = False
                    duration = round((time.time() - startTime) / 60)
                    logger.info("Service chain %s not ready (%s < %s)  after %s min, sleeping 60 sec" % (
                    vpn, vnfDone, wait_num_vnf, duration))
                    time.sleep(60)
            except NotFound as n:
                # This may be a false exception,waiting till the timeout ends
                logger.debug('sleeping 30 sec')
                time.sleep(30)
                continue


    def get_available_cpesn(self,startswith=None):
        """
        @param string startswith  option parameter to filter  the cpesn
        Return the serial number of a CPE that is currently not in use.
        """
        for cpeSN in self.get_cpesn_list():
            if self.is_cpe_available(cpeSN):
                if startswith is None:
                    return cpeSN
                elif startswith in cpeSN:
                    return cpeSN
                else:
                    continue
        raise NotFound('Unable to find available CPE.')
    def get_all_available_cpesn(self,startswith=None):
        """
        @param string startswith  option parameter to filter  the cpesn
        Return a list of available CPE serial numbers where the CPE is
        available and not used in a service chain.
        """
        cpeSNList = []
        for cpeSN in self.get_cpesn_list():
            if self.is_cpe_available(cpeSN):
                cpeSNList.append(cpeSN)
        if startswith is not None:
            #fitler list using list comprehension
            return [each for each in cpeSNList  if each.startswith(startswith)]
        else:
            return cpeSNList
    def is_cpe_available(self,cpeSN):
        """
        Check a CPE serial number to see if it is available and unused
        in a service chain.
        """
        try:
            state = self.get_pnp_device_state(cpeSN)
        except NotFound:
            return False
        else:
            if state['configured']:
                return False
            else:
                return True

    def is_cpe_registered(self,cpeSN):
        """
        Check a CPE serial number to see if it is registered with
        the PnP server.
        """
        try:
            state = self.get_pnp_device_state(cpeSN)
        except NotFound:
            return False
        else:
            return True

    def get_cpe_connect_info(self,cpeSN):
        """
        Return connection information for a CPE device with the given
        CPE serial number.
        """
        state = self.get_pnp_device_state(cpeSN)
        if state['synced']:
            logger.debug('CPE is synched')
            ip = self.get_device_address_nso("cpe-" + cpeSN)
        else:
            logger.debug('CPE is not synched')
            ip = state['ip-address']
        hostInfo = {
            'serial': state['serial'],
            'ip': ip,
            'deviceType': "IOS"
        }
        if state['username'] is not None:
            hostInfo['username'] = state['username']
        if state['password'] is not None:
            hostInfo['password'] = state['password']
        if state['sec-password'] is not None:
            hostInfo['enablePassword'] = state['sec-password']
        return hostInfo

    def get_vnf_connect_info(self, vpnName, vnfName):
        """
        Return connection information for VNF.
        """
        # set mgmt-hub ip later in mgmt_hub_security_check.MgmtHubSecurityCheck.connect_to_vnf
        if 'mgmt-hub' in vnfName:
            hostInfo = {}
        else:
            hostInfo = {'ip': self.get_device_address(vpnName, vnfName)}

        if any(item in vnfName.lower() for item in ['pxtr', 'rtr', 'keyserver', 'mapserver', 'mgmt-hub', 'cpe']):
            hostInfo['deviceType'] = "CSR"
        elif vnfName.endswith('firewall'):
            hostInfo['deviceType'] = "ASA"
        elif 'WSA' in vnfName:
            hostInfo['deviceType'] = "WSA"
        elif 'icsp' in vnfName:
            hostInfo['deviceType'] = "ICSP"
        elif 'IPS_Manager' in vnfName:
            hostInfo['deviceType'] = "IPS_Manager"
        elif 'IPS_Sensor' in vnfName:
            hostInfo['deviceType'] = "IPS_Sensor"
        else:
            raise Exception('Do not understand VNF type for "%s".' % vnfName)
        logger.debug('get_vnf_connect_info, returning ;   hostInfo: %s' % hostInfo)
        return hostInfo

    def get_data_centers(self):
        """
        Read data-center information from CSO
        """
        cmd = "show running-config ngena data-center | display json"
        out = self.execute(cmd)
        dc_info = json.loads(out)
        if not dc_info:
            logger.exception('Failed to get data-center info from CSO')
            return False
        try:
            dc_count = len(dc_info['data']['ngena-infra:ngena']['data-center'])
        except KeyError as e:
            logger.exception('Data-center structure not correct. Got exception: %s', e)
            raise

        self.dcs = dc_info['data']['ngena-infra:ngena']['data-center']
        logger.debug('Data-center info: %s' % self.dcs)
        return self.dcs

    def get_ncs_alarms(self,count=1):
        """
        Returns %count number of ncs_alarms
        @param int count
        @return  list , each item in the list is a dictionary
                        with k,v pairs for  that alarm
        """
        output = self.execute("show notification stream ncs-alarms last %s"%count )
        #The delimeter is !\r\n!\r\n" by default
        alarms=output.split("!\r\n!\r\n")
        alarm_list=[]
        for each in alarms:
            if len(each)>1:
                item=self.process_ncs_alarm(each)
                if item is not None:
                    if len(item)>1:
                        alarm_list.append(item)
        return  alarm_list
    def process_ncs_alarm(self,alarm):
        """
        @param  alarm  is the output of the command
        in the following format
        @return  a dictionary with  the  notification parsed
        notification
        eventTime 2016-02-19T13:25:58.017608+00:00
        alarm-notification
          alarm-class new-alarm
          device ncs
          type service-activation-failure
          managed-object /cloudvpn[name='persistentFFeb19201608-00']
          specific-problem
          event-type other
          has-clear unknown
          kind-of-alarm unknown
          probable-cause 0
          event-time 2016-02-19T13:25:57.24679+00:00
          perceived-severity critical
          alarm-text Network Element Driver error timeout for device
        """
        #split by alarm-text to get the string after alarm-text
        # as this is possibly multiline
        alarm_text=re.split("alarm-text",alarm)[1]
        notification=re.split("alarm-text",alarm)[0]
        # make notification a key-value pair
        b=re.sub("notification \r\n","notification NONE\r\n",notification)
        # make alarm-notification a key-value pair
        c=re.sub("alarm-notification \r\n","alarm-notification NONE\r\n",b)
        # make alarm-notification a key-value pair
        d= re.sub("specific-problem \r\n","specific-problem NONE\n",c)
        # remove all extra spaces
        e=re.sub(" +"," ",d)
        # split the list into lines
        f= re.split("\n",e)
        #strip the list of all extra un-needed characters
        g=map(str.strip,f)
        #create a tuple of key value pairs  which can be easily converted to a dictionary
        h=[tuple(each.split(" ",1)) for each in g if len(each.split(" ",1))>1]
        #    % Invalid input detected at '^' marker.
        i=dict(h)
        #sanitizing alarm_text
        logger.debug(alarm_text)
        alarm_text=alarm_text.strip()
        alarm_text=re.sub(" +"," ",alarm_text)
        alarm_text=re.sub("\n"," ",alarm_text)
        alarm_text=re.sub("\r"," ",alarm_text)
        i['alarm-text']=alarm_text.strip()
        return i

    def get_cpe_params(self, site_name):
        """
        Parse access design xml file to get all the interfaces configured in
        cpe parameters and switch mode , vlan id.
        returns dictionary with interface name as key and mode, vlan id as list
        """
        try:
            cmd = "show running-config access-design %s | display xml" % site_name
            output = self.execute(cmd)
            root = xmlET.fromstring(output)
        except KeyError as e:
            raise NotFound('Unable to find SITE_FILE msg:%s '%e)
        try:
            #Define empty dictionary
            cpe_dict = {}
            for site in root:
                siteName = site.find('ad:name', ns).text
                for params in site.findall('ad:cpe-parameters', ns):
                    for physical_name in params.findall('ad:physical-interface',ns):
                        intf_name = physical_name.find('ad:name',ns)
                        switchmode = physical_name.find('ad:switch-mode',ns)
                        if switchmode is not None:
                            vlan=[]
                            if switchmode.text == "trunk":
                                for trunk_vlan in physical_name.findall('ad:trunk-allowed-vlan-id',ns):
                                    vlan.append(trunk_vlan.text)
                            else:
                                access_vlan = physical_name.find('ad:access-vlan-id',ns)
                                vlan.append(access_vlan.text)
                            cpe_dict[intf_name.text] = [switchmode.text , vlan]

            return cpe_dict
        except Exception as e:
            raise Exception("ERROR: Could not get Customer CPE Params %s" %e)

    def get_cpe_lan(self, site_name):
        """
        Parse access design xml file to get the cpe lan parameters
        returns dictionary with vpn name as key and value is list of vlan-id, physical interfaces
        and ip addresses
        """
        try:
            cmd = "show running-config access-design %s | display xml" % site_name
            output = self.execute(cmd)
            root = xmlET.fromstring(output)
        except KeyError as e:
            raise NotFound('Unable to find SITE_FILE msg:%s '%e)
        try:
            #Define empty dictionary
            cust_lan={}
            for site in root:
                siteName = site.find('ad:name', ns).text
                for customer_lan in site.findall('ad:customer-lan', ns):
                    for vpn in customer_lan.findall('ad:vpn',ns):
                        vpn_name = vpn.find('ad:name',ns)
                        for l3intf in vpn.findall('ad:l3-interface',ns):
                            if l3intf is not None:
                                l3intf_name = l3intf.find('ad:name',ns)
                                phy_int = []
                                ip_addr = []
                                l2_domain = l3intf.find('ad:l2-domain',ns)
                                vlan = l2_domain.find('ad:vlan-id',ns)
                                for phy_int1 in l2_domain.findall('ad:physical-interface',ns):
                                    phy_name = phy_int1.find('ad:name',ns)
                                    phy_int.append(phy_name.text)
                                cpe = l3intf.find('ad:cpe',ns)
                                for ip in cpe.findall('ad:ip',ns):
                                    ip_name = ip.find('ad:ip-address-and-subnet',ns)
                                    ip_addr.append(ip_name.text)
                                cust_lan[vpn_name.text] = [vlan.text, phy_int, ip_addr]
            return cust_lan
        except Exception as e:
            raise Exception("ERROR: Could not get Customer LAN CPE parameters %s" %e)


    def export_config(self, vpn, vnfName):
        """
        Export VNF IOS config
        :param vpn:
        :param vnfName:
        :return:
        """
        # removed for now, re-add later


    def get_mgmthub_ikev2_keys(self, vpn):
        """
        Returns mgmt crypto ikev2 keyrings counter + structure
        :return: tupple (keycount, keys_struct)
        """
        logger.info('In def get_mgmthub_ikev2_keys')
        command = 'show devices brief'
        output = self.execute(command)
        m = re.search('\S+mgmt-hub\S+', output)
        if m:
            vnf = m.group()
            logger.info('Found mgmt-hub device: {}'.format(vnf))
            command = 'show running-config devices device {} config ios:crypto ikev2 | nomore'.format(vnf)
            logger.info('Command = {}'.format(command))
            output = self.execute(command)
            m = re.findall('peer (\S+)', output)
            if m:
                logger.info('Found {} keys on mgmt-hub: {}'.format(len(m), m))
                return len(m), m
            else:
                logger.info('No ikev2 keys found on mgmt-hub')
                return False, 0
        else:
            logger.info('Failed to find mgmt-hub device on NSO')
            return False, 0


    def __del__(self):
        """
        Exit the NCS CLI.
        """
        self.bash.execute("exit")

#Ncsconf class is used for connect with the cli port for configure NCS
class Ncsconf(object):
    def __init__(self,bash,user="admin",vmsModel="old"):
        """
        Create a session to the NCS command line interface.  The 'bash'
        argument is a Linux.Bash object which has access to the NCS CLI.
        """
        logger.info("reached init")
        self.bash = bash
        self.vmsModel = vmsModel
        self.session = bash.session
        self.session.sendline("ncs_cli -u %s" % user)
        self.session.expect('>')
        self.session.sendline("configure")
        self.session.expect('%')
        self.__init_cli()
    def __init_cli(self):
        """
        Optimize the CLI for automated input.
        """
        logger.info("REACHED INIT_CLI in ncsconf")
        self.prompt = "@nso"
    def config(self,command,timeout=-1):
        """
        Execute a config command on the NCSconfig prompt. This method has logic to
        detect a reset of the NCS CLI due to internal errors.  Upon
        this condition the CLI will be reinitialized and a CLI_Reset
        Exception will be raised.
        """
        logger.debug('NCS.py cmd = %s' % command)
        self.session.sendline(command)
        # Wait until command is echo'ed back on TTY. If for whatever
        # reason the command is not echo'ed back, then eventually the
        # expect statement for "\r\n" will run through the buffer
        # and timeout.
        done = False
        while not done:
            # Wait until the end of a line.
            self.session.expect_exact("\r\n")
            # Remove any backspaces from the buffer.
            before = re.sub('.\b',"",self.session.before)
            # Check to see if the command has been echo'ed back.
            if before.find(command) != -1:
                done = True
        index = self.session.expect(
            [
                self.prompt,
                "Internal error: Restarting CLI..."
            ],
            timeout
        )
        if index == 0:
            if re.search('-+\^\r\nsyntax error: unknown argument\r\n',
                         self.session.before):
                raise SyntaxError(
                    'Syntax error: unknown argument when executing command "%s"' % command
                )
            elif re.search('-+\^\r\nsyntax error: element does not exist\r\n',
                         self.session.before):
                raise SyntaxError(
                    'Syntax error: element does not exist when executing command "%s"' % command
                )
            elif re.search('-+\^\r\nsyntax error: \r\n',
                         self.session.before):
                raise SyntaxError(
                    'Syntax error: when executing command "%s"' % command
                )
            else:
                return self.session.before
        elif index == 1:
            self.__init_cli()
            raise CLI_Reset(
                "NCS CLI was reset due to internal error with NCS."
            )


class Netconf(Netconf.Control):
    def __init__(self,host,tbFile,port=830,debug=False,vmsModel="old"):
        """
        Connect to the NCS Netconf interface.
        """
        self.vmsModel = vmsModel
        super(Netconf,self).__init__(host,tbFile,port,debug)


    def create_service_chain(self, conn, dcs, template_xml, vpn,
                             cpeSN=None,
                             timeout=120,
                             sub=None,
                             ad=None,
                             cpe_sn=None,
                             cpe_cidr=None,
                             prefix=None
                             ):
        params = {
            'msgID': self.msgID,
            'vpn': vpn,
            'sub': sub,
            'ad': ad,
            'cpe_sn': cpe_sn,
            'dc': dcs[0]['name'],
            'cpe_cidr': cpe_cidr,
            'prefix':prefix
            }

        # if cpeSN is not None :
        #     if "_with_cpe" not in chainType:
        #         chainType=chainType+"_with_cpe"
        #     params['cpesn']=cpeSN
        #     params['cpe']='cpe-'+cpeSN

        result, reply = self.send_netconf_rpc(template_xml, params)
        if result:
            logger.info('xml response: got <OK>')
            service_chain = ServiceChain.NGENAServiceChain(
                conn,
                dcs,
                self.tbFile,
                vpn,
                debug=True
            )
            return service_chain
        else:
            logger.error('Create service chain ; RPC {} failed. Reason: {}'.format(template_xml, reply))

    def delete_service_chain(self,vpn, sub=None, ad=None):

       template_xml = 'ngena_delete_ad.xml'
       template_xml = 'ngena_delete_ad_subvpn_vpn.xml'
       params = {
                'msgID': self.msgID,
                'vpn': vpn,
                'sub': sub,
                'ad': ad
                }
       try:
            # subPath=subDir+"ngena_delete_subvpn_vpn.xml"
            subPath=subDir+template_xml
            filePath = os.path.join(libDir,subPath)
            with open(filePath,"r") as fh:
                for line in fh:
                    #print '--- xav3 ; xml line =', str(line % params).strip('\n')
                    self.session.send(line % params)
            self.session.sendline("]]>]]>")
            logger.debug('service chain deletion sent. %s %s %s' % (self.msgID, subPath, id))
            # self.session.expect_exact("service queued for deleted",timeout=180)
            self.session.expect_exact("ok",timeout=180)
            self.msgID += 1
            existval = False
            try :
                # wait for some time till ncs clears the DB
                time.sleep(30)
                existval=self.exist_service_chain(vpn)
                if existval == True:
                    raise Exception("ERROR: Could not Delete Service chain     %s \n Command in NCS is success"%(vpn))
            except Exception as  e:
                #"This exception is expected when the chain is deleted "
                return True
       except Exception as e :
            raise Exception("ERROR: Could not Delete Service chain %s \n %s "%(vpn,e.message))

    def create_basic(self,ncs_cli,vpn,provider,tenant):
        return self.create_service_chain('vpn',ncs_cli,
                                        vpn,provider,
                                        tenant,timeout=120
                                        )

    def create_vpn(self,ncs_cli,vpn,provider,tenant):
        return self.create_service_chain('vpn',ncs_cli,
                                        vpn,provider,
                                        tenant,timeout=120
                                        )

    def create_vpn_1subvpn(self,ncs_cli,vpn,sub,provider,tenant):
        return self.create_service_chain('vpn_1sub',ncs_cli,
                                        vpn,provider,
                                        tenant,timeout=120,sub=sub
                                        )

    def create_vpn_1subvpn_1ad(self,ncs_cli,vpn,sub,ad,cpe_sn,cpe_cidr,provider,tenant):
        return self.create_service_chain(
                                        'vpn_1sub_1ad',
                                        ncs_cli,
                                        vpn,provider,
                                        tenant,timeout=600,
                                        sub=sub,ad=ad,cpe_sn=cpe_sn,cpe_cidr=cpe_cidr
                                        )
    def create_access_design_xml(self, access_design, vpn, site_name, cpe_sn, dc):
        """
        Create COnfig XML file for Access design of Physical CPE.
                XML file will be generated in the name of <site_name>.xml
        Input: Access Design Parameter, Vpn name, site name and Cpe_serial no.
        Output: If succesfully ad_xml template is greated return True or False
        """
        try:
            cpe_name  = access_design["cpe"][0]["name"]

            chainType = "add_1ad_cpe_nolan"
            params = {
                'ad': site_name,
                'vpn': vpn,
                'cpe_name': ("cpe"+site_name),
                'cpe_sn': cpe_sn,
                'dc':dc
                }
        except :
            raise Exception("ERROR: Could not Parse Json input for VPN: %s\n "%(vpn))

        logger.debug('selected Params, chain type: ', params)
        try:
            template_Path=subDir+chainType+'.xml'
            filePath_template = os.path.join(libDir,template_Path)

            subPath=subDirConfig+site_name+'.xml'
            filePath = os.path.join(libDir,subPath)

            line_num = 0
            with open(filePath,"w") as f1:
                with open(filePath_template,"r") as fh:
                    for line in fh:
                        line_num += 1
                        f1.write(line % params)
            return True
        except Exception as e:
            raise Exception("ERROR: Could not Create temp xml file chain %s Err:%s\n "%(vpn,e))


    def cpe_interface_update(self, cpe_param, site_name):
        """
        Fun: Updating CPE interface configurations.
             Under cpe-parameter key word.
             This function update Interface Mode and Vlan
        Input: Cpe_params : List of interfaces per site
               Site_name
        """
        try:
            logger.info ("Inside CPE_PARAM_UPDATE")
            intf_name = cpe_param["name"]
            if ('switch-mode' in cpe_param):
                switch_mode = cpe_param["switch-mode"]
                if switch_mode == 'trunk':
                    vlan_ids = cpe_param["truck-allowed-vlan-id"]
                if switch_mode == 'access':
                    vlan_ids = cpe_param["access-vlan-id"]
                virtual_cpe = "False"
            else:
                switch_mode = 0
                vlan_ids = 0
                virtual_cpe = "True"
        except KeyError:
            raise NotFound('Unable to find keywords ')

        try:
            subPath=subDirConfig+site_name+'.xml'
            filePath = os.path.join(libDir,subPath)
            root = xmlET.parse(filePath)

            for node in root.iter():
                info = node.tag.split("}",1)
                if info[1] == 'cpe-parameters' :
                    phy_int = xmlET.SubElement(node, info[0]+'}'+"physical-interface")
                    title = xmlET.SubElement(phy_int, info[0]+'}'+"name")
                    title.text = intf_name
                    if virtual_cpe == "False":
                        mode = xmlET.SubElement(phy_int, info[0]+'}'+"switch-mode")
                        mode.text = switch_mode
                        if switch_mode == "trunk":
                            for vlan_id in vlan_ids:
                                vlan = xmlET.SubElement(phy_int, info[0]+'}'+"trunk-allowed-vlan-id")
                                vlan.text = str(vlan_id)
                        elif switch_mode == "access":
                            for vlan_id in vlan_ids:
                                vlan = xmlET.SubElement(phy_int, info[0]+'}'+"access-vlan-id")
                                vlan.text = str(vlan_id)
            root.write(filePath)
        except Exception as e:
            raise Exception("ERROR: Could not Create temp xml file msg:%s" %e)

    def customer_lan_update(self, sub_vpn, site_name):
        """
        Description: Update the Customer Lan Configuraion Per Site in config XML
        Input: Sub_vpn, site_name
        """
        try:
            subPath=subDirConfig+site_name+'.xml'
            filePath = os.path.join(libDir,subPath)
            root = xmlET.parse(filePath)

            for node in root.iter():
                info = node.tag.split("}",1)
                if info[1] == 'customer-lan' :
                    vpn = xmlET.SubElement(node, info[0]+'}'+"vpn")
                    title = xmlET.SubElement(vpn, info[0]+'}'+"name")
                    title.text = sub_vpn["name"]
            root.write(filePath)
        except Exception as e:
            raise Exception("ERROR: Could Not update Customer_lan vpn:%s ERR:%s"%(sub_vpn["name"],e))

    def provision_l3_interface(self, l3_interface, sub_vpn, site_name):
        """
        Description: Adding L3_interfaces per site with config XML file.
        Input : L3 interface, sub_vpn name and Site_name
        """
        try:
            subPath=subDirConfig+site_name+'.xml'
            filePath = os.path.join(libDir,subPath)
            root = xmlET.parse(filePath)

            l3_intf_name = l3_interface["name"]
        except KeyError:
            raise NotFound('Unable to find l3_interface_name keywords ')
        try:
            for node in root.iter():
                info = node.tag.split("}",1)
                if info[1] == 'vpn' :
                    for vpn_node in node.getiterator('{http://ngena.com/yang/cfs/ngena-access-design}name'):
                        if vpn_node.text == sub_vpn:
                            l3_intf = xmlET.SubElement(node, info[0]+'}'+"l3-interface")
                            l3_intf_title = xmlET.SubElement(l3_intf, info[0]+'}'+"name")
                            l3_intf_title.text = l3_intf_name
                            break
                root.write(filePath)
        except Exception as e:
            raise Exception("ERROR: Could Not update l3interface keyword for sub_vpn:%s, ERR:%s"%(sub_vpn,e))

    def create_cpe_lan_l2domain_cfg(self, l3_interface, site_name):
        """
        Description: Update the L2 domain config per l3 interface
        Input: L3_interface with the l2 domain config and Site_name
        """
        try:
            subPath=subDirConfig+site_name+'.xml'
            filePath = os.path.join(libDir,subPath)
            root = xmlET.parse(filePath)

            l3_intf_name = l3_interface["name"]
            l2_domain_node = l3_interface["l2-domain"]
            vlan_keyword = False

            if('vlan-id' in l2_domain_node):
                l2_vlan_id = l2_domain_node["vlan-id"]
                vlan_keyword = True
            phy_interfaces = l2_domain_node["physical-interface"]
        except KeyError:
            raise NotFound('Unable to find l2_domain keywords ')

        try:
            for node in root.iter():
                info = node.tag.split("}",1)
                if info[1] == 'l3-interface' :
                    # Find l3 Interface name node
                    for l3_node in node.getiterator('{http://ngena.com/yang/cfs/ngena-access-design}name'):
                        if l3_node.text == l3_intf_name:
                            l2_domain = xmlET.SubElement(node, info[0]+'}'+"l2-domain")
                            if vlan_keyword :
                                vlan_node = xmlET.SubElement(l2_domain, info[0]+'}'+"vlan-id")
                                vlan_node.text = str(l2_vlan_id)
                            for phy_intf in phy_interfaces:
                                intf = xmlET.SubElement(l2_domain, info[0]+'}'+"physical-interface")
                                phy_name = xmlET.SubElement(intf, info[0]+'}'+"name")
                                phy_name.text = phy_intf["name"]
                            break
                root.write(filePath)
        except Exception as e:
            raise Exception("ERROR: Could Not update Customer_lan l2-domain: %s" %e)

    def create_cpe_lan_cpe_cfg(self, l3_interface, site_name):
        """
        Description: Update CPE configuration Per L3_interface.
           - Creating CPE configuration under Customer-lan key word
             Ex: CPE ip address
        """
        try:
            subPath=subDirConfig+site_name+'.xml'
            filePath = os.path.join(libDir,subPath)
            root = xmlET.parse(filePath)

            l3_intf_name = l3_interface["name"]
            cpe_list = l3_interface["cpe"]
        except KeyError:
            raise NotFound('Unable to find customer_lan_cpe keywords ')

        try:
            for node in root.iter():
                info = node.tag.split("}",1)
                if info[1] == 'l3-interface' :
                    # Find L3 Interface
                    for l3_node in node.getiterator('{http://ngena.com/yang/cfs/ngena-access-design}name'):
                        if l3_node.text == l3_intf_name:
                            cpe_node = xmlET.SubElement(node, info[0]+'}'+"cpe")
                            # Adding CPE list in L3 interface
                            for cpe in cpe_list:
                                cpe_name = xmlET.SubElement(cpe_node, info[0]+'}'+"name")
                                cpe_name.text = cpe["name"]
                                ip_node = xmlET.SubElement(cpe_node, info[0]+'}'+"ip")
                                for ip in cpe["ip"]:
                                    intf = xmlET.SubElement(ip_node, info[0]+'}'+"ip-address-and-subnet")
                                    intf.text = ip["ip-address-and-subnet"]
                            break
                root.write(filePath)
        except Exception as e:
            raise Exception("ERROR: Could Not update Customer_lan cpe %s" %e)


    def create_int_list(self, site_name):
        """
        Use get_cpe_lan and get_cpe_params api's
        to get the values to validate interfaces on physical CPE
        """
        try:
            cpe_param = get_cpe_params(site_name)
            cpe_lan_param = get_cpe_lan(site_name)
        except KeyError as e:
            raise NotFound('Unable to find SITE_FILE msg:%s '%e)
        try:
            int_cfg = {}
            for key in cpe_lan_param:
                for phy_int in cpe_lan_param[key][1]:
                    if phy_int not in int_cfg:
                        int_cfg[phy_int] = [[key], cpe_param[phy_int][0]]
                    else:
                        int_cfg[phy_int][0].append(key)
            return int_cfg
        except Exception as e:
            raise Exception("ERROR: Could not create interface list %s" %e)

    def cpe_get_SN(self, site_name):
        """
        Parse access design xml file to get the cpe Serial Number
        returns CPE SN as string
        """
        try:

            #cpe_param = {}
            subPath = subDirConfig+site_name+'.xml'
            filePath = os.path.join(libDir, subPath)
            root = xmlET.parse(filePath)
        except KeyError as e:
            raise NotFound('Unable to find SITE_FILE msg:%s '%e)
        try:

            sn=''
            for node in root.iter():
                info = node.tag.split("}",1)
                if info[1] == 'serial-number':
                    for node1 in node.iter():
                        sn = node1.getiterator('{http://ngena.com/yang/cfs/ngena-access-design}serial-number')[0].text
                        break
                    break
            return sn

        except Exception as e:
            raise Exception("ERROR: Could not get CPE serial number %s"%e)

    def get_access_design_info (self, site_name):
        """
        Getting Access design infor from config Json file
        Access Design info is getting Per Site
        """
        try:
            subPath=subDirConfig+site_name+'.json'
            filePath = os.path.join(libDir,subPath)
            with open(filePath, "r") as fh:
                lookup = json.load(fh)
            lookup["service-chain"]["access-design"][0]
            return lookup["service-chain"]["access-design"][0]
        except Exception as e:
            raise Exception("Error: get_access_design_info get failed, Err_Msg:%s"%e)

    def create_topology_json(self, template, user_access_design, user_config, site_name):
        """
        Description:
        Create topology json file for Physical CPE configured site.
        Input: Template File, User configuration, User_access_design info and Sitename
        Output: Will be generate Config Json file for Each Site.
        """
        try:
            temp_cpe = template["service-chain"]["access-design"][0]["cpe-parameters"]
            phys_iface = []
            i = 0
            subvpn_count = user_config["service_chain"]["subvpn_count"]
            no_of_interface = len(user_access_design["port_list"])
        except Exception as e:
            logger.exception("User Config Read is failing, Err_Ms:%s"%e)
            return False

        try:
            #Adding Physical interface
            ports = user_access_design["port_list"]
            interface_prefix = user_access_design["interface_prefix"]
            for port in ports:
                temp_mode = {}
                temp_mode["name"] = interface_prefix + str(port["port_no"])
                if (port['mode'] == 'access'):
                    temp_mode["switch-mode"] = "access"
                    temp_mode["access-vlan-id"] = port['vlanlist']
                else:
                    temp_mode["switch-mode"] = "trunk"
                    temp_mode["truck-allowed-vlan-id"] = port['vlanlist']
                phys_iface.append(temp_mode)

            temp_cpe["physical-interface"] = phys_iface

            #Creating Multiple(subvpn * number of l3 intf per subvpn) L3-interface Template
            temp_customer_lan = copy.deepcopy(template["service-chain"]["access-design"][0]["customer-lan"])
            vpn_template = copy.deepcopy(temp_customer_lan["vpn"][0])
            temp_l3_interface = copy.deepcopy(vpn_template["l3-interface"][0])

            template["service-chain"]["access-design"][0]["customer-lan"]["vpn"] = [copy.deepcopy(vpn_template) for i in range(subvpn_count)]
            svpn_prefix = user_config["service_chain"]["subvpn_prefix"]

            for i in xrange(subvpn_count):
                vpn = template["service-chain"]["access-design"][0]["customer-lan"]["vpn"][i]
                vpn["name"] = user_config["service_chain"]["subvpn_prefix"] + str(i)
                # Creating L3 Interface per Sub vpn
                svpn_name = "SVPN-"+str(i)
                if svpn_name not in user_access_design:
                    logger.error("ERROR: In Config File,No of Subvpn Listed is less than Subvpn_count")
                    return False
                l3_intfs = user_access_design[svpn_name]
                l3_interface_list = [copy.deepcopy(temp_l3_interface) for k in range(len(l3_intfs))]
                vpn["l3-interface"] = copy.deepcopy(l3_interface_list)
                count = 0
                for l3_iface in vpn["l3-interface"]:
                    # vlan id is used as L3 interface name
                    l3_iface['name'] = l3_intfs[count]['vlanid']
                    l3_iface["l2-domain"]["vlan-id"] = l3_intfs[count]['vlanid']
                    l3_iface["l2-domain"]["physical-interface"] = [
                          {"name":interface_prefix + str(l2_intf_no)} \
                          for l2_intf_no in [port['port_no'] \
                          for port in ports if l3_intfs[count]['vlanid'] in port['vlanlist']] ]

                    l3_iface["cpe"] = [
                        {
                            "name": "cpe"+site_name,
                            "ip": [
                                {"ip-address-and-subnet": l3_intfs[count]['ip']}
                                ]
                        }
                    ]
                    count += 1

            subPath=subDirConfig+site_name+'.json'
            filePath = os.path.join(libDir,subPath)
            with open(filePath, 'w') as outfile:
                        json.dump(template, outfile)
            return True

        except Exception as e:
            raise Exception("ERROR: Could not Create Config Json: Err Msg: %s"%e)

    def create_subvpn(self, ncs_cli, vpn, sub, timeout=30):
        template_xml = 'sub.xml'
        params = {
            'msgID': self.msgID,
            'vpn': vpn,
            'sub': sub,
        }
        try:
            subPath=subDir+template_xml
            filePath = os.path.join(libDir,subPath)
            logger.debug('selected xml template: %s' % filePath)
            line_num = 0
            with open(filePath,"r") as fh:
                for line in fh:
                    line_num += 1
                    #print '   +++ xav2 xml{:>3} = {}'.format(line_num, str(line % params).strip('\n'))
                    self.session.send(line % params)
            self.session.sendline("]]>]]>")
            self.msgID += 1
            #print '+++ xav1 ; service chain config sent. ', self.msgID, subPath, id
            index = self.session.expect_exact(
                [
                    '<ok/>',
                    "No active ESCs found for given provider",
                ],
                timeout
            )
            time.sleep(10)
            if index == 0:
                #print '+++ xav8 creating object in SerciceChain for this new sub-vpn...'

                #print '+++ xav8 but the ServiceChain already exists, per vpn ? no need to recreat in this case ?'
                # service_chain = ServiceChain.NGENAServiceChain(
                #     ncs_cli,
                #     self.tbFile,
                #     vpn,
                #     debug=True
                # )
                # print '+++ xav8; returning Result  sc = ', service_chain
                # return service_chain
                return 1
            elif index == 1:
                raise Exception("No active ESCs found")
        except Exception as e :
            raise Exception("ERROR: Could not Create Service chain %s\n %s"%(vpn,e.message))

    def create_basic_with_cpe(self,ncs_cli,virtoName,cpeName,cpeSN,
                              provider,tenant,timeout=120):
        return self.create_service_chain('basic_with_cpe',ncs_cli,
                                        virtoName,provider,tenant,
                                        cpeSN,timeout=120
                                        )
    def create_medium(self,ncs_cli,virtoName,provider,tenant,timeout=120):
        return self.create_service_chain('medium',ncs_cli,
                                        virtoName,provider,
                                        tenant,timeout=120
                                        )

    def create_medium_vips(self,ncs_cli,virtoName,provider,tenant,timeout=120):
        return self.create_service_chain('medium_vips',ncs_cli,
                                         virtoName,provider,
                                         tenant,timeout=120
                                         )

    def create_medium_with_cpe(self,ncs_cli,virtoName,cpeName,cpeSN,
                              provider,tenant,timeout=120):
        return self.create_service_chain('medium_with_cpe',ncs_cli,
                                        virtoName,provider,tenant,
                                        cpeSN,timeout=120
                                        )

    def create_medium_vips_cpe(self,ncs_cli,virtoName,cpeName,cpeSN,
                              provider,tenant,timeout=120):
        return self.create_service_chain('medium_vips_cpe',ncs_cli,virtoName,
                                        cpeName,cpeSN,provider,
                                        tenant,timeout=120
                                        )
    def create_full(self,ncs_cli,virtoName,
                    provider,tenant,timeout=120):
        return self.create_service_chain('full',ncs_cli,virtoName,
                                        provider,tenant,timeout=120
                                        )

    def create_full_vips(self,ncs_cli,virtoName,
                                  provider,tenant,timeout=120):
        return self.create_service_chain('full_vips',ncs_cli,virtoName,
                                        provider,tenant,timeout=120
                                        )
    def create_full_with_cpe(self,ncs_cli,virtoName,cpeName,cpeSN,
                              provider,tenant,timeout=120):
        return self.create_service_chain('full_with_cpe',ncs_cli,virtoName,
                                        provider,tenant,cpeSN,timeout=120
                                        )

    def create_full_vips_cpe(self,ncs_cli,virtoName,cpeName,cpeSN,
                              provider,tenant,timeout=120):
        return self.create_service_chain('full_vips_cpe',ncs_cli,virtoName,
                                         cpeName,cpeSN,provider,
                                         tenant,timeout=120
                                         )
    def add_physical_cpe_ad(self, cpe_site,timeout=30):
        """
        Adding Physical CPE in the Access design.
        """
        params = {}
        template_xml = cpe_site['name']+'.xml'
        result, reply = self.send_netconf_rpc(template_xml, params,subDirConfig)
        return result, reply

    def add_cpe(self,vpn,sub,ad,cpe_sn,cpe_cidr,dc,lan_encap='native',timeout=30):
        """
        Add cpe to service chain.
        """
        if lan_encap == 'native':
            # Crude attempt to distinguish physical vs virtual CPEs.
            # Cisco has allocated sn starting with 9 for vCPEs
            if cpe_sn.startswith('9'):
                if len(cpe_cidr) > 1:
                    template_xml = "add_1ad_dual.xml"
                else:
                    template_xml = "add_1ad.xml"
            else:
                template_xml = "add_1ad_phy.xml"
        elif lan_encap == 'trunk':
            if cpe_sn.startswith('9'):
                logger.error("ERROR: vcpe trunk mode not implemented yet, aborting here...")
                exit()
                template_xml = "add_1ad.xml"
            else:
                template_xml = "add_1ad_phy_trunk.xml"

        params = {
            'msgID': self.msgID,
            'vpn': vpn,
            'sub': sub,
            'ad': ad,
            'cpe_sn': cpe_sn,
            'dc': dc
        }
        if len(cpe_cidr) > 1:
            params['cpe_cidr_v4'] = cpe_cidr['v4']
            params['cpe_cidr_v6'] = cpe_cidr['v6']
        else:
            params['cpe_cidr'] = cpe_cidr.values()[0]
        result, reply = self.send_netconf_rpc(template_xml, params)
        return result, reply

    def del_cpe(self,virtoName,cpeSN,timeout=30):
        """
         Delete cpe to service chain.
        """
        params = {
            'msgID': self.msgID,
            'name': virtoName,
            'cpesn': cpeSN
        }
        if self.vmsModel == "old":
            raise NotImplementedError("You should have implemented this!")
        elif self.vmsModel == "simple":
            filePath = os.path.join(
                libDir,
                "ncs-xml-templates/simple/del_cpe.xml"
            )
        else:
            raise Exception('Do not understand vMS model "%s".' %
                            self.vmsModel)
        try:

            with open(filePath,"r") as fh:
                for line in fh:
                    self.session.send(line % params)
                self.session.sendline("]]>]]>")
            self.session.expect_exact("<ok/>",timeout=timeout)
            self.msgID += 1
            return 1
        except:
            logger.exception("Could not delete CPE")
            raise


    def send_netconf_rpc(self, template_xml,  params, file_path=None, timeout=240):
        """
        Common method for sending netconf RPCs from script to CSO
        :param template_xml: string, RPC XML template filename,
                   assuming file is present in libDir/subDir
                   example:   ad.xml
        :param params: dict of parameters for the template
        :param timeout: optional integer, response timeout
        :return: boolean + string (<rpc-reply> section of the response from CSO)
        """
        line_num = 0
        logger.debug('xml --- Netconf RPC Query to CSO, msgId={} template_xml={}---'\
                                                  .format(self.msgID, template_xml))
        if file_path:
            fileName = os.path.join(libDir, subDirConfig, template_xml)
        else:
            fileName = os.path.join(libDir, subDir, template_xml)
        with open(fileName, "r") as fh:
            for line in fh:
                line_num += 1
                logger.debug('xml{:>3} -> {}'.format(line_num, str(line % params).strip('\n')))
                self.session.send(line % params)
                time.sleep(0.001)
        self.session.sendline("]]>]]>")
        ts_sent = int(round(time.time() * 1000))
        self.msgID += 1
        resp = self.session.expect_exact([
                            "</rpc-reply>",
                            pexpect.TIMEOUT
                            ], timeout=timeout)
        # TODO; xav add response time in return
        ts_reply = int(round(time.time() * 1000))
        ts_delay = 1.0 * (ts_reply - ts_sent) / 1000
        if resp == 0:
            logger.debug('Got response after {} seconds. resp code = {}'.format(ts_delay, resp))
            cso_before = self.session.before + '</rpc-reply>'
            # print "DEBUG; NCS.py send_netconf_rpc; xml response;\n{}\n".format(cso_before)
            m = re.search('(<rpc-reply.*</rpc-reply>)', cso_before, re.S)
            if m:
                cso_reply = m.group(1)
                # logger.debug('xml --- Netconf RPC Response from CSO ---')
                out_xml = xml.dom.minidom.parseString(cso_reply)
                line_num = 0
                for line in out_xml.toprettyxml().split('\n'):
                    if not line.isspace() and line != '':
                        line_num += 1
                        # print 'xml{:>3} <- {}'.format(line_num, str(line).strip('\n'))
                        logger.debug('xml{:>3} <- {}'.format(line_num, str(line).strip('\n')))
                        # logger.info('CSO response:\n{}\n'.format(out_xml.toprettyxml()))
                # todo; Could parse CSO response for error here, but not sure if necessary.
                # todo; return false, 'timeout' in case of timeout
                # If we don't get <ok/>, we return flag False + full <rpc-reply> section for parent method to
                # decide on how to proceed.
                # We don't want to raise an exception here in case of response not-OK (we don't want to fail
                # negative testcases.
                m = re.search('<ok/>', cso_reply)
                if m:
                    logger.debug('Got OK in response from CSO')
                    return True, cso_reply
                else:
                    logger.error('Got an error in response from CSO')
                    return False, cso_reply
        elif resp == 1:
            logger.error('ERORR; Got no response from CSO after {} seconds (TIMEOUT). resp code = {}'.format(ts_delay, resp))
            return False, 'timeout'
        else:
            logger.error('Failed to get response from CSO')
            return False, 'noreply'
