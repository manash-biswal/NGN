
#!/usr/bin/env python

"""
Single VPN manipulations
NGENA vpn + servicechain + access-design manipulations

Container for standard and non-standard operations
(will evolve to include corner case + negative cases)
"""

import logging
import sys
import os
import re
import datetime
import time
import json
from pytz import timezone

from vmsauto.lib import Automation
from vmsauto.lib import TestSuite as ts
from vmsauto.lib.ngena import NCS
from vmsauto.lib.ngena import Utills
from vmsauto.lib.ngena import ServiceChain
from vmsauto.lib import IDM
from vmsauto.lib import Testbed
from vmsauto.lib import Linux

utils = Utills.common_utills()


class FailureReport(Exception):
    pass


logger = logging.getLogger(__name__)

"""
ServiceChainFunctionalAPI derived class definition,
derived from class Testcase in lib/Automation.py to be used for this unit test
"""


class TataSF004Four(Automation.Testcase):
    def __init__(self, tbFile, configFile, manifest, debug=True, displayName=None):
        super(TataSF001Four, self).__init__(displayName)
        self.tbFile = tbFile
        self.configFile = configFile
        self.manifest = manifest
        self.debug = debug
        self.provider = tbFile.get_vms_provider()
        self.subtests_list = [
            'pre-test',
            'FUNC001_vpn_creation', 'FUNC002_subvpn_creation',
            'KS_version', 'KS_license', 'KS_config',
            'MS_version', 'MS_license', 'MS_config',
            'FUNC003_access_design_creation', 'CPE_onboarding',
            'FUNC011 Verify mgmt-hub ikev2 keys',
            'verify_service_chain',
            'PxTR_version', 'PxTR_config',
            'ASAv_version', 'ASAv_config',
            'CPE1_config', 'Ping_CPE_CPE', 'Ping_CPE_internet', 'CPE_LISP_counters',
            'access_design_deletion', 'CPE_offboarding',
            'subvpn_deletion', 'FUNC006 vpn deletion', 'tata vpn verify', 'tata subvpn verify','Ping_VM_Behind_CPE_internet','Ping_VM_Behind_CPE_VM_Behind_CPE'
        ]
        self.subtests_results = dict()

    def run(self):
        """
        Run test case.
        """
        self.set_test_passing()
        self.subtest_start('pre-test')
        try:
            if ts.gconn:
                logger.debug('connection looks ok.. Go Ahead')
        except:
            logger.exception("connection not initialized.. return")
            return
        self.subtest_pass('pre-test')

        # selectors for manual dev/repros
        # [Tata]: altered the flags for VPN provisioning
        create_vpn = True
        create_subvpn = True
        create_ad = True
        verify_vpn = True
        verify_subvpn = True
        tata_verify_ad = True
        verify_mgmt_hub = False
        do_pings = True
        tata_verify_xsad = True
        delete_ad = False
        delete_sub = False
        delete_vpn = False


        #[Tata] : altered logs for this tc
        logger.debug('create_vpn={}, verify_vpn={}, create_subvpn={}, verify_subvpn={}, create_ad={}, tata_verify_ad={}, tata_verify_xsad={}, do_pings={} '.format(create_vpn, verify_vpn, create_subvpn, verify_subvpn, create_ad, tata_verify_ad, tata_verify_xsad, do_pings))
        #logger.debug('create_subvpn={}, verify_vpn={}, create_ad={}, do_pings={}'.format(create_subvpn, verify_vpn, create_ad,
                                                                                      #do_pings))
        self.subtest_start('FUNC001_vpn_creation')
        self.subtest_start('FUNC002_subvpn_creation')
        self.vpn = self.configFile.configFile['service_chain']['vpn_name']
        sub = self.configFile.configFile['service_chain']['subvpn_name']
        self.dcs = ts.gconn['cso_cli'].get_data_centers()
                #[Tata : TBD] Extracting traffic_config. Verfication required
				traffic_config = utils.load_cpe_data(self.configFile.configFile['subconfigs']['traffic_vm_behind_cpe_config'])
				if not traffic_config:
            logger.debug('Could not load traffic configuration')
           return

        dcList = []
        for dc in self.dcs:
            dcList.append(dc['name'])

        logger.debug('DEBUG: dcList = {}'.format(dcList))

        # [tata]: Added code block to create VPN.
        if create_vpn:
            logger.info('Verifying if vpn {} already exists...'.format(self.vpn))
            try :
                while self.vpn in ts.gconn['cso_cli'].get_vpn_list():
                    logger.error('Error, vpn %s already exists, aborting'.format(self.vpn))
                    self.subtest_fail('FUNC001_vpn_creation', 'vpn {} already exists'.format(self.vpn))
                    self.subtest_fail('FUNC002_subvpn_creation', 'vpn {} already exists'.format(self.vpn))
                    return
            except:
                logger.exception("Could not connect to CSO CLI")
            else:
                logger.info("vpn name %s doesn't exist, continuing with creation..."%self.vpn)
                try :
                    prefix = self.configFile.configFile['service_chain']['prefix_nw']

                    sc = ts.gconn['cso'].create_service_chain(ts.gconn, self.dcs, "vpn_1sub.xml", self.vpn, sub=sub, prefix = prefix)
                    if sc:
                        logger.info("vpn %s creation request submitted successfully"%self.vpn)
                    else:
                        # if the ncs_create_basic returns Null, set the set_test_failing as below
                        self.subtest_fail('FUNC001_vpn_creation')
                        logger.error("vpn %s creation request failed"%self.vpn)
                        return
                except Exception as e:
                    # if the ncs_create_basic returns exception set the set_test_failing as below
                    logger.exception("Could not create vpn %s"%self.vpn)
                    self.subtest_fail('FUNC001_vpn_creation', e)
                    self.subtest_fail('FUNC002_subvpn_creation')
                    return

                # Wait for Service Chain to be active
                logger.info("Waiting for vpn %s to be active..."%self.vpn)
                try:
                    #[tata]: unit for timeout
                    timeout = 1800
                    ts.gconn['cso_cli'].wait_for_service_deploy_ngena(self.vpn, breakoutSubvpnCount=0, dcList=dcList,
                                                                       cpeList=[], timeout=timeout, virtoType='icsp')
                except NCS.Timeout as e:
                    logger.error(e.message)
                    self.subtest_failed('FUNC001_vpn_creation', '{} creation timed out after {} seconds.'.format(self.vpn, timeout))
                    self.subtest_failed('FUNC002_subvpn_creation')
                    return
                except:
                    logger.exception("Unexpected error encountered while waiting for service chain to deploy.")
                    self.subtest_failed('FUNC001_vpn_creation', 'Unexpected error')
                    self.subtest_failed('FUNC002_subvpn_creation')
                    return
                else:
                    logger.info("vpn infra ICSP %s is now ready"%self.vpn)
                    self.subtest_pass('FUNC001_vpn_creation')
                    self.subtest_pass('FUNC002_subvpn_creation')
            logger.debug('sleeping 30 seconds.')
            time.sleep(30)

        else:
            logger.info("Skipped vpn creation, using existing vpn %s" % self.vpn)
            self.subtest_skip('FUNC001_vpn_creation')
            self.subtest_skip('FUNC002_subvpn_creation')
            sc = ServiceChain.NGENAServiceChain(
                ts.gconn,
                self.dcs,
                self.tbFile,
                self.vpn,
                debug=True
            )

        # [tata]: Added code block to verify VPN.
        if verify_vpn:
            self.subtest_start('tata vpn verify')
            #[tata] changed vpn to boolean type
            vpn = False
            try:
                while self.vpn in ts.gconn['cso_cli'].get_vpn_list():
                    logger.info("VPN created successfully %s" % self.vpn)
                    vpn = True
                if vpn:
                    self.subtest_pass('tata vpn verify')
                else:
                    self.subtest_fail('tata vpn verify', "VPN not created")
            except:
                logger.exception("connection not initialized.. return")
                self.subtest_fail('tata vpn verify', 'connection to cso not initialized')
                return


        if create_subvpn:
            logger.info('Verifying if vpn {} already exists...'.format(self.vpn))
            try:
                while self.vpn in ts.gconn['cso_cli'].get_vpn_list():
                    # [Tata]: Altered logger
                    logger.error('VPN exists, proceeding to create subVPN'.format(self.vpn))
                    # [Tata]: self.subtest_fail('FUNC001_vpn_creation', 'vpn {} already exists'.format(self.vpn))
                    # [Tata]: self.subtest_fail('FUNC002_subvpn_creation', 'vpn {} already exists'.format(self.vpn))
                    return
            except:
                logger.exception("VPN does not exist")
            else:
                logger.info("vpn name %s doesn't exist, continuing with creation..." % self.vpn)
                try:
                    prefix = self.configFile.configFile['service_chain']['prefix_nw']
                    sc = ts.gconn['cso'].create_service_chain(ts.gconn, self.dcs, "vpn_1sub.xml", self.vpn, sub=sub, prefix = prefix)
                    if sc:
                        logger.info("vpn %s creation request submitted successfully" % self.vpn)
                    else:
                        # if the ncs_create_basic returns Null, set the set_test_failing as below
                        self.subtest_fail('FUNC002_subvpn_creation')
                        logger.error("subvpn %s creation request failed" % self.vpn)
                        return
                except Exception as e:
                    # if the ncs_create_basic returns exception set the set_test_failing as below
                    # [Tata]: logger.exception("Could not create vpn %s" % self.vpn)
                    # [tata]: self.subtest_fail('FUNC001_vpn_creation', e)
                    self.subtest_fail('FUNC002_subvpn_creation')
                    return

                # Wait for Service Chain to be active
                # [Tata]: Altered logger
                logger.info("Waiting for subvpn to be active...")
                try:
                    timeout = 1800
                    ts.gconn['cso_cli'].wait_for_service_deploy_ngena(self.vpn, breakoutSubvpnCount=0, dcList=dcList,
                                                                      cpeList=[], timeout=timeout, virtoType='icsp')
                except NCS.Timeout as e:
                    logger.error(e.message)
                    self.subtest_failed('FUNC002_subvpn_creation',
                                        'Timeout, subvpn creation failed')
                    # [tata]: self.subtest_failed('FUNC002_subvpn_creation')
                    return
                except:
                    logger.exception("Unexpected error encountered while waiting for service chain to deploy.")
                    self.subtest_failed('FUNC002_subvpn_creation', 'Unexpected error')
                    # [tata]: self.subtest_failed('FUNC002_subvpn_creation')
                    return
                else:
                    logger.info("vpn infra ICSP %s is now ready" % self.vpn)
                    # [tata]: self.subtest_pass('FUNC001_vpn_creation')
                    self.subtest_pass('FUNC002_subvpn_creation')
            logger.debug('sleeping 30 seconds.')
            time.sleep(30)

        else:
            logger.info("Skipped subvpn creation, already present")
            # [tata]: self.subtest_skip('FUNC001_vpn_creation')
            # [tata]: self.subtest_skip('FUNC002_subvpn_creation')
            sc = ServiceChain.NGENAServiceChain(
                ts.gconn,
                self.dcs,
                self.tbFile,
                self.vpn,
                debug=True
            )


        # [tata]: Added code block to verify sub-VPN.
        if verify_subvpn:
            self.subtest_start('tata vpn verify')
            #[tata] changed vpn to boolean type
            subvpn = False
            try:
                while sub in ts.gconn['cso_cli'].get_subvpn_list():
                    logger.info("subVPN created successfully %s" % self.vpn)
                    subvpn =  True
                if subvpn:
                    self.subtest_pass('tata subvpn verify')
                else:
                    self.subtest_fail('tata subvpn verify',"subvpn not created")
            except:
                logger.exception("connection not initialized.. return")
                self.subtest_fail('tata subvpn verify', 'connection to cso not initialized')
                return


        # Collect cpeInfo, populate dc and collect sites even if we don't create ads in this run
        # required for other sections, if run indenpendly.
        # [tata]: Commented the below code block to prevent uninitialized variables errors.
        # TATA TBD : check if any changes required in th config file for adding two CPEs -> looks like some config changes are required
        cpeInfo = sc.fetch_dynamic_cpe_info(self.configFile.get_sub_config('create_cpe_config'),
                                            self.configFile.configFile)
        if not cpeInfo:
            logger.exception("Looks like no CPE found from fetch_dynamic_cpe_info... Failed")
            self.suitePassed = False
            return False
        else:
            logger.info("CPE Info from fetch_dynamic_cpe_info: %s" % cpeInfo)
            sites = []
            count = 0
            breakoutSubvpnCount = 1
            vpn_name = self.configFile.configFile['service_chain']['vpn_name']
            for i in range(0, len(cpeInfo)):
                if 'subvpn_count' in self.configFile.configFile['service_chain']:
                    subvpn_count = self.configFile.configFile['service_chain']['subvpn_count']
                    breakoutSubvpnCount = subvpn_count
                    subvpn = self.configFile.configFile['service_chain']['subvpn_prefix'] + str(count)
                else:
                    subvpn = self.configFile.configFile['service_chain']['subvpn_name']
                sites.append(
                    {
                        'name': '%s%d' % (self.configFile.configFile['service_chain']['ad_prefix'], i),
                        'sn': cpeInfo[i]['Serial'],
                        'cidr': cpeInfo[i]['LAN-Net-ip'] + '/' + cpeInfo[i]['LAN-Net-mask'],
                        'lan_encap': 'native',
                        'subvpn': subvpn
                    }
                )
                cpeInfo[i].update({'subvpn': subvpn})
                if ('subvpn_count' in self.configFile.configFile['service_chain']) and (subvpn_count > 1):
                    count += 1
            logger.debug('sites = {}'.format(sites))
            cpe_list = []
            cpeNames = []
            for i, site in enumerate(sites):
                cpe_id = (site['cidr']).split('.')[-2]  # we know that lan ip 3rd octet is cpe id
                for key, val in (self.configFile.configFile['cpe_config']['cpe_dc_location']).iteritems():
                    if int(cpe_id) in val:
                        dc = self.dcs[int(key)]['name']
                        cpeInfo[i].update({'dc': dc})
                cpe_list.append(site['sn'])
                cpeNames.append(site['name'])

        if create_ad:
            logger.info('Creating access-designs')
            self.subtest_start('FUNC003_access_design_creation')
            count_ad_created = 0
            if cpeInfo:
                for i, site in enumerate(sites):
                    dc = cpeInfo[i]['dc']
                    template_xml = 'add_1ad.xml'
                    logger.info(
                        "Adding site, using direct send_netconf_rpc; %s cpe %s to vpn %s vrf %s, LAN %s, DC: %s, template_xml: %s" %
                        (site['name'], site['sn'], vpn_name, site['subvpn'], site['cidr'], dc, template_xml))
                    params1 = {
                        'msgID': 1,
                        'vpn': vpn_name,
                        'sub': sub,
                        'ad': site['name'],
                        'cpe_sn': site['sn'],
                        'dc': dc,
                        'cpe_cidr': site['cidr']
                    }
					params2 = {
                        'msgID': 1,
                        'vpn': vpn_name,
                        'sub': sub,
                        'ad': site['name'],
                        'cpe_sn': site['sn'],
                        'dc': dc,
                        'cpe_cidr': site['cidr']
                    }

                    result, reply = ts.gconn['cso'].send_netconf_rpc(template_xml, params1)
					result, reply = ts.gconn['cso'].send_netconf_rpc(template_xml, params2)
                    #[tata] adding send the netconf rpc
                    #result, reply = True, 'FAKE'
                    if result:
                        count_ad_created += 1
                        logger.info(
                            'Access-design {} {} creation success. result={}, reply={}'.format(site['name'], site['sn'],
                                                                                               result, reply))
                    else:
                        logger.error(
                            'Access-design {} {} creation failed. result={}, reply={}'.format(site['name'], site['sn'],
                                                                                              result, reply))

                    logger.info('Sleeping 10 seconds after each access-design creation')
                    time.sleep(10)

            logger.info('cpe_list = {}'.format(cpe_list))
            logger.info('cpe_list.len = {}'.format(len(cpe_list)))
            logger.info('cpeNames = {}'.format(cpeNames))
            logger.info('count_ad_created = {}'.format(count_ad_created))
            cpe_count = len(cpe_list)
            ## now write the data to the config file, so that others can read
            logging.info('Writing cpe data to {}'.format(self.configFile.configFile['common_config']['rw_conf_file']))
            try:
                suite = ts.TestSuite()
                suite.write_data_to_file(cpeInfo, self.configFile.configFile['common_config']['rw_conf_file'])
            except:
                e = sys.exc_info()[0]
                logger.exception('write file exception:%s' % e)
                self.suitePassed = False
                return False

            utils.set_cpe_info_file(self.configFile.configFile['common_config']['rw_conf_file'])

            if count_ad_created == len(cpe_list):
                self.subtest_pass('FUNC003_access_design_creation')
            else:
                self.subtest_fail('FUNC003_access_design_creation')

            logger.info('Waiting for CPEs to be synced')
            self.subtest_start('CPE_onboarding')
            num_cpe = len(cpe_list)
            num_cpe_onboarded = 0
            for cpe_sn in cpe_list:
                logger.info('Waiting for CPE {} to be in state synced'.format(cpe_sn))
                if sc.wait_for_cpe_synced(cpe_sn):
                    logger.info('CPE {} is synced'.format(cpe_sn))
                    num_cpe_onboarded += 1
                else:
                    logger.info("CPE %s PnP synced timed out" % (cpe_sn))

            # Wait for Service Chain to be active
            time.sleep(5)
            logger.info("Verify service chain %s status..." % self.vpn)
            try:
                ts.gconn['cso_cli'].wait_for_service_deploy_ngena(self.vpn, breakoutSubvpnCount=1, dcList=dcList,
                                                                  cpeList=cpeNames, timeout=1800)
            except NCS.Timeout as e:
                logger.error(e.message)
                self.subtest_fail('CPE_onboarding')
                return
            except:
                logger.exception("Unexpected error encountered while waiting for service chain to deploy.")
                self.subtest_fail('CPE_onboarding')
                return
            else:
                logger.info("Service chain %s is ready" % self.vpn)

            if num_cpe_onboarded == num_cpe:
                self.subtest_pass('CPE_onboarding')
            else:
                self.subtest_fail('CPE_onboarding')

        if tata_verify_ad:
            self.subtest_start('tata vpn verify')
            ad = False
            try:
                # [Tata]: Added get_access_design_list method in NCS.py
                while site['name'] in ts.gconn['cso_cli'].get_access_design_list():
                    logger.info("ad created successfully %s" % self.vpn)
                    ad = True
                if ad:
                    self.subtest_pass('tata ad verify')
                else:
                    self.subtest_fail('tata ad verify', "ad not created")
            except:
                logger.exception("connection not initialized.. return")
                self.subtest_fail('tata ad verify', 'connection to cso not initialized')
                return

        if tata_verify_xsad:

            '''
            [Tata]
            1. get_cpe_lan() - to get cpe lan ip info from the cso
            2. get_device_address() - to get the device ip directly. Need to check it returns ipv4 or
                ipv6. 
            FOR IP VALIDATION
            [Tata : TBD] sites variable is available from cpeinfo, returns a dictionary. create a dictionary (temp_dict) which has the mapping of
            cpeSN (ad:serial-number) and IP (ad:ip). 
            [Tata : TBD] snlist can be created from temp_dict
            '''
            self.subtest_start('tata xsad verify')
            try:
                cust_lan = ts.gconn['cso_cli'].get_cpe_lan(self, site_name=sites)
                #[Tata : TBD derived from cust_lan ] temp_dict = {}
                #[Tata : TBD snlist derived from temp_dict] snlist
                flag = False

                for sn in snlist:
                # [Tata : TBD]  device_lan_ip = sc.connect_to_cpe("cpeSN").execute("cmdForLanIp")
                # [Tata : TBD]  device_wan_ip = sc.connect_to_cpe("cpeSN").execute("cmdForWanIp")

                    if device_wan_ip == None || device_lan_ip == None:
                        logger.info('tata xsad verify : WAN/LAN IP is not set')
                        flag = False
                        self.subtest_fail('tata xsad verify : LAN/WAN IP is not set')
                        return flag

                    if device_lan_ip == temp_dict['sn']:
                        flag = True
                        logger.info('tata xsad verify : IP Devicename matched, proceeding to next device')
                    else:
                        flag = False
                        self.subtest_fail('tata xsad verify : CPE IP and SN mismatch')
                        return flag

                self.subtest_pass('tata xsad verify : Validation success')
                return flag
                
            except:
                logger.exception("connection not initialized.. return")
                self.subtest_fail('tata xsad verify, unexpected error ')
                return

		    if do_pings:
            """
            Ping VM behind CPE to Internet
            Ping VM behind CPE to VM Behind CPE
            CPE LISP counter Check
            """
            self.subtest_start('Ping_VM_Behind_CPE_internet')
            logger.info('Executing pings VM behind CPE to VM behind CPE and to internet, SNs: {}'.format(cpe_list))
            time.sleep(60)
            logger.info('ping VM behind CPE {} to Internet'.format(cpe_list))
            for cpe_sn in cpe_list:
                logger.info("Start pings  VM behind cpe %s to internet" % cpe_sn)
                                #Tata TBD verify the parameters(cpeInfo)
                ping_result = sc.ping_vm_behind_vcpe_to_internet(traffic_config,cpeInfo)
                #[Tata] trace route validation
                tracert_result = Control.verify_tracert(srcIP,8.8.8.8)
                if ping_result && tracert_result:
                    logger.info("Ping from VM behind cpe-%s to internet: Success" % cpe_sn)
                    self.subtest_pass('Ping_VM_Behind_CPE_internet')
                else:
                    self.subtest_fail('Ping_VM_Behind_CPE_internet')
                    logger.info("Ping from cpe-%s to internet FAILED" % cpe_sn)

            self.subtest_start('Ping_VM_Behind_CPE_VM_Behind_CPE')
            #logger.info('Ping CPE to CPE {} on vrf {}'.format(cpe_list, sub1))
                        #Tata TBD verify the parameters(cpeInfo)
            ping_result = sc.ping_vm_behind_vcpe_to_vm_behind_vcpe(traffic_config,cpeInfo)
            #[Tata] trace route validation
            tracert_result = Control.verify_tracert(srcIP,destIP)
            if ping_result && tracert_result:
                logger.info("Ping VM Behind CPE to VM Behind CPE : Success")
                self.subtest_pass('Ping_VM_Behind_CPE_VM_Behind_CPE')
            else:
                logger.error("Ping VM Behind CPE to VM Behind CPE FAILED")
                self.subtest_fail('Ping_VM_Behind_CPE_VM_Behind_CPE')

            #logger.info('Verify CPE Counters CPE {} on vrf {}'.format(cpe_list, sub1))
            self.subtest_start('CPE_LISP_counters')
                        #Tata TBD difference between sub vpn and vrf
                        #Tata TBD verify the parameter - Vm behind cpe list 
            lisp_cnt_result = sc.verify_lisp_counter(cpe_list, sub)
            if lisp_cnt_result:
                logger.info("CPE LISP counter Check : SUCCESS")
                self.subtest_pass('CPE_LISP_counters')
            else:
                logger.info("CPE LISP counter check: FAILED")
                self.subtest_fail('CPE_LISP_counters')

								
								
								
'''
        if verify_vpn:
            self.subtest_start('verify_service_chain')
            # Verify service chain (must be after first access-design has been deployed)
            logger.info('Verifying service chain {},{}'.format(self.vpn, sub))
            if sc.verify_service_chain_basic(sub):
                self.subtest_pass('verify_service_chain')
                logger.info("Service chain %s is verified successfully" % self.vpn)
            else:
                # if the verify_service_chain_full returns False set the set_test_failing as below
                self.subtest_fail('verify_service_chain')
                logger.error("Verify service chain %s failed" % self.vpn)

        if verify_mgmt_hub:
            time.sleep(3)
            subtest = 'FUNC011 Verify mgmt-hub ikev2 keys'
            self.subtest_start(subtest)
            logger.info('Verifying Crypto ikev2 sessions on mgmt-hub, while access-design configured')

            for dc in dcList:
                cpe_count_dc = 0
                for i in range(0, cpeInfo):
                    if cpeInfo[i]['dc'] == dc:
                        cpe_count_dc += 1
                num_keys, struct = ts.gconn[dc].get_mgmthub_ikev2_keys(self.vpn)
                if num_keys == cpe_count_dc:
                    logger.info('Found {} keys on mgmt-hub {}, as expected. {}'.format(num_keys, dc, struct))
                    self.subtest_pass(subtest)
                else:
                    logger.info('Error. Found {} keys on mgmt-hub {}. Expected {}'.format(num_keys, dc, struct))
                    self.subtest_fail(subtest)

        if do_pings:
            
            # Ping CPE to Internet
            # Ping CPE to CPE
            # CPE LISP counter Check
            
            
            logger.info('Executing pings CPE to CPE and to internet, SNs: {}'.format(cpe_list))
            time.sleep(60)
            logger.info('ping CPE {} to Internet'.format(cpe_list))
            for cpe_sn in cpe_list:
                logger.info("Start pings cpe %s to internet" % cpe_sn)
                ping_result = sc.ping_cpe_internet(cpe_sn, sub, '8.8.8.8')
                if ping_result:
                    logger.info("Ping from cpe-%s to internet: Success" % cpe_sn)
                    self.subtest_pass('Ping_CPE_internet')
                else:
                    self.subtest_fail('Ping_CPE_internet')
                    logger.info("Ping from cpe-%s to internet FAILED" % cpe_sn)

            self.subtest_start('Ping_CPE_CPE')
            logger.info('Ping CPE to CPE {} on vrf {}'.format(cpe_list, sub))
            ping_result = sc.ping_cpe_cpe(cpe_list, sub)
            if ping_result:
                logger.info("Ping CPE to CPE : Success")
                self.subtest_pass('Ping_CPE_CPE')
            else:
                logger.error("Ping CPE to CPE FAILED")
                self.subtest_fail('Ping_CPE_CPE')

            logger.info('Verify CPE Counters CPE {} on vrf {}'.format(cpe_list, sub))
            self.subtest_start('CPE_LISP_counters')
            lisp_cnt_result = sc.verify_lisp_counter(cpe_list, sub)
            if lisp_cnt_result:
                logger.info("CPE LISP counter Check : SUCCESS")
                self.subtest_pass('CPE_LISP_counters')
            else:
                logger.info("CPE LISP counter check: FAILED")
                self.subtest_fail('CPE_LISP_counters')

        if delete_ad:
            self.subtest_start('access_design_deletion')
            logger.info('Sleeping 60 seconds before ad deletion')
            time.sleep(60)
            # Need to delete only if it had been created...
            try:
                template_xml = 'ngena_delete_ad.xml'
                count_ad_deleted = 0
                for i, site in enumerate(sites):
                    site_name = '{}'.format(site['name'])
                    logger.info('Deleting access-design {}'.format(site_name))
                    params = {'ad': site_name}
                    result, reply = ts.gconn['cso'].send_netconf_rpc(template_xml, params)
                    if result:
                        count_ad_deleted += 1
                        logger.info("Access-design %s deleted successfully" % site_name)
                    else:
                        logger.error("Access-design %s deletion failed" % site_name)
                if count_ad_deleted == cpe_count:
                    self.subtest_pass('access_design_deletion')
                else:
                    self.subtest_fail('access_design_deletion', 'Failed to delete some ADs.')
            except:
                logger.exception("Failed to delete access-design on %s" % self.vpn)
                self.set_test_failed()

        time.sleep(10)
        if verify_mgmt_hub:
            subtest = 'FUNC011 Verify mgmt-hub ikev2 keys, after access-designs deletion.'
            self.subtest_start(subtest)
            logger.info('Verifying Crypto ikev2 sessions on mgmt-hub')

            for dc in dcList:
                num_keys, struct = ts.gconn[dc].get_mgmthub_ikev2_keys(self.vpn)
                if num_keys:
                    logger.info('Error. Found {} keys on mgmt-hub {}, expected None.  {}'.format(num_keys, dc, struct))
                    self.subtest_fail(subtest)
                else:
                    logger.info('Found {} keys on mgmt-hub {}, as expected. {}'.format(num_keys, dc, struct))
                    self.subtest_pass(subtest)
                    self.subtest_pass(subtest)

        if delete_sub:
            self.subtest_start('subvpn_deletion')
            logger.info("Deleting individual subvpn %s" % sub)
            template_xml = 'ngena_delete_subvpn.xml'
            params = {'vpn': self.vpn, 'sub': sub}
            logger.info('Deleting subvpn {}'.format(params))
            result, reply = ts.gconn['cso'].send_netconf_rpc(template_xml, params)
            if result is True:
                self.subtest_pass('subvpn_deletion')
                logger.info("subvpn %s deleted successfully" % sub)
            else:
                self.subtest_fail('subvpn_deletion', failure=reply)
                logger.error("subvpn %s deletion failed" % sub)

            time.sleep(10)
            logger.info("Deleting subvpns container")
            template_xml = 'ngena_delete_subvpns.xml'
            params = {'vpn': self.vpn}
            logger.info('Deleting subvpns container {}'.format(params))
            result, reply = ts.gconn['cso'].send_netconf_rpc(template_xml, params)
            if result is True:
                self.subtest_pass('subvpn_deletion')
                logger.info("subvpns container %s deleted successfully" % self.vpn)
            else:
                self.subtest_fail('subvpn_deletion', failure=reply)
                logger.error("subvpns container %s deletion failed" % self.vpn)

        if delete_vpn:
            self.subtest_start('FUNC006 vpn deletion')
            logger.info("Deleting vpn %s" % self.vpn)
            template_xml = 'ngena_delete_vpn.xml'
            params = {'vpn': self.vpn}
            logger.info('Deleting vpn {}'.format(self.vpn))
            result, reply = ts.gconn['cso'].send_netconf_rpc(template_xml, params)
            logger.debug('DEBUGx3: result:{}\nreply:{}'.format(result, reply))
            if result:
                self.subtest_pass('FUNC006 vpn deletion')
                logger.info("vpn %s deleted successfully" % self.vpn)
            else:
                self.subtest_fail('FUNC006 vpn deletion', failure=reply)
                logger.error("vpn %s deletion failed" % self.vpn)
 """
"""
TC_Single_vpn_Script derived class definition,
derived from class ScriptTemplate in lib/Automation.py to be used for this unit test
'''


class TC_Dual_Cpe_Script(Automation.ScriptTemplate):
    def main(self):
        tc = TataSF004Four(
            self.tbFile,
            self.manifest,
            debug=self.options.debug,
            displayName="XS - Inter region communication(Basic)"
        )
        logger.info('Running testcase: %s', tc.displayName)
        tc.run()
        if tc.testPassed:
            logger.info('TEST PASSED: %s', tc.displayName)
            sys.exit(0)
        else:
            logger.critical('TEST FAILED: %s', tc.displayName)
            sys.exit(2)


if __name__ == "__main__":
    script = TC_Dual_Cpe_Script()
    script.main()
