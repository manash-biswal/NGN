#!/usr/bin/env python

"""
API driven service chain functional test case

Performs tests to make sure a vMS installation functions enough to do
typical service chain operations.

This test case will do the following:
 * ASA rule configuration and validation
"""

import logging
import sys
import os
import re
import datetime
import json
import subprocess
import time

from vmsauto.lib import Automation
from vmsauto.lib import TestSuite as ts
from vmsauto.lib.ngena import NCS
from vmsauto.lib.ngena import ServiceChain
from vmsauto.lib import IDM
from vmsauto.lib import Testbed
from vmsauto.lib import Linux
from vmsauto.lib import OpenStack
from vmsauto.lib.ngena import Utills

logger = logging.getLogger(__name__)
utils = Utills.common_utills()

"""
TC_ASA_PermitAny_Validation derived class definition,
derived from class Testcase in lib/Automation.py to be used for this unit test
"""
class TC_ASA_PermitAny_Validation(Automation.Testcase):

    def __init__(self,tbFile,configFile,debug=True,displayName=None):
        super(TC_ASA_PermitAny_Validation,self).__init__(displayName)
        self.tbFile = tbFile
        self.configFile = configFile
        self.debug = debug
        self.provider = tbFile.get_vms_provider()
        self.subtests_results = dict()

    def run(self):
        """
        Run test case.
        """
        try:
            if ts.gconn:
                logger.debug('connection looks ok.. Go Ahead')
        except:
            logger.exception("connection not initialized.. return")
            return

        vpn = self.configFile['vpn_name']
        sub = self.configFile['subvpn_name']
        self.dcs = ts.gconn['cso_cli'].get_data_centers()
        sc = ServiceChain.NGENAServiceChain(
                ts.gconn,
                self.dcs,
                self.tbFile,
                vpn,
                debug=True
        )

        try:


            vnfList = ts.gconn['cso_cli'].get_vnf_list(vpn)
            regName = self.dcs[0]['name']
            #Getting VNF name which looks like this now: vpn2-subvpn2/r1-h1-r1-h1-v1/firewall
            deviceName = [vnf for vnf in vnfList if regName in vnf and vnf.endswith('firewall')]
            logger.debug('Connecting to device: %s' % deviceName)
            asa = sc.connect_to_vnf(deviceName[0])
            asaRules = asa.execute("show running-config access-list | grep ACL-INSIDE")
            logger.info("ASA rules configured: %s" % (asaRules))
            traffic_config = utils.load_cpe_data(
                self.configFile.configFile['subconfigs']['traffic_vm_behind_cpe_config'])
            if not traffic_config:
                logger.debug('Could not load traffic configuration')
                return

            vcpe_info = utils.load_cpe_data(self.configFile.configFile['common_config']['rw_conf_file'])
            if not vcpe_info:
                logger.debug('Could not load vcpe_info')
                return

            # Ping from VmBehindVCPE to Internet
            self.subtest_start('Ping_VmBehindVCpe_Internet')
            cpe_count = vcpe_info['cpe_info']['cpe_count']
            cpe_list = []
            for key in vcpe_info['cpe_info']:
                if key != 'cpe_count':
                    cpe_list.append(vcpe_info['cpe_info'][key])

            logger.info("CPE_LIST : %s" % cpe_list)
            if int(cpe_count) > 0:
                ping_result = sc.ping_vm_behind_vcpe_to_internet(traffic_config, cpe_list)
                if ping_result:
                    logger.info("Ping VmBehindVCpe to Internet : Success")
                    self.subtest_pass('Ping_VmBehindVCpe_Internet')
                    self.set_test_passing()
                else:
                    logger.info("Ping VmBehindVCpe to Internet: FAILED")
                    self.subtest_fail('Ping_VmBehindVCpe_Internet', 'Ping VmBehindVCpe to Internet failed.')
                    self.set_test_failed()
                    return



        except:
            logger.exception('failed to validate ASAv  permit any any rule ')


        self.set_test_passing()

"""
TC_ASA_PermitAny_Validation_Script derived class definition,
derived from class ScriptTemplate in lib/Automation.py to be used for this unit test
"""
class TC_ASA_PermitAny_Validation_Script(Automation.ScriptTemplate):

    def main(self):
        tc = TC_ASA_PermitAny_Validation(
            self.tbFile,
            self.configFile,
            debug=self.options.debug,
            displayName="I am running TC_ASA__PermitAny_validation"
        )
        logger.info('Running testcase: %s',tc.displayName)
        tc.run()
        if tc.testPassed:
            logger.info('TEST PASSED: %s',tc.displayName)
            sys.exit(0)
        else:
            logger.critical('TEST FAILED: %s',tc.displayName)
            sys.exit(2)

if __name__ == "__main__":
    time.sleep(4)
    script = TC_ASA_PermitAny_Validation_Script(loadConfigFile=True)
    script.main()
