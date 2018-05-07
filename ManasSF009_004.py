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
TC_ASA_Delete_PermitAny derived class definition,
derived from class Testcase in lib/Automation.py to be used for this unit test
"""
class TC_ASA_Delete_PermitAny(Automation.Testcase):

    def __init__(self,tbFile,configFile,debug=True,displayName=None):
        super(TC_ASA_Delete_PermitAny,self).__init__(displayName)
        self.tbFile = tbFile
        self.configFile = configFile
        self.debug = debug
        self.provider = tbFile.get_vms_provider()

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
        template_xml = self.configFile['delete_rule_permit_any_any']


        params = {
            'vpn': vpn,
            'sub': sub,
        }
        ret = ts.gconn['cso'].send_netconf_rpc(template_xml, params)
        if not ret[0]:
            self.subtest_fail('Configure_ASA_Rules', 'Configuration of rules failed')
            logger.debug('return value after netconf send:%s' % ret[0])
            return False

        print 'sleeping for 30 secs.. to let rules propagate till asa'
        time.sleep(30)

        try:
            cmd = ("show running-config sub-vpns %s sub-vpn %s outbound-firewall-rules | display json"
                    % (vpn, sub))
            csoRules = ts.gconn['cso_cli'].execute(cmd)
            logger.debug("rules from cso in json format: %s" % csoRules)
            jsonStr = json.loads(csoRules)
            fromCSO = jsonStr['data']['ngena-sub-vpns-cfs:sub-vpns'][0]['sub-vpn'][0]['outbound-firewall-rules']['rule']

            vnfList = ts.gconn['cso_cli'].get_vnf_list(vpn)
            regName = self.dcs[0]['name']
            #Getting VNF name which looks like this now: vpn2-subvpn2/r1-h1-r1-h1-v1/firewall
            deviceName = [vnf for vnf in vnfList if regName in vnf and vnf.endswith('firewall')]
            logger.debug('Connecting to device: %s' % deviceName)
            asa = sc.connect_to_vnf(deviceName[0])
            asaRules = asa.execute("show running-config access-list | grep ACL-INSIDE")
            logger.info("ASA rules configured: %s" % (asaRules))

            ret = utils.validate_asa_config(asaRules, fromCSO)
            logger.debug('\nDone with rule validation. Number of rules validated: %s' % ret)
            if not ret:
                self.subtest_fail('Configure_ASA_Rules', 'Rule deletion on CSO and ASA failed')
        except:
            logger.exception('failed to delete CSO and ASA rule')
            self.subtest_fail('Configure_ASA_Rules', 'Exception while rule deletion on CSO and ASA')

        self.set_test_passing()

"""
TC_ASA_Delete_PermitAny_Script derived class definition,
derived from class ScriptTemplate in lib/Automation.py to be used for this unit test
"""
class TC_ASA_Delete_PermitAny_Script(Automation.ScriptTemplate):

    def main(self):
        tc = TC_ASA_Delete_PermitAny(
            self.tbFile,
            self.configFile,
            debug=self.options.debug,
            displayName="I am running TC_ASA_Delete_PermitAny"
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
    script = TC_ASA_Delete_PermitAny_Script(loadConfigFile=True)
    script.main()
