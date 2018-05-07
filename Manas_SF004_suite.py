#!/usr/bin/env python

"""
Test Suite script which does following:
1) create vpn + sub-vpn
2) create access-design(s)
3) veryfy full service chain
4) tbd..  just trying to get the wrapper ok for now
For SF004
1) create access-design (xs)
2) TBD Intra region communication
3) IBD Inter region communication (premium)
4) TBD Inter region communication (basic)
"""

import sys
import logging

from vmsauto.lib import Automation
from vmsauto.testcases.ngena import TataSF004One
#from vmsauto.testcases.ngena import TataSF004Two
from vmsauto.lib.ngena import Utills
from vmsauto.lib.ngena import Create_vCSR_CPE

logger = logging.getLogger(__name__)
utils = Utills.common_utills()


class SF004SuiteScript(Automation.SuiteScriptTemplate):
    def main(self):
        logger.happy("STARTING SUITE {}".format(__file__))
        suite = Automation.TestSuite(displayName='XS communications suite')
        suite.tbFile = self.tbFile
        suite.manifest = self.manifest
        suite.suitePassed = True
        ## pre-healthcheck

        conn = suite.configure_setup(self.tbFile)
        if not conn:
            logger.exception('connection setup failed')
        logger.debug('connection successful. Details:%s' % conn)

        if (self.suiteConfig.configFile['common_config']['create_vcpe']):
            cpeConfigFiles = utils.update_day_minus_one_for_all_nso(self.tbFile.all_nso, self.tbFile.testbedFile,
                                                                    self.suiteConfig.get_sub_config(
                                                                        'create_cpe_config')['cpe_vm']['config_file'])
            logger.debug('Initiating vCPE creation...')
            cpe = Create_vCSR_CPE.CreateCPE()
            # Workaround for access-design deletion issues
            # Making vCPE_num_start/end per suite, reading
            # from suiteConfigFile instead of global configfile
            cpe.main(self.tbFile, self.suiteConfig.get_sub_config('create_cpe_config'), self.suiteConfig.configFile,
                     suite.dcs, cpeConfigFiles)
            logger.debug('vCPE creation complete... proceeding with suite setup')
        ## currently a placeholder.. this is under-development..perform health-check of VMs before proceeding
        suite.health_check(self.tbFile)

        SF004One = TataSF004One.TataSF004One(
            self.tbFile,
            self.suiteConfig,
            self.manifest,
            self.options.debug,
            displayName="Deploy AD XS"
        )

        '''
        SF001Two = TataSF001Two.TataSF001Two(
            self.tbFile,
            self.suiteConfig,
            self.manifest,
            self.options.debug,
            displayName="Single vpn Single subvpn operations"
        )
        '''

        suite.add_test_case(SF001One, group="executeAll")
       #suite.add_test_case(SF001Two, group="executeAll")

        # this tells how the suite will be executed.. all sequentially or concurrently
        suite.set_tc_group_exec_strategy(self.suiteConfig.configFile['suite_run']['exec_group'],
                                         strategy=self.suiteConfig.configFile['suite_run']['exec_strategy'])

        logger.info("Running suite...")
        if suite.suitePassed:
            suite.run()

        suite.summary_results(resultsFile=self.options.resultsFile)
        if suite.suitePassed:
            logger.happy("SUITE PASSED")
        else:
            logger.critical("SUITE FAILED")

            ## post-healthcheck


if __name__ == "__main__":
    script = SF004SuiteScript(loadConfigFile=True)
    script.run()
