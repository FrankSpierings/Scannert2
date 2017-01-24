import subprocess
from  lib.modules import common
import logging
logger = logging.getLogger(__name__)

config = common.get_config()
CONFIG_TESTSSL = config.get('testssl', 'testssl')
CONFIG_OPENSSL = config.get('testssl', 'testssl_openssl')


def scan(target, port=443, path='/tmp'):
    output = '{path}/testssl__{target}_{port}.txt'\
    		 .format(path=path, target=common.target_to_filename(target), port=port)
    cmdline = '"{testssl}" ' \
              '--openssl "{openssl}" ' \
              '--wide --color 0 ' \
              '--logfile="{output}" ' \
              '{target}:{port}'.format(testssl=CONFIG_TESTSSL, openssl=CONFIG_OPENSSL,
                                       output=output, target=target, port=port)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
