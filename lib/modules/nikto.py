import subprocess
from lib.modules import common
import logging

config = common.get_config()
CONFIG_NIKTO = config.get('nikto', 'nikto')

logger = logging.getLogger(__name__)
        
def scan(target, port=80, ssl=False, path='/tmp'):
    output='{path}/nikto__{target}_{port}.txt'\
           .format(path=path, target=common.target_to_filename(target), port=port)
    sslstr=''
    if (ssl==True):
    	sslstr = "-ssl "    
    cmdline = '{nikto} -Format txt -output "{output}" -Save "{path}" {sslstr}-host {target}:{port}'\
    	      .format(nikto=CONFIG_NIKTO, output=output, path=path, sslstr=sslstr, target=target, port=port)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
