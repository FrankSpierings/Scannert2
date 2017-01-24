import subprocess
from lib.modules import common
import logging
logger = logging.getLogger(__name__)

config = common.get_config()
CONF_SMBCLIENT = config.get('smbclient', 'smbclient')
        
def scan(target, path='/tmp'):
    output='{path}/smb_shares__{target}.txt'\
           .format(path=path, target=common.target_to_filename(target))
           
    cmd     = 'printf "shares\\nwho\\nexit\\n" | {smbclient} {target}'.format(smbclient=CONF_SMBCLIENT, target=target)
    #The no append in tee is decision!.
    cmdline = 'echo "{cmd}" | tee {output}'.format(cmd=cmd, output=output)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
    
    cmdline = '{cmd} 2>&1 | tee -a {output}'.format(cmd=cmd, output=output)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
