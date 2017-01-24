import subprocess
import time
from lib.modules import common
import logging
logger = logging.getLogger(__name__)
        
def gather(path='/tmp'):
    epoch = int(time.time())
    output='{path}/nmcli__{epoch}.txt'\
           .format(path=path, epoch=epoch)
           
    cmd     = 'nmcli c'
    #The no append in tee is decision!.
    cmdline = 'echo {cmd} | tee {output}'.format(cmd=cmd, output=output)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)

    cmdline = '{cmd} 2>&1 | tee -a {output}'.format(cmd=cmd, output=output)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)

    output='{path}/ifconfig__{epoch}.txt' \
       .format(path=path, epoch=epoch)

    cmd     = 'ifconfig'
    #The no append in tee is decision!.
    cmdline = 'echo {cmd} | tee {output}'.format(cmd=cmd, output=output)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)

    cmdline = '{cmd} 2>&1 | tee -a {output}'.format(cmd=cmd, output=output)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
