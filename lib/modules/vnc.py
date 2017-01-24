import subprocess
import modules.common
import logging
logger = logging.getLogger(__name__)
        
def scan(target, port, path='/tmp'):
    output='{path}/vnc_screenshot_{target}_{port}.jpg'\
           .format(path=path, target=common.target_to_filename(target), port=port)
           
    cmdline = 'vncdo -p "" -v -s {target}::{port} key ctrl pause 3 capture {output}'.format(
               target=target, port=port, output=output)
    logger.info("Command: {0}".format(cmdline))
    subprocess.call(cmdline, shell=True)
