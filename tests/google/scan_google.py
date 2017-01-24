#!/usr/bin/python3
import os
import sys
import tempfile
sys.path.insert(0, os.path.abspath('../..'))

from lib.modules import nmap
from lib.modules import webscreenshot
from lib.modules import dns
from lib.modules import nikto
from lib.modules import testssl
from lib.modules import netconfig

target='www.google.com'
path = tempfile.mkdtemp(prefix='scan_{0}_'.format(target))

netconfig.gather(path=path)
n = nmap.nmap(target, path=path)
n.scan_whois()
#n.scan_quick()
n.ports_from_xml('www.google.com.xml')

dns.scan(target, path=path, dnsrecon=False)

for port in n.ports.filter('ssl'):
	testssl.scan(target, port=port.portid, path=path)

for port in n.ports.filter('http'):
    webscreenshot.browser_url('{0}://{1}:{2}'.format(port.service, target, port.portid), path=path)

for port in n.ports.filter('http'):
    nikto.scan(target, port=port.portid, ssl=port.ssl, path=path)