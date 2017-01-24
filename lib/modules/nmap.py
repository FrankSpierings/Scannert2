import os
import subprocess
import xml.etree.ElementTree as ET
import re

from lib.modules import common

config = common.get_config()
CONFIG_NMAP = config.get('nmap', 'nmap')


import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

class nmap(object): 
    def string(self):
        return '{0}: {1}'.format(self.target, self.ports)
    def __repr__(self):
        return self.string()
    def __str__(self):
        return self.string()

    def __init__(self, target, path='/tmp'):
        self.target = target
        self.path   = path
        self.ports  = Ports()
        self.__result_xml = None
        self.__default_parameters = ['-T4', '-d', '-v']
        self.__DEFAULT_SERVICE_SCRIPTS = 'all and (not broadcast and not dos and not external and not fuzzer) and not http-slowloris-check'

    def __scan(self, parameters, suffix='unknown'):
        filename = common.target_to_filename('nmap__{0}__{1}'.format(self.target, suffix))
        output_file = os.path.join(self.path, filename)
        parameters.extend(self.__default_parameters)
        parameters.append('-oA "{0}"'.format(output_file))
        parameters.append(self.target)
        cmdline = '{0} {1}'.format(CONFIG_NMAP, ' '.join(parameters))
        log.info(cmdline)
        subprocess.call(cmdline, shell=True)
        self.__result_xml = output_file + ".xml"
        self.__parse_ports(self.__result_xml)

    def ports_from_xml(self, xml_path):
        self.__parse_ports(xml_path)

    def __parse_ports(self, xml_path):
        log.debug("Parsing xml: {0}".format(xml_path))
        xml = ET.parse(xml_path)
        for xml_port in xml.findall('.//ports/port'):
            portid = xml_port.attrib['portid']
            protocol =  xml_port.attrib['protocol']
            service = ''
            ssl = False
            found = False
            try:
                if (xml_port.find('.//state').attrib['state'] == 'open'):
                    try:
                        service = xml_port.find('.//service').attrib['name']
                    except:
                        pass
                    try:        
                        if (xml_port.find('.//service').attrib['tunnel'] == 'ssl'):
                            ssl = True
                    except:
                        pass
                    found = True
            except:
                pass
            if found:
                self.ports.add_port(Port(int(portid), protocol, service, ssl))
        log.debug("Parsed ports: {0}".format(self.ports))

    def scan_quick(self):
        parameters = [
            '-sT',
            '-sV',
            '--top-ports 1000',
        ]
        self.__scan(parameters, suffix='quick scan')
    
    def scan_tcp_ports(self, ports='-'):
        parameters = [
            '-Pn',
            '-p "{0}"'.format(ports), 
            '-sV', 
            '--reason', 
            '--open',
            '--traceroute', 
            '--max-retries 1'
        ]
        self.__scan(parameters, suffix='tcp ports')

    def scan_tcp_services(self, ports='-'):
        parameters = [
            '-Pn',
            '-p "{0}"'.format(ports),
            '-sV',
            '--script "{0}"'.format(self.__DEFAULT_SERVICE_SCRIPTS), 
            #'--script-args="{0}"'.format(TODO),
            '--reason', 
            '--open',
            '--traceroute',
            '-O',
            '--max-retries 1'
        ]
        self.__scan(parameters, suffix='tcp services')


    def scan_udp_ports(self, ports='-', topports=None):
        if topports:
            port_specs = '--top-ports {0}'.format(topports)
        else:
            port_specs = '-p "{0}"'.format(ports)
        parameters = [
            '-Pn',
            '-sU',
            port_specs,
            '-sV',
            '--reason', 
            '--open',
            '--traceroute',
            '-O',
            '--max-retries 1',
            '--min-rate 500'
        ]
        self.__scan(parameters, suffix='udp ports')

    def scan_udp_services(self, ports='-', topports=None):
        if topports:
            port_specs = '--top-ports {0}'.format(topports)
        else:
            port_specs = '-p "{0}"'.format(ports)
        parameters = [
            '-Pn',
            '-sU',
            port_specs,
            '-sV',
            '--script "{0}"'.format(self.__DEFAULT_SERVICE_SCRIPTS), 
            #'--script-args="{0}"'.format(TODO),
            '--reason', 
            '--open',
            '--traceroute',
            '-O',
            '--max-retries 1',
            '--min-rate 500'
        ]
        self.__scan(parameters, suffix='udp services')

    def scan_whois(self):
        parameters = [
            '-Pn',
            '-sn',
            '-sV',
            '--script "whois-domain,whois-ip"', 
            '--script-args="whodb=arin+ripe+afrinic"',
        ]
        self.__scan(parameters, suffix='whois')

class Port(object):
    valid_protocols = ["tcp", "udp"]
    def __init__(self, portid, protocol, service='unknown', ssl=False):
        if not isinstance(portid, int):
            raise ValueError('Port is not an integer: {0}.'.format(repr(port)))
        else:
            self.portid = portid
        if protocol not in self.valid_protocols:
            raise ValueError('Protocol value is not a recognised protocol: {0}.'.format(repr(protocol)))
        else:
            self.protocol = protocol
        if not isinstance(service, str):
            raise ValueError('Service is not a string: {0}.'.format(repr(service)))
        else:
            self.service = service
        if not isinstance(ssl, bool):
            raise ValueError('SSL is not a boolean: {0}.'.format(repr(service)))
        else:
            self.ssl = ssl
    
    def __str__(self):
        return self.string()

    def __repr__(self):
        return self.string()
    
    def string(self):
        portid = self.portid
        service = self.service.replace('/','\/')
        protocol = self.protocol
        if self.ssl:
            ssl = 'ssl'
        else:
            ssl = ''
        return "{0}/{1}/{2}/{3}/".format(portid, protocol, service, ssl)
    
    def __eq__(self, other):
        if self.portid != other.portid:
            return False
        if self.protocol != other.protocol:
            return False
        if self.service != other.service:
            return False
        if self.ssl != other.ssl:
            return False
        return True

class Ports(object):
    def __init__(self):
        self.ports = []

    def add_port(self, port):
        if type(port) is not Port:
            raise ValueError('Given parameter is not of type Port')
        else:
            i = self.indexof(port)
            if i >= 0:
                self.ports[i] = port
            else:
                self.ports += [port]

    def indexof(self, port):
        i = 0
        for p in self.ports:
            if (p.portid == port.portid) and (p.protocol == port.protocol):
                return i
            i += 1
        return -1

    def del_port(self, port):
        i = self.indexof(port)
        if i >= 0:
            self.ports.pop(i)
        else:
            raise IndexError('Given port not in the list.')

    def __contains__(self, port):
        if type(port) is not Port:
            raise ValueError('Given parameter is not of type Port')
        else:
            if self.indexof(port) >= 0:
                return True
        return False

    def __iter__(self):
        return iter(self.ports)

    def __repr__(self):
        return self.string()

    def __str__(self):
        return self.string()

    def string(self):
        return ', '.join([repr(p) for p in self.ports])

    def filter(self, what):
        result = Ports()
        if isinstance(what, int):
            for p in self.ports:
                if what == p.portid:
                    result.add_port(p)
        elif isinstance(what, str):
            if what.upper() == 'SSL':
                for p in self.ports:
                    if p.ssl:
                        result.add_port(p)
            else:    
                for p in self.ports:
                    if what.upper() in p.service.upper():
                        result.add_port(p)
        return result