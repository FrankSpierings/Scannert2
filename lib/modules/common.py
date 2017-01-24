import re
import os
import configparser

def target_to_filename(target):
    return re.sub('[^a-zA-Z0-9-_.]', '_', target)

def get_config():
	__dir__ = os.path.dirname(os.path.realpath(__file__))
	config_file = os.path.join(__dir__, '../../config/scannert.conf')
	config = configparser.ConfigParser()
	print(config_file)
	config.read(config_file)
	return config