# Credentials
import os

WAZUH_API_ACCOUNT =  os.environ.get('WAZUH_ACCOUNT', 'wazuh-wui')
WAZUH_API_PASSWORD = os.environ.get('WAZUH_PASSWORD', 'wazuh-wui')

ELASTIC_ACCOUNT = os.environ.get('ELASTIC_ACCOUNT', 'elastic')
ELASTIC_PASSWORD = os.environ.get('ELASTIC_PASSWORD', 'juYLh1iSDO8TnB9yBOJl')

PDP_URL = os.environ.get('PDP_URL', 'http://localhost:8087')
PDP_ACCOUNT = os.environ.get('PDP_USER', 'admin')
PDP_PASSWORD = os.environ.get('PDP_PASSWORD', 'Kioxia1!')

#URLs
WAZUH_API_URL = os.environ.get('WAZUH_API_URL', 'https://192.168.142.131:55000')
ELASTIC_API_URL = os.environ.get('ELASTIC_API_URL', 'https://192.168.142.131:9200/')



WINDOWS10_RELEASE_URL = "https://learn.microsoft.com/en-us/windows/release-health/release-information"
WINDOWS11_RELEASE_URL = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
WINDOWS_SUPPORT_URL = "https://endoflife.date/windows"

#WindowsVersionName
ENTERPRISE = ['Education', 'Enterprise', 'Pro for Workstations']
HOME = ['Pro', 'Home', 'SE', 'Pro Education']
LTS = ['Enterprise LTSC', 'LTS']
