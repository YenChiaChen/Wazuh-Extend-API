import auth
import re
import config
import requests
import windowsVersionWebCrawler
import pandas as pd
from elasticsearch import Elasticsearch

def getAgentVersion(agentID):
    token = auth.getWazuhAPIKey()
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{config.WAZUH_API_URL}/syscollector/{agentID}/os"
    response = requests.get(url, headers=headers, verify=False)
    data = response.json()
    try:
        return data['data']['affected_items'][0]['os']
    except (KeyError, IndexError):
        return None, "Unable to retrieve version."
    

def isAgentOSVersionStillSupport(agentID):
    osData = getAgentVersion(agentID)
    osType = osData['name']
    result = re.search(r'\d+\s(.+)', osType)
    parsed_osType = None
    if result:
        parsed_osType = result.group(1)
    
    if parsed_osType == None:
        return 'Error: Can not read agent OS version :' + osType 
    
    try: 
        df = pd.read_csv('Windows_Support_Release.csv')
    except:
        windowsVersionWebCrawler.getWindowsSupportRelease()
        df = pd.read_csv('Windows_Support_Release.csv')
    
    supported = df[
        (df['Major'] == float(osData['major'])) &
        (df['Specific'] == osData['display_version']) &
        ((df['EType'] == 1) if parsed_osType in config.ENTERPRISE else (df['EType'] == 0)) &
        ((df['HType'] == 1) if parsed_osType in config.HOME else (df['HType'] == 0)) &
        ((df['LTS'] == 1) if parsed_osType in config.LTS else (df['LTS'] == 0))
    ]

    try:
        return sum(supported['Active Support']) + sum(supported['Security Support'])
    except:
        return 0
    

def isAgentPatchesNewest(agentID):
    osData = getAgentVersion(agentID)
    targetVersion = osData['build']
    target_prefix = int(targetVersion.split('.')[0])
    target_code = int(targetVersion.split('.')[1])
    version_found = False

    try:
        df = pd.read_csv('Windows_Patches_Update.csv')
    except:
        windowsVersionWebCrawler.getWindowsPatchesUpdate
        df = pd.read_csv('Windows_Support_Release.csv')

    for index, row in df.iterrows():
        version = str(row['Build'])
        availability_date = row['Availability Date']
        prefix = int(version.split('.')[0])
        code = int(version.split('.')[1])

        if prefix == target_prefix and code > target_code:
            return 0

    return 1

def getAgentAllAvailablePatches(agentID):
    osData = getAgentVersion(agentID)
    targetVersion = osData['build']
    target_prefix = int(targetVersion.split('.')[0])
    target_code = int(targetVersion.split('.')[1])
    version_found = False
    availablePatches = []
    availableDates = []

    try:
        df = pd.read_csv('Windows_Patches_Update.csv')
    except:
        windowsVersionWebCrawler.getWindowsPatchesUpdate
        df = pd.read_csv('Windows_Support_Release.csv')

    for index, row in df.iterrows():
        version = str(row['Build'])
        availability_date = row['Availability Date']
        prefix = int(version.split('.')[0])
        code = int(version.split('.')[1])

        if prefix == target_prefix and code > target_code:
            version_found = True
            availablePatches.append(version)
            availableDates.append(availability_date)

    if version_found == False:
        return None
    else:
        return pd.DataFrame({'patch_version': availablePatches, 'release_date': availableDates})
    

def restartAgent():
    token = auth.getWazuhAPIKey()
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{config.WAZUH_API_URL}/agents/restart"
    response = requests.put(url, headers=headers, verify=False)
    return response

def getSCAResult(agentID):
    token = auth.getWazuhAPIKey()
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{config.WAZUH_API_URL}/sca/{agentID}"
    response = requests.get(url, headers=headers, verify=False)
    data = response.json()
    try:
        return data
    except (KeyError, IndexError):
        return None, "Unable to retrieve SCA result."
    
def getSCAPolicy(agentID, policyID):
    token = auth.getWazuhAPIKey()
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{config.WAZUH_API_URL}/sca/{agentID}/checks/{policyID}"
    response = requests.get(url, headers=headers, verify=False)
    data = response.json()
    try:
        return data
    except (KeyError, IndexError):
        return None, "Unable to retrieve SCA result."
    
def find_registry(json_data, desired_registry):
    for entry in json_data:
        try:
            if entry['registry'] == desired_registry:
                if entry['result'] == 'passed':
                    return 1
                else:
                    return 0
        except:
            continue
    return 'None'


def checkFireWallStatus(agentID):
    policyID = ''
    try:
        policyID = getSCAResult(agentID)['data']['affected_items'][0]['policy_id']
    except:
        return None, "Unable to get policy ID"
    
    policyData = getSCAPolicy(agentID, policyID)['data']['affected_items']
    result = []
    result.append(find_registry(policyData, 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'))
    result.append(find_registry(policyData, 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'))
    result.append(find_registry(policyData, 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'))

    return result

def checkAccountManagement(agentID):
    policyID = ''
    try:
        policyID = getSCAResult(agentID)['data']['affected_items'][0]['policy_id']
    except:
        return None, "Unable to get policy ID"
    
    policyData = getSCAPolicy(agentID, policyID)['data']['affected_items']
    result = []
    for policy in policyData:
        try:
            if policy['command'] == 'net.exe accounts':
                if policy['result'] == 'passed':
                    result.append({"policy_title" : policy['title'], "checked" : 1})
                else:
                    result.append({"policy_title" : policy['title'], "checked" : 0})
        except:
            continue
    return result

def accountManagementSimplfy(data):
    result = {}
    for i, item in enumerate(data):
        result[f'account_criteria_{i}'] = item['checked']
    return result  

    
def checkAntivirusRealtime(agentID):
    es = Elasticsearch([config.ELASTIC_API_URL], http_auth=(config.ELASTIC_ACCOUNT, config.ELASTIC_PASSWORD),  verify_certs=False)
    query = {
      "size": 10,
      "query": {
        "bool": {
          "must": [
            {
              "term": {
                "agent.id": agentID
              }
            },
            {
              "terms": {
                "rule.id": ["62152", "62151"]
              }
            }
          ]
        }
      },
      "sort": [
        {
          "timestamp": {
            "order": "desc"
          }
        }
      ]
    }
    response = es.search(index='wazuh-alerts-4.x-*', body=query)
    try:
        if response['hits']['hits'][0]['_source']['rule']['id'] == '62151':
            return 1
        else: return 0
    except:
        return 1

def checkAntivirusScanMalware(agentID):
    es = Elasticsearch([config.ELASTIC_API_URL], http_auth=(config.ELASTIC_ACCOUNT, config.ELASTIC_PASSWORD),  verify_certs=False)
    query = {
      "size": 10,
      "query": {
        "bool": {
          "must": [
            {
              "term": {
                "agent.id": agentID
              }
            },
            {
              "terms": {
                "rule.id": ["62156", "62157"]
              }
            }
          ]
        }
      },
      "sort": [
        {
          "timestamp": {
            "order": "desc"
          }
        }
      ]
    }
    response = es.search(index='wazuh-alerts-4.x-*', body=query)
    try:
        if response['hits']['hits'][0]['_source']['rule']['id'] == '62156':
            return 1
        else: return 0
    except:
        return 1
    
def checkAntivirusScanViruses(agentID):
    es = Elasticsearch([config.ELASTIC_API_URL], http_auth=(config.ELASTIC_ACCOUNT, config.ELASTIC_PASSWORD),  verify_certs=False)
    query = {
      "size": 10,
      "query": {
        "bool": {
          "must": [
            {
              "term": {
                "agent.id": agentID
              }
            },
            {
              "terms": {
                "rule.id": ["62158", "62159"]
              }
            }
          ]
        }
      },
      "sort": [
        {
          "timestamp": {
            "order": "desc"
          }
        }
      ]
    }
    response = es.search(index='wazuh-alerts-4.x-*', body=query)
    try:
        if response['hits']['hits'][0]['_source']['rule']['id'] == '62158':
            return 1
        else: return 0
    except:
        return 1

    