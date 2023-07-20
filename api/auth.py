import requests
import json
from config import WAZUH_API_ACCOUNT, WAZUH_API_PASSWORD, WAZUH_API_URL

def getWazuhAPIKey():
    try:
        response = requests.post(WAZUH_API_URL + "/security/user/authenticate", 
                            auth=(WAZUH_API_ACCOUNT, WAZUH_API_PASSWORD), verify=False)
        return json.loads(response.content.decode("utf-8"))['data']['token']
    except:
        return None