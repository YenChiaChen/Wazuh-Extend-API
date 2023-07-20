import requests
import re
import pandas as pd
import pandas as pd
import config
from bs4 import BeautifulSoup

def supportStateTrans(color):
    if color and 'bg-green-000' in color:
        return 1
    elif color and 'bg-red-000' in color:
        return 0
    elif color and 'bg-yellow-200' in color:
        return 2
    else:
        return -1
    
def releaseToVersion(release):
    try:
        major_version_match = re.search(r"Windows (\d+)", release)
        major_version = major_version_match.group(1) if major_version_match else None

        specific_version_match = re.search(r"version (\w+)", release)
        specific_version = specific_version_match.group(1) if specific_version_match else None  
        return major_version, specific_version
    except:
        return 'None'
    

def getWindowsSupportRelease():
    response = requests.get(config.WINDOWS_SUPPORT_URL)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")

    table = soup.find('table', {'class': 'lifecycle'})
    data_list = [] 
    for row in table.find_all('tr'):
        cells = row.find_all('td')
        if len(cells) >= 4:
            releaseText = cells[0].text.strip()
            mversion, release = releaseToVersion(releaseText) 
            EType = 1 if '(E)' in releaseText else 0
            HType = 1 if '(W)' in releaseText else 0
            LType = 1 if '(LTS)' in releaseText else 0
            activeSupport = cells[2].get('class')
            securitySupport = cells[3].get('class')
            activeSupport = activeSupport[0] if activeSupport else None
            securitySupport = securitySupport[0] if securitySupport else None
            activeSupport = supportStateTrans(activeSupport)
            securitySupport = supportStateTrans(securitySupport)

            if release != 'None':
                data_list.append((mversion, release, activeSupport, securitySupport, EType, HType, LType))
    df = pd.DataFrame(data_list, columns=['Major', 'Specific','Active Support', 'Security Support', 'EType', 'HType', 'LTS'])
    df.to_csv('Windows_Support_Release.csv', index=False)


def getWindowsPatchesUpdate():
    response = requests.get(config.WINDOWS10_RELEASE_URL)
    soup = BeautifulSoup(response.content, "html.parser")

    availability_dates = []
    builds = []
    kb = [] 

    table_id = 0    

    while True:
        current_table_id = f"historyTable_{table_id}"

        table = soup.find("table", {"id": current_table_id})

        if table is None:
            break   

        rows = table.find_all("tr")[1:] 

        for row in rows:
            data = row.find_all("td")
            availability_date = data[1].text.strip()
            build = data[2].text.strip()
            kbArticle = data[3].text.strip()    

            availability_dates.append(availability_date)
            builds.append(build)
            kb.append(kbArticle)    

        table_id += 1   

    data = {"Availability Date": availability_dates, "Build": builds, "KB Article": kb}
    df = pd.DataFrame(data)
    df.to_csv('Windows_Patches_Update.csv', index=False)
