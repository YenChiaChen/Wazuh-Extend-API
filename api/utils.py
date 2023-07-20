import deviceAnalysis
import pandas as pd
from flask import jsonify
import windowsVersionWebCrawler

def checkOSVersion(agentID):
    try:
        OSData = deviceAnalysis.getAgentVersion(agentID)
        activeSupport = 0
        securitySupport = 0
        supportPoint = deviceAnalysis.isAgentOSVersionStillSupport(agentID)

        if supportPoint == 2:
            activeSupport = 1
            securitySupport = 1
        elif supportPoint == 1:
            securitySupport = 1

        return jsonify({
                'agent_id' : agentID,
                'os_name' : OSData['name'],
                'os_version' : OSData['version'],
                'is_active_support' : activeSupport,
                'is_security_support' : securitySupport
            })
    except Exception as e:
        return jsonify({
            'Agent ID' : agentID,
            'Error Message' : str(e)
        }), 500
    

def checkPatchesVersion(agentID):
    try:
        isNewestPatch = deviceAnalysis.isAgentPatchesNewest(agentID)
        if isNewestPatch == True:
            return jsonify({
                'agent_id' : agentID,
                'is_newest_patch' : isNewestPatch,
                'updates' : []
            })
        else:
            updates_list = deviceAnalysis.getAgentAllAvailablePatches(agentID)
            updates_list = updates_list.to_dict('records')
            return jsonify({
                'agent_id' : agentID,
                'is_newest_patch' : isNewestPatch,
                'updates' : updates_list
            })
    except Exception as e:
        return jsonify({
            'Agent ID' : agentID,
            'Error Message' : str(e)
        }), 500
    
def checkFirewallStatus(agentID):
    try:
        fireWallStatus = deviceAnalysis.checkFireWallStatus(agentID)
        return jsonify({
            'agent_id' : agentID,
            'firewall_status' : [
                {
                    "domain_firewall" : fireWallStatus[0],
                    "private_firewall" : fireWallStatus[1],
                    "public_firewall" : fireWallStatus[2]
                }
            ]
        })
    except Exception as e:
        return jsonify({
            'Agent ID' : agentID,
            'Error Message' : str(e)
        }), 500

def checkAntiVirusStatus(agentID):
    try:
        realtimeStatus = deviceAnalysis.checkAntivirusRealtime(agentID)
        malwareStatus = deviceAnalysis.checkAntivirusScanMalware(agentID)
        virusStatus = deviceAnalysis.checkAntivirusScanViruses(agentID)
        return jsonify({
            'agent_id' : agentID,
            'antivirus_status' : [
                {
                    "realtime_scan" : realtimeStatus,
                    "malware_scan" : malwareStatus,
                    "viruses_scan" : virusStatus
                }
            ]
        })
    except Exception as e:
        return jsonify({
            'Agent ID' : agentID,
            'Error Message' : str(e)
        }), 500
    
def checkAccountManagement(agentID):
    try:
        accountStatus = deviceAnalysis.checkAccountManagement(agentID)
        return jsonify({
            'agent_id' : agentID,
            'account_stauts': accountStatus
        })
    except Exception as e:
        return jsonify({
            'Agent ID' : agentID,
            'Error Message' : str(e)
        }), 500


def checkCombineStatus(agentID):
    try:
        OSData = deviceAnalysis.getAgentVersion(agentID)
        activeSupport = 0
        securitySupport = 0
        supportPoint = deviceAnalysis.isAgentOSVersionStillSupport(agentID)

        if supportPoint == 2:
            activeSupport = 1
            securitySupport = 1
        elif supportPoint == 1:
            securitySupport = 1

        isNewestPatch = deviceAnalysis.isAgentPatchesNewest(agentID)
        fireWallStatus = deviceAnalysis.checkFireWallStatus(agentID)
        realtimeStatus = deviceAnalysis.checkAntivirusRealtime(agentID)
        malwareStatus = deviceAnalysis.checkAntivirusScanMalware(agentID)
        virusStatus = deviceAnalysis.checkAntivirusScanViruses(agentID)
        accountStatus = deviceAnalysis.checkAccountManagement(agentID)
        updates_list = deviceAnalysis.getAgentAllAvailablePatches(agentID)
        updates_list = updates_list.to_dict('records')

        return jsonify({
            "agent_id" : agentID,
            "analysis_status":[
                {
                    "os":[{
                    'os_name' : OSData['name'],
                    'os_version' : OSData['version'],
                    'is_active_support' : activeSupport,
                    'is_security_support' : securitySupport
                }]},
                {
                    "patch":[{
                    'is_newest_patch' : isNewestPatch,
                    'updates' : updates_list
                }]},
                {
                    'firewall_status' : [{
                    "domain_firewall" : fireWallStatus[0],
                    "private_firewall" : fireWallStatus[1],
                    "public_firewall" : fireWallStatus[2]
                }]},
                {
                    'antivirus_status' : [{
                    "realtime_scan" : realtimeStatus,
                    "malware_scan" : malwareStatus,
                    "viruses_scan" : virusStatus
                }]},
                {
                    "account_status" :accountStatus
                }
            ]
        })
        
    except Exception as e:
        return jsonify({
            'Agent ID' : agentID,
            'Error Message' : str(e)
        }), 500

def getCriteria():
    try:
        df = pd.read_csv('weights.csv')
        weights = df.iloc[0].to_dict()
    except:
        weights = {
            'os': 1.0,
            'firewall': 1.0,
            'antivirus': 1.0,
            'account': 1.0
        }
        df = pd.DataFrame(weights, index=[0])
        df.to_csv('weights.csv', index=False)     
    
    return jsonify(weights)

def checkComnineStatusSimple(agentID):
    try:
        OSData = deviceAnalysis.getAgentVersion(agentID)
        activeSupport = 0
        securitySupport = 0
        supportPoint = deviceAnalysis.isAgentOSVersionStillSupport(agentID)

        if supportPoint == 2:
            activeSupport = 1
            securitySupport = 1
        elif supportPoint == 1:
            securitySupport = 1

        isNewestPatch = deviceAnalysis.isAgentPatchesNewest(agentID)
        fireWallStatus = deviceAnalysis.checkFireWallStatus(agentID)
        realtimeStatus = deviceAnalysis.checkAntivirusRealtime(agentID)
        malwareStatus = deviceAnalysis.checkAntivirusScanMalware(agentID)
        virusStatus = deviceAnalysis.checkAntivirusScanViruses(agentID)
        accountStatus = deviceAnalysis.checkAccountManagement(agentID)
        accountStatus = deviceAnalysis.accountManagementSimplfy(accountStatus)

        try:
            df = pd.read_csv('weights.csv')
            weights = df.iloc[0].to_dict()
        except:
            weights = {
                'os': 1.0,
                'firewall': 1.0,
                'antivirus': 1.0,
                'account': 1.0
            }
            df = pd.DataFrame(weights, index=[0])
            df.to_csv('weights.csv', index=False) 

        weight_os = weights['os']
        weight_firewall = weights['firewall']
        weight_antivirus = weights['antivirus']
        weight_account = weights['account']

        score_os = (activeSupport + securitySupport + isNewestPatch) / 3
        score_firewall = (fireWallStatus[0] + fireWallStatus[1] + fireWallStatus[2]) / 3
        score_antivirus = (realtimeStatus + malwareStatus + virusStatus) / 3
        score_account = sum(accountStatus.values()) / (len(accountStatus) + 1)
        score_weighted = score_os*weight_os + score_firewall*weight_firewall + score_antivirus*weight_antivirus + score_account*weight_account
        score_weighted = score_weighted / (weight_os + weight_firewall + weight_antivirus + weight_account)
        return jsonify({
            "agent_id": agentID,
            "criteria": [{
                "is_os_active_support": activeSupport,
                "is_os_security_support": securitySupport,
                "is_newest_patch": isNewestPatch,
                "is_domain_firwall_enable": fireWallStatus[0],
                "is_private_firewall_enable": fireWallStatus[1],
                "is_public_firewall_enable": fireWallStatus[2],
                "is_antivirus_realtime_scan_enable": realtimeStatus,
                "is_antivirus_malware_scan_enable": malwareStatus,
                "is_antivirus_viruses_scan_enable": virusStatus,
                **accountStatus
            }],
            "scores": [{
                "weighted" : score_weighted,
                "os": score_os,
                "firewall": score_firewall,
                "antivirus": score_antivirus,
                "account": score_account
            }]
        })

        
    except Exception as e:
        return jsonify({
            'Agent ID' : agentID,
            'Error Message' : str(e)
        }), 500
    

def update_os_file():
    try:
        windowsVersionWebCrawler.getWindowsSupportRelease()
        return jsonify({
            "msg" : "update success"
        })
    except Exception as e:
        return jsonify({
            'Error Message' : str(e)
        }), 500
    
def update_patch_file():
    try:
        windowsVersionWebCrawler.getWindowsPatchesUpdate()
        return jsonify({
            "msg" : "update success"
        })
    except Exception as e:
        return jsonify({
            'Error Message' : str(e)
        }), 500
        