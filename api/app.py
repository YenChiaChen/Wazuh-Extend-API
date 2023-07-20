import utils
import pandas as pd
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route('/api/hids/<agentID>/os', methods=['GET'])
def check_os_version(agentID):
    return utils.checkOSVersion(agentID)

@app.route('/api/hids/<agentID>/patches' , methods=['GET'])
def check_patch_version(agentID):
    return utils.checkPatchesVersion(agentID)

@app.route('/api/hids/<agentID>/firewall' , methods=['GET'])
def check_firewall_status(agentID):
    return utils.checkFirewallStatus(agentID)

@app.route('/api/hids/<agentID>/antivirus' , methods=['GET'])
def check_antivirus_status(agentID):
    return utils.checkAntiVirusStatus(agentID)

@app.route('/api/hids/<agentID>/account' , methods=['GET'])
def check_account_management(agentID):
    return utils.checkAccountManagement(agentID)

@app.route('/api/hids/<agentID>/evaluation/detail' , methods=['GET'])
def check_all_status(agentID):
    return utils.checkCombineStatus(agentID)

@app.route('/api/hids/<agentID>/evaluation')
def get_evaluation(agentID):
    return utils.checkComnineStatusSimple(agentID)

@app.route('/api/hids/criteria' , methods=['GET'])
def get_criteria():
    return utils.getCriteria()

@app.route('/api/hids/os', methods=['PUT'])
def update_os_file():
    return utils.update_os_file()
@app.route('/api/hids/patch', methods=['PUT'])
def update_patch_file():
    return utils.update_patch_file()

@app.route('/api/hids/criteria' , methods=['POST'])
def set_criteria():
    data = request.json
    required_fields = ['os', 'firewall', 'antivirus', 'account']
    for field in required_fields:
        if field not in data:
            return f"Field '{field}' is missing in the payload", 400
    df = pd.DataFrame(data, index=[0])
    df.to_csv('weights.csv', index=False)
    return  jsonify({"msg":'Weight set and saved successfully'})


if __name__ == "__main__":
    app.run(debug=True)