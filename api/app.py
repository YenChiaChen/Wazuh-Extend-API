import utils
import config
import requests
import pandas as pd
from flask import Flask, jsonify, request
from flasgger import Swagger
from apscheduler.schedulers.background import BackgroundScheduler

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "title": "Kioxia Device Risk API",
    "version": "1.0.0",
    "description": "Designed to extend the capabilities of the Wazuh Manager by focusing on hardware security analysis. By integrating with the existing Wazuh infrastructure, it provides detailed insights into various aspects of security, including operating system versions, patch management, firewall configurations, antivirus status, and account policies.",
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/swagger/"
}

app = Flask(__name__)
swagger = Swagger(app, config=swagger_config)

@app.route('/api/hids/<agentID>/os', methods=['GET'])
def check_os_version(agentID):
    """
    Retrieve OS Version along with support information
    ---
    parameters:
      - name: agentID
        in: path
        type: string
        required: trueF
        description: ID of the agent
    responses:
      200:
        description: A JSON object containing OS information
        schema:
          type: object
          properties:
            agent_id:
              type: string
            os_name:
              type: string
            os_version:
              type: string
            is_active_support:
              type: integer
            is_security_support:
              type: integer
      500:
        description: An error message if an exception occurs
        schema:
          type: object
          properties:
            Agent ID:
              type: string
            Error Message:
              type: string
    """
    return utils.checkOSVersion(agentID)

@app.route('/api/hids/<agentID>/patches' , methods=['GET'])
def check_patch_version(agentID):
    """
    Retrieve Patch Version Information
    ---
    parameters:
      - name: agentID
        in: path
        type: string
        required: true
        description: ID of the agent
    responses:
      200:
        description: Information about the newest patch and available updates
        schema:
          type: object
          properties:
            agent_id:
              type: string
            is_newest_patch:
              type: integer
            updates:
              type: array
              items:
                type: object
                properties:
                  patch_version:
                    type: string
                  release_date:
                    type: string
              description: List of available updates, can be null
      500:
        description: Error retrieving information
        schema:
          type: object
          properties:
            Agent ID:
              type: string
            Error Message:
              type: string
    """
    return utils.checkPatchesVersion(agentID)

@app.route('/api/hids/<agentID>/firewall' , methods=['GET'])
def check_firewall_status(agentID):
    """
    Retrieve Firewall Status
    ---
    parameters:
      - name: agentID
        in: path
        type: string
        required: true
        description: ID of the agent
    responses:
      200:
        description: Firewall status for the agent
        schema:
          type: object
          properties:
            agent_id:
              type: string
            firewall_status:
              type: array
              items:
                type: object
                properties:
                  domain_firewall:
                    type: integer
                  private_firewall:
                    type: integer
                  public_firewall:
                    type: integer
      500:
        description: Error retrieving the firewall status
        schema:
          type: object
          properties:
            Agent ID:
              type: string
            Error Message:
              type: string
    """
    return utils.checkFirewallStatus(agentID)

@app.route('/api/hids/<agentID>/antivirus' , methods=['GET'])
def check_antivirus_status(agentID):
    """
    Check Antivirus Status
    ---
    parameters:
      - name: agentID
        in: path
        type: string
        required: true
        description: ID of the agent
    responses:
      200:
        description: Antivirus Status
        schema:
          type: object
          properties:
            agent_id:
              type: string
            antivirus_status:
              type: array
              items:
                type: object
                properties:
                  realtime_scan:
                    type: integer
                  malware_scan:
                    type: integer
                  viruses_scan:
                    type: integer
      500:
        description: Error
        schema:
          type: object
          properties:
            Agent ID:
              type: string
            Error Message:
              type: string
    """
    return utils.checkAntiVirusStatus(agentID)

@app.route('/api/hids/<agentID>/account' , methods=['GET'])
def check_account_management(agentID):
    """
    Retrieve Account Management Status
    ---
    parameters:
      - name: agentID
        in: path
        type: string
        required: true
        description: ID of the agent
    responses:
      200:
        description: Account Management Status
        schema:
          type: object
          properties:
            agent_id:
              type: string
              example: "001"
            account_stauts:
              type: array
              items:
                type: object
                properties:
                  checked:
                    type: integer
                    example: 0
                  policy_title:
                    type: string
                    example: "Ensure 'Enforce password history' is set to '24 or more password(s)'."
      500:
        description: Error Message
        schema:
          type: object
          properties:
            Agent ID:
              type: string
            Error Message:
              type: string
    """
    return utils.checkAccountManagement(agentID)

@app.route("/api/hids/<agentID>/evaluation/auto", methods=['POST'])
def label_agent():
    data = utils.deviceRiskLabeling('003')
    url = config.PDP_URL
    headers = {'Content-type': 'application/json'}
    response = requests.post(url, json=data.json, headers=headers)
    if response.status_code == 200:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': response.text}), response.status_code

@app.route('/api/hids/<agentID>/evaluation/detail' , methods=['GET'])
def check_all_status(agentID):
    """
    Retrieve a Combined Analysis of Agent
    ---
    parameters:
      - name: agentID
        in: path
        type: string
        required: true
        description: ID of the agent
    responses:
      200:
        description: Combined Analysis of Agent including OS, Patch, Firewall, and Antivirus status
        schema:
          type: object
          properties:
            agent_id:
              type: string
            analysis_status:
              type: array
              items:
                type: object
                properties:
                  os:
                    type: array
                    items:
                      $ref: '#/definitions/OSStatus'
                  patch:
                    type: array
                    items:
                      $ref: '#/definitions/PatchStatus'
                  firewall_status:
                    type: array
                    items:
                      $ref: '#/definitions/FirewallStatus'
                  antivirus_status:
                    type: array
                    items:
                      $ref: '#/definitions/AntivirusStatus'
                  account_status:
                    $ref: '#/definitions/AccountStatus'
      500:
        description: Error Message
        schema:
          type: object
          properties:
            Agent ID:
              type: string
            Error Message:
              type: string
    definitions:
         OSStatus:
           type: object
           properties:
             os_name:
               type: string
             os_version:
               type: string
             is_active_support:
               type: integer
             is_security_support:
               type: integer
         PatchStatus:
           type: object
           properties:
             is_newest_patch:
               type: integer
             updates:
               type: array
               items:
                 type: object
                 properties:
                   patch_version:
                     type: string
                   release_date:
                     type: string
               description: List of available updates, can be null
         FirewallStatus:
           type: object
           properties:
             domain_firewall:
               type: integer
             private_firewall:
               type: integer
             public_firewall:
               type: integer
         AntivirusStatus:
           type: object
           properties:
             realtime_scan:
               type: integer
             malware_scan:
               type: integer
             viruses_scan:
               type: integer
         AccountStatus:
           type: object
           properties:
             account_status:
               type: array
               items:
                 type: object
                 properties:
                   checked:
                     type: integer
                     example: 0
                   policy_title:
                     type: string
                     example: "Ensure 'Enforce password history' is set to '24 or more password(s)'."
    """
    return utils.checkCombineStatus(agentID)

@app.route('/api/hids/<agentID>/evaluation')
def get_evaluation(agentID):
    """
    Retrieve a Simplified Combined Analysis of Agent
    ---
    parameters:
      - name: agentID
        in: path
        type: string
        required: true
        description: ID of the agent
    responses:
      200:
        description: A JSON object containing simplified criteria analysis and scores
        schema:
          type: object
          properties:
            agent_id:
              type: string
            criteria:
              type: array
              items:
                type: object
                properties:
                  is_os_active_support:
                    type: integer
                  is_os_security_support:
                    type: integer
                  is_newest_patch:
                    type: integer
                  is_domain_firewall_enable:
                    type: integer
                  is_private_firewall_enable:
                    type: integer
                  is_public_firewall_enable:
                    type: integer
                  is_antivirus_realtime_scan_enable:
                    type: integer
                  is_antivirus_malware_scan_enable:
                    type: integer
                  is_antivirus_viruses_scan_enable:
                    type: integer
                  account_criteria_0:
                    type: integer
                  account_criteria_1:
                    type: integer
                  account_criteria_2:
                    type: integer
                  account_criteria_3:
                    type: integer
                  account_criteria_4:
                    type: integer
                  account_criteria_5:
                    type: integer
                  account_criteria_6:
                    type: integer
                  account_criteria_7:
                    type: integer
            scores:
              type: array
              items:
                type: object
                properties:
                  weighted:
                    type: number
                  os:
                    type: number
                  firewall:
                    type: number
                  antivirus:
                    type: number
                  account:
                    type: number
      500:
        description: An error message if an exception occurs
        schema:
          type: object
          properties:
            Agent ID:
              type: string
            Error Message:
              type: string
    """
    return utils.checkComnineStatusSimple(agentID)

@app.route('/api/hids/criteria' , methods=['GET'])
def get_criteria():
    """
    Retrieve Criteria Weights
    ---
    responses:
      200:
        description: A JSON object containing criteria weights for different categories
        schema:
          type: object
          properties:
            os:
              type: number
              format: float
              description: Weight for the OS category
            firewall:
              type: number
              format: float
              description: Weight for the Firewall category
            antivirus:
              type: number
              format: float
              description: Weight for the Antivirus category
            account:
              type: number
              format: float
              description: Weight for the Account category
      500:
        description: An error message if an exception occurs
        schema:
          type: object
          properties:
            Error Message:
              type: string
    """
    return utils.getCriteria()

@app.route('/api/hids/os', methods=['PUT'])
def update_os_file():
    """
    Update the OS Support Information
    This endpoint retrieves the newest Windows support information using a web crawler and stores it as a CSV file on the server.
    ---
    responses:
      200:
        description: Successful update message
        schema:
          type: object
          properties:
            msg:
              type: string
      500:
        description: An error message if an exception occurs
        schema:
          type: object
          properties:
            Error Message:
              type: string
    """
    return utils.update_os_file()
@app.route('/api/hids/patch', methods=['PUT'])
def update_patch_file():
    """
    Retrieve and Update the Newest Windows Patch File and stores it as a CSV file on the server.
    ---
    responses:
      200:
        description: A success message indicating that the update was successful
        schema:
          type: object
          properties:
            msg:
              type: string
      500:
        description: An error message if an exception occurs
        schema:
          type: object
          properties:
            Error Message:
              type: string
    """
    return utils.update_patch_file()

@app.route('/api/hids/criteria' , methods=['POST'])
def set_criteria():
    """
    Set the Criteria for Analysis
    ---
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            os:
              type: integer
              description: Weight for OS analysis
            firewall:
              type: integer
              description: Weight for Firewall analysis
            antivirus:
              type: integer
              description: Weight for Antivirus analysis
            account:
              type: integer
              description: Weight for Account analysis
    responses:
      200:
        description: Confirmation that the weights were set and saved successfully
        schema:
          type: object
          properties:
            msg:
              type: string
      400:
        description: An error message if a required field is missing
        schema:
          type: string
    """
    data = request.json
    required_fields = ['os', 'firewall', 'antivirus', 'account']
    for field in required_fields:
        if field not in data:
            return f"Field '{field}' is missing in the payload", 400
    df = pd.DataFrame(data, index=[0])
    df.to_csv('weights.csv', index=False)
    return  jsonify({"msg":'Weight set and saved successfully'})

def run_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(label_agent, 'interval', minutes=5)
    scheduler.start()


if __name__ == "__main__":
    run_scheduler()
    app.run(host='0.0.0.0',port=5000)