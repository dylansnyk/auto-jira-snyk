import hmac
import hashlib
import os
import requests
import json

secret = os.environ.get("WEBHOOK_SECRET")
SNYK_TOKEN = os.environ.get("SNYK_TOKEN")
ORG_ID = os.environ.get("ORG_ID")

def verify_signature(request):

    # encode secet
    byte_key = secret.encode()
    
    # create hmac digest
    digest = hmac.new( byte_key, request.data, hashlib.sha256 ).hexdigest()
    signature = f'sha256={digest}'

    # compare signatures
    return signature == request.headers['x-hub-signature']


def create_ticket_from_issue(issue, event):

    url = f"https://api.snyk.io/v1/org/{ORG_ID}/project/{event['project']['id']}/issue/{issue['id']}/jira-issue"

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'token {SNYK_TOKEN}'
    }

    body = json.dumps({
        "fields":  {
            "project": { "key": "DD" },
            "issuetype": { "id": "10005"},
            "summary": issue['id'],
            "description": f"Snyk Vuln DB: {issue['issueData']['url']}",
            "customfield_10038": issue['pkgName'], # package name
            "customfield_10039": event['project']['name'] # project
        }
    })

    response = requests.request("POST", url, headers=headers, data=body)

    return response