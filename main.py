from flask import Flask, jsonify, request
from util import verify_signature

app = Flask(__name__)

@app.route("/healthcheck", methods=['GET'])
def health_check():
    return jsonify({"status": "up"})

@app.route("/event", methods=['POST'])
def consume_event():

    is_valid = verify_signature(request)

    print('event received - is valid:', is_valid)

    # process event only if verified
    if is_valid and request.headers['X-Snyk-Event'] == 'project_snapshot/v0':
        event = request.get_json()

        # log event
        print('event body:', event)

        # process event
        for new_issue in event['newIssues']:
            print('new issue found:', new_issue['id'])

    return jsonify({}), 200
