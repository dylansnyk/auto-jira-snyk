# Snyk Webhook Consumer

## Create the Webhook

Latest docs for creating a Snyk Webhook found here: https://snyk.docs.apiary.io/#reference/webhooks/webhook-collection/create-a-webhook

For your convenience, here is the required API call to make:
```
curl --location --request POST 'https://snyk.io/api/v1/org/ORG_ID/webhooks' \
--header 'Authorization: token SNYK_API_TOKEN' \
--header 'Content-Type: application/json' \
--data-raw '{
    "url": "https://your-url-to-consume-event.herokuapp.com/event",
    "secret": "WEBHOOK_SECRET"
}'
```
## Run Snyk Webhook Consumer in Heroku

Sign up / log in to Heroku: https://id.heroku.com/login

Create a new app in Heroku: https://dashboard.heroku.com/new-app

Add your `WEBHOOK_SECRET` config var in the Settings tab of the app in Heroku

Deploy in Heroku by configuring either the CLI or GitHub Deployment Method, found in the Deploy tab of the newly created app in Heroku

Verify the app is running correctly by tailing the logs within Heroku

## Modifying Snyk Webhook Consumer

This repo can be forked, then modify the following section of code. This is where they logic can be added to process the event and connect to other APIs as needed:
https://github.com/dylansnyk/webhook-consumer/blob/6b4d30c194dab41ca99c4954f849981ba54f999e/main.py#L24

## Local Development

Create virtual environment: `python -m venv env`

Activate the environment: `source ./env/bin/activate`

Install dependencies: `pip install -r requirements.txt`

Run application in develop mode: 
```
export FLASK_APP=main
flask run
```
