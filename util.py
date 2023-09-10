import hmac
import hashlib
import os

secret = os.environ.get("WEBHOOK_SECRET")

def verify_signature(request):

    # encode secet
    byte_key = secret.encode()
    
    # create hmac digest
    digest = hmac.new( byte_key, request.data, hashlib.sha256 ).hexdigest()
    signature = f'sha256={digest}'

    # compare signatures
    return signature == request.headers['x-hub-signature']
