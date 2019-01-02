"""
See https://www.w3.org/TR/webauthn/#api
"""
import base64

from botocore import xform_name
from chalice import Chalice, Response

from pywarp import RelyingPartyManager
from pywarp.backends import DynamoBackend

app = Chalice(app_name='cwa')
app.debug = True

@app.route('/')
def index():
    with open("chalicelib/index.html") as fh:
        return Response(status_code=200,
                        headers={"Content-Type": "text/html"},
                        body=fh.read())

@app.route('/getCredentialCreateOptions', methods=["POST"])
def get_credential_create_options():
    rp.rp_id = app.current_request.context["domainName"]
    return rp.get_registration_options(**app.current_request.json_body)

@app.route('/registerCredential', methods=["POST"])
def register_credential():
    rp.rp_id = app.current_request.context["domainName"]
    req = {xform_name(f): base64.b64decode(app.current_request.json_body[f]) for f in app.current_request.json_body}
    print("registerCredential inputs:", req)
    return rp.register(**req)

@app.route('/getCredentialGetOptions', methods=["POST"])
def get_credential_get_options():
    rp.rp_id = app.current_request.context["domainName"]
    return rp.get_authentication_options(**app.current_request.json_body)

@app.route('/verifyAssertion', methods=["POST"])
def verify_assertion():
    rp.rp_id = app.current_request.context["domainName"]
    req = {xform_name(f): base64.b64decode(app.current_request.json_body[f]) for f in app.current_request.json_body}
    print("verify_assertion inputs:", req)
    return rp.verify(**req)

rp = RelyingPartyManager("PyWARP demo", credential_storage_backend=DynamoBackend())
