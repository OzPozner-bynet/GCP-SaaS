import os
import json
import jwt
import requests
from datetime import datetime, timezone

import uuid
#import sys
import pprint

from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# GCP specific imports
from google.cloud import pubsub_v1
from google.oauth2 import service_account
from google.api_core.exceptions import GoogleAPIError
from googleapiclient.discovery import build, build_from_document


# Replace with your actual project ID and topic name
# Consider using environment variables or a config.py for these
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "bynet-public")
PUBSUB_SUBSCRIPTION_NAME = os.environ.get("PUBSUB_SUBSCRIPTION_NAME", "bynet-public-sub") # Subscription name for 'mytopic'
MARKETPLACE_API_SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
MARKETPLACE_API_VERSION = 'v1'
PROCUREMENT_API = 'cloudcommerceprocurement'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", "a_very_secret_key_for_dev") # Change for production!

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

from google.api_core.exceptions import PermissionDenied
from google.cloud import pubsub_v1

#PROJECT_ID = os.environ['GOOGLE_CLOUD_PROJECT']
#PROJECT_ID = os.environ.get("#PROJECT_ID", "bynet-public")


PROJECT_IAM_PAGE = 'https://console.cloud.google.com/iam-admin/iam?project={}'
PROJECT_PUBSUB_PAGE = 'https://console.cloud.google.com/apis/library/pubsub.googleapis.com?project={}'

TOPIC_PROJECT = 'cloudcommerceproc-prod'
#TOPIC_NAME_PREFIX = 'DEMO-'
#SUBSCRIPTION_NAME = 'codelab'

# --- User Management (Simplified for this example) ---
class User(UserMixin):
    def __init__(self, id):
        self.id = id

    @property
    def is_active(self):
        return True # All users are active

    @property
    def is_authenticated(self):
        return True # User is authenticated once logged in

    @property
    def is_anonymous(self):
        return False # Not an anonymous user

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    # In a real app, you'd load user from a database
    if user_id == "admin": # Simple hardcoded user for demonstration
        return User("admin")
    return None

# --- Helper Functions for Account Management ---
ACCOUNT_DIR = 'accounts'
ENTITLEMENTS_DIR = 'entitlements'
os.makedirs(ACCOUNT_DIR, exist_ok=True)
os.makedirs(ENTITLEMENTS_DIR, exist_ok=True)



# New directory for Pub/Sub messages
MESSAGES_DIR = 'messages'
os.makedirs(MESSAGES_DIR, exist_ok=True)

def get_account_path(account_id):
    """
    Constructs the file path for a given account ID.
    Args:
        account_id (str): The unique ID of the account.
    Returns:
        str: The full path to the account's JSON file.
    """
    clean_account_id=clean_gcp_account_id_prefix(account_id)
    if clean_account_id.startswith("providers/bynet-public/accounts/"):
        clean_account_id=clean_account_id[len("providers/bynet-public/accounts/"):]
    return os.path.join(ACCOUNT_DIR, f"{clean_account_id}.json")



def get_entitlement_path(entitlement_id):
    """
    Constructs the file path for a given account ID.
    Args:
        account_id (str): The unique ID of the account.
    Returns:
        str: The full path to the account's JSON file.
    """
    return os.path.join(ENTITLEMENTS_DIR, f"{entitlement_id}.json")

def load_entitlement(entitlement_id):  
    entitlement_path = get_entitlement_path(entitlement_id)
    if os.path.exists(entitlement_path):
        with open(entitlement_path, 'r') as f:
            return json.load(f)
    return None

def load_account(account_id):
    """
    Loads account details from its JSON file.
    Args:
        account_id (str): The unique ID of the account.
    Returns:
        dict or None: The account dictionary if found, otherwise None.
    """
    account_path = get_account_path(clean_gcp_account_id_prefix( account_id))
    print(f"loading path {account_path}")
    if os.path.exists(account_path):
        with open(account_path, 'r') as f:
            return json.load(f)
    return None

def save_account(account_data):
    """
    Saves account details to its JSON file.
    Args:
        account_data (dict): The dictionary containing account details.
    """
    account_id = account_data.get('account_id')

    if not account_id:
        raise ValueError("Account data must contain 'account_id'.")
    account_path = get_account_path(account_id)
    print(f"saving path {account_path}")
    with open(account_path, 'w') as f:
        json.dump(account_data, f, indent=4)

def save_entitlement(entitlement_data):
    """
    Saves entitlement details to its JSON file.
    Args:
        entitlement_data (dict): The dictionary containing account details.
    """
    entitlement_id = entitlement_data.get('id')
    if not entitlement_id:
        raise ValueError("entitlement data must contain 'entitlement_id'.")
    entitlement_path = get_entitlement_path(entitlement_id)
    with open(entitlement_path, 'w') as f:
        json.dump(entitlement_data, f, indent=4)        

def get_all_accounts():
    """
    Retrieves all stored accounts.
    Returns:
        list: A list of dictionaries, each representing an account.
    """
    accounts = []
    for filename in os.listdir(ACCOUNT_DIR):
        if filename.endswith(".json"):
            account_id = filename.replace(".json", "")
            account = load_account(account_id)
            if account:
                accounts.append(account)
    return accounts

def get_all_entitlements_from_dir()  -> list[str]:
    """
    Retrieves all stored accounts.
    Returns:
        list: A list of dictionaries, each representing an account.
    """
    entitlements = []
    for filename in os.listdir(ENTITLEMENTS_DIR):
        if filename.endswith(".json"):
            entitlement_id = filename.replace(".json", "")
            entitlement = load_entitlement(entitlement_id)
            if entitlement:
                entitlements.append(entitlement)
    return entitlements


def save_pubsub_message(message_data):
    """
    Saves a Pub/Sub message to a JSON file in the messages directory.
    Args:
        message_data (dict): The dictionary containing the Pub/Sub message details.
    """
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    message_id = message_data.get('message_id', uuid.uuid4().hex)
    filename = f"pubsub_message_{timestamp}_{message_id}.json"
    filepath = os.path.join(MESSAGES_DIR, filename)
    with open(filepath, 'w') as f:
        json.dump(message_data, f, indent=4)
    print(f"Saved Pub/Sub message to {filepath}")

def load_all_pubsub_messages():
    """
    Loads all stored Pub/Sub messages from the messages directory.
    Returns:
        list: A list of dictionaries, each representing a stored Pub/Sub message.
    """
    messages = []
    for filename in os.listdir(MESSAGES_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(MESSAGES_DIR, filename)
            try:
                with open(filepath, 'r') as f:
                    messages.append(json.load(f))
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON from {filepath}: {e}")
            except Exception as e:
                print(f"Error reading file {filepath}: {e}")
    # Sort messages by timestamp, newest first
    messages.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return messages







# --- GCP Marketplace API Client (Placeholder) ---
def get_marketplace_api_client():
    """
    Initializes and returns a Google Cloud Marketplace API client.
    This will require proper authentication setup (e.g., Service Account).
    For a real application, consider using google-auth library for more robust authentication.
    """
    # Placeholder for actual API client initialization.
    # In a real scenario, you'd use service account credentials.
    from google.oauth2 import service_account
    credentials = service_account.Credentials.from_service_account_file( os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") )
    #
    DISCOVERY_SERVICE_URL = 'https://cloudcommerceprocurement.googleapis.com/$discovery/rest?version=v1'
    client = build('cloudcommerceprocurement', MARKETPLACE_API_VERSION, credentials=credentials, discoveryServiceUrl=DISCOVERY_SERVICE_URL)
    return client
    # flash("Marketplace API client is a placeholder. Needs real implementation.", "warning")
    # return None # Return None for now

def approve_entitlement(entitlement_name):
    """
    Sends an API call to approve a Google Cloud Marketplace entitlement.
    Args:
        entitlement_name (str): The full resource name of the entitlement (e.g., 'projects/YOUR_PROJECT/entitlements/ENTITLEMENT_ID').
    Returns:
        bool: True if approval was successful, False otherwise.
    """
    print(f"Attempting to approve entitlement: {entitlement_name}")
    client = get_marketplace_api_client()
    if not client:
        print("Marketplace API client not initialized.")
        return False
    try:
        # This is a conceptual call. Refer to GCP Marketplace Procurement API documentation.
        # Example: client.projects().entitlements().approve(name=entitlement_name, body={"reason": "New subscription"}).execute()
        print(f"Simulating approval for {entitlement_name}")
        # In a real scenario, handle the API response
        return True
    except GoogleAPIError as e:
        print(f"Error approving entitlement {entitlement_name}: {e}")
        return False

def reject_entitlement(entitlement_name):
    """
    Sends an API call to reject a Google Cloud Marketplace entitlement.
    Args:
        entitlement_name (str): The full resource name of the entitlement.
    Returns:
        bool: True if rejection was successful, False otherwise.
    """
    print(f"Attempting to reject entitlement: {entitlement_name}")
    client = get_marketplace_api_client()
    if not client:
        print("Marketplace API client not initialized.")
        return False
    try:
        # Example: client.projects().entitlements().reject(name=entitlement_name, body={"reason": "Duplicate account"}).execute()
        print(f"Simulating rejection for {entitlement_name}")
        return True
    except GoogleAPIError as e:
        print(f"Error rejecting entitlement {entitlement_name}: {e}")
        return False

def send_metering_usage_report(account_id, usage_data):
    """
    Sends a metering usage report to Google Cloud Marketplace.
    This is highly dependent on your product's metering dimensions.
    Args:
        account_id (str): The ID of the account to bill.
        usage_data (dict): A dictionary containing metering dimensions and values.
                          Example: {'metric_name': {'units': 100}}
    Returns:
        bool: True if the report was sent successfully, False otherwise.
        str: The billing message ID from GCP if successful, None otherwise.
    """
    print(f"Sending metering usage report for account: {account_id}")
    client = get_marketplace_api_client()
    if not client:
        print("Marketplace API client not initialized.")
        return False, None
    try:
        # This is a conceptual call. Refer to GCP Marketplace Producer API documentation for metering.
        # Example for a hypothetical 'user_count' metric:
        # report_body = {
        #     "meteringTime": datetime.utcnow().isoformat() + "Z",
        #     "metricGroup": [
        #         {
        #             "metric": "user_count",
        #             "value": usage_data.get('user_count', 0)
        #         }
        #     ]
        # }
        # response = client.projects().services().report(
        #     serviceId='YOUR_SERVICE_ID', projectId=GCP_PROJECT_ID, body=report_body
        # ).execute()
        # metering_id = response.get('name') # or similar field
        metering_id = f"mock-billing-{uuid.uuid4()}"
        print(f"Simulating metering report for {account_id}. Message ID: {metering_id}")
        return True, metering_id
    except GoogleAPIError as e:
        print(f"Error sending metering report for {account_id}: {e}")
        return False, None

# --- Pub/Sub Listener (As a separate thread/process in production) ---

# --- Pub/Sub Listener (As a separate thread/process in production) ---


import google.auth # Corrected import
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# The API discovery URL for the Cloud Commerce Partner Procurement API
# This is used to dynamically build the client.
PARTNER_PROCUREMENT_API_DISCOVERY_URL = "https://cloudcommerceprocurement.googleapis.com/$discovery/rest?version=v1"

def clean_gcp_account_id_prefix(account_id: str) -> str:
    """
    Checks if the account_id string contains 'accounts/providers/bynet-public/accounts/'
    as a prefix and removes it.

    Args:
        account_id: The input account ID string, potentially with an extra prefix.

    Returns:
        The cleaned account ID string without the specified prefix.
    """
    cleaned_id=account_id
    # The problematic prefix identified in your error message
    problematic_prefix = 'accounts/providers/bynet-public/accounts/'

    if account_id.startswith(problematic_prefix):
        print(f"Detected and removing problematic prefix: '{problematic_prefix}' from '{account_id}'")
        cleaned_id = account_id[len(problematic_prefix):]
    
    if account_id.startswith("providers/bynet-public/accounts/"):
        cleaned_id = account_id[len("providers/bynet-public/accounts/"):]
    
    if account_id.startswith('accounts/'):
        cleaned_id = account_id[len('accounts/'):]
    
    #print(f"got account id:{account_id} returning: {cleaned_id}")
    return cleaned_id

def get_gcp_account_id_from_entitlement_id(entitlement_id: str) -> str | None:
    """
    Retrieves the GCP account ID associated with a GCP Marketplace entitlement ID
    by calling the Google Cloud Commerce Partner Procurement API's get method for entitlements.

    Args:
        entitlement_id: The GCP Marketplace entitlement ID string. It will be
                        prefixed with "providers/bynet-public/entitlements/"
                        if it doesn't already start with it. This ID is used
                        as the 'name' for the get_entitlement API call.

    Returns:
        The GCP account ID as a string, or None if it cannot be extracted
        (e.g., if the entitlement ID format is unexpected or the API call fails).
    """
    # Define the expected prefix for the entitlement name
    expected_prefix = "providers/bynet-public/entitlements/"

    # Add the prefix if the input entitlement_id does not start with it
    if not entitlement_id.startswith(expected_prefix):
        print(f"Adding prefix '{expected_prefix}' to entitlement ID: {entitlement_id}")
        # The API expects the full resource name, e.g., "providers/p/entitlements/e"
        full_resource_name = expected_prefix + entitlement_id
    else:
        full_resource_name = entitlement_id

    print(f"Attempting to get GCP account ID for entitlement: {full_resource_name}")

    try:
        # Build the API client dynamically using the discovery document.
        # This requires the 'google-api-python-client' library.
        # Ensure your environment is authenticated (e.g., via gcloud auth application-default login)
        # The default credentials will be used.
        credentials, project = google.auth.default() # Using google.auth.default()
        service = build(
            "cloudcommerceprocurement",
            "v1",
            credentials=credentials,
            discoveryServiceUrl=PARTNER_PROCUREMENT_API_DISCOVERY_URL,
            cache_discovery=False # Set to True in production for better performance
        )

        # Make the API call to get the entitlement resource.
        # The 'get' method on the 'entitlements' resource of the Partner Procurement API
        # expects the full resource path.
        entitlement_resource = service.providers().entitlements().get(name=full_resource_name).execute()

        # The 'account' field is expected to be part of the Entitlement resource
        gcp_account_id = entitlement_resource.get("account")

        if gcp_account_id:
            # The account ID often comes in the format "accounts/ACCOUNT_NUMBER".
            # Extract just the number part for cleaner usage.
            if gcp_account_id.startswith("accounts/"):
                return gcp_account_id.split("accounts/")[1]
            return clean_gcp_account_id_prefix(gcp_account_id)
        else:
            print("Error: 'account' field not found in the retrieved entitlement resource.")
            return None
    except HttpError as e:
        print(f"HTTP Error calling API: {e.resp.status} - {e.content.decode()}")
        print("Please ensure:")
        print("1. The Cloud Commerce Partner Procurement API is enabled in your GCP project.")
        print("2. Your authenticated service account has the 'Cloud Commerce Partner Procurement Viewer' role (or equivalent) for the relevant provider and entitlements.")
        print("3. The entitlement ID is correct and exists for 'bynet-public' provider.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def listen_to_pubsub():
    """
    Listens for messages on the specified Pub/Sub subscription for new entitlements
    and entitlement updates (e.g., cancellations).
    This function should ideally run in a separate thread or process to avoid blocking the Flask app.
    """
    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(GCP_PROJECT_ID, PUBSUB_SUBSCRIPTION_NAME)

    print(f"Listening for messages on {subscription_path}...")

    def callback(message: pubsub_v1.subscriber.message.Message):
        print(f"Received message: {message.data.decode('utf-8')}")
        try:
            payload = json.loads(message.data.decode('utf-8'))
           
            # Store the raw message and some metadata
            message_to_store = {
                "message_id": message.message_id,
                "publish_time": message.publish_time.isoformat(),
                "data": payload, # Store the parsed payload
                "raw_data": message.data.decode('utf-8'), # Store raw string for debugging
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "eventType": payload["eventType"]
            }
            save_pubsub_message(message_to_store)

            """ 
            "account_id":  payload["entitlement"]["orderId"] if payload["entitlement"] else "",  
            "state":  payload["entitlement"]["state"] if payload["entitlement"] else "", 
            "usageReportingId": payload["usageReportingId"] if payload["usageReportingId"] else ""
            """

            raw_entitlement = payload.get('entitlement')
            entitlement_id = None

            if isinstance(raw_entitlement, dict):
                entitlement_id = raw_entitlement.get('id')
                pprint.pprint('saveing enttitlment')
                pprint.pprint(raw_entitlement)
                save_entitlement(raw_entitlement)
            elif isinstance(raw_entitlement, str):
                print("instace of str")
                pprint.pprint(raw_entitlement)
                entitlement_id = None

            event_type = payload.get('eventType')
            #pprint.pprint("got message event type is {event_type}")
           

            if not entitlement_id:
                print("Message missing 'entitlement' or 'entitlement.name' field. Acknowledging. ")
                pprint.pprint(payload)
                message.ack()
                return
            else:
                 pprint.pprint(payload)

            entitlement_parts = entitlement_id.split('/')
            entitlement_id_from_gcp = entitlement_parts[-1]
            dummy_account_id = f"gcp-user-{entitlement_id_from_gcp}"

            #account = load_account(dummy_account_id)
            #entitlment = load_entitlement(entitlement_id_from_gcp)

            if (event_type == 'ACCOUNT_ACTIVE'):
                message.ack()
                return

            if (event_type == "ENTITLEMENT_ACTIVE"):    
                message.ack()
                return
            
            try:
                my_accouunt_id = clean_gcp_account_id_prefix( get_gcp_account_id_from_entitlement_id(raw_entitlement.get( "id")) )
                #print(f"got account id {my_accouunt_id}")
            except Exception as e:
                    print(f"An unexpected error occurred: {e}")
                    my_accouunt_id = dummy_account_id

            account = load_account(clean_gcp_account_id_prefix(my_accouunt_id))

            if ((event_type == 'ENTITLEMENT_NEW' ) or ( event_type == 'ENTITLEMENT_CREATION_REQUESTED')):
                print(f"New subscription received for entitlement: {entitlement_id}")               
               
                if not account:              
                    new_account = {
                        "id": my_accouunt_id,
                        "newPlan": raw_entitlement.get( "newPlan"),
                        "newProduct": raw_entitlement.get("newProduct"),
                        "newOffer": raw_entitlement.get("newOffer"),
                        "orderId": raw_entitlement.get( "orderId"),
                        "account_id": my_accouunt_id,
                    #    "email": f"user_{dummy_account_id}@example.com",
                    #    "company_name": f"Company {dummy_account_id}",
                        "status": "CREATION_REQUESTED",
                        "created_at": datetime.utcnow().isoformat() + "Z",
                        "last_updated": datetime.utcnow().isoformat() + "Z",
                        "marketplace_entitlement_id": raw_entitlement.get( "id"),
                         "billing_history": []
                    }
                    save_account(new_account)
                    account=new_account
                    print(f"Account {my_accouunt_id } created with pending status.Approved entitlement {entitlement_id}")
                    approve_marketplace_entitlement("bynet-public", "bynet-public", entitlement_id)
                    flash(f"New account {my_accouunt_id } from Marketplace is pending review.approved {entitlement_id}", "info")
                    message.ack()
                    return()
                else:
                    print(f"Account {my_accouunt_id} already exists. Updating status if needed.")
                    if account['status'] == 'canceled' or account['status'] == 'suspended':
                        account['status'] = 'pending'
                        save_account(account)
                        flash(f"Account {dummy_account_id} re-activated to pending from Marketplace.", "info")
                        message.ack()
                        return()
                    message.ack()
                    return()    

            elif event_type == 'ENTITLEMENT_CANCELED':
                if account:
                    print(f"Cancellation message received for entitlement: {entitlement_id}")
                    account['status'] = 'canceled'
                    account['last_updated'] = datetime.utcnow().isoformat() + "Z"
                    save_account(account)
                    print(f"Account {dummy_account_id} status updated to canceled.")
                    flash(f"Account {dummy_account_id} cancelled via Marketplace.", "warning")
                    return
                else:
                    print(f"Cancellation for unknown account/entitlement: {entitlement_id}")

            elif event_type == 'ENTITLEMENT_PLAN_CHANGED':
                if account:
                    print(f"Plan change message received for entitlement: {entitlement_id}")
                    account['last_updated'] = datetime.utcnow().isoformat() + "Z"
                    save_account(account)
                    print(f"Account {dummy_account_id} plan updated.")
                else:
                    print(f"Plan change for unknown account/entitlement: {entitlement_id}")

            message.ack()
            print(f"Message acknowledged: {message.message_id}")

        except Exception as e:
            print(f"Processing error: {e}")
            message.nack()

    future = subscriber.subscribe(subscription_path, callback)
    try:
        future.result()
    except TimeoutError:
        future.cancel()
        print("Pub/Sub listener stopped due to timeout or shutdown.")
    except Exception as e:
        future.cancel()
        print(f"Listening threw an exception: {e}")

# --- Flask Routes ---

@app.route('/')
def home():
    """
    Renders the home page of the application.
    """
    return render_template('home.html')






def decode_gcp_marketplace_token(token: str, expected_audience: str) -> dict:
    """
    Decodes and verifies an x-gcp-marketplace-token.

    Args:
        token: The x-gcp-marketplace-token string.
        expected_audience: Your product's domain (e.g., "your-product.com").

    Returns:
        A dictionary containing the decoded payload if successful.

    Raises:
        jwt.InvalidTokenError: If the token is invalid, expired, or has an incorrect signature/claims.
        requests.exceptions.RequestException: If there's an issue fetching Google's public keys.
    """
    try:
        # 1. Decode the header to get the key ID (kid) and issuer (iss)
        # We decode without verification first to get the issuer URL
        header = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
        kid = header.get("kid")
        if not kid:
            raise jwt.InvalidTokenError("Missing 'kid' in token header.")

        # Extract the issuer from the payload (you might need to decode the payload without verification first)
        unverified_payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
        issuer_url = unverified_payload.get("iss")
        if not issuer_url:
            raise jwt.InvalidTokenError("Missing 'iss' in token payload.")

        # 2. Fetch Google's public keys from the issuer URL
        # Google's public keys are usually available at a URL like 'https://www.googleapis.com/oauth2/v3/certs'
        # or similar to the 'iss' value. The 'iss' claim will point to the correct certs URL.
        # For GCP Marketplace, it's often something like 'https://www.googleapis.com/robot/v1/metadata/x509/cloud-marketplace-partner@prod-env.iam.gserviceaccount.com'
        certs_url = issuer_url # In many cases, the issuer URL itself is the JWKS endpoint
        if issuer_url.endswith(".iam.gserviceaccount.com"):
            certs_url = f"https://www.googleapis.com/oauth2/v3/certs" # Standard Google certs endpoint

        jwks_client = jwt.PyJWKClient(certs_url)
        signing_key = jwks_client.get_signing_key(kid)

        # 3. Decode and verify the token using the public key
        decoded_payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=expected_audience, # Validate 'aud' claim
            options={
                "require": ["exp", "aud", "iss", "sub"], # Ensure these claims exist
                "verify_exp": True, # Verify expiration time
                "verify_aud": True, # Verify audience
                "verify_iss": True, # Verify issuer
                "verify_nbf": True, # Verify not before time
            }
        )

        # 4. Perform additional custom validations on the payload if needed
        # For example, check 'sub' is not empty, or validate specific 'roles'

        return decoded_payload

    except jwt.ExpiredSignatureError:
        print("Token has expired.")
        raise
    except jwt.InvalidAudienceError:
        print(f"Token audience is invalid. Expected: {expected_audience}")
        raise
    except jwt.InvalidIssuerError:
        print(f"Token issuer is invalid.")
        raise
    except jwt.InvalidSignatureError:
        print("Token signature is invalid.")
        raise
    except jwt.DecodeError as e:
        print(f"Error decoding token: {e}")
        raise
    except requests.exceptions.RequestException as e:
        print(f"Error fetching public keys from Google: {e}")
        raise
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise

# --- Example Usage ---



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles new account sign-ups. This route is for direct sign-ups,
    separate from GCP Marketplace Pub/Sub notifications.
    """
    if request.method == 'POST':
        try:
            real_gcp_marketplace_token=dict(request.form)['x-gcp-marketplace-token']
            print(dict(request.form).keys)
            your_product_domain="marketplace"
            if  (True ):    
                try:
                        print("\n--- Attempting to decode mock/example token (no signature verification) ---")
                        decoded_data = jwt.decode(real_gcp_marketplace_token, options={"verify_signature": False}, algorithms=["RS256"])
                        #payload = jwt.decode(real_gcp_marketplace_token, options={"verify_signature": False}, algorithms=["RS256"])
                        print("decoded:", json.dumps(decoded_data, indent=2))
                        #print("Payload:", json.dumps(payload, indent=2))
                        print("\nNOTE: This is an unverified decode. For security, always use a real token and verify its signature.")
                except Exception as e:
                        print(f"Could not even decode the token: {e}")
            else:
                    try:
                        print(f"Attempting to decode and verify token for audience: {your_product_domain}")
                        decoded_data = decode_gcp_marketplace_token(real_gcp_marketplace_token, your_product_domain)
                        print("\nSuccessfully decoded and verified token!")
                        print(json.dumps(decoded_data, indent=4))

                      
                    except Exception as e:
                        print(f"\nFailed to decode or verify token: {e}")
        
            if decoded_data:
            # Access specific claims:
                user_id = decoded_data.get("sub")
                roles = decoded_data.get("roles", [])
                print(f"\nUser ID: {user_id}")
                print(f"User Roles: {roles}")
                pprint.pprint(decoded_data)
                account_id =user_id
            else:
                account_id = f"direct-signup-{uuid.uuid4().hex[:8]}" # Generate a unique ID




            company_name = request.form['company_name']
            email = request.form['email']
            phone = request.form['phone']
            
        except KeyError as e:
            flash(f"Missing required form field: {e}. Please ensure all fields are filled.", 'danger')
            return redirect(url_for('signup'))    

        new_account = {
            "account_id": account_id,
            "email": email,
            "company_name": company_name,
            "phone": phone,
            "status": "pending", # Set to pending for admin review
            "created_at": datetime.utcnow().isoformat() + "Z",
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "marketplace_entitlement_id": None, # Not from Marketplace initially
            "marketplace_product_id": None,
            "marketplace_plan_id": None,
            "billing_history": []
        }
        save_account(new_account)
        flash('Your account signup request has been received. It is pending review.', 'success')
        return redirect(url_for('home'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login for authenticated routes.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Simple hardcoded authentication for demonstration
        if username == os.environ.get("ADMIN_USERNAME", "BynetAdmin") and password == os.environ.get("ADMIN_PASSWORD", "changM3in.env"): # Use env var for production!
            user = User(username)
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(request.args.get('next') or url_for('accounts'))
        else:
            print("faild login for {username} with pass:{password}")
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """
    Logs out the current user.
    """
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/accounts')
@login_required
def accounts():
    """
    Displays a list of all customer accounts and their statuses.
    Requires authentication.
    """
    all_accounts = get_all_accounts()
    # Sort by created_at descending for most recent first
    all_accounts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return render_template('accounts.html', accounts=all_accounts)

@app.route('/accounts/<account_id>')
@login_required
def account_detail(account_id):
    """
    Displays detailed information for a specific account.
    Allows actions like accepting/cancelling accounts.
    Requires authentication.
    Args:
        account_id (str): The ID of the account to display.
    """
    account = load_account(account_id)
    if not account:
        flash('Account not found.', 'danger')
        return redirect(url_for('accounts'))
    return render_template('account_detail.html', account=account)

@app.route('/accounts/<account_id>/accept', methods=['POST'])
@login_required
def accept_account(account_id):
    """
    Endpoint to accept a pending account.
    If the account originated from GCP Marketplace, it calls the Procurement API to approve the entitlement.
    Requires authentication.
    Args:
        account_id (str): The ID of the account to accept.
    """
    account = load_account(account_id)
    if not account:
        flash('Account not found.', 'danger')
        return redirect(url_for('accounts'))

    if account['status'] == 'pending':
        if account.get('marketplace_entitlement_id'):
            Eid= account['marketplace_entitlement_id']
            # This account came from GCP Marketplace via Pub/Sub
            if approve_entitlement(Eid):
                account['status'] = 'active'
                account['last_updated'] = datetime.utcnow().isoformat() + "Z"
                save_account(account)
                print(f'Account {account_id} [{Eid}]naccepted and Marketplace entitlement approved! - success')
                flash(f'Account {account_id}[{Eid}] accepted and Marketplace entitlement approved!', 'success')
            else:
                print(f'Failed to approve Marketplace entitlement for {account_id} [{Eid}]. Eid  Please check logs.', 'danger')
                flash(f'Failed to approve Marketplace entitlement for {account_id}. [{Eid}] Please check logs.', 'danger')
        else:
            # This account was a direct signup
            account['status'] = 'active'
            account['last_updated'] = datetime.utcnow().isoformat() + "Z"
            save_account(account)
            flash(f'Account {account_id} accepted!', 'success')
    else:
        flash(f'Account {account_id} is not in pending status.', 'warning')
    return redirect(url_for('account_detail', account_id=account_id))

@app.route('/accounts/<account_id>/cancel', methods=['POST'])
@login_required
def cancel_account(account_id):
    """
    Endpoint to cancel an active account.
    Requires authentication.
    Args:
        account_id (str): The ID of the account to cancel.
    """
    account = load_account(account_id)
    if not account:
        flash('Account not found.', 'danger')
        return redirect(url_for('accounts'))

    if account['status'] == 'active':
        # In a real scenario, you might also call a GCP Marketplace API to suspend/cancel entitlement
        # For simplicity, we just update internal status here.
        # GCP Pub/Sub for 'ENTITLEMENT_CANCELED' will handle the actual Marketplace cancellation flow.
        account['status'] = 'canceled'
        account['last_updated'] = datetime.utcnow().isoformat() + "Z"
        save_account(account)
        flash(f'Account {account_id} cancelled.', 'info')
    else:
        flash(f'Account {account_id} is not active and cannot be cancelled.', 'warning')
    return redirect(url_for('account_detail', account_id=account_id))

@app.route('/accounts/<account_id>/reactivate', methods=['POST'])
@login_required
def reactivate_account(account_id):
    """
    Endpoint to reactivate a canceled account.
    Requires authentication.
    Args:
        account_id (str): The ID of the account to reactivate.
    """
    account = load_account(account_id)
    if not account:
        flash('Account not found.', 'danger')
        return redirect(url_for('accounts'))

    if account['status'] == 'canceled':
        # In a real scenario, you might interact with GCP Marketplace to resume subscription
        account['status'] = 'active' # Reactivate internally
        account['last_updated'] = datetime.utcnow().isoformat() + "Z"
        save_account(account)
        flash(f'Account {account_id} reactivated.', 'success')
    else:
        flash(f'Account {account_id} is not in canceled status.', 'warning')
    return redirect(url_for('account_detail', account_id=account_id))


@app.route('/billing')
@login_required
def billing():
    """
    Displays billing and metering messages/status for all accounts.
    Requires authentication.
    """
    all_accounts = get_all_accounts()
    billing_data = {}
    for account in all_accounts:
        if account.get('billing_history'):
            billing_data[account['account_id']] = account['billing_history']
    return render_template('billing.html', billing_data=billing_data)

@app.route('/listings')
@login_required
def listings():
    """
    Displays information about products/listings used by the system.
    Requires authentication.
    """
    return render_template('listings.html')

@app.route('/messages')
@login_required
def messages():
    """
    Displays all stored Pub/Sub messages.
    Requires authentication.
    """
    all_messages = load_all_pubsub_messages()
    return render_template('messages.html', messages=all_messages)

"""
{
  "name": "providers/bynet-public/entitlements/f6f025fa-35eb-40c0-a617-4c4c9b9c8188",
  "account": "providers/bynet-public/accounts/909aac59-92bb-4684-bf9e-b9fe440e7a71",
  "provider": "bynet-public",
  "product": "hossted.endpoints.bynet-public.cloud.goog",
  "plan": "per-user-12-month",
  "state": "ENTITLEMENT_ACTIVE",
  "updateTime": "2025-07-16T13:13:57.948233Z",
  "createTime": "2025-07-16T13:13:46.533633Z",
  "usageReportingId": "project_number:212706713297",
  "productExternalName": "hossted.endpoints.bynet-public.cloud.goog",
  "offer": "projects/679054047603/services/hossted.endpoints.bynet-public.cloud.goog/standardOffers/a6c2587d-7e8d-4681-b4a7-8146817baf89",
  "orderId": "f6f025fa-35eb-40c0-a617-4c4c9b9c8188",
  "entitlementBenefitIds": [
    "fbde38ed-7793-475f-98c3-8b873f20e6b1"
  ]
}
"""

# --- Monthly Billing Function (Can be called via CLI or a cron job) ---

import json
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# The API discovery URL for the Cloud Commerce Partner Procurement API
PARTNER_PROCUREMENT_API_DISCOVERY_URL = "https://cloudcommerceprocurement.googleapis.com/$discovery/rest?version=v1"

def get_entitlement_from_api_by_id(entitlement_uuid: str) -> dict | None:
    """
    Retrieves the full entitlement resource from the Google Cloud Commerce
    Partner Procurement API using its UUID.

    Args:
        entitlement_uuid: The UUID part of the entitlement ID (e.g.,
                          "f6f025fa-35eb-40c0-a617-4c4c9b9c8188").

    Returns:
        A dictionary representing the entitlement resource, or None if an error occurs.
    """
    # Construct the full resource name for the API call
    full_resource_name = f"providers/bynet-public/entitlements/{entitlement_uuid}"
    print(f"Attempting to retrieve entitlement: {full_resource_name}")

    try:
        # Get default credentials
        credentials, project = google.auth.default()

        # Build the API client dynamically
        service = build(
            "cloudcommerceprocurement",
            "v1",
            credentials=credentials,
            discoveryServiceUrl=PARTNER_PROCUREMENT_API_DISCOVERY_URL,
            cache_discovery=False # Set to True in production for better performance
        )

        # Make the API call to get the entitlement resource
        entitlement_resource = service.providers().entitlements().get(name=full_resource_name).execute()
        return entitlement_resource
    except HttpError as e:
        print(f"HTTP Error retrieving entitlement {entitlement_uuid}: {e.resp.status} - {e.content.decode()}")
        print("Please ensure:")
        print("1. The Cloud Commerce Partner Procurement API is enabled in your GCP project.")
        print("2. Your authenticated service account has the 'Cloud Commerce Partner Procurement Viewer' role (or equivalent) for the 'bynet-public' provider and the specific entitlement.")
        print("3. The entitlement UUID is correct and exists for 'bynet-public' provider.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while retrieving entitlement {entitlement_uuid}: {e}")
        return None

# Placeholder for your existing function to get entitlement IDs from a directory
# You would replace this with your actual implementation.






# --- perform reporting

import json
import uuid
import pprint
from datetime import datetime, timedelta
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Configuration ---
# The API discovery URL for the Cloud Commerce Partner Procurement API
PARTNER_PROCUREMENT_API_DISCOVERY_URL = "https://cloudcommerceprocurement.googleapis.com/$discovery/rest?version=v1"
# The API discovery URL for the Service Control API (for metering reports)
SERVICE_CONTROL_API_DISCOVERY_URL = "https://servicecontrol.googleapis.com/$discovery/rest?version=v1"
# Your service name for metering, as configured in Google Cloud Marketplace
# IMPORTANT: Replace with your actual service name (e.g., "your-product-service.endpoints.your-project.cloud.goog")
# This is the service name associated with your product in Cloud Marketplace.
YOUR_SERVICE_NAME = "hossted.endpoints.bynet-public.cloud.goog"
# The metric name for your usage, as defined in your service configuration
# IMPORTANT: Replace with your actual metric name (e.g., "your-product-service/users_active")
YOUR_METRIC_NAME = "hossted.endpoints.bynet-public.cloud.goog/user"
"""
# Metrics IDs
# per user 12 month
hossted.endpoints.bynet-public.cloud.goog/user"""

# --- Simulated Local Storage for Account Billing History ---
# In a real application, this would be a persistent database (e.g., Firestore)
# or a file-based storage. For this example, it's an in-memory dictionary.
_LOCAL_ACCOUNT_BILLING_DATA = {}

def _load_account_billing_data(gcp_account_id: str) -> dict:
    """Simulates loading an account's billing history from local storage."""
    return _LOCAL_ACCOUNT_BILLING_DATA.get(gcp_account_id, {'billing_history': []})

def _save_account_billing_data(gcp_account_id: str, account_data: dict):
    """Simulates saving an account's billing history to local storage."""
    _LOCAL_ACCOUNT_BILLING_DATA[gcp_account_id] = account_data
    print(f"Saved billing data for account: {gcp_account_id}")

# --- Entitlement Retrieval Functions (from previous turns) ---

def get_entitlement_from_api_by_id(entitlement_uuid: str) -> dict | None:
    """
    Retrieves the full entitlement resource from the Google Cloud Commerce
    Partner Procurement API using its UUID.

    Args:
        entitlement_uuid: The UUID part of the entitlement ID (e.g.,
                          "f6f025fa-35eb-40c0-a617-4c4c9b9c8188").

    Returns:
        A dictionary representing the entitlement resource, or None if an error occurs.
    """
    # Construct the full resource name for the API call
    full_resource_name = f"providers/bynet-public/entitlements/{entitlement_uuid}"
    # print(f"Attempting to retrieve entitlement: {full_resource_name}") # Uncomment for detailed logging

    try:
        credentials, project = google.auth.default()
        service = build(
            "cloudcommerceprocurement",
            "v1",
            credentials=credentials,
            discoveryServiceUrl=PARTNER_PROCUREMENT_API_DISCOVERY_URL,
            cache_discovery=False
        )
        entitlement_resource = service.providers().entitlements().get(name=full_resource_name).execute()
        return entitlement_resource
    except HttpError as e:
        print(f"HTTP Error retrieving entitlement {entitlement_uuid}: {e.resp.status} - {e.content.decode()}")
        # print detailed instructions only once or if specifically requested for brevity
        return None
    except Exception as e:
        print(f"An unexpected error occurred while retrieving entitlement {entitlement_uuid}: {e}")
        return None



def get_all_active_entitlements() -> list[dict]:
    """
    Retrieves all active entitlements by fetching their details from the API.

    Returns:
        A list of dictionaries, where each dictionary represents an active entitlement.
    """
    print("\n--- Getting all active entitlements ---")
    ids = get_all_entitlements_from_dir()
    active_entitlements = []
    for entitlement_uuid in ids:
        my_id=entitlement_uuid["id"]
        entitlement = get_entitlement_from_api_by_id(my_id)
        if entitlement:
            if entitlement.get("state") == "ENTITLEMENT_ACTIVE":
                print(f"Found active entitlement: {entitlement.get('name')}")
                active_entitlements.append(entitlement)
            else:
                print(f"Entitlement {entitlement.get('name')} is not active (state: {entitlement.get('state')}).")
        else:
            print(f"Skipping entitlement with UUID '{entitlement_uuid}' due to retrieval error.")
    return active_entitlements

# --- Metering Report Function ---

def send_metering_usage_report(usage_reporting_id: str, usage_data: dict, entitlement_name: str) -> tuple[bool, str | None]:
    """
    Sends a usage report to the Google Cloud Service Control API.

    Args:
        usage_reporting_id: The consumerId for the metering report (e.g., "project_number:12345").
        usage_data: A dictionary containing the usage metrics (e.g., {'user_count': 100}).
        entitlement_name: The full resource name of the entitlement
                          (e.g., "providers/p/entitlements/e").

    Returns:
        A tuple (success: bool, operation_id: str | None).
    """
    print(f"Preparing usage report for {usage_reporting_id}...")

    # Calculate start and end times for the reporting period
    # For monthly billing, this would typically be the previous month
    # For simplicity here, let's assume it's for a fixed recent period or current month
    # Adjust this logic based on your actual billing cycle.
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=30) # Example: last 30 days

    # Format times as required by the API
    start_time_str = start_time.isoformat(timespec='milliseconds') + "Z"
    end_time_str = end_time.isoformat(timespec='milliseconds') + "Z"

    # Construct metricValueSets based on usage_data
    metric_value_sets = []
    # Assuming usage_data contains 'user_count' for 'per-user' plan or 'UsageInGiB' for 'per-gib'
    # You'll need to adapt this based on your actual metrics and plan.
    if 'user_count' in usage_data:
        metric_value_sets.append({
            "metricName": YOUR_METRIC_NAME, # e.g., "example-messaging-service/active_users"
            "metricValues": [{"int64Value": str(usage_data['user_count'])}]
        })
    elif 'UsageInGiB' in usage_data:
        metric_value_sets.append({
            "metricName": YOUR_METRIC_NAME, # e.g., "example-messaging-service/UsageInGiB"
            "metricValues": [{"int64Value": str(usage_data['UsageInGiB'])}]
        })
    else:
        print("Warning: No recognized usage data found in usage_data dictionary.")
        return False, None

    # Construct the operation payload
    operation_payload = {
        "operationId": str(uuid.uuid4()), # Unique ID for each report operation
        "operationName": "Monthly Usage Report",
        "consumerId": usage_reporting_id,
        "startTime": start_time_str,
        "endTime": end_time_str,
        "metricValueSets": metric_value_sets,
        "userLabels": {
            # These labels are useful for filtering and analysis in GCP
            "cloudmarketplace.googleapis.com/resource_name": entitlement_name.split('/')[-1], # Entitlement UUID
            "cloudmarketplace.googleapis.com/container_name": "saas-platform", # Your platform identifier
            "environment": "prod", # Or 'dev', 'staging'
            "reporting_period": end_time.strftime('%Y-%m')
        }
    }

    report_request_body = {
        "operations": [operation_payload]
    }

    try:
        credentials, project = google.auth.default()
        service_control_client = build(
            "servicecontrol",
            "v1",
            credentials=credentials,
            discoveryServiceUrl=SERVICE_CONTROL_API_DISCOVERY_URL,
            cache_discovery=False
        )

        # Send the report
        request = service_control_client.services().report(
            serviceName=YOUR_SERVICE_NAME,
            body=report_request_body
        )
        response = request.execute()

        if response and not response.get('reportErrors'):
            print(f"Successfully sent metering report for {usage_reporting_id}. Operation ID: {operation_payload['operationId']}")
            return True, operation_payload['operationId']
        else:
            errors = response.get('reportErrors', [])
            print(f"Failed to send metering report for {usage_reporting_id}. Errors: {errors}")
            return False, None
    except HttpError as e:
        print(f"HTTP Error sending metering report: {e.resp.status} - {e.content.decode()}")
        print("Please ensure:")
        print(f"1. Service Control API is enabled for service '{YOUR_SERVICE_NAME}'.")
        print("2. Your authenticated service account has 'Service Control Reporter' role (roles/servicecontrol.reporter) for the project associated with your service.")
        print("3. The 'YOUR_SERVICE_NAME' and 'YOUR_METRIC_NAME' are correctly configured in your Cloud Marketplace product.")
        print("4. The 'usage_reporting_id' (consumerId) is valid.")
        return False, None
    except Exception as e:
        print(f"An unexpected error occurred while sending metering report: {e}")
        return False, None

# --- Main Billing Function ---

def perform_monthly_billing():
    """
    Iterates through active entitlements and sends a monthly usage report to GCP.
    This function is intended to be run periodically (e.g., cron job on the 1st of every month).
    """
    current_month_str = datetime.utcnow().strftime('%Y-%m')
    print(f"Initiating monthly billing run at {datetime.now()} for month: {current_month_str }")

   
    active_entitlements = get_all_active_entitlements()

    for ent in active_entitlements:
        entitlement_uuid = ent.get("id") # The UUID part
        print(f"reportint ent{ entitlement_uuid)}")
        pprint.print(ent)
        entitlement_name = ent.get("name") # Full resource name: providers/p/entitlements/e
       
        usage_reporting_id = ent.get("usageReportingId") # e.g., "project_number:12345"

        if not usage_reporting_id:
            print(f"Skipping entitlement {entitlement_name}: 'usageReportingId' not found.")
            continue

        # Load the account's local billing history
        # We'll use the usageReportingId as the key for local billing history
        account_data = _load_account_billing_data(usage_reporting_id)

        already_billed = any(
            record['month'] == current_month_str and record['status'] == 'billed'
            for record in account_data.get('billing_history', [])
        )

        if not already_billed:
            print(f"Processing billing for entitlement: {entitlement_name} (Usage Reporting ID: {usage_reporting_id})")

            # --- Determine usage for the month ---
            # This is where your actual usage tracking logic would go.
            # You need to query your internal systems to get the actual usage for this
            # specific usage_reporting_id for the current month.
            # For demonstration, we'll use a dummy usage amount.
            # The metric name (e.g., "UsageInGiB" or "user_count") must match your product's configuration.
            dummy_usage = {"int64Value": "1" } # Example: 150 GiB used for the month
            # Or if your plan is per-user:
            # dummy_usage = {'user_count': 50} # Example: 50 active users for the month

            success, billing_message_id = send_metering_usage_report(usage_reporting_id, dummy_usage, entitlement_name)
            print("success:")
            pprint.pprint(success) 
            print("billing_message:")
            pprint.pprint(billing_message_id) 

            new_billing_record = {
                "month": current_month_str,
                "status": "billed" if success else "failed",
                "billing_message_id": billing_message_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "usage_reported": dummy_usage,
                "entitlement_name": entitlement_name
            }
            if not success:
                new_billing_record["error"] = "Metering report failed"

            # Update and save the local billing history
            account_data.setdefault('billing_history', []).append(new_billing_record)
            _save_account_billing_data(usage_reporting_id, account_data)

            if success:
                print(f"Successfully reported usage for entitlement {entitlement_name} for {current_month_str}.")
            else:
                print(f"Failed to report usage for entitlement {entitlement_name} for {current_month_str}.")
        else:
            print(f"Entitlement {entitlement_name} (Usage Reporting ID: {usage_reporting_id}) already billed for {current_month_str}. Skipping.")

    print("Monthly billing run completed.")






# --- CLI Commands (Using Flask's Click integration) ---
@app.cli.command("bill-month")
def bill_month_command():
    """
    CLI command to manually trigger monthly billing for all active accounts.
    Usage: flask bill-month
    """
    perform_monthly_billing()
    print("Monthly billing command executed.")

@app.cli.command("listen-pubsub")
def listen_pubsub_command():
    """
    CLI command to start listening to Pub/Sub for Marketplace events.
    Usage: flask listen-pubsub
    """
    print("Starting Pub/Sub listener...")
    listen_to_pubsub()
    print("Pub/Sub listener stopped.")

############3

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


def approve_marketplace_entitlement(project_id: str, provider_id: str, entitlement_id: str) -> None:
    """
    Approves a Google Cloud Marketplace entitlement.

    Args:
        project_id: Your Google Cloud Project ID.
        provider_id: Your Google Cloud Marketplace Provider ID.
        entitlement_id: The ID of the entitlement to approve.
    """
    try:
        # Build the Cloud Commerce Procurement API client
        # The 'v1' refers to the API version
        service = build('cloudcommerceprocurement', 'v1')

        # Construct the full entitlement name
        # Format: providers/{providerId}/entitlements/{entitlement_id}
        entitlement_name = f"providers/{provider_id}/entitlements/{entitlement_id}"

        print(f"Attempting to approve entitlement: {entitlement_name}")

        # Call the approve method
        request_body = {} # The approve method typically takes an empty body for simple approval
        
        request = service.providers().entitlements().approve(
            name=entitlement_name,
            body=request_body
        )
        
        response = request.execute()

        print(f"Entitlement '{entitlement_id}' approval initiated successfully.")
        print("Response:")
        print(json.dumps(response, indent=2))
        print("\nNote: The entitlement state might not immediately change to 'ACTIVE'.")
        print("You will likely receive another Pub/Sub notification (ENTITLEMENT_ACTIVE) ")
        print("when the approval process is complete and the entitlement becomes active.")

    except HttpError as e:
        print(f"An HTTP error occurred: {e.resp.status} - {e.content.decode('utf-8')}")
        print("Please check your Provider ID, Entitlement ID, and IAM permissions.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
      





###############



if __name__ == '__main__':
    # It's generally not recommended to run Pub/Sub listener directly in the Flask development server
    # as it's blocking. For development, you might run it in a separate terminal.
    # For production, use a dedicated worker (e.g., Celery, separate GKE pod, Cloud Run job).

    # To run the Pub/Sub listener in a separate thread for local development:
    import threading
    pubsub_thread = threading.Thread(target=listen_to_pubsub, daemon=True)
    pubsub_thread.start()

    app.run(debug=True, host='0.0.0.0', port=80)
