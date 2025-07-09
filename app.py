import os
import json
import datetime
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
os.makedirs(ACCOUNT_DIR, exist_ok=True)


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
    return os.path.join(ACCOUNT_DIR, f"{account_id}.json")

def load_account(account_id):
    """
    Loads account details from its JSON file.
    Args:
        account_id (str): The unique ID of the account.
    Returns:
        dict or None: The account dictionary if found, otherwise None.
    """
    account_path = get_account_path(account_id)
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
    with open(account_path, 'w') as f:
        json.dump(account_data, f, indent=4)

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


def save_pubsub_message(message_data):
    """
    Saves a Pub/Sub message to a JSON file in the messages directory.
    Args:
        message_data (dict): The dictionary containing the Pub/Sub message details.
    """
    timestamp = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')
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
        #     "meteringTime": datetime.datetime.utcnow().isoformat() + "Z",
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
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            }
            save_pubsub_message(message_to_store)

            raw_entitlement = payload.get('entitlement')
            entitlement_name = None

            if isinstance(raw_entitlement, dict):
                entitlement_name = raw_entitlement.get('name')
            elif isinstance(raw_entitlement, str):
                entitlement_name = raw_entitlement

            event_type = payload.get('eventType')

            if not entitlement_name:
                print("Message missing 'entitlement' or 'entitlement.name' field. Acknowledging.")
                message.ack()
                return

            entitlement_parts = entitlement_name.split('/')
            entitlement_id_from_gcp = entitlement_parts[-1]
            dummy_account_id = f"gcp-user-{entitlement_id_from_gcp}"

            account = load_account(dummy_account_id)

            if event_type == 'ENTITLEMENT_NEW':
                if not account:
                    print(f"New subscription received for entitlement: {entitlement_name}")
                    new_account = {
                        "account_id": dummy_account_id,
                        "email": f"user_{dummy_account_id}@example.com",
                        "company_name": f"Company {dummy_account_id}",
                        "status": "pending",
                        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                        "last_updated": datetime.datetime.utcnow().isoformat() + "Z",
                        "marketplace_entitlement_id": entitlement_name,
                        "marketplace_product_id": "your-saas-product-id",
                        "marketplace_plan_id": "basic-plan-id",
                        "billing_history": []
                    }
                    save_account(new_account)
                    print(f"Account {dummy_account_id} created with pending status.")
                    flash(f"New account {dummy_account_id} from Marketplace is pending review.", "info")
                else:
                    print(f"Account {dummy_account_id} already exists. Updating status if needed.")
                    if account['status'] == 'canceled' or account['status'] == 'suspended':
                        account['status'] = 'pending'
                        save_account(account)
                        flash(f"Account {dummy_account_id} re-activated to pending from Marketplace.", "info")

            elif event_type == 'ENTITLEMENT_CANCELED':
                if account:
                    print(f"Cancellation message received for entitlement: {entitlement_name}")
                    account['status'] = 'canceled'
                    account['last_updated'] = datetime.datetime.utcnow().isoformat() + "Z"
                    save_account(account)
                    print(f"Account {dummy_account_id} status updated to canceled.")
                    flash(f"Account {dummy_account_id} cancelled via Marketplace.", "warning")
                else:
                    print(f"Cancellation for unknown account/entitlement: {entitlement_name}")

            elif event_type == 'ENTITLEMENT_PLAN_CHANGED':
                if account:
                    print(f"Plan change message received for entitlement: {entitlement_name}")
                    account['last_updated'] = datetime.datetime.utcnow().isoformat() + "Z"
                    save_account(account)
                    print(f"Account {dummy_account_id} plan updated.")
                else:
                    print(f"Plan change for unknown account/entitlement: {entitlement_name}")

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




import jwt
import requests
import json
from datetime import datetime, timezone

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
            if (dict(request.form).keys > 1  ):    
                try:
                        print("\n--- Attempting to decode mock/example token (no signature verification) ---")
                        header = jwt.decode(real_gcp_marketplace_token, options={"verify_signature": False}, algorithms=["RS256"])
                        payload = jwt.decode(real_gcp_marketplace_token, options={"verify_signature": False}, algorithms=["RS256"])
                        print("Header:", json.dumps(header, indent=2))
                        print("Payload:", json.dumps(payload, indent=2))
                        print("\nNOTE: This is an unverified decode. For security, always use a real token and verify its signature.")
                except Exception as e:
                        print(f"Could not even unverified decode the placeholder token: {e}")
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





            company_name = request.form['company_name']
            email = request.form['email']
            phone = request.form['phone']
            account_id = f"direct-signup-{uuid.uuid4().hex[:8]}" # Generate a unique ID
        except KeyError as e:
            flash(f"Missing required form field: {e}. Please ensure all fields are filled.", 'danger')
            return redirect(url_for('signup'))    

        new_account = {
            "account_id": account_id,
            "email": email,
            "company_name": company_name,
            "phone": phone,
            "status": "pending", # Set to pending for admin review
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "last_updated": datetime.datetime.utcnow().isoformat() + "Z",
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
            # This account came from GCP Marketplace via Pub/Sub
            if approve_entitlement(account['marketplace_entitlement_id']):
                account['status'] = 'active'
                account['last_updated'] = datetime.datetime.utcnow().isoformat() + "Z"
                save_account(account)
                flash(f'Account {account_id} accepted and Marketplace entitlement approved!', 'success')
            else:
                flash(f'Failed to approve Marketplace entitlement for {account_id}. Please check logs.', 'danger')
        else:
            # This account was a direct signup
            account['status'] = 'active'
            account['last_updated'] = datetime.datetime.utcnow().isoformat() + "Z"
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
        account['last_updated'] = datetime.datetime.utcnow().isoformat() + "Z"
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
        account['last_updated'] = datetime.datetime.utcnow().isoformat() + "Z"
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



# --- Monthly Billing Function (Can be called via CLI or a cron job) ---
def perform_monthly_billing():
    """
    Iterates through active accounts and sends a monthly billing message to GCP.
    This function is intended to be run periodically (e.g., cron job on the 1st of every month).
    """
    print(f"Initiating monthly billing run at {datetime.datetime.now()}")
    active_accounts = [acc for acc in get_all_accounts() if acc['status'] == 'active']
    current_month = datetime.datetime.utcnow().strftime('%Y-%m')

    for account in active_accounts:
        account_id = account['account_id']
        # Check if already billed for the current month
        already_billed = any(
            record['month'] == current_month and record['status'] == 'billed'
            for record in account.get('billing_history', [])
        )

        if not already_billed:
            print(f"Processing billing for account: {account_id}")
            # --- Determine usage for the month ---
            # This is where your actual usage tracking logic would go.
            # For demonstration, we'll use a dummy usage amount.
            dummy_usage = {'user_count': 100} # Example metering dimension

            success, billing_message_id = send_metering_usage_report(account_id, dummy_usage)

            if success:
                new_billing_record = {
                    "month": current_month,
                    "amount_usd": 100.00, # This would be calculated based on usage and plan
                    "status": "billed",
                    "billing_message_id": billing_message_id,
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                }
                account.setdefault('billing_history', []).append(new_billing_record)
                save_account(account)
                print(f"Successfully billed account {account_id} for {current_month}.")
            else:
                print(f"Failed to bill account {account_id} for {current_month}.")
                # Log this error and potentially retry later
                failed_billing_record = {
                    "month": current_month,
                    "amount_usd": 0.00, # Or estimated amount
                    "status": "failed",
                    "billing_message_id": None,
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "error": "Metering report failed"
                }
                account.setdefault('billing_history', []).append(failed_billing_record)
                save_account(account)
        else:
            print(f"Account {account_id} already billed for {current_month}. Skipping.")
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

if __name__ == '__main__':
    # It's generally not recommended to run Pub/Sub listener directly in the Flask development server
    # as it's blocking. For development, you might run it in a separate terminal.
    # For production, use a dedicated worker (e.g., Celery, separate GKE pod, Cloud Run job).

    # To run the Pub/Sub listener in a separate thread for local development:
    import threading
    pubsub_thread = threading.Thread(target=listen_to_pubsub, daemon=True)
    pubsub_thread.start()

    app.run(debug=True, host='0.0.0.0', port=80)
