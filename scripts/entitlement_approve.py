import os
import argparse
import google.auth
from google.auth.transport.requests import AuthorizedSession
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# --- Configuration ---
# Retrieve your Provider and Project IDs from environment variables
PROVIDER_ID = os.getenv("GCP_PROVIDER_ID","bynet-public")
PROJECT_ID = os.getenv("GCP_PROJECT_ID","bynet-public") 

# The base URL for the Cloud Commerce Partner Procurement API
API_BASE_URL = "https://cloudcommerceprocurement.googleapis.com/v1"

#https://cloudcommerceprocurement.googleapis.com/v1/providers/bynet-public/entitlements/entitlement_id=b85b0360-0810-4e3e-88a2-61a1846beccb:approve

def approve_entitlement(entitlement_id: str):
    """
    Approves a pending entitlement creation request.

    This function sends a POST request to the Partner Procurement API to approve
    a specified entitlement.

    Args:
        entitlement_id: The unique identifier of the entitlement to approve.

    Returns:
        A dictionary containing the API response, or None if an error occurs.
    """
    if not PROVIDER_ID or not PROJECT_ID:
        print("Error: GCP_PROVIDER_ID and GCP_PROJECT_ID must be set in the .env file.")
        return

    print(f"Attempting to approve entitlement: {entitlement_id}")

    try:
        # Authenticate and get credentials
        credentials, project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        authed_session = AuthorizedSession(credentials)

        # Construct the API endpoint URL
        url = f"{API_BASE_URL}/providers/{PROVIDER_ID}/entitlements/{entitlement_id}:approve"

        # The request body is currently empty for the approve method
        # as per the latest documentation.
        request_body = {}

        # Send the POST request to approve the entitlement
        response = authed_session.post(url, json=request_body)
        response.raise_for_status()  # Raise an exception for bad status codes

        print("Successfully approved entitlement.")
        return response.json()

    except google.auth.exceptions.DefaultCredentialsError:
        print(
            "Authentication failed. Please configure your GCP credentials."
            "See: https://cloud.google.com/docs/authentication/getting-started"
        )
    except Exception as e:
        print(f"An error occurred: {e}")
        if "response" in locals():
            print(f"Response content: {response.text}")

    return None


if __name__ == "__main__":
    # Set up the command-line argument parser
    parser = argparse.ArgumentParser(
        description="Approve a pending GCP Marketplace entitlement."
    )
    parser.add_argument(
        "entitlement_id",
        type=str,
        help="The ID of the entitlement to approve.",
    )

    args = parser.parse_args()

    # Call the approval function with the provided entitlement ID
    approve_entitlement(args.entitlement_id)
