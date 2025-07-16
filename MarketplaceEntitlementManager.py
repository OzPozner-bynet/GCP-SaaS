from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import json
import os

# Import dotenv to load environment variables from .env file
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class MarketplaceEntitlementManager:
    """
    Manages Google Cloud Marketplace entitlements by directly interacting with
    the Cloud Commerce Procurement API. Does NOT use Firebase for local record keeping.
    """

    def __init__(self, project_id: str):
        """
        Initializes the MarketplaceEntitlementManager.

        Args:
            project_id: Your Google Cloud Project ID.
        """
        self.project_id = project_id
        # Build the Cloud Commerce Procurement API client
        # The 'v1' refers to the API version
        self.service = build('cloudcommerceprocurement', 'v1')
        print(f"MarketplaceEntitlementManager initialized for project: {self.project_id}")
        print("Note: This version does NOT use Firebase for local record keeping.")

    def _get_entitlement_details_from_api(self, entitlement_id: str, provider_id: str) -> dict | None:
        """
        Fetches the latest entitlement details from the Google Cloud Commerce Procurement API.
        
        Args:
            entitlement_id: The ID of the entitlement.
            provider_id: The provider ID.
            
        Returns:
            dict | None: The entitlement object from the API, or None if not found/error.
        """
        entitlement_name = f"providers/{provider_id}/entitlements/{entitlement_id}"
        print(f"  API: Fetching latest details for entitlement: {entitlement_name}")
        try:
            request = self.service.providers().entitlements().get(name=entitlement_name)
            response = request.execute()
            print(f"  API: Successfully fetched entitlement details.")
            return response
        except HttpError as e:
            if e.resp.status == 404:
                print(f"  API Warning: Entitlement {entitlement_id} not found.")
                return None
            else:
                error_message = f"  API Error: Failed to get entitlement {entitlement_id}: {e.resp.status} - {e.content.decode('utf-8')}"
                print(error_message)
                raise
        except Exception as e:
            print(f"  API Error: An unexpected error occurred while getting entitlement {entitlement_id}: {e}")
            raise

    def approve_entitlement_by_id(self, entitlement_id: str, provider_id: str) -> dict:
        """
        Sends an approval request for a specific Google Cloud Marketplace entitlement.

        Args:
            entitlement_id: The ID of the entitlement to approve.
            provider_id: The provider ID associated with the entitlement.

        Returns:
            dict: The API response from the approval request.

        Raises:
            HttpError: If an HTTP error occurs during the API call.
            Exception: For any other unexpected errors.
        """
        entitlement_name = f"providers/{provider_id}/entitlements/{entitlement_id}"
        print(f"\n--- Approving Entitlement: {entitlement_name} ---")

        # Fetch current entitlement details from API before approval (for logging/context)
        current_entitlement_from_api = self._get_entitlement_details_from_api(entitlement_id, provider_id)
        if current_entitlement_from_api:
            print(f"  Entitlement state before approval: {current_entitlement_from_api.get('state')}")
        else:
            print(f"  Warning: Could not retrieve current details for entitlement {entitlement_id} before approval.")

        # Send the approval request to Google API
        try:
            request_body = {} # The approve method typically takes an empty body for simple approval
            
            request = self.service.providers().entitlements().approve(
                name=entitlement_name,
                body=request_body
            )
            
            response = request.execute()
            print(f"Entitlement '{entitlement_id}' approval initiated successfully.")
            print("API Response for approval request:")
            print(json.dumps(response, indent=2))

            # Get the status from Google API *after* the approval request
            # Note: The state won't immediately be 'ACTIVE' right after 'approve' call.
            # It will likely be 'ENTITLEMENT_ACTIVATION_REQUESTED' or 'ENTITLEMENT_PENDING_APPROVAL'.
            # The final 'ACTIVE' state is confirmed via a separate Pub/Sub notification.
            updated_entitlement_after_approve = self._get_entitlement_details_from_api(entitlement_id, provider_id)
            if updated_entitlement_after_approve:
                print(f"  Current Entitlement State (after approve call): {updated_entitlement_after_approve.get('state')}")
            else:
                print(f"  Warning: Could not fetch updated entitlement details after approval request.")

            print("\nNote: The entitlement state might not immediately change to 'ACTIVE'.")
            print("You will likely receive another Pub/Sub notification (ENTITLEMENT_ACTIVE) ")
            print("when the approval process is complete and the entitlement becomes active.")
            return response
        except HttpError as e:
            error_message = f"HTTP error approving entitlement {entitlement_id}: {e.resp.status} - {e.content.decode('utf-8')}"
            print(error_message)
            raise HttpError(e.resp, e.content, uri=e.uri) from e
        except Exception as e:
            error_message = f"An unexpected error occurred while approving entitlement {entitlement_id}: {e}"
            print(error_message)
            raise Exception(error_message) from e

    def approve_entitlement_from_message(self, pubsub_message_data: bytes) -> dict:
        """
        Processes a Pub/Sub message containing marketplace entitlement details
        and approves the entitlement.

        Args:
            pubsub_message_data: The raw bytes data from the Pub/Sub message.

        Returns:
            dict: The API response from the approval request.

        Raises:
            json.JSONDecodeError: If the message data is not valid JSON.
            ValueError: If 'entitlement' or 'providerId' is missing from the message.
            HttpError: If an HTTP error occurs during the API call.
            Exception: For any other unexpected errors.
        """
        print(f"\n--- Processing Pub/Sub message for entitlement approval ---")
        try:
            message_data_str = pubsub_message_data.decode('utf-8')
            notification_payload = json.loads(message_data_str)

            entitlement = notification_payload.get("entitlement")
            provider_id = notification_payload.get("providerId")

            if not entitlement:
                raise ValueError("Pub/Sub message missing 'entitlement' object.")
            if not provider_id:
                raise ValueError("Pub/Sub message missing 'providerId'.")

            entitlement_id = entitlement.get("id")
            if not entitlement_id:
                raise ValueError("Entitlement object missing 'id'.")

            print(f"  Extracted Entitlement ID: {entitlement_id}, Provider ID: {provider_id}")
            return self.approve_entitlement_by_id(entitlement_id, provider_id)

        except json.JSONDecodeError as e:
            print(f"Error: Pub/Sub message data is not valid JSON: {e}")
            raise
        except ValueError as e:
            print(f"Error: Invalid Pub/Sub message format: {e}")
            raise
        except HttpError:
            # HttpError is already printed by approve_entitlement_by_id, just re-raise
            raise
        except Exception as e:
            print(f"An unexpected error occurred while processing Pub/Sub message: {e}")
            raise


# --- Example Usage ---
if __name__ == "__main__":
    # IMPORTANT: Configure these in your .env file
    # Example .env content:
    # GCP_PROJECT_ID="your-google-cloud-project-id"
    # GCP_MARKETPLACE_PROVIDER_ID="your-marketplace-provider-id"

    YOUR_PROJECT_ID = os.getenv('GCP_PROJECT_ID')
    YOUR_PROVIDER_ID = os.getenv('GCP_MARKETPLACE_PROVIDER_ID')

    if not YOUR_PROJECT_ID:
        print("Error: GCP_PROJECT_ID not found in .env file or environment variables.")
        print("Please create a .env file with GCP_PROJECT_ID=<your-project-id>")
        exit(1)
    if not YOUR_PROVIDER_ID:
        print("Error: GCP_MARKETPLACE_PROVIDER_ID not found in .env file or environment variables.")
        print("Please create a .env file with GCP_MARKETPLACE_PROVIDER_ID=<your-provider-id>")
        exit(1)

    # --- Example 1: Approving an entitlement directly by ID ---
    # You would typically get this entitlement ID from a Pub/Sub message
    # or from your system's record of pending entitlements.
    example_entitlement_id = "13d8d1e9-14f7-47c9-9b23-f2d961591f5b" # Replace with a real entitlement ID

    print("\n--- Example Usage: Approving by Entitlement ID ---")
    try:
        manager = MarketplaceEntitlementManager(YOUR_PROJECT_ID)
        manager.approve_entitlement_by_id(example_entitlement_id, YOUR_PROVIDER_ID)
    except (HttpError, ValueError, Exception) as e:
        print(f"Failed to approve entitlement by ID: {e}")

    # --- Example 2: Approving an entitlement from a raw Pub/Sub message ---
    print("\n--- Example Usage: Approving from Pub/Sub Message ---")
    # This is the raw data you provided, typically received from Pub/Sub
    sample_pubsub_message_data = b"""{
      "eventId": "CREATE_ENTITLEMENT-bdcb81de-ca24-48d8-875f-a8417717dbf4",
      "eventType": "ENTITLEMENT_CREATION_REQUESTED",
      "entitlement": {
        "id": "13d8d1e9-14f7-47c9-9b23-f2d961591f5b",
        "updateTime": "2025-07-09T01:47:12.874046Z",
        "newPlan": "per-user-12-month",
        "newProduct": "hossted.endpoints.bynet-public.cloud.goog",
        "newOffer": "projects/679054047603/services/hossted.endpoints.bynet-public.cloud.goog/standardOffers/a6c2587d-7e8d-4681-b4a7-8146817baf89",
        "orderId": "13d8d1e9-14f7-47c9-9b23-f2d961591f5b",
        "entitlementBenefitIds": ["50421e3f-a91f-4475-996a-b48a2328b6f1"]
      },
      "providerId": "bynet-public"
    }"""

    try:
        manager_from_message = MarketplaceEntitlementManager(YOUR_PROJECT_ID)
        manager_from_message.approve_entitlement_from_message(sample_pubsub_message_data)
    except (json.JSONDecodeError, ValueError, HttpError, Exception) as e:
        print(f"Failed to approve entitlement from message: {e}")

