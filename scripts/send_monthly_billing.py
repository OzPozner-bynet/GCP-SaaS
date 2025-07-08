import os
import sys
from dotenv import load_dotenv

# Add the parent directory to the Python path to import app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import perform_monthly_billing

if __name__ == '__main__':
    load_dotenv() # Load environment variables from .env file
    # This script should be configured as a cron job to run on the 1st of every month.
    perform_monthly_billing()
