# pubsub_listener.py
import os
import sys
from dotenv import load_dotenv

# Add the parent directory to the Python path to import app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import listen_to_pubsub

if __name__ == '__main__':
    load_dotenv() # Load environment variables from .env file
    listen_to_pubsub()
