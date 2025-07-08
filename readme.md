# Clone your Git repository
git clone https://github.com/your-username/GCP-Marketplace-SaaS-Integration.git
cd GCP-Marketplace-SaaS-Integration

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# --- Configure Environment Variables ---
# Create a .env file (this will be ignored by Git)
nano .env
