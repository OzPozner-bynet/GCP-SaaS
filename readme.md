# Clone your Git repository

cd /opt
sudo git clone https://github.com/OzPozner-bynet/GCP-SaaS.git
sudo mv /opt/GCP-SaaS /opt/GCP-Marketplace-SaaS-Integration
#sudo chown -R your_username:your_username /opt/GCP-Marketplace-SaaS-Integration
sudo chown -R ozp:ozp /opt/GCP-Marketplace-SaaS-Integration
cd /opt/GCP-Marketplace-SaaS-Integration
source venv/bin/activate
pip install -r requirements.txt
mv .env.example .env
nano .env


sudo nano /etc/systemd/system/gcp_saas_app.service

[Unit]
Description=GCP Marketplace SaaS Flask App Gunicorn
After=network.target

[Service]
User=your_username
WorkingDirectory=/opt/GCP-Marketplace-SaaS-Integration # <--- UPDATED PATH
EnvironmentFile=/opt/GCP-Marketplace-SaaS-Integration/.env # <--- UPDATED PATH
ExecStart=/opt/GCP-Marketplace-SaaS-Integration/venv/bin/gunicorn --workers 4 --bind 0.0.0.0:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target


sudo nano /etc/systemd/system/gcp_saas_pubsub.service

[Unit]
Description=GCP Marketplace SaaS Pub/Sub Listener
After=network.target

[Service]
User=your_username # Make sure this is your non-root user that owns the app directory
WorkingDirectory=/opt/GCP-Marketplace-SaaS-Integration # UPDATED PATH
EnvironmentFile=/opt/GCP-Marketplace-SaaS-Integration/.env # UPDATED PATH
ExecStart=/opt/GCP-Marketplace-SaaS-Integration/venv/bin/python3 pubsub_listener.py # UPDATED PATH
Restart=always

[Install]
WantedBy=multi-user.target
3. Reload systemd and restart the service:


Bash

sudo systemctl daemon-reload
sudo systemctl restart gcp_saas_pubsub
sudo systemctl enable gcp_saas_pubsub # Ensure it starts on boot
sudo systemctl status gcp_saas_pubsub

Update Crontab Entry
1. Edit your user's crontab:

Bash

sudo crontab -e

0 0 1 * * /opt/GCP-Marketplace-SaaS-Integration/venv/bin/python3 /opt/GCP-Marketplace-SaaS-Integration/scripts/send_monthly_billing.py >> /var/log/monthly_billing.log 2>&1

Explanation of the Crontab Entry:

0 0 1 * *: This is the schedule. It means:

0: At minute 0

0: At hour 0 (midnight)

1: On day 1 of the month

*: Every month

*: Every day of the week

Effectively: On the 1st of every month at midnight.

/opt/GCP-Marketplace-SaaS-Integration/venv/bin/python3: This is the absolute path to your Python interpreter inside your virtual environment located in the new /opt directory.

/opt/GCP-Marketplace-SaaS-Integration/scripts/send_monthly_billing.py: This is the absolute path to your monthly billing script.

>> /var/log/monthly_billing.log 2>&1: This redirects both standard output and standard error to the /var/log/monthly_billing.log file, which is good for debugging cron jobs.




curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$(base64 -w 0 < service_account_key.json)"  https://oauth2.googleapis.com/token



# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies

# --- Configure Environment Variables ---
# Create a .env file (this will be ignored by Git)
nano .env

