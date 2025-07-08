import os
from dotenv import load_dotenv, set_key, dotenv_values

def set_admin_password(password):
    """
    Sets or updates the ADMIN_PASSWORD in the .env file.

    Args:
        password (str): The password to set for the admin user.
    """
    dotenv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')

    # Load existing .env values
    current_values = dotenv_values(dotenv_path)

    # Update or add ADMIN_PASSWORD
    set_key(dotenv_path, "ADMIN_PASSWORD", password)
    print(f"ADMIN_PASSWORD has been set in {dotenv_path}")
    print("Remember to restart your Flask application for changes to take effect.")

if __name__ == "__main__":
    admin_password = "bynet8001!" # The desired password
    set_admin_password(admin_password)
