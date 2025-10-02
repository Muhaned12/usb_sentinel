import pandas as pd
import datetime
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the encryption key from the environment (it must be a 32-byte base64-encoded key)
KEY = os.environ.get("APP_ENCRYPTION_KEY")
if KEY is None:
    raise ValueError("APP_ENCRYPTION_KEY not set in environment variables.")
KEY = KEY.encode()  # Ensure it is in bytes
cipher_suite = Fernet(KEY)

# Global dictionary to track USB usage activity
usb_usage_counter = {}

def update_usb_insert(device_name, serial_number):
    """Update the counter for a USB insertion event."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if device_name in usb_usage_counter:
        usb_usage_counter[device_name]["Insertions"] += 1
        usb_usage_counter[device_name]["Last_Used"] = now
    else:
        usb_usage_counter[device_name] = {
            "Device": device_name,
            "Serial_Number": serial_number,
            "Insertions": 1,
            "Removals": 0,
            "Last_Used": now
        }

def update_usb_remove():
    """Increment the removal count for all devices (or adapt per your requirements)."""
    for device in usb_usage_counter.values():
        device["Removals"] += 1

def generate_report(filename="usb_activity_log.csv"):
    """Generate a CSV report from the usb_usage_counter dictionary and then encrypt it."""
    if not usb_usage_counter:
        print("[Report] No USB activity to save.")
        return
    # Create a DataFrame from the dictionary values
    df = pd.DataFrame(list(usb_usage_counter.values()))
    try:
        if os.path.exists(filename):
            os.remove(filename)
        df.to_csv(filename, index=False)
        encrypt_file(filename)
        print(f"[Report] Saved and encrypted as {filename}")
    except PermissionError:
        print("[ERROR] Cannot overwrite the report. Close the file if it's open.")
    except Exception as e:
        print(f"[ERROR] Could not save the report: {e}")

def encrypt_file(file_path):
    """Encrypt the specified file using Fernet symmetric encryption."""
    try:
        with open(file_path, "rb") as file:
            data = file.read()
        encrypted_data = cipher_suite.encrypt(data)
        with open(file_path, "wb") as file:
            file.write(encrypted_data)
    except Exception as e:
        print(f"[ERROR] Could not encrypt file {file_path}: {e}")

if __name__ == "__main__":
    # For testing purposes: simulate an insertion and removal event.
    update_usb_insert("Test USB", "123456")
    update_usb_remove()
    generate_report("test_report.csv")
