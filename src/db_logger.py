import sqlite3
import datetime
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


KEY = os.environ.get("APP_ENCRYPTION_KEY").encode()
cipher_suite = Fernet(KEY)

DB_FILE = "usb_events.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            device_name TEXT,
            serial TEXT,
            username TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def encrypt(text):
    return cipher_suite.encrypt(text.encode()).decode()

def decrypt(token):
    return cipher_suite.decrypt(token.encode()).decode()

def log_event(event_type, device_name, serial, username=""):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Encrypt the username (or any other sensitive field)
    enc_username = encrypt(username) if username else ""
    cursor.execute(
        "INSERT INTO events (event_type, device_name, serial, username, timestamp) VALUES (?, ?, ?, ?, ?)",
        (event_type, device_name, serial, enc_username, timestamp)
    )
    conn.commit()
    conn.close()

def fetch_events():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT event_type, device_name, serial, username, timestamp FROM events ORDER BY timestamp")
    events = []
    for row in cursor.fetchall():
        event_type, device_name, serial, enc_username, timestamp = row
        try:
            username = decrypt(enc_username) if enc_username else ""
        except Exception:
            username = enc_username
        events.append((event_type, device_name, serial, username, timestamp))
    conn.close()
    return events

if __name__ == "__main__":
    init_db()
    log_event("insertion", "Test USB", "12345", "alice")
    for event in fetch_events():
        print(event)
