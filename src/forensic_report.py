from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
import sqlite3
import datetime
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables from .env
load_dotenv()

# Retrieve encryption key from .env (must be a 32-byte base64-encoded key)
APP_ENCRYPTION_KEY = os.environ.get("APP_ENCRYPTION_KEY")
if not APP_ENCRYPTION_KEY:
    raise ValueError("APP_ENCRYPTION_KEY not set in environment variables.")
KEY = APP_ENCRYPTION_KEY.encode()
cipher_suite = Fernet(KEY)

# Database file (same one used by db_logger.py)
DB_FILE = "usb_events.db"

# SMTP settings
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
ALERT_RECIPIENTS = os.environ.get("ALERT_RECIPIENTS", "security@example.com").split(",")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Global styles for ReportLab
styles = getSampleStyleSheet()
normal_style = styles["Normal"]

def fetch_forensic_data():
    """
    Fetch all USB events from the SQLite database.
    Returns a list of tuples: (event_type, device_name, serial, username, timestamp).
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT event_type, device_name, serial, username, timestamp FROM events ORDER BY timestamp")
    data = cursor.fetchall()
    conn.close()
    return data

def gather_file_details(drive_letter):
    """
    Return a list of [filename, sha256, size, type, modification_time, vt_result]
    for each file on the specified drive_letter (e.g., 'E:\\').
    """
    import file_scanner  # Must have compute_sha256 and get_file_metadata functions
    import virus_total   # Must have check_usb_threat function

    if not drive_letter.endswith("\\"):
        drive_letter += "\\"

    file_list = []
    try:
        filenames = [f for f in os.listdir(drive_letter) if os.path.isfile(os.path.join(drive_letter, f))]
        for filename in filenames:
            full_path = os.path.join(drive_letter, filename)
            sha256_hash = file_scanner.compute_sha256(full_path)
            metadata = file_scanner.get_file_metadata(full_path)

            vt_result = "N/A"
            if sha256_hash:
                vt = virus_total.check_usb_threat(sha256_hash)
                if "error" in vt:
                    vt_result = f"Error ({vt['error']})"
                elif "unknown" in vt and vt["unknown"]:
                    vt_result = "Unknown"
                else:
                    malicious = vt.get("malicious", 0)
                    suspicious = vt.get("suspicious", 0)
                    if malicious > 0 or suspicious > 0:
                        vt_result = "Threat Detected"
                    else:
                        vt_result = "Safe"

            file_list.append([
                filename,
                sha256_hash or "N/A",
                metadata.get("size", "N/A"),
                metadata.get("file_type", "N/A"),
                metadata.get("modification_time", "N/A"),
                vt_result
            ])
    except Exception as e:
        print(f"[ERROR] Could not gather file details from {drive_letter}: {e}")
    return file_list

def generate_pdf_report(filename, drive_letter=None):
    """
    Generate a PDF report with USB event data and, if drive_letter is provided,
    include file-level analysis details.
    """
    data = fetch_forensic_data()
    doc = SimpleDocTemplate(filename, pagesize=letter)
    flowables = []

    # Title and subtitle
    title_para = Paragraph("USB Forensic Report", styles["Title"])
    flowables.append(title_para)
    flowables.append(Spacer(1, 12))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subtitle_para = Paragraph(f"Report generated on: {now}", normal_style)
    flowables.append(subtitle_para)
    flowables.append(Spacer(1, 12))

    # Build event table
    event_table_data = [["Event Type", "Device", "Serial", "Username", "Timestamp"]]
    event_col_widths = [80, 90, 120, 90, 110]

    for row in data:
        event_type_par = Paragraph(str(row[0]), normal_style)
        device_par = Paragraph(str(row[1]), normal_style)
        serial_par = Paragraph(str(row[2]), normal_style)
        user_par = Paragraph(str(row[3]), normal_style)
        time_par = Paragraph(str(row[4]), normal_style)
        event_table_data.append([event_type_par, device_par, serial_par, user_par, time_par])

    event_table = Table(event_table_data, repeatRows=1, colWidths=event_col_widths)
    event_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.gray),
        ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 10),
        ("BOTTOMPADDING", (0,0), (-1,0), 8),
        ("GRID", (0,0), (-1,-1), 1, colors.black),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]))
    flowables.append(event_table)
    flowables.append(Spacer(1, 12))

    # If drive_letter is specified, add file-level details
    if drive_letter:
        file_data = gather_file_details(drive_letter)
        if file_data:
            flowables.append(Paragraph("File-Level Analysis", styles["Heading2"]))
            flowables.append(Spacer(1, 6))

            file_table_data = [["Filename", "SHA-256", "Size (bytes)", "Type", "Modified", "VT Result"]]
            file_col_widths = [80, 150, 60, 60, 80, 80]

            for row in file_data:
                fname_par = Paragraph(str(row[0]), normal_style)
                sha_par = Paragraph(str(row[1]), normal_style)
                size_par = Paragraph(str(row[2]), normal_style)
                type_par = Paragraph(str(row[3]), normal_style)
                mod_par = Paragraph(str(row[4]), normal_style)
                vt_par = Paragraph(str(row[5]), normal_style)
                file_table_data.append([fname_par, sha_par, size_par, type_par, mod_par, vt_par])

            file_table = Table(file_table_data, repeatRows=1, colWidths=file_col_widths)
            file_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.darkgray),
                ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
                ("ALIGN", (0,0), (-1,-1), "LEFT"),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,0), 10),
                ("BOTTOMPADDING", (0,0), (-1,0), 8),
                ("GRID", (0,0), (-1,-1), 1, colors.black),
                ("VALIGN", (0,0), (-1,-1), "TOP"),
            ]))
            flowables.append(file_table)
        else:
            flowables.append(Paragraph("No file-level data found or unable to read drive.", normal_style))
    else:
        # No drive letter provided; no file-level analysis.
        pass

    doc.build(flowables)
    print(f"PDF report generated: {filename}")

def encrypt_file(file_path):
    """
    Encrypt the specified file using Fernet encryption.
    """
    try:
        with open(file_path, "rb") as file:
            data = file.read()
        encrypted_data = cipher_suite.encrypt(data)
        with open(file_path, "wb") as file:
            file.write(encrypted_data)
        print(f"Encrypted file: {file_path}")
    except Exception as e:
        print(f"[ERROR] Could not encrypt file {file_path}: {e}")

def send_incident_alert(subject, body):
    """
    Send an email alert for incident response.
    """
    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(ALERT_RECIPIENTS)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, ALERT_RECIPIENTS, msg.as_string())
        server.quit()
        print("Incident alert email sent successfully.")
    except Exception as e:
        print(f"Failed to send incident alert email: {e}")

def generate_and_encrypt_report(drive_letter=None, filename=None):
    """
    Generate the PDF forensic report (optionally including file-level analysis if drive_letter is given),
    then encrypt it. If critical events exist, send an incident alert.
    If no filename is provided and no drive_letter is given, use a fixed name ("forensic_report.pdf")
    to ease decryption; if drive_letter is provided (detailed report), use a timestamped filename.
    """
    if filename is None:
        if drive_letter:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"forensic_report_{timestamp}.pdf"
        else:
            filename = "forensic_report.pdf"
    
    generate_pdf_report(filename, drive_letter=drive_letter)

    data = fetch_forensic_data()
    critical_events = [row for row in data if row[0].lower() == "insertion_untrusted" or "threat" in row[0].lower()]
    if critical_events:
        subject = "Critical USB Incident Report"
        body = f"Critical events detected:\n{critical_events}\n\nPlease review the attached report."
        send_incident_alert(subject, body)

    encrypt_file(filename)

if __name__ == "__main__":
    # Example usage: Generate a report without file-level details (fixed name)
    generate_and_encrypt_report(drive_letter=None)
