import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()

def send_email_alert(subject, body, to_emails, from_email, smtp_server, smtp_port, smtp_user, smtp_pass):
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = ", ".join(to_emails)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, to_emails, msg.as_string())
        server.quit()
        print("[ALERT] Email alert sent successfully.")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send email alert: {e}")
        return False

if __name__ == "__main__":
    subject = "USB Threat Alert"
    body = "A suspicious USB device has been detected. Please review immediately."
    to_emails = ["mohanadali123@hotmail.com"]
    from_email = os.environ.get("SMTP_USER")
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    send_email_alert(subject, body, to_emails, from_email, smtp_server, smtp_port, smtp_user, smtp_pass)
