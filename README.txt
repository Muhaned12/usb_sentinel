================================================================================
USB Connection Detector
================================================================================

Project Overview:
-----------------
USB Connection Detector is a secure forensic tool developed as part of the 
Bachelor of Science in Cyber Security & Digital Forensics degree project. 
The application monitors USB device insertions and removals, logs events, 
performs file-level analysis (including SHA‑256 hash calculation, file metadata 
retrieval, and VirusTotal threat analysis), and generates encrypted forensic 
reports. This tool is designed especially for small and medium-sized enterprises 
(SMEs) to help prevent data breaches and improve digital forensic capabilities.

Key Features:
-------------
• Real-time USB device monitoring and event logging.
• Detailed forensic logging with user identification.
• File-level analysis:
    - Compute SHA‑256 hashes.
    - Retrieve file metadata (size, type, modification date).
    - Integrate with VirusTotal for threat detection.
• Encrypted PDF forensic report generation.
• Admin portal for:
    - Managing the whitelist of trusted USB devices.
    - Generating and decrypting forensic reports (with optional file-level details).
    - Viewing a detailed dashboard of USB event history.
• Email alerting for critical security events.

Installation Instructions:
--------------------------
1. Requirements:
   - Python 3.9+ (or later)
   - Required Python packages: reportlab, cryptography, python-dotenv, pandas, requests, numpy, pywin32

2. Install dependencies using pip:
      pip install reportlab cryptography python-dotenv pandas requests numpy pywin32

3. Download or clone the project files into your working directory.

4. Create a file named ".env" in the project root directory with the following content 
   (replace placeholder values with your actual settings):

      APP_ENCRYPTION_KEY=your_generated_32_byte_base64_key_here
      SMTP_USER=usb.sentinel1@gmail.com
      SMTP_PASS=Usb112@@
      ALERT_RECIPIENTS=security@example.com

   To generate an encryption key, run:
      from cryptography.fernet import Fernet
      print(Fernet.generate_key())
   Copy the output (without b'' markers) as the value for APP_ENCRYPTION_KEY.

Usage Guidelines:
-----------------
1. Running the Application:
   - Open an elevated Command Prompt or PowerShell (Run as Administrator).
   - Navigate to the project directory.
   - Run the application:
         python main.py

2. User Login:
   - A login screen appears.
   - Use the following credentials:
         alice:   alicepass
         bob:     bobpass
         Admin:   Muhaned / pass112@@

3. Main Application:
   - Standard users can view real-time USB events, perform manual file analysis,
     and generate basic CSV reports.

4. Admin Portal:
   - Click the "Admin Portal" button to access advanced features.
   - Log in with the admin credentials (Username: Muhaned, Password: pass112@@).
   - In the Admin Portal, you can:
         • Manage the whitelist of trusted USB devices.
         • Generate forensic reports. When generating a report, you will be prompted 
           whether to include file-level analysis:
               - If yes, enter the USB drive letter (e.g., "E:\").
               - Detailed reports are saved with a timestamped filename.
         • Decrypt and open encrypted forensic reports.
         • Open a dashboard displaying detailed USB event history.

Project Structure:
------------------
- main.py             : Main application entry point.
- gui.py              : GUI code including user login and admin portal.
- db_logger.py        : Handles logging of USB events to an SQLite database.
- report_generator.py : Generates basic CSV reports from USB events.
- forensic_report.py  : Generates, encrypts, and (if needed) decrypts forensic PDF reports.
- file_scanner.py     : Provides functions for computing file hashes and retrieving file metadata.
- virus_total.py      : Interfaces with the VirusTotal API for threat analysis.
- alert.py            : Sends email alerts for critical USB events.
- usb_remediation.py  : Contains functions to safely eject USB devices.
- whitelist_manager.py: Manages the trusted USB device whitelist.
- registry_parser.py  : Parses USB connection history from system registries.
- .env                : Contains environment variables (encryption key, SMTP credentials, etc.).

Additional Information:
-----------------------
This project was developed to provide SMEs with an affordable, secure, 
and user-friendly tool for monitoring USB connections and preventing data breaches. 
Future enhancements may include cross-platform support, machine learning-based anomaly 
detection, and integration with enterprise SIEM systems.

Contact & Support:
------------------
For further inquiries or support, please contact:

   [Muhaned Nouman]
   [MN982@live.mdx.ac.uk]
  
================================================================================
© [2025] [Middlesex university] - All Rights Reserved
================================================================================
