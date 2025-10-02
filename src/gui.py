import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os
import registry_parser
import report_generator
from virus_total import check_usb_threat
from file_scanner import compute_sha256, get_file_metadata
from usb_monitor import get_drive_letter_by_serial
from alert import send_email_alert
from usb_remediation import eject_drive
import whitelist_manager
import db_logger
import numpy as np

# For decryption functionality in the admin portal
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
APP_ENCRYPTION_KEY = os.environ.get("APP_ENCRYPTION_KEY")
if APP_ENCRYPTION_KEY is None:
    raise ValueError("APP_ENCRYPTION_KEY not set in environment variables.")
KEY = APP_ENCRYPTION_KEY.encode()
cipher_suite = Fernet(KEY)

# Admin credentials for the admin portal
ADMIN_USERNAME = "Muhaned"
ADMIN_PASSWORD = "pass112@@"

# Hard-coded user credentials for general login (demo only)
USERS = {
    "alice": "alicepass",
    "bob": "bobpass",
    "Muhaned": "pass112@@"
}

class LoginFrame(ttk.Frame):
    def __init__(self, master, on_success):
        super().__init__(master)
        self.on_success = on_success
        self.pack(fill="both", expand=True, padx=20, pady=20)
        ttk.Label(self, text="User Login", font=("Helvetica", 14, "bold")).pack(pady=10)
        ttk.Label(self, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self)
        self.username_entry.pack(pady=5)
        ttk.Label(self, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.pack(pady=5)
        ttk.Button(self, text="Login", command=self.attempt_login).pack(pady=10)

    def attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if username in USERS and USERS[username] == password:
            self.on_success(username)
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")

class USBMonitorApp:
    def __init__(self, root, start_monitor_func, current_user):
        db_logger.init_db()
        self.current_user = current_user
        self.root = root
        self.root.title("USB Sentinel")
        self.root.geometry("600x550")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TLabel", font=("Helvetica", 11))
        style.configure("TButton", font=("Helvetica", 10), padding=5)

        self.title_label = ttk.Label(root, text="USB Sentinel - Real-time USB Monitoring", font=("Helvetica", 16, "bold"))
        self.title_label.pack(pady=15)

        # Listbox for logging events
        list_frame = ttk.Frame(root)
        list_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        self.listbox = tk.Listbox(list_frame, font=("Helvetica", 10), yscrollcommand=self.scrollbar.set, height=10)
        self.scrollbar.config(command=self.listbox.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Frame for buttons
        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=10)
        self.history_button = ttk.Button(btn_frame, text="Check USB History", command=self.show_usb_history)
        self.history_button.grid(row=0, column=0, padx=5, pady=5)
        self.report_button = ttk.Button(btn_frame, text="Generate USB Report", command=self.generate_report)
        self.report_button.grid(row=0, column=1, padx=5, pady=5)
        self.whitelist_button = ttk.Button(btn_frame, text="Admin Portal", command=self.open_whitelist_manager)
        self.whitelist_button.grid(row=0, column=2, padx=5, pady=5)
        self.manual_analysis_button = ttk.Button(btn_frame, text="Manual File Analysis", command=self.manual_file_analysis)
        self.manual_analysis_button.grid(row=0, column=3, padx=5, pady=5)

        self.status_label = ttk.Label(root, text="Status: Ready", font=("Helvetica", 10, "italic"))
        self.status_label.pack(pady=5)

        self.last_device_name = None
        self.last_serial = None

        start_monitor_func(self.on_usb_insert, self.on_usb_remove)

    def manual_file_analysis(self):
        file_path = filedialog.askopenfilename(title="Select a File for Analysis")
        if not file_path:
            return
        self.status_label.config(text="Status: Analyzing file...")
        file_hash = compute_sha256(file_path)
        metadata = get_file_metadata(file_path)
        if file_hash:
            vt_result = check_usb_threat(file_hash)
            if "error" in vt_result:
                result_msg = f"VirusTotal error: {vt_result['error']}"
            elif "unknown" in vt_result and vt_result["unknown"]:
                result_msg = "This file is unknown to VirusTotal (treated as safe)."
            else:
                malicious = vt_result.get("malicious", 0)
                suspicious = vt_result.get("suspicious", 0)
                if malicious > 0 or suspicious > 0:
                    result_msg = "Threat detected on this file!"
                else:
                    result_msg = "This file is safe."
            meta_info = (f"Size: {metadata.get('size', 'N/A')} bytes\n"
                         f"Type: {metadata.get('file_type', 'N/A')}\n"
                         f"Modified: {metadata.get('modification_time', 'N/A')}")
            full_msg = (f"File: {os.path.basename(file_path)}\n"
                        f"Hash: {file_hash}\n\n"
                        f"Metadata:\n{meta_info}\n\n"
                        f"Analysis: {result_msg}")
            messagebox.showinfo("Manual File Analysis", full_msg)
            self.status_label.config(text="Status: Manual analysis complete.")
        else:
            messagebox.showerror("Error", "Failed to compute file hash.")
            self.status_label.config(text="Status: Manual analysis failed.")

    def on_usb_insert(self, device_name, serial_number):
        whitelist = whitelist_manager.load_whitelist()
        if serial_number not in whitelist:
            warning_msg = f"Untrusted USB device detected: {device_name} (Serial: {serial_number})"
            self.listbox.insert(tk.END, warning_msg)
            self.status_label.config(text="Status: Untrusted USB detected!")
            if messagebox.askyesno("Untrusted USB Detected", f"{warning_msg}\n\nDo you want to eject the USB?"):
                drive_letter = None
                try:
                    drive_letter = get_drive_letter_by_serial(serial_number)
                except Exception as e:
                    print(f"[ERROR] Could not get drive letter: {e}")
                if drive_letter:
                    if eject_drive(drive_letter):
                        messagebox.showinfo("Ejection Successful", f"{device_name} has been ejected.")
                        self.listbox.insert(tk.END, f"{device_name} ejected.")
                    else:
                        messagebox.showerror("Ejection Failed", f"Failed to eject {device_name}.")
                else:
                    messagebox.showerror("Drive Letter Not Found", "Could not determine drive letter for the untrusted USB.")
            db_logger.log_event("insertion_untrusted", device_name, serial_number, self.current_user)
            return

        self.listbox.insert(tk.END, f"Inserted: {device_name} (Serial: {serial_number})")
        report_generator.update_usb_insert(device_name, serial_number)
        report_generator.generate_report("usb_activity_log.csv")
        self.status_label.config(text=f"Status: USB inserted - {device_name}")
        db_logger.log_event("insertion", device_name, serial_number, self.current_user)
        self.last_device_name = device_name
        self.last_serial = serial_number

        drive_letter = None
        try:
            drive_letter = get_drive_letter_by_serial(serial_number)
        except Exception as e:
            print(f"[ERROR] Could not get drive letter: {e}")

        if drive_letter:
            usb_path = drive_letter + os.sep
            try:
                files = [f for f in os.listdir(usb_path) if os.path.isfile(os.path.join(usb_path, f))]
            except Exception as e:
                files = []
                print(f"[ERROR] Could not list files in {usb_path}: {e}")

            if files:
                threat_found = False
                threat_messages = []
                for filename in files:
                    full_path = os.path.join(usb_path, filename)
                    file_hash = compute_sha256(full_path)
                    metadata = get_file_metadata(full_path)
                    if file_hash:
                        vt_result = check_usb_threat(file_hash)
                        if "error" in vt_result:
                            threat_messages.append(f"{filename}: VirusTotal error ({vt_result['error']})")
                        elif "unknown" in vt_result and vt_result["unknown"]:
                            threat_messages.append(f"{filename}: Unknown to VirusTotal (treated as safe).")
                        else:
                            malicious = vt_result.get("malicious", 0)
                            suspicious = vt_result.get("suspicious", 0)
                            if malicious > 0 or suspicious > 0:
                                threat_found = True
                                threat_messages.append(f"{filename}: Threat detected!")
                            else:
                                threat_messages.append(f"{filename}: Safe.")
                        threat_messages[-1] += (f" | Size: {metadata.get('size', 'N/A')} bytes, "
                                                 f"Type: {metadata.get('file_type', 'N/A')}, "
                                                 f"Modified: {metadata.get('modification_time', 'N/A')}")
                if threat_found:
                    result_msg = "WARNING: Some files may be dangerous!\n" + "\n".join(threat_messages)
                    if messagebox.askyesno("Threat Detected", result_msg + "\n\nDo you want to send an alert email?"):
                        subject = "USB Threat Alert"
                        body = f"Threat detected on USB device '{device_name}' (Serial: {serial_number}).\n\nDetails:\n{result_msg}"
                        to_emails = ["mohanadali123@hotmail.com"]
                        from_email = "usb.sentinel1@gmail.com"
                        smtp_server = "smtp.gmail.com"
                        smtp_port = 587
                        smtp_user = "usb.sentinel1@gmail.com"
                        smtp_pass = "Usb112@@"
                        send_email_alert(subject, body, to_emails, from_email, smtp_server, smtp_port, smtp_user, smtp_pass)
                else:
                    result_msg = "All files are safe.\n" + "\n".join(threat_messages)
            else:
                result_msg = "No files found on the USB."
        else:
            result_msg = "Could not determine drive letter for the inserted USB."

        messagebox.showinfo("VirusTotal Check", result_msg)
        self.listbox.insert(tk.END, f"VirusTotal: {result_msg}")
        self.status_label.config(text="Status: Scan complete.")

    def on_usb_remove(self):
        self.listbox.insert(tk.END, "USB Removed")
        report_generator.update_usb_remove()
        report_generator.generate_report("usb_activity_log.csv")
        self.status_label.config(text="Status: USB removed.")
        if self.last_device_name and self.last_serial:
            db_logger.log_event("removal", self.last_device_name, self.last_serial, self.current_user)

    def show_usb_history(self):
        df = registry_parser.get_usb_history()
        if df.empty:
            messagebox.showinfo("USB History", "No USB history found or permission denied.")
        else:
            messagebox.showinfo("USB History", df.to_string())

    def generate_report(self):
        report_generator.generate_report("usb_activity_log.csv")
        messagebox.showinfo("Report Generated", "USB report saved as usb_activity_log.csv")
        self.status_label.config(text="Status: Report generated.")

    def open_dashboard(self):
        dashboard_window = tk.Toplevel(self.root)
        dashboard_window.title("USB Activity Dashboard")
        dashboard_window.geometry("700x400")

        columns = ("Event Type", "Device", "Serial", "Username", "Timestamp")
        tree = ttk.Treeview(dashboard_window, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor="center")

        scrollbar = ttk.Scrollbar(dashboard_window, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        events = db_logger.fetch_events()
        for event in events:
            tree.insert("", tk.END, values=event)

        def refresh_table():
            for i in tree.get_children():
                tree.delete(i)
            new_events = db_logger.fetch_events()
            for ev in new_events:
                tree.insert("", tk.END, values=ev)
        refresh_btn = ttk.Button(dashboard_window, text="Refresh", command=refresh_table)
        refresh_btn.pack(pady=5)

    def open_whitelist_manager(self):
        if not self.admin_login():
            messagebox.showerror("Access Denied", "Invalid admin credentials. Access to admin portal denied.")
            return

        win = tk.Toplevel(self.root)
        win.title("Admin Portal")
        win.geometry("400x350")

        lbl = ttk.Label(win, text="Trusted USB Devices (Serial, Employee)", font=("Helvetica", 12, "bold"))
        lbl.pack(pady=10)

        columns = ("Serial", "Employee")
        tree = ttk.Treeview(win, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor="center")
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        def refresh_list():
            for item in tree.get_children():
                tree.delete(item)
            whitelist = whitelist_manager.load_whitelist()
            for serial, employee in whitelist.items():
                tree.insert("", tk.END, values=(serial, employee))
        refresh_list()

        entry_frame = ttk.Frame(win)
        entry_frame.pack(pady=5, padx=10, fill=tk.X)
        ttk.Label(entry_frame, text="Serial:").grid(row=0, column=0, padx=5, pady=2, sticky="e")
        serial_entry = ttk.Entry(entry_frame)
        serial_entry.grid(row=0, column=1, padx=5, pady=2, sticky="we")
        ttk.Label(entry_frame, text="Employee:").grid(row=1, column=0, padx=5, pady=2, sticky="e")
        employee_entry = ttk.Entry(entry_frame)
        employee_entry.grid(row=1, column=1, padx=5, pady=2, sticky="we")
        entry_frame.columnconfigure(1, weight=1)

        def add_or_update_entry():
            serial = serial_entry.get().strip()
            employee = employee_entry.get().strip()
            if not serial:
                messagebox.showerror("Error", "Serial cannot be empty.")
                return
            wl = whitelist_manager.load_whitelist()
            if serial in wl:
                whitelist_manager.update_whitelist(serial, employee)
                messagebox.showinfo("Success", f"Updated {serial} with employee {employee}.")
            else:
                if whitelist_manager.add_to_whitelist(serial, employee):
                    messagebox.showinfo("Success", f"Added {serial} with employee {employee} to whitelist.")
                else:
                    messagebox.showerror("Error", f"Could not add {serial} to whitelist.")
            refresh_list()
            serial_entry.delete(0, tk.END)
            employee_entry.delete(0, tk.END)

        add_update_button = ttk.Button(win, text="Add/Update", command=add_or_update_entry)
        add_update_button.pack(pady=5)

        def remove_selected():
            selected = tree.selection()
            if not selected:
                messagebox.showerror("Error", "No entry selected.")
                return
            for item in selected:
                serial = tree.item(item, "values")[0]
                if whitelist_manager.remove_from_whitelist(serial):
                    messagebox.showinfo("Success", f"Removed {serial} from whitelist.")
                else:
                    messagebox.showerror("Error", f"Failed to remove {serial} from whitelist.")
            refresh_list()

        remove_button = ttk.Button(win, text="Remove Selected", command=remove_selected)
        remove_button.pack(pady=5)

        # Forensic reporting section in Admin Portal
        from forensic_report import generate_and_encrypt_report
        def generate_forensic_report():
            include_files = messagebox.askyesno("File-Level Details", "Include file-level analysis details?")
            drive_letter = None
            if include_files:
                drive_letter = simpledialog.askstring("Drive Letter", "Enter the USB drive letter (e.g., E:\\):")
            try:
                generate_and_encrypt_report(drive_letter=drive_letter)
                messagebox.showinfo("Forensic Report", "Forensic report generated and encrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate forensic report: {e}")

        admin_report_btn = ttk.Button(win, text="Generate Forensic Report", command=generate_forensic_report)
        admin_report_btn.pack(pady=5)

        # Decrypt & open forensic report: now prompt user to select the report file
        def decrypt_forensic_report():
            report_file = filedialog.askopenfilename(title="Select the Encrypted Forensic Report",
                                                     filetypes=[("PDF Files", "*.pdf")])
            if not report_file:
                return
            decrypted_file = "decrypted_report.pdf"
            if os.path.exists(decrypted_file):
                try:
                    os.remove(decrypted_file)
                except Exception as exc:
                    messagebox.showerror("Error", f"Failed to remove old decrypted file: {exc}")
                    return
            try:
                with open(report_file, "rb") as file:
                    encrypted_data = file.read()
                decrypted_data = cipher_suite.decrypt(encrypted_data)
                with open(decrypted_file, "wb") as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Forensic Report", f"Decrypted report saved as {decrypted_file}.")
                os.startfile(decrypted_file)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt report: {e}")

        decrypt_report_btn = ttk.Button(win, text="Decrypt Forensic Report", command=decrypt_forensic_report)
        decrypt_report_btn.pack(pady=5)

        # Add button to open the dashboard (admin-only)
        def open_dashboard_admin():
            self.open_dashboard()
        admin_dash_btn = ttk.Button(win, text="Open Dashboard", command=open_dashboard_admin)
        admin_dash_btn.pack(pady=5)

    def admin_login(self):
        login_win = tk.Toplevel(self.root)
        login_win.title("Admin Login")
        login_win.geometry("300x150")
        login_win.grab_set()

        ttk.Label(login_win, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(login_win)
        username_entry.pack(pady=5)
        ttk.Label(login_win, text="Password:").pack(pady=5)
        password_entry = ttk.Entry(login_win, show="*")
        password_entry.pack(pady=5)

        result = {"success": False}
        def attempt_login():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                result["success"] = True
                login_win.destroy()
            else:
                messagebox.showerror("Login Failed", "Invalid credentials")
        ttk.Button(login_win, text="Login", command=attempt_login).pack(pady=10)
        login_win.wait_window()
        return result["success"]

def run_app(start_usb_monitor):
    root = tk.Tk()
    def on_login_success(username):
        for widget in root.winfo_children():
            widget.destroy()
        USBMonitorApp(root, start_usb_monitor, current_user=username)
    LoginFrame(root, on_success=on_login_success)
    root.mainloop()

if __name__ == "__main__":
    run_app(lambda ins, rem: None)
