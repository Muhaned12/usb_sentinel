import win32api
import win32gui
import win32con
import time
import wmi
import pythoncom

# Global dictionary to track currently detected USB storage devices by serial number
detected_usb = {}

def get_usb_storage_details():
    r"""
    Returns a dictionary mapping USB storage device serial numbers to device names.
    Uses Win32_DiskDrive filtered by InterfaceType="USB".
    Example PNPDeviceID: "USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001220218115301&0"
    The serial number is extracted as the last part.
    """
    result = {}
    try:
        pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
        c = wmi.WMI()
        drives = c.Win32_DiskDrive(InterfaceType="USB")
        for drive in drives:
            if drive.PNPDeviceID:
                parts = drive.PNPDeviceID.split("\\")
                serial = parts[-1] if parts else "Unknown Serial"
            else:
                serial = "Unknown Serial"
            result[serial] = drive.Caption
    except Exception as e:
        print(f"[ERROR] get_usb_storage_details failed: {e}")
    finally:
        pythoncom.CoUninitialize()
    return result

def get_drive_letter_by_serial(serial):
    """
    Returns the drive letter (e.g., "E:") for the USB storage device with the given serial.
    It uses WMI associations between Win32_DiskDrive, DiskPartition, and LogicalDisk.
    """
    drive_letter = None
    try:
        pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
        c = wmi.WMI()
        for drive in c.Win32_DiskDrive(InterfaceType="USB"):
            if drive.PNPDeviceID:
                parts = drive.PNPDeviceID.split("\\")
                drive_serial = parts[-1] if parts else ""
                if drive_serial == serial:
                    for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
                        for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                            drive_letter = logical_disk.DeviceID  # e.g., "E:"
                            break
                        if drive_letter:
                            break
            if drive_letter:
                break
    except Exception as e:
        print(f"[ERROR] get_drive_letter_by_serial failed: {e}")
    finally:
        pythoncom.CoUninitialize()
    return drive_letter

class DeviceNotificationWindow:
    def __init__(self, on_insert, on_remove):
        """
        :param on_insert: Callback function(device_name, serial_number) for USB insertion.
        :param on_remove: Callback function() for USB removal.
        """
        self.on_insert = on_insert
        self.on_remove = on_remove

        message_map = {
            win32con.WM_DEVICECHANGE: self.on_device_change
        }
        wc = win32gui.WNDCLASS()
        self.hinst = wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpszClassName = "DeviceChangeClass"
        wc.lpfnWndProc = message_map
        self.classAtom = win32gui.RegisterClass(wc)
        self.hwnd = win32gui.CreateWindow(
            self.classAtom,
            "DeviceChangeWindow",
            0,
            0, 0,
            win32con.CW_USEDEFAULT,
            win32con.CW_USEDEFAULT,
            0, 0,
            self.hinst,
            None
        )
        win32gui.UpdateWindow(self.hwnd)

    def on_device_change(self, hwnd, msg, wparam, lparam):
        global detected_usb
        if wparam == win32con.DBT_DEVICEARRIVAL:
            print("[DEBUG] Device arrival event detected.")
            new_devices = get_usb_storage_details()
            print("[DEBUG] Current USB storage devices:", new_devices)
            for serial, name in new_devices.items():
                if serial not in detected_usb:
                    detected_usb[serial] = name
                    print(f"[PyWin32] Inserted: {name} (Serial: {serial})")
                    self.on_insert(name, serial)
        elif wparam == win32con.DBT_DEVICEREMOVECOMPLETE:
            print("[DEBUG] Device removal event detected.")
            new_devices = get_usb_storage_details()
            print("[DEBUG] USB storage devices after removal:", new_devices)
            removed = [serial for serial in detected_usb if serial not in new_devices]
            for serial in removed:
                name = detected_usb[serial]
                print(f"[PyWin32] Removed: {name} (Serial: {serial})")
                self.on_remove()
                del detected_usb[serial]
        return True

def usb_monitor(callback_insert, callback_remove):
    dnw = DeviceNotificationWindow(callback_insert, callback_remove)
    while True:
        win32gui.PumpWaitingMessages()
        time.sleep(0.1)

if __name__ == "__main__":
    def on_insert(name, serial):
        print(f"Inserted: {name} (Serial: {serial})")
    def on_remove():
        print("USB Removed")
    usb_monitor(on_insert, on_remove)
