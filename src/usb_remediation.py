import win32file
import winioctlcon

def eject_drive(drive_letter):
    """
    Attempts to eject (safely remove) the USB drive with the specified drive letter.
    The drive_letter should be in the form "E:".
    Returns True if ejection succeeded; otherwise, prints an error and returns False.
    """
    device_path = r"\\.\%s" % drive_letter
    try:
        # Open a handle to the drive
        handle = win32file.CreateFile(
            device_path,
            win32file.GENERIC_READ,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        # Send the eject media command
        win32file.DeviceIoControl(handle, winioctlcon.IOCTL_STORAGE_EJECT_MEDIA, None, 0)
        handle.Close()
        return True
    except Exception as e:
        print(f"[ERROR] Could not eject drive {drive_letter}: {e}")
        return False

if __name__ == "__main__":
    # Test by trying to eject drive E: (adjust as needed)
    success = eject_drive("E:")
    print("Ejection succeeded." if success else "Ejection failed.")
