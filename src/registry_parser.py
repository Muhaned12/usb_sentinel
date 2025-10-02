import winreg
import pandas as pd

def get_usb_history():
    r"""
    Reads USB history from the live Windows registry using winreg.
    Queries the key: HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\USBSTOR
    Returns a pandas DataFrame with a column named 'Device'.
    """
    devices = []
    reg_path = r"SYSTEM\ControlSet001\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    devices.append({"Device": subkey_name})
                    i += 1
                except OSError:
                    break
    except PermissionError:
        print("[Registry Parser] Permission denied. Run as Administrator.")
        return pd.DataFrame()
    except Exception as e:
        print(f"[Registry Parser] Error: {e}")
        return pd.DataFrame()
    return pd.DataFrame(devices)

if __name__ == "__main__":
    df = get_usb_history()
    print(df if not df.empty else "No devices found.")
