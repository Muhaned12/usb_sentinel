import threading
import usb_monitor
import gui

def start_usb_monitor(callback_insert, callback_remove):
    def monitor_thread():
        usb_monitor.usb_monitor(callback_insert, callback_remove)
    t = threading.Thread(target=monitor_thread, daemon=True)
    t.start()

if __name__ == "__main__":
    gui.run_app(start_usb_monitor)
