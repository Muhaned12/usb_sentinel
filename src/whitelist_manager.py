import os

WHITELIST_FILE = "whitelist.csv"

def load_whitelist():
    whitelist = {}
    if not os.path.exists(WHITELIST_FILE):
        return whitelist
    with open(WHITELIST_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                parts = line.split(",")
                if len(parts) >= 2:
                    serial = parts[0].strip()
                    employee = parts[1].strip()
                    whitelist[serial] = employee
                else:
                    serial = parts[0].strip()
                    whitelist[serial] = ""
    return whitelist

def save_whitelist(whitelist):
    with open(WHITELIST_FILE, "w") as f:
        for serial, employee in whitelist.items():
            f.write(f"{serial},{employee}\n")

def add_to_whitelist(serial, employee):
    whitelist = load_whitelist()
    if serial in whitelist:
        return False  # already exists; use update_whitelist instead
    whitelist[serial] = employee
    save_whitelist(whitelist)
    return True

def update_whitelist(serial, employee):
    whitelist = load_whitelist()
    whitelist[serial] = employee
    save_whitelist(whitelist)

def remove_from_whitelist(serial):
    whitelist = load_whitelist()
    if serial in whitelist:
        del whitelist[serial]
        save_whitelist(whitelist)
        return True
    return False

if __name__ == "__main__":
    print("Current whitelist:", load_whitelist())
    add_to_whitelist("TEST_SERIAL", "John Doe")
    print("After adding TEST_SERIAL:", load_whitelist())
    update_whitelist("TEST_SERIAL", "Jane Doe")
    print("After updating TEST_SERIAL:", load_whitelist())
    remove_from_whitelist("TEST_SERIAL")
    print("After removing TEST_SERIAL:", load_whitelist())
