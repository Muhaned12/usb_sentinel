import hashlib
import os
import mimetypes
import datetime

def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[ERROR] Failed to compute hash for {file_path}: {e}")
        return None

def get_file_metadata(file_path):
    try:
        stats = os.stat(file_path)
        size = stats.st_size
        modification_time = datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        file_type, _ = mimetypes.guess_type(file_path)
        if not file_type:
            file_type = "Unknown"
        return {"size": size, "modification_time": modification_time, "file_type": file_type}
    except Exception as e:
        print(f"[ERROR] Could not get metadata for {file_path}: {e}")
        return {}
        
if __name__ == "__main__":
    print(compute_sha256("test.exe"))
    print(get_file_metadata("test.exe"))
