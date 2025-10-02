import requests

VIRUSTOTAL_API_KEY = "ce8c943433437567bf10edc202c12a8237b80d70ab9f525c4009f0db0e9bfd6c"

def check_usb_threat(file_hash):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not set."}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats
    elif response.status_code == 404:
        # Instead of returning an error for 404, return {"unknown": True}
        return {"unknown": True}
    else:
        return {"error": f"HTTP {response.status_code}"}

if __name__ == "__main__":
    result = check_usb_threat("ABC123")
    print(result)
