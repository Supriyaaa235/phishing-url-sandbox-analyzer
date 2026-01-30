import requests
import time
import json
from config import API_KEY, BASE_URL

headers = {
    "x-apikey": API_KEY
}

# ✅ Handles rate limits automatically
def safe_request(method, url, **kwargs):
    while True:
        response = requests.request(method, url, **kwargs)
        if response.status_code == 429:
            print("⚠️ Rate limit hit. Waiting 60 seconds...")
            time.sleep(60)
        else:
            response.raise_for_status()
            return response


def submit_url(url):
    data = {"url": url}
    response = safe_request(
        "POST",
        f"{BASE_URL}/urls",
        headers=headers,
        data=data
    )
    return response.json()["data"]["id"]


def get_analysis_report(analysis_id):
    while True:
        response = safe_request(
            "GET",
            f"{BASE_URL}/analyses/{analysis_id}",
            headers=headers
        )
        result = response.json()
        status = result["data"]["attributes"]["status"]

        if status == "completed":
            return result

        print("⏳ Waiting for analysis...")
        time.sleep(15)


def get_url_relationships(url_id, relationship):
    url = f"{BASE_URL}/urls/{url_id}/relationships/{relationship}"
    try:
        response = safe_request("GET", url, headers=headers)
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"❌ Could not fetch {relationship}: {e}")
        return {"data": []}


def extract_iocs(report, url_id):
    iocs = {
        "malicious_ips": set(),
        "malicious_domains": set(),
        "file_hashes": set()
    }

    # 🔍 IPs contacted by URL
    ip_data = get_url_relationships(url_id, "contacted_ips")
    for item in ip_data.get("data", []):
        stats = item["attributes"].get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0:
            iocs["malicious_ips"].add(item["id"])

    # 🔍 Domains contacted by URL
    domain_data = get_url_relationships(url_id, "contacted_domains")
    for item in domain_data.get("data", []):
        stats = item["attributes"].get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0:
            iocs["malicious_domains"].add(item["id"])

    return {k: list(v) for k, v in iocs.items()}


def save_output(iocs):
    if not iocs:
        iocs = {"message": "No IOCs found or data unavailable from API"}

    with open("sample_output.json", "w") as f:
        json.dump(iocs, f, indent=4)

    print("✅ IOCs saved to sample_output.json")


# ================== MAIN PROGRAM ==================

if __name__ == "__main__":
    url = input("Enter URL to analyze: ").strip()

    print("🚀 Submitting URL...")
    analysis_id = submit_url(url)

    print("📊 Fetching report...")
    report = get_analysis_report(analysis_id)

    # VirusTotal URL ID needed for relationships
    url_id = report.get("meta", {}).get("url_info", {}).get("id")

    if not url_id:
        print("⚠️ Could not retrieve URL ID for relationship data.")
        iocs = {}
    else:
        print("🔍 Extracting IOCs...")
        iocs = extract_iocs(report, url_id)

    print("\n🎯 IOC Results:")
    print(json.dumps(iocs, indent=4))

    save_output(iocs)
