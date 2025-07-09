import os
import json
from subprocess import run
from datetime import datetime

def download_geolite_if_needed():
    print("=== [14] Checking GeoLite2 database ===")

    mmdb_path = "/etc/nginx/geoip/GeoLite2-Country.mmdb"
    api_url = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"

    # Get latest release info
    api_response = run(["curl", "-s", api_url], capture_output=True, text=True)
    if api_response.returncode != 0:
        print("❌ Failed to fetch release information")
        return False

    try:
        release_info = json.loads(api_response.stdout)
    except json.JSONDecodeError:
        print("❌ Failed to parse release information")
        return False

    # Find the mmdb asset
    mmdb_asset = None
    for asset in release_info.get("assets", []):
        if asset.get("name") == "GeoLite2-Country.mmdb":
            mmdb_asset = asset
            break

    if not mmdb_asset:
        print("❌ Could not find GeoLite2-Country.mmdb in the latest release.")
        return False

    # Check if file exists and compare dates
    if os.path.exists(mmdb_path):
        # Get local file modification time
        local_mtime = os.path.getmtime(mmdb_path)
        local_date = datetime.fromtimestamp(local_mtime)

        # Get remote file update time
        remote_date_str = mmdb_asset.get("updated_at")
        if remote_date_str:
            remote_date = datetime.fromisoformat(remote_date_str.replace('Z', '+00:00'))

            if local_date >= remote_date.replace(tzinfo=None):
                print("✅ Local GeoLite2 database is already up to date")
                return True

    # Download the file
    mmdb_url = mmdb_asset.get("browser_download_url")
    print(f"📥 Downloading latest GeoLite2 database from: {mmdb_url}")

    download_result = run([
        "wget", "-O", mmdb_path, mmdb_url
    ], capture_output=True)

    if download_result.returncode == 0:
        print("✅ GeoLite2-Country.mmdb updated successfully")
        return True
    else:
        print("❌ Failed to download GeoLite2-Country.mmdb")
        return False

# Usage
download_geolite_if_needed()
