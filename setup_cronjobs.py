#!/usr/bin/env python3

import subprocess
import os
import tempfile

def run_command(command, shell=True):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(command, shell=shell, check=True,
                              capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr

def add_cronjobs():
    """Add cronjobs for WAF rules, GeoLite2 database updates, and log clearing"""

    # Define the cronjob entries
    cronjobs = [
        "# WAF Rules Update - Every Sunday at 7:30 AM IST",
        "30 7 * * 0 /usr/bin/python3 /opt/automate_waf_rules.py",
        "",
        "# GeoLite2 Database Update - Every Saturday at 7:30 AM IST",
        "30 7 * * 6 /usr/bin/python3 /opt/country_mmdb.py",
        "",
        "# Clear Logs - Every Saturday at 7:30 AM IST",
        "30 7 * * 6 /usr/bin/python3 /opt/clear_logs.py",
        ""
    ]

    print("Adding cronjobs...")

    # Get current crontab
    success, current_crontab, stderr = run_command("crontab -l")
    if not success and "no crontab for" not in stderr:
        print(f"Error reading current crontab: {stderr}")
        return False

    # If no crontab exists, start with empty
    if not success:
        current_crontab = ""

    # Check if our jobs already exist
    if "/opt/automate_waf_rules.py" in current_crontab:
        print("⚠️  WAF rules cronjob already exists")
    if "/opt/country_mmdb.py" in current_crontab:
        print("⚠️  GeoLite2 database cronjob already exists")
    if "/opt/clear_logs.py" in current_crontab:
        print("⚠️  Clear logs cronjob already exists")

    # Add new cronjobs if they don't exist
    new_crontab = current_crontab

    if "/opt/automate_waf_rules.py" not in current_crontab:
        new_crontab += "\n" + cronjobs[0] + "\n" + cronjobs[1] + "\n"
        print("✅ Added WAF rules update cronjob")

    if "/opt/country_mmdb.py" not in current_crontab:
        new_crontab += "\n" + cronjobs[3] + "\n" + cronjobs[4] + "\n"
        print("✅ Added GeoLite2 database update cronjob")

    if "/opt/clear_logs.py" not in current_crontab:
        new_crontab += "\n" + cronjobs[6] + "\n" + cronjobs[7] + "\n"
        print("✅ Added clear logs cronjob")

    # Write the new crontab
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        temp_file.write(new_crontab.strip() + "\n")
        temp_file_path = temp_file.name

    try:
        success, stdout, stderr = run_command(f"crontab {temp_file_path}")
        if success:
            print("✅ Crontab updated successfully")
        else:
            print(f"❌ Failed to update crontab: {stderr}")
            return False
    finally:
        os.unlink(temp_file_path)

    return True

def restart_cron_service():
    """Restart and check cron service status"""

    print("\nRestarting cron service...")
    success, stdout, stderr = run_command("systemctl restart cron")

    if success:
        print("✅ Cron service restarted successfully")
    else:
        print(f"❌ Failed to restart cron service: {stderr}")
        return False

    print("\nChecking cron service status...")
    success, stdout, stderr = run_command("systemctl status cron --no-pager")

    if success:
        print("✅ Cron service status:")
        print(stdout)
    else:
        print(f"❌ Failed to get cron service status: {stderr}")
        return False

    return True

def main():
    """Main function to add cronjobs and restart cron service"""

    print("=== Setting up Cronjobs ===")

    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script must be run as root")
        return

    # Add cronjobs
    if not add_cronjobs():
        print("❌ Failed to add cronjobs")
        return

    # Restart cron service
    if not restart_cron_service():
        print("❌ Failed to restart cron service")
        return

    print("\n🎉 All done! Cronjobs have been set up successfully.")
    print("\nScheduled jobs:")
    print("• WAF Rules Update: Every Sunday at 7:30 AM IST")
    print("• GeoLite2 Database Update: Every Saturday at 7:30 AM IST")
    print("• Clear Logs: Every Saturday at 7:30 AM IST")

if __name__ == "__main__":
    main()
