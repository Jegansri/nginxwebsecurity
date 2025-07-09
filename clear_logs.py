#!/usr/bin/env python3

import os
import subprocess

def run_command(command, shell=True):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(command, shell=shell, check=True,
                              capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr

def clear_log_file(log_path):
    """Clear a log file using the :> command"""
    success, stdout, stderr = run_command(f":> {log_path}")
    if success:
        print(f"✅ Cleared: {log_path}")
        return True
    else:
        print(f"❌ Failed to clear {log_path}: {stderr}")
        return False

def main():
    """Main function to clear all specified log files"""

    print("=== Clearing Log Files ===")

    # Define log files to clear
    log_files = [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/modsec_audit.log"
    ]

    cleared_count = 0

    for log_file in log_files:
        # Check if file exists
        if os.path.exists(log_file):
            if clear_log_file(log_file):
                cleared_count += 1
        else:
            print(f"⚠️  File not found: {log_file}")

    print(f"\n🎉 Successfully cleared {cleared_count} out of {len(log_files)} log files")

if __name__ == "__main__":
    main()
