#!/usr/bin/env python3
import subprocess

def run(command, shell=False, use_sudo=False):
    if use_sudo:
        if isinstance(command, str):
            command = f"sudo {command}"
        else:
            command = ["sudo"] + command

    try:
        result = subprocess.run(command, shell=shell, check=True, capture_output=True, text=True)
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr

# Test the command
success, stdout, stderr = run("rm -rf /root/nginx-1.*", shell=True, use_sudo=True)
if success:
    print("✅ Files deleted successfully")
else:
    print(f"❌ Error: {stderr}")
