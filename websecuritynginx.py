#!/usr/bin/env python3
import subprocess
import os
import sys
import json
import re

def run(command, cwd=None, capture_output=False, use_sudo=False, return_stderr=False):
    if use_sudo:
        if isinstance(command, str):
            command = f"sudo {command}"
        elif isinstance(command, list):
            if command[0] != "sudo":
                command.insert(0, "sudo")
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            check=True,
            shell=isinstance(command, str),
            capture_output=capture_output
        )
        if capture_output:
            return result.stderr.strip() if return_stderr else result.stdout.strip()
        return None
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {command}\n{e}")
        sys.exit(1)

home = os.path.expanduser("~")

def install_nginx_and_deps():
    print("🔧 Installing base dependencies and NGINX...")
    run("apt-get update", use_sudo=True)
    run("apt-get install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring unzip libmaxminddb-dev mmdb-bin", use_sudo=True)
    run("curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg > /dev/null", use_sudo=True)
    distro = run("lsb_release -cs", capture_output=True)
    repo = f"deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu {distro} nginx"
    run(f'echo "{repo}" | tee /etc/apt/sources.list.d/nginx.list', use_sudo=True)
    run("apt-get update", use_sudo=True)
    run("apt-get install -y nginx", use_sudo=True)
    run("systemctl enable nginx", use_sudo=True)
    run("systemctl start nginx", use_sudo=True)

def build_modsecurity():
    print("🔨 Building ModSecurity...")
    run("apt-get install -y git build-essential libtool automake autoconf libxml2-dev libyajl-dev pkgconf zlib1g-dev libcurl4-gnutls-dev libgeoip-dev liblmdb-dev libpcre2-dev", use_sudo=True)
    if not os.path.isdir("ModSecurity"):
        run("git clone https://github.com/SpiderLabs/ModSecurity")
    os.chdir("ModSecurity")
    run("git submodule init", use_sudo=True)
    run("git submodule update", use_sudo=True)
    run("./build.sh", use_sudo=True)
    run("./configure")
    run("make")
    run("make install", use_sudo=True)
    os.chdir(home)

def build_modsecurity_connector():
    print("🔩 Building ModSecurity-NGINX connector...")
    nginx_version_output = run(["nginx", "-v"], capture_output=True, return_stderr=True)
    version_match = re.search(r'nginx/([\d.]+)', nginx_version_output)
    if not version_match:
        print("❌ Could not detect NGINX version.")
        sys.exit(1)
    version = version_match.group(1)
    if not os.path.isdir("ModSecurity-nginx"):
        run("git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git")
    run(f"wget https://nginx.org/download/nginx-{version}.tar.gz")
    run(f"tar -zxvf nginx-{version}.tar.gz")
    os.chdir(f"nginx-{version}")
    run(f"./configure --with-compat --add-dynamic-module=../ModSecurity-nginx")
    run("make")
    run("make install", use_sudo=True)
    os.chdir(home)

def configure_crs_and_modsec():
    print("🛡️ Setting up ModSecurity CRS and configuration...")
    run("git clone https://github.com/coreruleset/coreruleset modsecurity-crs")
    os.chdir("modsecurity-crs")
    run("rm -f crs-setup.conf.example")
    run("wget -O crs-setup.conf https://raw.githubusercontent.com/Jegansri/swgopenrestyautomation/main/crs-setup.conf")
    os.chdir("rules")
    run("rm -f REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example")
    run("wget -O REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf https://raw.githubusercontent.com/Jegansri/swgopenrestyautomation/main/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf")
    os.chdir(home)
    run("mv modsecurity-crs /usr/local/", use_sudo=True)
    run("mkdir -p /etc/nginx/modsec", use_sudo=True)
    run("cp /root/ModSecurity/unicode.mapping /etc/nginx/modsec", use_sudo=True)
    run("wget -O /etc/nginx/modsec/modsecurity.conf https://raw.githubusercontent.com/Jegansri/swgopenrestyautomation/main/modsecurity.conf", use_sudo=True)
    run("wget -O /etc/nginx/modsec/main.conf https://raw.githubusercontent.com/Jegansri/swgopenrestyautomation/main/main.conf", use_sudo=True)

def setup_geoip2():
    print("🌐 Setting up GeoIP2 dynamic module and country database...")
    geoip2_dir = os.path.join(home, "ngx_http_geoip2_module-master")
    if not os.path.isdir(geoip2_dir):
        run(["wget", "-O", "master.zip", "https://github.com/leev/ngx_http_geoip2_module/archive/master.zip"], cwd=home)
        run(["unzip", "-o", "master.zip"], cwd=home)
    nginx_version_output = run(["nginx", "-v"], capture_output=True, return_stderr=True)
    version = re.search(r'nginx/([\d.]+)', nginx_version_output).group(1)
    archive = f"nginx-{version}.tar.gz"
    if not os.path.exists(os.path.join(home, archive)):
        run(["wget", f"https://nginx.org/download/{archive}"], cwd=home)
        run(["tar", "-zxvf", archive], cwd=home)
    src_dir = os.path.join(home, f"nginx-{version}")
    run(["./configure", "--with-compat", f"--add-dynamic-module={geoip2_dir}"], cwd=src_dir)
    run(["make"], cwd=src_dir)
    run(["make", "install"], cwd=src_dir, use_sudo=True)
    run(["mkdir", "-p", "/etc/nginx/geoip"], use_sudo=True)
    api_url = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"
    response = run(["curl", "-s", api_url], capture_output=True)
    mmdb_url = next(
        (asset["browser_download_url"]
         for asset in json.loads(response).get("assets", [])
         if asset["name"] == "GeoLite2-Country.mmdb"), None
    )
    if not mmdb_url:
        print("❌ GeoLite2-Country.mmdb not found.")
        sys.exit(1)
    run(["wget", "-O", "/etc/nginx/geoip/GeoLite2-Country.mmdb", mmdb_url], use_sudo=True)

def apply_configs_and_activate():
    print("🚀 Applying NGINX configs and enabling cron tasks...")
    files = [
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/nginx.conf", "/etc/nginx/nginx.conf"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/default.conf", "/etc/nginx/conf.d/default.conf"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/automate_waf_rules.py", "/opt/automate_waf_rules.py"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/clear_logs.py", "/opt/clear_logs.py"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/country_mmdb.py", "/opt/country_mmdb.py"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/setup_cronjobs.py", "/opt/setup_cronjobs.py"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/delete_nginx_files.py", "/root/delete_nginx_files.py"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/alluri.py", "/var/log/alluri.py"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/400.py", "/var/log/400.py"),
        ("https://raw.githubusercontent.com/Jegansri/nginxwebsecurity/main/403.py", "/var/log/403.py")
    ]
    for url, path in files:
        run(["wget", "-O", path, url], use_sudo=True)
        if path.endswith(".py"):
            run(["chmod", "+x", path], use_sudo=True)
    run(["/usr/bin/python3", "/opt/setup_cronjobs.py"], use_sudo=True)
    run(["/usr/bin/python3", "/root/delete_nginx_files.py"], use_sudo=True)
    run(["rm", "-rf", "/root/delete_nginx_files.py"], use_sudo=True)
    run(["rm", "-rf", "/root/master.zip"], use_sudo=True)
    run(["rm", "-rf", "/root/ModSecurity"], use_sudo=True)
    run(["rm", "-rf", "/root/ModSecurity-nginx"], use_sudo=True)
    run(["rm", "-rf", "/root/websecuritynginx.py"], use_sudo=True)
    run(["rm", "-rf", "/root/ngx_http_geoip2_module-master"], use_sudo=True)
    run(["systemctl", "restart", "nginx"], use_sudo=True)
    run(["systemctl", "status", "nginx"], use_sudo=True)

    print("\n✅ NGINX is secured, modules enabled, and automation initialized.\n")

def main():
    install_nginx_and_deps()
    build_modsecurity()
    build_modsecurity_connector()
    configure_crs_and_modsec()
    setup_geoip2()
    apply_configs_and_activate()

if __name__ == "__main__":
    main()

