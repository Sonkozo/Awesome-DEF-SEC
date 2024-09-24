import os
import subprocess
import psutil
import smtplib
import platform
from email.mime.text import MIMEText

# Configurable: List of allowed admin users
ALLOWED_ADMINS = ['Administrator', 'MyAdminUser']
EMAIL_ALERT = "security@example.com"  # Replace with your email
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "your_smtp_user"
SMTP_PASSWORD = "your_smtp_password"

def send_email_alert(subject, body):
    """Send an email alert in case of any issues."""
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ALERT
    msg['To'] = EMAIL_ALERT
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_ALERT, EMAIL_ALERT, msg.as_string())
    except Exception as e:
        print(f"Failed to send email alert: {e}")

def check_open_ports():
    """Check for open ports using netstat."""
    try:
        output = subprocess.check_output(['netstat', '-an'], universal_newlines=True)
        return output
    except Exception as e:
        send_email_alert("Port Check Failed", f"Failed to run netstat: {e}")
        return None

def check_windows_updates():
    """Check for missing security patches."""
    try:
        output = subprocess.check_output(['powershell', '-Command', 'Get-WindowsUpdateLog'], universal_newlines=True)
        return output
    except Exception as e:
        send_email_alert("Windows Update Check Failed", f"Failed to check Windows updates: {e}")
        return None

def check_antivirus_status():
    """Check the status of Windows Defender or other antivirus."""
    try:
        output = subprocess.check_output(['powershell', '-Command', 'Get-MpComputerStatus'], universal_newlines=True)
        if "AMServiceEnabled" in output:
            return "Antivirus is active"
        else:
            send_email_alert("Antivirus Status Alert", "Windows Defender or another antivirus is not running.")
            return "Antivirus not active"
    except Exception as e:
        send_email_alert("Antivirus Check Failed", f"Failed to check antivirus status: {e}")
        return None

def check_admin_users():
    """Check for unauthorized admin users."""
    try:
        output = subprocess.check_output(['powershell', '-Command', 'Get-LocalGroupMember -Group "Administrators"'], universal_newlines=True)
        admins = [line.strip() for line in output.splitlines()]
        unauthorized_admins = [admin for admin in admins if admin not in ALLOWED_ADMINS]
        if unauthorized_admins:
            send_email_alert("Unauthorized Admin Alert", f"Unauthorized admin users found: {unauthorized_admins}")
        return admins
    except Exception as e:
        send_email_alert("Admin Check Failed", f"Failed to check admin users: {e}")
        return None

def check_failed_login_attempts():
    """Check for failed login attempts."""
    try:
        output = subprocess.check_output(['powershell', '-Command', 'Get-EventLog -LogName Security -InstanceId 4625'], universal_newlines=True)
        return output
    except Exception as e:
        send_email_alert("Login Attempt Check Failed", f"Failed to check failed logins: {e}")
        return None

def check_suspicious_processes():
    """Monitor processes for suspicious activity."""
    suspicious_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            # Custom logic to identify suspicious processes
            if proc.info['name'] in ["malicious.exe", "unknown.exe"]:  # Example
                suspicious_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if suspicious_processes:
        send_email_alert("Suspicious Process Alert", f"Suspicious processes found: {suspicious_processes}")
    return suspicious_processes

def check_firewall_status():
    """Check if Windows Firewall is enabled."""
    try:
        output = subprocess.check_output(['netsh', 'advfirewall', 'show', 'allprofiles'], universal_newlines=True)
        if "State ON" not in output:
            send_email_alert("Firewall Status Alert", "Windows Firewall is not enabled.")
        return output
    except Exception as e:
        send_email_alert("Firewall Check Failed", f"Failed to check firewall status: {e}")
        return None

def run_security_checks():
    """Run all the security checks."""
    print("Running security checks...")
    
    # 1. Check open ports
    open_ports = check_open_ports()
    if open_ports:
        print(f"Open ports:\n{open_ports}")
    
    # 2. Check for missing updates
    missing_updates = check_windows_updates()
    if missing_updates:
        print(f"Windows Updates:\n{missing_updates}")
    
    # 3. Check antivirus status
    antivirus_status = check_antivirus_status()
    if antivirus_status:
        print(f"Antivirus Status: {antivirus_status}")
    
    # 4. Check for unauthorized admin users
    admins = check_admin_users()
    if admins:
        print(f"Admin Users: {admins}")
    
    # 5. Check failed login attempts
    failed_logins = check_failed_login_attempts()
    if failed_logins:
        print(f"Failed Login Attempts:\n{failed_logins}")
    
    # 6. Check suspicious processes
    suspicious_processes = check_suspicious_processes()
    if suspicious_processes:
        print(f"Suspicious Processes: {suspicious_processes}")
    
    # 7. Check firewall status
    firewall_status = check_firewall_status()
    if firewall_status:
        print(f"Firewall Status:\n{firewall_status}")

if __name__ == "__main__":
    run_security_checks()
