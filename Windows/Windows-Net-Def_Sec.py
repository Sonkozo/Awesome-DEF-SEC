import subprocess
import psutil
import smtplib
from email.mime.text import MIMEText

# Configurable
ALLOWED_AD_USERS = ['AdminUser1', 'AdminUser2']
ALLOWED_GPO_POLICIES = ['EnforcePasswordPolicy', 'NetworkAccessControl']
EMAIL_ALERT = "networksecurity@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "smtp_user"
SMTP_PASSWORD = "smtp_password"

def send_email_alert(subject, body):
    """Send an email alert for network security issues."""
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

def check_inactive_ad_users():
    """Check for inactive or expired Active Directory (AD) users."""
    try:
        output = subprocess.check_output(
            ['powershell', '-Command', 'Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00'], 
            universal_newlines=True
        )
        if output:
            send_email_alert("Inactive AD Users Alert", f"Inactive or expired AD users found:\n{output}")
        return output
    except Exception as e:
        send_email_alert("AD User Check Failed", f"Failed to check AD users: {e}")
        return None

def check_gpo_policies():
    """Check for compliance with key GPO policies."""
    try:
        output = subprocess.check_output(['powershell', '-Command', 'Get-GPO -All'], universal_newlines=True)
        non_compliant_policies = [policy for policy in ALLOWED_GPO_POLICIES if policy not in output]
        if non_compliant_policies:
            send_email_alert("GPO Compliance Alert", f"Non-compliant GPO policies: {non_compliant_policies}")
        return output
    except Exception as e:
        send_email_alert("GPO Check Failed", f"Failed to check GPO policies: {e}")
        return None

def check_network_shares():
    """Audit access permissions to sensitive network shares."""
    try:
        output = subprocess.check_output(['powershell', '-Command', 'Get-SmbShare'], universal_newlines=True)
        shares = output.splitlines()
        sensitive_shares = [share for share in shares if 'sensitive' in share.lower()]  # Example logic
        if sensitive_shares:
            send_email_alert("Network Share Alert", f"Sensitive network shares found:\n{sensitive_shares}")
        return shares
    except Exception as e:
        send_email_alert("Network Share Check Failed", f"Failed to check network shares: {e}")
        return None

def check_secure_network_protocols():
    """Ensure that only secure protocols (e.g., TLS 1.2) are enabled."""
    try:
        output = subprocess.check_output(
            ['powershell', '-Command', 'Get-TlsCipherSuite'], universal_newlines=True
        )
        if 'TLS_RSA_WITH_AES_128_CBC_SHA' not in output:  # Example logic for TLS 1.2
            send_email_alert("Network Protocol Alert", "Insecure protocols detected, TLS 1.2 not enforced.")
        return output
    except Exception as e:
        send_email_alert("Network Protocol Check Failed", f"Failed to check network protocols: {e}")
        return None

def check_event_logs():
    """Monitor event logs for network-specific security issues."""
    try:
        output = subprocess.check_output(
            ['powershell', '-Command', 'Get-EventLog -LogName Security -Newest 100'], 
            universal_newlines=True
        )
        suspicious_events = [line for line in output.splitlines() if 'failure' in line.lower()]  # Example logic
        if suspicious_events:
            send_email_alert("Event Log Alert", f"Suspicious events found:\n{suspicious_events}")
        return output
    except Exception as e:
        send_email_alert("Event Log Check Failed", f"Failed to check event logs: {e}")
        return None

def check_dns_dhcp_audits():
    """Verify DNS and DHCP server configuration."""
    try:
        dns_output = subprocess.check_output(['powershell', '-Command', 'Get-DnsServer'], universal_newlines=True)
        dhcp_output = subprocess.check_output(['powershell', '-Command', 'Get-DhcpServerv4Scope'], universal_newlines=True)
        
        # Simple check for DNS misconfiguration (example)
        if 'forwarders' not in dns_output:
            send_email_alert("DNS Misconfiguration Alert", "DNS server misconfigured (no forwarders).")
        
        # Simple check for DHCP misconfiguration (example)
        if 'ActiveState' not in dhcp_output:
            send_email_alert("DHCP Misconfiguration Alert", "DHCP server misconfigured or inactive.")
        
        return dns_output, dhcp_output
    except Exception as e:
        send_email_alert("DNS/DHCP Check Failed", f"Failed to check DNS or DHCP settings: {e}")
        return None

def check_smb_security():
    """Ensure that insecure versions of SMB (e.g., SMBv1) are disabled."""
    try:
        output = subprocess.check_output(
            ['powershell', '-Command', 'Get-WindowsFeature -Name FS-SMB1'], 
            universal_newlines=True
        )
        if 'Installed' in output:
            send_email_alert("SMB Security Alert", "SMBv1 is enabled. Disable it for better security.")
        return output
    except Exception as e:
        send_email_alert("SMB Security Check Failed", f"Failed to check SMB status: {e}")
        return None

def run_network_security_checks():
    """Run all network security checks."""
    print("Running network security checks...")
    
    # 1. Check for inactive AD users
    ad_users = check_inactive_ad_users()
    if ad_users:
        print(f"Inactive AD Users:\n{ad_users}")
    
    # 2. Check GPO compliance
    gpo_policies = check_gpo_policies()
    if gpo_policies:
        print(f"GPO Policies:\n{gpo_policies}")
    
    # 3. Check network shares
    network_shares = check_network_shares()
    if network_shares:
        print(f"Network Shares:\n{network_shares}")
    
    # 4. Check secure network protocols (e.g., TLS 1.2)
    secure_protocols = check_secure_network_protocols()
    if secure_protocols:
        print(f"Network Protocols:\n{secure_protocols}")
    
    # 5. Check event logs for suspicious network activity
    event_logs = check_event_logs()
    if event_logs:
        print(f"Event Logs:\n{event_logs}")
    
    # 6. Check DNS and DHCP server settings
    dns_dhcp = check_dns_dhcp_audits()
    if dns_dhcp:
        print(f"DNS and DHCP Settings:\n{dns_dhcp}")
    
    # 7. Check for SMBv1 (insecure)
    smb_security = check_smb_security()
    if smb_security:
        print(f"SMB Status:\n{smb_security}")

if __name__ == "__main__":
    run_network_security_checks()
