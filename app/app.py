import imaplib
import smtplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import os
import time
import datetime
import ssl
import threading
from netmiko import ConnectHandler

# --- CONFIGURATION (LOAD FROM ENV) ---
IMAP_SERVER = os.getenv('IMAP_SERVER')
IMAP_PORT = int(os.getenv('IMAP_PORT', 993))
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER') 
EMAIL_PASS = os.getenv('EMAIL_PASS')

# Mail Settings
SENDER_ADDR = os.getenv('SENDER_ADDR', EMAIL_USER)
REPLY_TO_ADDR = os.getenv('REPLY_TO_ADDR', EMAIL_USER)
COMPANY_DOMAIN = os.getenv('COMPANY_DOMAIN', '@example.com') # Örn: @sirket.com

# Reply Verification Account (Usually same as EMAIL_USER)
REPLY_CHECK_USER = os.getenv('REPLY_CHECK_USER', EMAIL_USER)
REPLY_CHECK_PASS = os.getenv('REPLY_CHECK_PASS', EMAIL_PASS)

# Logic Settings
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', 60))
WAIT_TIME_SECONDS = int(os.getenv('WAIT_TIME_SECONDS', 120))
TARGET_SUBJECT = os.getenv('TARGET_SUBJECT', 'MESAI SAATI DISI VPN ERISIMI')

# Firewall Settings (FortiGate)
FG_IP = os.getenv('FG_IP')
FG_USER = os.getenv('FG_USER')
FG_PASS = os.getenv('FG_PASS')
FG_SSH_PORT = int(os.getenv('FG_SSH_PORT', 22))

# --- HELPER FUNCTIONS ---

def create_unverified_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def get_imap_connection(user, password):
    ssl_context = create_unverified_context()
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, ssl_context=ssl_context)
    mail.login(user, password)
    return mail

def get_decoded_header(header_value):
    if not header_value: return ""
    decoded_list = decode_header(header_value)
    full_subject = ""
    for content, encoding in decoded_list:
        if isinstance(content, bytes):
            full_subject += content.decode(encoding if encoding else 'utf-8', errors='ignore')
        else:
            full_subject += content
    return full_subject

# --- ACTIVE RESPONSE (FIREWALL BLOCK) ---

def kill_vpn_session_ssh(username):
    """Connects to FortiGate via SSH and terminates the VPN session."""
    if not FG_IP or not FG_USER:
        print("[WARN] Firewall configuration missing. Skipping kill action.")
        return

    print(f"[ACTION] Terminating VPN session for {username} via SSH...")
    
    fg_device = {
        'device_type': 'fortinet',
        'host': FG_IP,
        'username': FG_USER,
        'password': FG_PASS,
        'port': FG_SSH_PORT,
        'global_delay_factor': 2
    }

    try:
        net_connect = ConnectHandler(**fg_device)
        # Command syntax for FortiOS
        command = f"execute vpn ssl disconnect user {username}"
        output = net_connect.send_command(command)
        print(f"[FIREWALL] Output: {output}")
        net_connect.disconnect()
        print(f"[SUCCESS] User {username} kicked from VPN.")
    except Exception as e:
        print(f"[ERROR] Firewall SSH Connection Error: {e}")

# --- VERIFICATION THREAD ---

def verify_response_and_act(target_user, target_ip):
    """Waits for X seconds, checks for a reply, and kills session if no reply found."""
    
    print(f"[TIMER] Countdown started for {target_user} ({WAIT_TIME_SECONDS}s)...")
    time.sleep(WAIT_TIME_SECONDS)
    
    print(f"[TIMER] Time is up for {target_user}. Checking replies...")
    
    try:
        mail = get_imap_connection(REPLY_CHECK_USER, REPLY_CHECK_PASS)
        mail.select("inbox")
        
        # Search for mails FROM the user
        user_email = f"{target_user}{COMPANY_DOMAIN}"
        search_criteria = f'(FROM "{user_email}")'
        
        # Note: Ideally, we should check the time of the email too.
        # This simple check looks for ANY unread email from the user in the inbox.
        status, messages = mail.search(None, search_criteria)
        
        has_replied = False
        if messages[0]:
            has_replied = True
            print(f"[VERIFIED] Reply received from {target_user}. No action needed.")
        
        mail.close()
        mail.logout()
        
        if not has_replied:
            print(f"[ALERT] NO REPLY from {target_user} (IP: {target_ip})! Initiating Active Response...")
            kill_vpn_session_ssh(target_user)
            
    except Exception as e:
        print(f"[ERROR] Error verifying response: {e}")

# --- EMAIL LOGIC ---

def send_inquiry_email(target_user, event_time, remote_ip):
    target_email = f"{target_user}{COMPANY_DOMAIN}"
    subject = f"SECURITY ALERT: VPN Access Detected ({target_user})"
    
    body = f"""
    Hello {target_user.split('.')[0].capitalize()},

    [AUTOMATED SECURITY CHECK]
    
    A VPN session was detected with your account at {event_time}.
    Source IP: {remote_ip}
    
    Since this access is outside of standard business hours (or flagged by SIEM), verification is required.

    ACTION REQUIRED:
    If this is you, please REPLY to this email within {int(WAIT_TIME_SECONDS/60)} MINUTES with a brief explanation (e.g., "Approved").
    
    If we do not receive a reply, your VPN session will be TERMINATED automatically.
    
    If this was not you, please contact the Security Team immediately.

    SecOps Automation
    """

    msg = MIMEMultipart()
    msg['From'] = SENDER_ADDR
    msg['To'] = target_email
    msg['Subject'] = subject
    msg['Reply-To'] = REPLY_TO_ADDR 
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        try:
            ssl_context = create_unverified_context()
            server.starttls(context=ssl_context)
        except: pass

        try:
            server.login(EMAIL_USER, EMAIL_PASS)
        except: 
            print("[INFO] SMTP Auth not supported/needed. Trying anonymous...")

        server.sendmail(SENDER_ADDR, target_email, msg.as_string())
        server.quit()
        print(f"[SUCCESS] Warning email sent to {target_email}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
        return False

def delete_logs_from_trash(mail):
    """Tries to find and delete logs from 'Deleted Items' or 'Trash'."""
    try:
        trash_folders = ["Deleted Items", "Silinmiş Öğeler", "Trash", "Bin"]
        selected_folder = None
        for folder in trash_folders:
            try:
                if mail.select(folder)[0] == 'OK':
                    selected_folder = folder
                    break
            except: continue
        
        if not selected_folder: return

        status, messages = mail.search(None, 'ALL')
        if not messages[0]: return

        email_ids = messages[0].split()
        count = 0
        for e_id in email_ids:
            res, msg_data = mail.fetch(e_id, '(RFC822.HEADER)')
            for part in msg_data:
                if isinstance(part, tuple):
                    msg = email.message_from_bytes(part[1])
                    sub = get_decoded_header(msg.get("Subject"))
                    if TARGET_SUBJECT in sub.upper():
                        mail.store(e_id, '+FLAGS', '\\Deleted')
                        count += 1
        if count > 0: mail.expunge()
    except: pass

def process_emails():
    try:
        mail = get_imap_connection(EMAIL_USER, EMAIL_PASS)
        mail.select("inbox")

        status, messages = mail.search(None, 'UNSEEN')
        processed = False

        if messages[0]:
            email_ids = messages[0].split()
            print(f"[DEBUG] Processing {len(email_ids)} unread emails...")

            for e_id in email_ids:
                res, msg_data = mail.fetch(e_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        raw_sub = msg.get("Subject")
                        sub = get_decoded_header(raw_sub)
                        
                        # Filter by Subject
                        if TARGET_SUBJECT not in sub.upper(): continue

                        print(f"[MATCH] Log Found: {sub}")

                        # Combine Text and HTML parts
                        full_body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() in ["text/plain", "text/html"]:
                                    p = part.get_payload(decode=True)
                                    if p: full_body += p.decode(errors='ignore')
                        else:
                            full_body = msg.get_payload(decode=True).decode(errors='ignore')

                        # REGEX Extraction
                        user_match = re.search(r'user=["\']?([^"\s\']+)["\']?', full_body, re.IGNORECASE)
                        time_match = re.search(r'date=(\S+)\s+time=(\S+)', full_body)
                        ip_match = re.search(r'remip=([\d\.]+)', full_body)
                        
                        if user_match:
                            raw_user = user_match.group(1)
                            user = raw_user.replace("&quot;", "").replace('"', "").replace("'", "").strip()
                            
                            ts = f"{time_match.group(1)} {time_match.group(2)}" if time_match else "Unknown Time"
                            ip = ip_match.group(1) if ip_match else "0.0.0.0"
                            
                            print(f"[INFO] User: {user} | IP: {ip}")
                            
                            # 1. Send Warning Email
                            sent = send_inquiry_email(user, ts, ip)
                            
                            if sent:
                                # 2. Delete Log from Inbox
                                mail.store(e_id, '+FLAGS', '\\Deleted')
                                processed = True
                                
                                # 3. Start Verification Timer (Async)
                                t = threading.Thread(target=verify_response_and_act, args=(user, ip))
                                t.start()

            if processed:
                mail.expunge()
                delete_logs_from_trash(mail)

        mail.close()
        mail.logout()

    except Exception as e:
        print(f"[ERROR] Main Loop Error: {e}")

if __name__ == "__main__":
    print(f"VPN Guard Bot Started...")
    print(f"Target Subject: {TARGET_SUBJECT}")
    print(f"Active Response Wait Time: {WAIT_TIME_SECONDS}s")
    while True:
        process_emails()
        time.sleep(POLL_INTERVAL)
