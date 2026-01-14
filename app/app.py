import os
import time
import ssl
import re
import logging
import threading
import imaplib
import smtplib
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from netmiko import ConnectHandler

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("VPNSentinel")

# --- CONFIGURATION CLASS ---
class Config:
    """Loads and validates environment variables."""
    # Email Server
    IMAP_HOST = os.getenv('IMAP_SERVER')
    IMAP_PORT = int(os.getenv('IMAP_PORT', 993))
    SMTP_HOST = os.getenv('SMTP_SERVER')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    
    # Credentials
    AUTH_EMAIL = os.getenv('EMAIL_USER')
    AUTH_PASS = os.getenv('EMAIL_PASS')
    
    # Sender Info
    SENDER_EMAIL = os.getenv('SENDER_ADDR', AUTH_EMAIL)
    REPLY_TO = os.getenv('REPLY_TO_ADDR', AUTH_EMAIL)
    ORG_DOMAIN = os.getenv('COMPANY_DOMAIN', '@example.com')

    # Logic
    CHECK_INTERVAL = int(os.getenv('POLL_INTERVAL', 60))
    GRACE_PERIOD = int(os.getenv('WAIT_TIME_SECONDS', 120))
    TRIGGER_SUBJECT = os.getenv('TARGET_SUBJECT', 'VPN Access Detected').upper()

    # Firewall (FortiOS)
    FW_HOST = os.getenv('FG_IP')
    FW_USER = os.getenv('FG_USER')
    FW_PASS = os.getenv('FG_PASS')
    FW_PORT = int(os.getenv('FG_SSH_PORT', 22))

# --- FIREWALL MANAGER ---
class FirewallManager:
    """Handles SSH connections and command execution on the Firewall."""
    
    def __init__(self):
        self.device_config = {
            'device_type': 'fortinet',
            'host': Config.FW_HOST,
            'username': Config.FW_USER,
            'password': Config.FW_PASS,
            'port': Config.FW_PORT,
            'global_delay_factor': 2
        }

    def terminate_session(self, username: str) -> bool:
        """Kicks the user off the VPN."""
        if not Config.FW_HOST:
            logger.warning("Firewall IP not configured. Skipping active response.")
            return False

        logger.info(f"Initiating active response against user: {username}")
        
        try:
            with ConnectHandler(**self.device_config) as ssh:
                # FortiOS command to kill SSL VPN user
                cmd = f"execute vpn ssl disconnect user {username}"
                output = ssh.send_command(cmd)
                logger.info(f"Firewall Output: {output}")
                return True
        except Exception as e:
            logger.error(f"Failed to execute firewall command: {e}")
            return False

# --- EMAIL SERVICE ---
class EmailService:
    """Handles IMAP reading and SMTP sending."""

    def _get_ssl_context(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def connect_imap(self):
        client = imaplib.IMAP4_SSL(
            Config.IMAP_HOST, 
            Config.IMAP_PORT, 
            ssl_context=self._get_ssl_context()
        )
        client.login(Config.AUTH_EMAIL, Config.AUTH_PASS)
        return client

    def decode_subject(self, header_val):
        if not header_val: return ""
        decoded_list = decode_header(header_val)
        result = ""
        for content, encoding in decoded_list:
            if isinstance(content, bytes):
                result += content.decode(encoding if encoding else 'utf-8', errors='ignore')
            else:
                result += content
        return result

    def send_verification_request(self, username: str, timestamp: str, src_ip: str) -> bool:
        """Sends the challenge email to the user."""
        recipient = f"{username}{Config.ORG_DOMAIN}"
        subject = f"SECURITY ACTION REQUIRED: VPN Verification ({username})"
        
        body = f"""
        Hello {username},

        A VPN connection was established using your credentials.
        
        Time: {timestamp}
        Source IP: {src_ip}
        
        SYSTEM ACTION:
        If you do not REPLY to this email within {int(Config.GRACE_PERIOD/60)} minutes, 
        your session will be forcefully terminated.
        
        If this wasn't you, contact Security Operations immediately.
        """

        msg = MIMEMultipart()
        msg['From'] = Config.SENDER_EMAIL
        msg['To'] = recipient
        msg['Subject'] = subject
        msg['Reply-To'] = Config.REPLY_TO
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as server:
                try:
                    server.starttls(context=self._get_ssl_context())
                    server.login(Config.AUTH_EMAIL, Config.AUTH_PASS)
                except Exception as auth_err:
                    logger.debug(f"SMTP Auth skipped or failed: {auth_err}")
                
                server.sendmail(Config.SENDER_EMAIL, recipient, msg.as_string())
                logger.info(f"Verification email sent to {recipient}")
                return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    def check_for_reply(self, username: str) -> bool:
        """Searches Inbox for any recent email from the user."""
        try:
            client = self.connect_imap()
            client.select("inbox")
            
            user_email = f"{username}{Config.ORG_DOMAIN}"
            # Search logic: Emails FROM the user
            status, messages = client.search(None, f'(FROM "{user_email}")')
            
            has_reply = False
            if status == 'OK' and messages[0]:
                has_reply = True
            
            client.close()
            client.logout()
            return has_reply
        except Exception as e:
            logger.error(f"Error checking replies: {e}")
            return False

    def cleanup_mailbox(self, client, deleted_ids):
        """Expunges deleted emails from Inbox and cleans Trash folder."""
        if not deleted_ids: return
        
        # Expunge Inbox
        client.expunge()
        
        # Clean Trash
        trash_folders = ["Deleted Items", "Trash", "Bin", "Silinmiş Öğeler"]
        for folder in trash_folders:
            try:
                status, _ = client.select(folder)
                if status == 'OK':
                    # Search for our bot's emails in trash
                    stat, msgs = client.search(None, f'(SUBJECT "{Config.TRIGGER_SUBJECT}")')
                    if msgs[0]:
                        for num in msgs[0].split():
                            client.store(num, '+FLAGS', '\\Deleted')
                        client.expunge()
                    break
            except:
                continue

# --- MAIN SENTINEL LOGIC ---
class VPNSentinel:
    """Main Orchestrator."""
    
    def __init__(self):
        self.email_svc = EmailService()
        self.fw_manager = FirewallManager()

    def parse_log_content(self, raw_body: str):
        """Extracts User, IP, and Time using Regex."""
        # Generic patterns to catch common log formats
        user_pattern = re.search(r'user=["\']?([^"\s\']+)["\']?', raw_body, re.IGNORECASE)
        ip_pattern = re.search(r'remip=([\d\.]+)', raw_body)
        time_pattern = re.search(r'date=(\S+)\s+time=(\S+)', raw_body)

        return {
            "user": user_pattern.group(1).replace("&quot;", "").strip() if user_pattern else None,
            "ip": ip_pattern.group(1) if ip_pattern else "0.0.0.0",
            "time": f"{time_pattern.group(1)} {time_pattern.group(2)}" if time_pattern else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def verification_task(self, username: str, ip: str):
        """Threaded task: Waits -> Checks Reply -> Kills Session."""
        logger.info(f"Timer started for {username}. Waiting {Config.GRACE_PERIOD}s...")
        time.sleep(Config.GRACE_PERIOD)
        
        logger.info(f"Time's up for {username}. Verifying response...")
        
        if self.email_svc.check_for_reply(username):
            logger.info(f"User {username} verified successfully. No action taken.")
        else:
            logger.warning(f"NO REPLY from {username}! Terminating session...")
            self.fw_manager.terminate_session(username)

    def scan_cycle(self):
        """One complete scan of the inbox."""
        try:
            client = self.email_svc.connect_imap()
            client.select("inbox")
            
            # Fetch unread emails
            status, messages = client.search(None, 'UNSEEN')
            if not messages[0]:
                client.close()
                client.logout()
                return

            email_ids = messages[0].split()
            logger.info(f"Found {len(email_ids)} unread emails. Analyzing...")
            
            deleted_ids = []

            for e_id in email_ids:
                res, data = client.fetch(e_id, "(RFC822)")
                raw_email = data[0][1]
                msg = email.message_from_bytes(raw_email)
                
                # Check Subject
                subject = self.email_svc.decode_subject(msg.get("Subject")).upper()
                if Config.TRIGGER_SUBJECT not in subject:
                    continue
                
                logger.info(f"Target log detected: {subject}")

                # Extract Body (HTML or Text)
                body_content = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() in ["text/plain", "text/html"]:
                            payload = part.get_payload(decode=True)
                            if payload: body_content += payload.decode(errors='ignore')
                else:
                    body_content = msg.get_payload(decode=True).decode(errors='ignore')

                # Parse Data
                log_data = self.parse_log_content(body_content)
                
                if log_data["user"]:
                    logger.info(f"Extracted -> User: {log_data['user']} | IP: {log_data['ip']}")
                    
                    # 1. Send Email
                    if self.email_svc.send_verification_request(log_data["user"], log_data["time"], log_data["ip"]):
                        # 2. Mark for deletion
                        client.store(e_id, '+FLAGS', '\\Deleted')
                        deleted_ids.append(e_id)
                        
                        # 3. Start Timer Thread
                        t = threading.Thread(
                            target=self.verification_task, 
                            args=(log_data["user"], log_data["ip"])
                        )
                        t.start()
                else:
                    logger.warning("Could not parse username from log body.")

            # Cleanup
            self.email_svc.cleanup_mailbox(client, deleted_ids)
            
            client.close()
            client.logout()

        except Exception as e:
            logger.error(f"Runtime loop error: {e}")

    def start(self):
        logger.info("VPN Sentinel is online. Monitoring logs...")
        logger.info(f"Target Subject: '{Config.TRIGGER_SUBJECT}'")
        
        while True:
            self.scan_cycle()
            time.sleep(Config.CHECK_INTERVAL)

# --- ENTRY POINT ---
if __name__ == "__main__":
    bot = VPNSentinel()
    bot.start()
