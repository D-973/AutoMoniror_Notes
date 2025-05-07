#!/usr/bin/env python3
import google.generativeai as genai
import datetime
import requests
import subprocess
import json
import os
import re
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("monitoring.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Monitor")

# Konfigurasi API Gemini
GEMINI_API_KEY = "AIzaSyDSILjc0WLk3FpLdpkmWvEbt1hZnuCQeo0"
GEMINI_MODEL = "gemini-1.5-flash"

# WhatsApp Configuration
WHATSAPP_TOKEN = "B9onMvcpADMhWgHXxjq9"
WHATSAPP_TARGET = "628981659030"

# Monitoring Configuration
ENDPOINT_URL = "https://myjenkinsnotes.duckdns.org/AutoDeploy_Notes/index.php"
LOG_FILES = {
    "ssh": "/var/log/auth.log",
    "apache": "/var/log/apache2/error.log",
    "system": "/var/log/syslog"
}

# Initialize Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(model_name=GEMINI_MODEL)

def get_ssh_attempts():
    """Get recent SSH login attempts"""
    try:
        if not os.path.exists(LOG_FILES["ssh"]):
            logger.warning(f"SSH log file not found: {LOG_FILES['ssh']}")
            return "Log file not found"
            
        result = subprocess.check_output(
            f"grep 'Failed password' {LOG_FILES['ssh']} | tail -n 10", 
            shell=True
        )
        return result.decode()
    except subprocess.SubprocessError as e:
        logger.error(f"Error getting SSH attempts: {e}")
        return f"Error retrieving SSH logs: {e}"

def get_gemini_analysis(log_text):
    """Get AI analysis from Gemini"""
    try:
        prompt = f"""Ambil percobaan login hanya hari ini dan 1 percobaan login terakhir saja. 
Ada percobaan login brute force:
{log_text}

Apa yang sebaiknya saya lakukan? Responnya jangan terlalu panjang. 
Output deskripsi singkat percobaan login terakhir."""
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Failed to get Gemini analysis: {e}")
        return f"⚠️ Gagal mendapatkan analisis dari Gemini: {e}"

def send_whatsapp(message):
    """Send message via WhatsApp using Fonnte API"""
    token = WHATSAPP_TOKEN
    payload = {
        "target": WHATSAPP_TARGET,
        "message": message,
    }
    headers = {"Authorization": token}
    
    try:
        r = requests.post("https://api.fonnte.com/send", data=payload, headers=headers)
        logger.info(f"WhatsApp API response status: {r.status_code}")
        logger.info(f"Response content: {r.text}")
        return r.status_code
    except Exception as e:
        logger.error(f"Error sending WhatsApp message: {e}")
        return None

def check_endpoint():
    """Check if the endpoint is accessible"""
    try:
        response = requests.get(ENDPOINT_URL, timeout=10)
        status_code = response.status_code
        is_success = 200 <= status_code < 400
        
        if not is_success:
            send_alert(f"🔴 ENDPOINT DOWN: {ENDPOINT_URL} returned status code {status_code}")
            return False
        
        return True
    except requests.RequestException as e:
        send_alert(f"🔴 ENDPOINT UNREACHABLE: {ENDPOINT_URL} - {str(e)}")
        return False

def check_new_ssh_attempts(ssh_log):
    """Check if there are new SSH login attempts"""
    state_file = Path("ssh_state.json")
    last_attempt = None
    
    # Load previous state if exists
    if state_file.exists():
        try:
            with open(state_file, "r") as f:
                state = json.load(f)
                last_attempt = state.get("last_ssh_attempt")
        except Exception as e:
            logger.error(f"Error loading state file: {e}")
    
    # Extract today's attempts
    today = datetime.datetime.now().strftime("%b %d")
    today_pattern = re.compile(f"{today}.*Failed password")
    today_attempts = [line for line in ssh_log.split("\n") if today_pattern.search(line)]
    
    if not today_attempts:
        logger.info("No SSH login attempts today")
        return False
        
    # Get the most recent attempt
    current_attempt = today_attempts[-1]
    
    # Check if this is a new attempt
    if last_attempt != current_attempt and current_attempt:
        # Extract IP from the log line
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", current_attempt)
        ip = ip_match.group(1) if ip_match else "unknown IP"
        
        # Extract username
        user_match = re.search(r"for (\w+) from", current_attempt)
        username = user_match.group(1) if user_match else "unknown user"
        
        # Save state
        try:
            with open(state_file, "w") as f:
                json.dump({"last_ssh_attempt": current_attempt}, f)
        except Exception as e:
            logger.error(f"Error saving state file: {e}")
        
        # Get AI analysis
        ai_response = get_gemini_analysis(ssh_log)
        
        # Send alert
        send_alert(f"⚠️ SSH Login Attempt: {username}@{ip}\n🧠 Gemini says:\n{ai_response}")
        return True
        
    return False

def check_system_logs():
    """Check system logs for errors"""
    try:
        for log_name, log_path in LOG_FILES.items():
            if os.path.exists(log_path):
                # Skip SSH log as it's handled separately
                if log_name == "ssh":
                    continue
                    
                # Get recent errors/warnings
                if log_name == "apache":
                    cmd = f"grep -E '\\[error\\]|\\[warn\\]' {log_path} | tail -n 5"
                elif log_name == "system":
                    cmd = f"grep -E 'error|warning|fail' {log_path} | tail -n 5"
                    
                result = subprocess.check_output(cmd, shell=True)
                log_content = result.decode().strip()
                
                if log_content:
                    # Count errors
                    error_count = len(re.findall(r'error|Error|ERROR', log_content))
                    warning_count = len(re.findall(r'warn|Warn|WARNING', log_content))
                    
                    if error_count > 0:
                        # Get AI analysis
                        analysis = get_gemini_analysis(log_content)
                        send_alert(f"⚠️ System Errors Detected in {log_name}:\n{error_count} errors, {warning_count} warnings\n🧠 Gemini says:\n{analysis}")
                        return True
        
        return False
    except Exception as e:
        logger.error(f"Error checking system logs: {e}")
        return False

def send_alert(message):
    """Send alert message via WhatsApp"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    
    logger.info(f"Sending alert: {message}")
    send_whatsapp(full_message)

def main():
    """Main function to run all monitoring checks"""
    logger.info("Starting monitoring check")
    
    # Check endpoint status
    endpoint_status = check_endpoint()
    logger.info(f"Endpoint status: {'UP' if endpoint_status else 'DOWN'}")
    
    # Check SSH attempts
    ssh_log = get_ssh_attempts()
    new_ssh = check_new_ssh_attempts(ssh_log)
    logger.info(f"New SSH attempts: {'Yes' if new_ssh else 'No'}")
    
    # Check system logs
    system_issues = check_system_logs()
    logger.info(f"System issues: {'Yes' if system_issues else 'No'}")
    
    # If no issues were detected, send a heartbeat message
    if not new_ssh and endpoint_status and not system_issues:
        # Only send heartbeat once a day (8:00 AM)
        current_hour = datetime.datetime.now().hour
        if current_hour == 8:
            send_alert("✅ Systems normal. Daily status check passed.")
    
    logger.info("Monitoring check completed")

if __name__ == "__main__":
    main()