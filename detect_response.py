import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import pickle
import pandas as pd
import subprocess
import time
import requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# ============================================================
# CONFIGURATION
# ============================================================

API_USER = "wazuh-wui"
API_PASS = "CHANGE_ME"
WAZUH_API = "https://localhost:55000"

WINDOWS_AGENT_ID = "001"

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

LOCAL_IPS = [
    "",
    "127.0.0.1",
    "192.168.45.1",
    "192.168.45.10"
]

# ============================================================
# LOAD MODELS
# ============================================================

rf = pickle.load(open("rf_model.pkl", "rb"))
iso = pickle.load(open("iso_model.pkl", "rb"))
le = pickle.load(open("label_encoder.pkl", "rb"))

blocked_ips = set()

# ============================================================
# ATTACK MAPPING
# ============================================================

ATTACK_TYPES = {

    60122: "Windows Failed Login",
    60204: "Windows Bruteforce Attack",

    60144: "Account Lockout",
    60145: "Multiple Authentication Failures",
    60146: "Authentication Attack",

    60109: "User Account Created",

    60170: "Users Group Changed",
    60171: "Privileges Modified",
    60172: "Security Group Modification",

    92031: "PowerShell Execution",
    92033: "PowerShell Discovery",
    92039: "Net.exe Account Discovery",

    92213: "Encoded PowerShell",
    92200: "Suspicious Command Execution",
    92201: "Malicious PowerShell Activity",

    92302: "Persistence Activity",

    92657: "Credential Access Activity",

    40111: "Sysmon Registry Modification",
    40112: "Sysmon Suspicious Registry Activity",

    86601: "Network Scan / Suricata Alert",

    100001: "Potential Malware Activity"
}

# ============================================================
# GET WAZUH TOKEN
# ============================================================

def get_token():

    try:

        response = requests.get(
            f"{WAZUH_API}/security/user/authenticate",
            auth=(API_USER, API_PASS),
            verify=False
        )

        if response.status_code == 200:

            return response.json()["data"]["token"]

        return None

    except Exception as e:
        print(f"❌ Erreur token: {e}")
        return None
# ============================================================
# ACTIVE RESPONSE
# ============================================================


def block_ip(ip):
    if not ip or ip in blocked_ips or ip in LOCAL_IPS:
        return
    
    blocked_ips.add(ip)
    
    # 1. Blacklist
    with open('/home/amir/soc-ml/blacklist.txt', 'a') as f:
        f.write(f"[{datetime.now()}] {ip}\n")
    print(f"⛔ IP {ip} ajoutée à la blacklist !")
    
    # 2. Log
    log = f"[{datetime.now()}] 🚨 IP BLOQUEE: {ip}"
    print(log)
    with open('/home/amir/soc-ml/blocked_ips.log', 'a') as f:
        f.write(log + '\n')
    # --------------------------------------------------------
    # Windows Active Response
    # --------------------------------------------------------

    try:

        token = get_token()

        if token:

            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            payload = {
                "command": "block-ip",
                "custom": True,
                "arguments": ["add", "null", ip]            }

            response = requests.put(
                f"{WAZUH_API}/active-response?agents_list={WINDOWS_AGENT_ID}",
                headers=headers,
                json=payload,
                verify=False
            )

            print(f"✅ Windows Active Response: {response.status_code}")

    except Exception as e:

        print(f"❌ Active Response Error: {e}")

    blocked_ips.add(ip)
    # Blacklist
    with open('/home/amir/soc-ml/blacklist.txt', 'a') as f:
         f.write(f"{datetime.now()} | {ip}\n")
    print(f"⛔ IP {ip} ajoutée à la blacklist")

    print(f"🚨 IP BLOCKED : {ip}")

# ============================================================
# RESPONSE ACTIONS
# ============================================================

def response_action(rule_id, src_ip):

    # SMB / Bruteforce
    if rule_id in [60204, 60122]:
        if src_ip:
            block_ip(src_ip)

    # PowerShell
    elif rule_id in [92033, 92050, 92051]:

        print("⚡ Suspicious PowerShell Activity Detected")

    # User Manipulation
    elif rule_id in [60109, 60110, 60111]:

        print("👤 User Account Manipulation Detected")

    # Discovery
    elif rule_id == 92039:

        print("🔍 Discovery Command Detected")

    # Group Changes
    elif rule_id in [60160, 60170]:

        print("🛡️ Privilege Escalation Activity Detected")

# ============================================================
# ANALYZE ALERT
# ============================================================

def analyze_alert(alert):

    try:

        rule = alert.get("rule", {})

        rule_id = int(rule.get("id", 0))

        rule_level = float(rule.get("level", 0))

        firedtimes = float(rule.get("firedtimes", 0))

        description = rule.get("description", "")

        # ----------------------------------------------------
        # Source IP
        # ----------------------------------------------------

        src_ip = (

            alert.get("data", {}).get("srcip", "")

            or

            alert.get("data", {})
            .get("win", {})
            .get("eventdata", {})
            .get("ipAddress", "")

            or

            alert.get("data", {})
            .get("win", {})
            .get("eventdata", {})
            .get("IpAddress", "")
        )

        # ----------------------------------------------------
        # Event ID
        # ----------------------------------------------------

        event_id = float(

            alert.get("data", {})
            .get("win", {})
            .get("system", {})
            .get("eventID", 0)

            or 0
        )

        # ----------------------------------------------------
        # Agent
        # ----------------------------------------------------

        agent_name = (
            alert.get("agent", {})
            .get("name", "unknown")
        )

        try:

            agent_enc = le.transform([agent_name])[0]

        except:

            agent_enc = 0

        # ----------------------------------------------------
        # FEATURES
        # ----------------------------------------------------

        X = pd.DataFrame(
            [[
                rule_id,
                rule_level,
                firedtimes,
                event_id,
                agent_enc
            ]],
            columns=[
                "rule_id_num",
                "rule_level",
                "firedtimes",
                "event_id_num",
                "agent_encoded"
            ]
        )

        # ----------------------------------------------------
        # ML PREDICTION
        # ----------------------------------------------------

        rf_pred = rf.predict(X)[0]

        iso_score = iso.decision_function(X)[0]

        # ----------------------------------------------------
        # ATTACK NAME
        # ----------------------------------------------------

        attack_name = ATTACK_TYPES.get(
            rule_id,
            "Suspicious Activity"
        )

        # ----------------------------------------------------
        # DETECTION LOGIC
        # ----------------------------------------------------

        suspicious = (

            (rf_pred == 1 and rule_level >= 5)

            or

            (rule_id in ATTACK_TYPES)

            or
 
            (rule_level >= 10)
        )
        # ----------------------------------------------------
        # ALERT
        # ----------------------------------------------------

        if suspicious:

            print("\n" + "=" * 60)

            print(f"[{datetime.now()}] ⚠️ ATTACK DETECTED")

            print(f"Attack Type   : {attack_name}")

            print(f"Rule ID       : {rule_id}")

            print(f"Rule Level    : {int(rule_level)}")

            print(f"Event ID      : {int(event_id)}")

            print(f"Fired Times   : {int(firedtimes)}")

            print(f"Source IP     : {src_ip}")

            print(f"Description   : {description}")

            print(f"RF Prediction : {rf_pred}")

            print(f"ISO Score     : {iso_score:.4f}")

            print("=" * 60)
            attack_type = ATTACK_TYPES.get(
              int(rule_id),
              "Suspicious Activity"
            )
            send_email(attack_type, src_ip, description)

            response_action(rule_id, src_ip)

    except Exception as e:

        print(f"❌ Analysis Error: {e}")

# ============================================================
# REALTIME MONITOR
# ============================================================

def monitor():

    print("\n" + "=" * 60)
    print("🔍 SOC ML - REALTIME DETECTION")
    print("=" * 60)

    with open(ALERTS_FILE, "r", encoding="utf-8", errors="ignore") as f:

        f.seek(0, 2)

        while True:

            line = f.readline()

            if line:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    analyze_alert(alert)
                except json.JSONDecodeError:
                    pass
                except Exception:
                    pass
            else:

                time.sleep(1)
def send_email(attack_type, src_ip, description):

    sender_email = "emirghdiri12@gmail.com"

    sender_password = "cldw goyz uzuc bbre"

    receiver_email = "emirghdiri12@gmail.com"

    subject = f"[SOC ALERT] {attack_type}"

    body = f"""
SOC ML ALERT

Attack Type : {attack_type}

Source IP   : {src_ip}

Description : {description}

Time        : {datetime.now()}
"""

    try:

        msg = MIMEMultipart()

        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)

        server.starttls()

        server.login(sender_email, sender_password)

        server.sendmail(
            sender_email,
            receiver_email,
            msg.as_string()
        )

        server.quit()

        print("📧 Email alert sent")

    except Exception as e:

        print(f"❌ Email error: {e}")
# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    monitor()

amir@wazuh:~/soc-ml$ 
