"""
SPEMCS Python Endpoint Agent & Deep Process Inspector
Monitors active and background processes on the workstation (including Task Manager background services).
Detects unauthorized remote desktop tools (dwagent, anydesk, teamviewer), AI apps (chatgpt, claude, codex),
unapproved browsers (Edge, Firefox), and proctoring violations.
Publishes violation events to the SPEMCS Central Server and Database in real time.
"""

import sys
import os
import time
import uuid
import socket
import logging
import urllib.request
import urllib.error
import json
import psutil
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SpemcsEndpointAgent")

SERVER_URL = os.environ.get("SPEMCS_SERVER_URL", "http://10.0.2.15:8000")

# Core system processes that are part of Windows infrastructure (Allowed)
ESSENTIAL_SYSTEM_PROCESSES = {
    "system", "idle", "registry", "secure system", "memory compression", "interrupts",
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "svchost.exe", "fontdrvhost.exe", "wudfhost.exe", "dwm.exe", "sihost.exe",
    "taskhostw.exe", "explorer.exe", "spoolsv.exe", "ctfmon.exe", "searchindexer.exe",
    "securityhealthservice.exe", "msmpeng.exe", "mpdefendercorereservice.exe", "nissrv.exe",
    "ngciso.exe", "smartscreen.exe", "applicationframehost.exe", "systemsettings.exe",
    "audiodg.exe", "dashost.exe", "dllhost.exe", "runtimebroker.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe", "conhost.exe", "wlanext.exe"
}

# Explicit Forbidden Applications & Remote Tools
FORBIDDEN_KEYWORDS = [
    "dwagent", "dwagsvc", "dwrcs", "dwservice", "chatgpt", "claude", "codex",
    "anydesk", "teamviewer", "rustdesk", "ultraviewer", "parsec", "splashtop",
    "ammyy", "supremo", "logmein", "tightvnc", "realvnc", "winvnc", "screenconnect",
    "connectwise", "cheatengine", "discord", "telegram", "whatsapp", "slack",
    "wireshark", "processhacker", "msedge", "firefox", "brave", "opera", "tor"
]

class EndpointAgent:
    def __init__(self, server_url=SERVER_URL, device_name=None):
        self.server_url = server_url.rstrip("/")
        self.device_name = device_name or socket.gethostname()
        self.hardware_uuid = self._get_hardware_uuid()
        self.ip_address = self._get_local_ip()
        self.seen_pids = set()
        self.reported_violations = set() # (name, pid) to avoid duplicate spamming
        self.device_id = None
        self.active_session_id = None
        self.active_exam_id = None

    def _get_hardware_uuid(self):
        try:
            import subprocess
            output = subprocess.check_output("wmic csproduct get uuid", shell=True).decode()
            lines = [l.strip() for l in output.splitlines() if l.strip() and "UUID" not in l]
            if lines:
                return lines[0]
        except Exception:
            pass
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname()))

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def http_post(self, path, payload):
        url = f"{self.server_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def register(self):
        logger.info(f"Registering endpoint agent '{self.device_name}' (HW UUID: {self.hardware_uuid}, IP: {self.ip_address})...")
        payload = {
            "deviceName": self.device_name,
            "ipAddress": self.ip_address,
            "hardwareUuid": self.hardware_uuid,
            "hostname": socket.gethostname(),
        }
        try:
            res = self.http_post("/api/v1/devices/register", payload)
            self.device_id = res.get("deviceId")
            logger.info(f"Registered successfully! Device ID: {self.device_id}")
            return True
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return False

    def classify_process(self, name, exe_path):
        name_lower = (name or "").lower()
        exe_lower = (exe_path or "").lower()

        # Check for essential system processes
        if name_lower in ESSENTIAL_SYSTEM_PROCESSES or name_lower.rstrip(".exe") in ESSENTIAL_SYSTEM_PROCESSES:
            return False, "Essential Windows System Service"

        # Check for Google Chrome (Approved Browser)
        if name_lower in ["chrome.exe", "chrome"] and "google\\chrome" in exe_lower:
            return False, "Approved Examination Browser (Google Chrome)"

        # Check for Forbidden Keywords (Remote Desktop, AI Assistants, Unapproved Browsers, etc.)
        for kw in FORBIDDEN_KEYWORDS:
            if kw in name_lower or (exe_lower and kw in exe_lower):
                if "dwagent" in kw or "dwagsvc" in kw or "dwrcs" in kw:
                    return True, f"Prohibited Remote Control Background Service ({name})"
                elif "chatgpt" in kw or "claude" in kw or "codex" in kw:
                    return True, f"Prohibited AI Assistant Application ({name})"
                elif "anydesk" in kw or "teamviewer" in kw or "rustdesk" in kw:
                    return True, f"Prohibited Remote Desktop Tool ({name})"
                elif "edge" in kw or "firefox" in kw or "brave" in kw or "opera" in kw:
                    return True, f"Unapproved Browser Detected ({name})"
                else:
                    return True, f"Prohibited Application / Process ({name})"

        return False, "Allowed"

    def scan_and_reconcile(self):
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or 'unknown'
                exe_path = proc.info.get('exe') or None
                current_pids.add(pid)

                is_suspicious, reason = self.classify_process(name, exe_path)

                violation_key = (name, pid)
                if is_suspicious and violation_key not in self.reported_violations:
                    self.reported_violations.add(violation_key)
                    self.report_violation(pid, name, exe_path, reason)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Clean up exited processes from tracked violations
        exited = [k for k in self.reported_violations if k[1] not in current_pids]
        for k in exited:
            self.reported_violations.remove(k)
            logger.info(f"Process exited: {k[0]} (PID {k[1]})")

        self.seen_pids = current_pids

    def report_violation(self, pid, process_name, exe_path, reason):
        logger.warning(f"SUSPICIOUS PROCESS DETECTED: {process_name} (PID {pid}, Path: {exe_path}) -> {reason}")
        event_id = str(uuid.uuid4())
        payload = {
            "eventId": event_id,
            "deviceName": self.device_name,
            "studentRollNumber": "CS2024001",
            "eventType": "BLOCKED_PROCESS",
            "processId": pid,
            "processName": process_name,
            "timestampUtc": datetime.utcnow().isoformat() + "Z",
            "executablePath": exe_path or f"C:\\Windows\\System32\\{process_name}",
            "reason": reason,
        }
        try:
            res = self.http_post("/api/v1/events", payload)
            logger.info(f"Violation successfully uploaded to backend! Alert ID: {res.get('alertId')}")
        except Exception as e:
            logger.error(f"Failed to post violation event: {e}")

    def run_monitor_loop(self, poll_interval=2):
        if not self.register():
            logger.error("Cannot start monitor without registration.")
            return

        logger.info(f"Starting continuous background process scanner (polling every {poll_interval}s)...")
        try:
            while True:
                self.scan_and_reconcile()
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Agent monitoring stopped by user.")

if __name__ == "__main__":
    agent = EndpointAgent()
    # Perform single initial sweep or start continuous monitor
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        agent.register()
        agent.scan_and_reconcile()
    else:
        agent.run_monitor_loop()
