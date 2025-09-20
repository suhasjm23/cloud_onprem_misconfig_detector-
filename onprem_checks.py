# onprem_checks.py
import paramiko
import yaml
from utils import format_findings
from typing import List
import os

class OnPremChecker:
    """
    Expects inventory YAML like:
    hosts:
      - name: test-vm
        host: 192.168.1.100
        user: ubuntu
        port: 22
        pkey: /path/to/key.pem    # optional; if omitted, will attempt password prompt
    """
    def __init__(self, inventory_file="sample_inventory.yml", dry_run=True):
        self.inventory_file = inventory_file
        self.dry_run = dry_run
        self.inventory = self._load_inventory()

    def _load_inventory(self):
        if not os.path.exists(self.inventory_file):
            return {"hosts": []}
        with open(self.inventory_file, "r") as f:
            return yaml.safe_load(f) or {"hosts": []}

    def run_all(self, remediate=False, force=False):
        findings = []
        for h in self.inventory.get("hosts", []):
            host = h.get("host")
            port = h.get("port", 22)
            user = h.get("user", "ubuntu")
            pkey = h.get("pkey")
            c = self._connect(host, port, user, pkey)
            if not c:
                findings.append({
                    "target": host,
                    "check": "SSH connection",
                    "severity": "High",
                    "description": "Unable to connect via SSH (check credentials/firewall).",
                    "remediate_action": None
                })
                continue
            # Run checks
            findings.extend(self._check_sshd_config(c, host))
            findings.extend(self._check_package_updates(c, host))
            c.close()

        report_lines = format_findings(findings)
        if remediate:
            rem_results = []
            for f in findings:
                if f.get("remediate_action") and (force or self._confirm_remediation(f)):
                    r = self._apply_remediation(f)
                    rem_results.append(r)
            report_lines.append("\n=== On-Prem Remediation ===")
            report_lines.extend(rem_results)
        return report_lines

    def _connect(self, host, port, user, pkey):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if pkey:
                key = paramiko.RSAKey.from_private_key_file(pkey)
                ssh.connect(hostname=host, port=port, username=user, pkey=key, timeout=10)
            else:
                # try without key (may prompt for password) - avoid interactive prompt here
                ssh.connect(hostname=host, port=port, username=user, timeout=10)
            return ssh
        except Exception as e:
            return None

    def _run_cmd(self, ssh_client, cmd):
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        return out.strip(), err.strip()

    def _check_sshd_config(self, ssh_client, host) -> List[dict]:
        findings = []
        out, err = self._run_cmd(ssh_client, "cat /etc/ssh/sshd_config || true")
        if not out:
            findings.append({
                "target": host,
                "check": "sshd_config unreadable",
                "severity": "Medium",
                "description": "/etc/ssh/sshd_config is not readable or not present.",
                "remediate_action": None
            })
            return findings
        # crude parsing
        if "PermitRootLogin yes" in out:
            findings.append({
                "target": host,
                "check": "PermitRootLogin",
                "severity": "High",
                "description": "sshd_config allows root login (PermitRootLogin yes).",
                "remediate_action": "Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd"
            })
        if "PasswordAuthentication yes" in out:
            findings.append({
                "target": host,
                "check": "PasswordAuthentication",
                "severity": "Medium",
                "description": "sshd_config allows password authentication; consider using key-based auth.",
                "remediate_action": "Set PasswordAuthentication no in /etc/ssh/sshd_config"
            })
        return findings

    def _check_package_updates(self, ssh_client, host) -> List[dict]:
        findings = []
        # Try Debian-based apt check; fallback returns unknown
        out, err = self._run_cmd(ssh_client, "uname -a || true")
        if "Linux" in out:
            # try apt
            out, err = self._run_cmd(ssh_client, "test -f /usr/bin/apt && apt list --upgradable 2>/dev/null | tail -n +2 || true")
            if out:
                # There are upgradable packages
                findings.append({
                    "target": host,
                    "check": "Package updates available",
                    "severity": "Low",
                    "description": "Host has packages that appear upgradable (outdated software).",
                    "remediate_action": "Run package upgrades (apt upgrade) after maintenance window"
                })
        return findings

    def _confirm_remediation(self, finding):
        prompt = f"Remediate {finding.get('target')} - {finding.get('check')}? [y/N]: "
        resp = input(prompt).strip().lower()
        return resp == 'y'

    def _apply_remediation(self, finding):
        # For on-prem remediation we will only attempt the sshd_config edits if pkey is present in inventory.
        hosts = [h for h in self.inventory.get("hosts", []) if h.get("host") == finding.get("target")]
        if not hosts:
            return "No host config found for remediation."
        h = hosts[0]
        ssh = self._connect(h['host'], h.get('port',22), h.get('user','ubuntu'), h.get('pkey'))
        if not ssh:
            return f"Unable to connect to {h['host']} to remediate."
        try:
            if finding.get("check") == "PermitRootLogin":
                # Backup and replace
                cmd_backup = "sudo cp /etc/ssh/sshd_config /tmp/sshd_config.bak_$(date +%s)"
                ssh.exec_command(cmd_backup)
                # replace line or append
                sed_cmd = r"sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config"
                ssh.exec_command(sed_cmd)
                # restart sshd
                ssh.exec_command("sudo systemctl restart sshd || sudo service ssh restart || true")
                ssh.close()
                return f"Set PermitRootLogin no on {h['host']}"
            if finding.get("check") == "PasswordAuthentication":
                ssh.exec_command("sudo cp /etc/ssh/sshd_config /tmp/sshd_config.bak_$(date +%s)")
                sed_cmd = r"sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config"
                ssh.exec_command(sed_cmd)
                ssh.exec_command("sudo systemctl restart sshd || sudo service ssh restart || true")
                ssh.close()
                return f"Set PasswordAuthentication no on {h['host']}"
            if finding.get("check") == "Package updates available":
                ssh.exec_command("sudo apt update && sudo apt -y upgrade")
                ssh.close()
                return f"Attempted package upgrade on {h['host']} (check logs on host)."
            return f"No automatic remediation implemented for check {finding.get('check')}"
        except Exception as e:
            return f"Error during remediation: {str(e)}"
