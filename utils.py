# utils.py
import logging
from tabulate import tabulate

def setup_logger():
    logger = logging.getLogger("misconfig_detector")
    if not logger.handlers:
        h = logging.StreamHandler()
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        h.setFormatter(fmt)
        logger.addHandler(h)
        logger.setLevel(logging.INFO)
    return logger

def format_findings(findings):
    """
    findings: list of dicts with keys: target, check, severity, description, remediate_action (optional)
    returns list of strings for report.
    """
    lines = []
    if not findings:
        lines.append("No findings.")
        return lines
    headers = ["Target", "Check", "Severity", "Description", "Remediation"]
    rows = []
    for f in findings:
        rows.append([
            f.get("target"),
            f.get("check"),
            f.get("severity"),
            f.get("description"),
            f.get("remediate_action", "N/A")
        ])
    lines.append(tabulate(rows, headers=headers, tablefmt="github"))
    return lines
