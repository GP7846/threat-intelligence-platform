"""
enforcer/firewall_enforcer.py — Dynamic kernel-level firewall policy engine.
Uses Linux iptables via subprocess to block high-risk IPs automatically.
Sends Discord / Slack alerts on each successful block.
"""

from __future__ import annotations

import shutil
import subprocess
import platform

from database.mongo_handler import MongoHandler
from utils.logger import enforcer_logger
from utils.alerter import send_alert


class FirewallEnforcer:
    """
    Reads unblocked high-risk indicators from MongoDB and applies
    iptables DROP rules to the host kernel firewall.

    Safety guarantees
    -----------------
    • Checks whether a rule already exists before inserting (idempotent).
    • Only processes IPv4 / IPv6 addresses (not raw domains).
    • Validates that iptables binary is present before attempting any call.
    • Updates the database *after* a confirmed successful iptables call.
    """

    def __init__(self):
        self.db = MongoHandler()
        self._iptables_available = bool(shutil.which("iptables"))

        if not self._iptables_available:
            enforcer_logger.warning(
                "[Enforcer] iptables binary not found. "
                "Firewall enforcement is DISABLED (non-Linux or no privilege)."
            )

        if platform.system() != "Linux":
            enforcer_logger.warning(
                "[Enforcer] Non-Linux OS detected — iptables rules will be simulated."
            )

    # ── Public API ────────────────────────────────────────────

    def enforce_policies(self):
        """Block all unblocked high-risk IPs that are above the risk threshold."""
        targets = self.db.get_high_risk_unblocked()

        if not targets:
            enforcer_logger.info(
                "[Enforcer] Monitoring cycle clean — no unblocked high-risk targets."
            )
            return

        enforcer_logger.info(
            f"[Enforcer] {len(targets)} unblocked threat vectors identified. "
            "Processing blocks..."
        )

        blocked_count  = 0
        skipped_count  = 0
        failed_count   = 0

        for target in targets:
            ip          = (target.get("indicator") or "").strip()
            threat_type = target.get("threat_type", "unknown")
            risk_score  = target.get("risk_score", 0)

            if not ip:
                continue

            result = self._block_ip(ip)

            if result == "already_exists":
                # Rule is in kernel but DB wasn't updated — fix the DB state
                self.db.mark_blocked(ip)
                skipped_count += 1

            elif result == "success":
                self.db.mark_blocked(ip)
                send_alert(ip, threat_type, risk_score)
                blocked_count += 1

            else:
                failed_count += 1

        enforcer_logger.info(
            f"[Enforcer] Cycle summary — "
            f"Newly blocked: {blocked_count} | "
            f"Already present: {skipped_count} | "
            f"Failed: {failed_count}"
        )

    # ── Private helpers ───────────────────────────────────────

    def _block_ip(self, ip_address: str) -> str:
        """
        Apply an iptables DROP rule for `ip_address`.
        Returns: 'success' | 'already_exists' | 'error' | 'simulated'
        """
        if not self._iptables_available:
            enforcer_logger.info(f"[Enforcer][SIM] Would block: {ip_address}")
            return "simulated"

        # 1. Check if rule already exists (-C returns 0 if found)
        check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        check = subprocess.run(
            check_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if check.returncode == 0:
            enforcer_logger.warning(
                f"[Enforcer] Rule already in iptables for {ip_address} — skipping."
            )
            return "already_exists"

        # 2. Insert the DROP rule
        block_cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        result = subprocess.run(
            block_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if result.returncode == 0:
            enforcer_logger.info(
                f"[BLOCKED] {ip_address} — kernel DROP rule applied successfully."
            )
            return "success"
        else:
            enforcer_logger.error(
                f"[Enforcer] Failed to block {ip_address}: {result.stderr.strip()}"
            )
            return "error"
