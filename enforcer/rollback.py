"""
enforcer/rollback.py — Emergency SOC rollback engine.
Strips a specific iptables DROP rule and resets the DB flag.

Usage:
    sudo python3 -m enforcer.rollback <IP_ADDRESS>
    sudo python3 -m enforcer.rollback --all          # Wipe ALL TIP-managed rules
"""

from __future__ import annotations

import re
import subprocess
import sys

from database.mongo_handler import MongoHandler
from utils.logger import enforcer_logger
from utils.validator import is_valid_ip


class RollbackEngine:
    """Safely reverses kernel-level firewall blocks and resets DB tracking state."""

    def __init__(self):
        self.db = MongoHandler()

    def unblock_ip(self, ip_address: str) -> bool:
        """Remove the iptables DROP rule for `ip_address` and reset the DB flag."""
        if not is_valid_ip(ip_address):
            enforcer_logger.error(
                f"[Rollback] '{ip_address}' is not a valid IP address. Aborting."
            )
            return False

        enforcer_logger.info(f"[Rollback] Initiating emergency rollback for: {ip_address}")

        # 1. Remove from kernel firewall
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        rule_removed = result.returncode == 0
        rule_missing = "Bad rule" in result.stderr or "No chain/target/match" in result.stderr

        if rule_removed:
            enforcer_logger.info(
                f"[Rollback] iptables DROP rule successfully removed for {ip_address}."
            )
        elif rule_missing:
            enforcer_logger.warning(
                f"[Rollback] Rule not present in iptables for {ip_address} "
                "(possibly already removed). Continuing DB sync..."
            )
        else:
            enforcer_logger.error(
                f"[Rollback] iptables error for {ip_address}: {result.stderr.strip()}"
            )
            return False

        # 2. Reset DB state regardless (bring DB in sync with reality)
        synced = self.db.mark_unblocked(ip_address)
        if synced:
            enforcer_logger.info(
                f"[Rollback] Database state reset for {ip_address}: is_blocked → False."
            )
        else:
            enforcer_logger.warning(
                f"[Rollback] {ip_address} not found in DB or already unblocked."
            )

        return True

    def unblock_all(self) -> int:
        """
        Flush ALL INPUT DROP rules managed by TIP.
        Reads blocked IPs from DB and removes them one by one.
        Returns count of successfully unblocked IPs.
        """
        enforcer_logger.info("[Rollback] FULL ROLLBACK initiated — removing all TIP-managed rules.")
        blocked = [
            doc["indicator"]
            for doc in self.db.get_all()
            if doc.get("is_blocked") and doc.get("type") == "ip"
        ]

        if not blocked:
            enforcer_logger.info("[Rollback] No blocked IPs found in database.")
            return 0

        enforcer_logger.info(f"[Rollback] {len(blocked)} IPs to unblock...")
        success = sum(1 for ip in blocked if self.unblock_ip(ip))
        enforcer_logger.info(f"[Rollback] Full rollback complete. Unblocked: {success}/{len(blocked)}")
        return success


# ── CLI entry point ───────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:")
        print("  sudo python3 -m enforcer.rollback <IP_ADDRESS>")
        print("  sudo python3 -m enforcer.rollback --all")
        sys.exit(1)

    arg = sys.argv[1]
    engine = RollbackEngine()

    if arg == "--all":
        count = engine.unblock_all()
        print(f"Full rollback complete. Unblocked {count} IPs.")
    else:
        success = engine.unblock_ip(arg)
        sys.exit(0 if success else 1)
