"""
IAMGuard - Core Scanner
Orchestrates all IAM security checks
"""

import boto3
import json
from datetime import datetime, timezone
from colorama import Fore, Style
from iamguard.checks.users import check_mfa_disabled, check_admin_access, check_inactive_users
from iamguard.checks.keys import check_old_access_keys, check_unused_access_keys
from iamguard.checks.policies import check_wildcard_policies
from iamguard.checks.root import check_root_account

class IAMScanner:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.findings = []
        self.scan_time = datetime.now(timezone.utc)
        print(Fore.CYAN + f"[*] Scan started at {self.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    def add_finding(self, severity, title, resource, detail, recommendation):
        """Add a finding to the results"""
        self.findings.append({
            'severity': severity,
            'title': title,
            'resource': resource,
            'detail': detail,
            'recommendation': recommendation,
            'timestamp': self.scan_time.isoformat()
        })

    def run_all_checks(self):
        """Run all security checks"""
        print(Fore.CYAN + "\n[*] Starting IAMGuard security scan...\n")
        print("-" * 60)

        check_mfa_disabled(self.iam, self.add_finding)
        check_admin_access(self.iam, self.add_finding)
        check_inactive_users(self.iam, self.add_finding)
        check_old_access_keys(self.iam, self.add_finding)
        check_unused_access_keys(self.iam, self.add_finding)
        check_wildcard_policies(self.iam, self.add_finding)
        check_root_account(self.iam, self.add_finding)

        print("-" * 60)
        print(Fore.GREEN + f"\n[+] All checks complete. {len(self.findings)} findings identified.")

    def get_summary(self):
        """Get findings summary by severity"""
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'total': len(self.findings)
        }
        for finding in self.findings:
            summary[finding['severity']] += 1
        return summary

    def export_json(self, filename='iamguard_results.json'):
        """Export findings to JSON"""
        output = {
            'scan_time': self.scan_time.isoformat(),
            'summary': self.get_summary(),
            'findings': self.findings
        }
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        print(Fore.GREEN + f"\n[+] Results exported to {filename}")