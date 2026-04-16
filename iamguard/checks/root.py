"""
IAMGuard - Root Account Checks
Checks for root account security issues
"""

from colorama import Fore

def check_root_account(iam, add_finding):
    """Check root account security configuration"""
    print(Fore.CYAN + "[*] Checking root account security...")

    summary = iam.get_account_summary()['SummaryMap']

    # Check root MFA
    if summary.get('AccountMFAEnabled', 0) == 0:
        add_finding(
            severity='CRITICAL',
            title='Root account does not have MFA enabled',
            resource='Root Account',
            detail="The AWS root account does not have MFA enabled. "
                   "This is a critical security risk as root has "
                   "unrestricted access to all AWS services and "
                   "cannot be restricted by IAM policies",
            recommendation="Enable MFA on the root account immediately. "
                         "Use a hardware MFA device for maximum security. "
                         "Never use root credentials for day-to-day operations."
        )
        print(Fore.RED + "  🚨 CRITICAL: Root account - No MFA enabled")
    else:
        print(Fore.GREEN + "  ✅ Root account MFA is enabled")

    # Check root access keys
    if summary.get('AccountAccessKeysPresent', 0) > 0:
        add_finding(
            severity='CRITICAL',
            title='Root account has active access keys',
            resource='Root Account',
            detail="The AWS root account has active access keys. "
                   "Root access keys provide unrestricted API access "
                   "and should never exist",
            recommendation="Delete all root account access keys immediately. "
                         "Use IAM users or roles with appropriate permissions instead."
        )
        print(Fore.RED + "  🚨 CRITICAL: Root account - Active access keys detected")
    else:
        print(Fore.GREEN + "  ✅ No root account access keys present")

    # Check number of users
    user_count = summary.get('Users', 0)
    if user_count == 0:
        add_finding(
            severity='HIGH',
            title='No IAM users found',
            resource='AWS Account',
            detail="No IAM users exist in this account. "
                   "This may indicate root credentials are being "
                   "used for all operations",
            recommendation="Create individual IAM users with appropriate "
                         "permissions instead of using root credentials"
        )
        print(Fore.YELLOW + "  ⚠️  HIGH: No IAM users found in account")

    print(Fore.GREEN + "  [+] Root account check complete.\n")