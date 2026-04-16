"""
IAMGuard - User Checks
Checks for user-based IAM misconfigurations
"""

from datetime import datetime, timezone
from colorama import Fore

def check_mfa_disabled(iam, add_finding):
    """Check for users without MFA enabled"""
    print(Fore.CYAN + "[*] Checking MFA status for all users...")
    users = iam.list_users()['Users']

    for user in users:
        mfa_devices = iam.list_mfa_devices(
            UserName=user['UserName']
        )['MFADevices']

        if not mfa_devices:
            add_finding(
                severity='HIGH',
                title='User has no MFA enabled',
                resource=user['UserName'],
                detail=f"User {user['UserName']} does not have "
                       f"Multi-Factor Authentication enabled",
                recommendation="Enable MFA for this user immediately "
                             "to prevent unauthorized access"
            )
            print(Fore.YELLOW + f"  ⚠️  HIGH: {user['UserName']} - No MFA enabled")

    print(Fore.GREEN + f"  [+] MFA check complete. {len(users)} users scanned.\n")


def check_admin_access(iam, add_finding):
    """Check for users with AdministratorAccess policy"""
    print(Fore.CYAN + "[*] Checking for administrator access...")
    users = iam.list_users()['Users']

    for user in users:
        policies = iam.list_attached_user_policies(
            UserName=user['UserName']
        )['AttachedPolicies']

        for policy in policies:
            if 'AdministratorAccess' in policy['PolicyName']:
                add_finding(
                    severity='CRITICAL',
                    title='User has AdministratorAccess policy attached',
                    resource=user['UserName'],
                    detail=f"User {user['UserName']} has the "
                           f"AdministratorAccess policy attached, "
                           f"granting unrestricted access to all AWS services",
                    recommendation="Remove AdministratorAccess and apply "
                                 "least-privilege permissions specific "
                                 "to the user's role"
                )
                print(Fore.RED + f"  🚨 CRITICAL: {user['UserName']} - AdministratorAccess detected")

    print(Fore.GREEN + f"  [+] Admin access check complete.\n")


def check_inactive_users(iam, add_finding, days_threshold=90):
    """Check for users inactive for more than threshold days"""
    print(Fore.CYAN + f"[*] Checking for users inactive > {days_threshold} days...")
    users = iam.list_users()['Users']
    now = datetime.now(timezone.utc)

    for user in users:
        last_used = user.get('PasswordLastUsed')

        if last_used is None:
            add_finding(
                severity='MEDIUM',
                title='User has never logged in',
                resource=user['UserName'],
                detail=f"User {user['UserName']} has never logged "
                       f"into the AWS console",
                recommendation="Review if this user account is still "
                             "needed. If not, disable or delete it."
            )
            print(Fore.BLUE + f"  ⚠️  MEDIUM: {user['UserName']} - Never logged in")

        else:
            days_inactive = (now - last_used).days
            if days_inactive > days_threshold:
                add_finding(
                    severity='MEDIUM',
                    title=f'User inactive for {days_inactive} days',
                    resource=user['UserName'],
                    detail=f"User {user['UserName']} has not logged "
                           f"in for {days_inactive} days",
                    recommendation="Review if this account is still needed "
                                 "and disable if no longer in use"
                )
                print(Fore.BLUE + f"  ⚠️  MEDIUM: {user['UserName']} - "
                      f"Inactive {days_inactive} days")

    print(Fore.GREEN + f"  [+] Inactive user check complete.\n")