"""
IAMGuard - Access Key Checks
Checks for access key misconfigurations
"""

from datetime import datetime, timezone
from colorama import Fore

def check_old_access_keys(iam, add_finding, days_threshold=90):
    """Check for access keys older than threshold days"""
    print(Fore.CYAN + f"[*] Checking for access keys older than {days_threshold} days...")
    users = iam.list_users()['Users']
    now = datetime.now(timezone.utc)

    for user in users:
        keys = iam.list_access_keys(
            UserName=user['UserName']
        )['AccessKeyMetadata']

        for key in keys:
            if key['Status'] == 'Active':
                key_age = (now - key['CreateDate']).days
                if key_age > days_threshold:
                    add_finding(
                        severity='HIGH',
                        title=f'Access key is {key_age} days old',
                        resource=user['UserName'],
                        detail=f"Access key {key['AccessKeyId']} for "
                               f"user {user['UserName']} was created "
                               f"{key_age} days ago and should be rotated",
                        recommendation="Rotate this access key immediately. "
                                     "Keys should be rotated every 90 days."
                    )
                    print(Fore.YELLOW + f"  ⚠️  HIGH: {user['UserName']} - "
                          f"Key {key['AccessKeyId']} is {key_age} days old")

    print(Fore.GREEN + f"  [+] Access key age check complete.\n")


def check_unused_access_keys(iam, add_finding):
    """Check for access keys that have never been used"""
    print(Fore.CYAN + "[*] Checking for unused access keys...")
    users = iam.list_users()['Users']

    for user in users:
        keys = iam.list_access_keys(
            UserName=user['UserName']
        )['AccessKeyMetadata']

        for key in keys:
            if key['Status'] == 'Active':
                key_last_used = iam.get_access_key_last_used(
                    AccessKeyId=key['AccessKeyId']
                )['AccessKeyLastUsed']

                if 'LastUsedDate' not in key_last_used:
                    add_finding(
                        severity='MEDIUM',
                        title='Active access key has never been used',
                        resource=user['UserName'],
                        detail=f"Access key {key['AccessKeyId']} for "
                               f"user {user['UserName']} is active "
                               f"but has never been used",
                        recommendation="Delete this access key if it is "
                                     "no longer needed to reduce "
                                     "attack surface"
                    )
                    print(Fore.BLUE + f"  ⚠️  MEDIUM: {user['UserName']} - "
                          f"Unused key {key['AccessKeyId']}")

    print(Fore.GREEN + f"  [+] Unused access key check complete.\n")