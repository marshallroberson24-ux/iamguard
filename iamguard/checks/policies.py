"""
IAMGuard - Policy Checks
Checks for policy-based IAM misconfigurations
"""

from colorama import Fore

def check_wildcard_policies(iam, add_finding):
    """Check for policies with wildcard permissions"""
    print(Fore.CYAN + "[*] Checking for wildcard permissions in policies...")

    paginator = iam.get_paginator('list_policies')
    flagged = 0

    for page in paginator.paginate(Scope='Local'):
        for policy in page['Policies']:
            version = iam.get_policy_version(
                PolicyArn=policy['Arn'],
                VersionId=policy['DefaultVersionId']
            )['PolicyVersion']

            doc = version['Document']
            statements = doc.get('Statement', [])

            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]

                if '*' in actions and statement.get('Effect') == 'Allow':
                    add_finding(
                        severity='CRITICAL',
                        title='Policy allows all actions (*)',
                        resource=policy['PolicyName'],
                        detail=f"Policy {policy['PolicyName']} contains "
                               f"a wildcard (*) action, granting "
                               f"unrestricted permissions to resources",
                        recommendation="Replace wildcard actions with "
                                     "specific permissions following "
                                     "least-privilege principles"
                    )
                    print(Fore.RED + f"  🚨 CRITICAL: {policy['PolicyName']} - "
                          f"Wildcard action detected")
                    flagged += 1

                elif '*' in resources and statement.get('Effect') == 'Allow':
                    add_finding(
                        severity='HIGH',
                        title='Policy allows access to all resources (*)',
                        resource=policy['PolicyName'],
                        detail=f"Policy {policy['PolicyName']} grants "
                               f"access to all resources (*), which "
                               f"violates least-privilege principles",
                        recommendation="Scope resource access to specific "
                                     "ARNs rather than using wildcards"
                    )
                    print(Fore.YELLOW + f"  ⚠️  HIGH: {policy['PolicyName']} - "
                          f"Wildcard resource detected")
                    flagged += 1

    print(Fore.GREEN + f"  [+] Policy check complete. {flagged} wildcard policies found.\n")