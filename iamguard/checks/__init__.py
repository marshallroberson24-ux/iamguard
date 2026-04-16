"""
IAMGuard - Checks Package
"""

from iamguard.checks.users import (
    check_mfa_disabled,
    check_admin_access,
    check_inactive_users
)
from iamguard.checks.keys import (
    check_old_access_keys,
    check_unused_access_keys
)
from iamguard.checks.policies import check_wildcard_policies
from iamguard.checks.root import check_root_account