import logging
import pandas as pd
from src.utils.config import setup_logging

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

def find_permission_mismatches_and_sod(user_details, role_matrix, group_memberships, app_roles, app_role_assignments, conditional_access_policies, signin_logs):
    logger.info("Analyzing permission mismatches and SoD violations")
    try:
        mismatches = {}
        sod_violations = {}

        group_to_role = dict(zip(group_memberships["groupId"], group_memberships["groupName"]))
        user_groups = group_memberships.groupby("userId")["groupId"].apply(list).to_dict()
        role_id_to_permission = dict(zip(app_roles["roleId"], app_roles["roleName"]))
        
        app_to_roles = {}
        for _, role in app_roles.iterrows():
            app_name = role.get("appDisplayName", "Unknown").lower()
            role_name = role["roleName"]
            if app_name not in app_to_roles:
                app_to_roles[app_name] = set()
            app_to_roles[app_name].add(role_name)

        expected_permissions = {}
        for group_id, group_name in group_to_role.items():
            users_in_group = group_memberships[group_memberships["groupId"] == group_id]["userId"].tolist()
            group_assignments = app_role_assignments[app_role_assignments["userId"].isin(users_in_group)]
            total_users = len(users_in_group)
            if total_users == 0:
                continue
            
            permission_counts = {}
            for _, assignment in group_assignments.iterrows():
                permission = role_id_to_permission.get(assignment["roleId"])
                if permission:
                    user_id = assignment["userId"]
                    if user_id in users_in_group:
                        permission_counts[permission] = permission_counts.get(permission, 0) + 1
            
            expected = set()
            for permission, count in permission_counts.items():
                if count / total_users >= 0.8:
                    expected.add(permission)
            expected_permissions[group_name] = expected

        policy_violations = {}
        if not conditional_access_policies.empty:
            for _, policy in conditional_access_policies.iterrows():
                policy_name = policy.get("policyName", "Unknown")
                conditions = policy.get("conditions", {})
                grant_controls = policy.get("grantControls", {})
                policy_groups = []
                if isinstance(conditions, dict):
                    policy_groups = conditions.get("users", [])
                elif isinstance(conditions, (list, str)):
                    policy_groups = conditions if isinstance(conditions, list) else [conditions]
                if not policy_groups:
                    continue
                for key, value in (grant_controls.items() if isinstance(grant_controls, dict) else {}):
                    if value:
                        for group_id in policy_groups:
                            if group_id not in policy_violations:
                                policy_violations[group_id] = []
                            policy_violations[group_id].append(f"Violates policy '{policy_name}' ({key})")

        # Build userId -> userName mapping
        user_id_col = None
        user_name_col = None
        for col in ['userId', 'User ID']:
            if col in user_details.columns:
                user_id_col = col
                break
        for col in ['userName', 'UserName', 'Display Name', 'Name']:
            if col in user_details.columns:
                user_name_col = col
                break
        if not user_id_col or not user_name_col:
            logger.warning("Could not find userId or userName column in user_details.")
            user_id_to_name = lambda x: x
        else:
            user_id_to_name_map = dict(zip(user_details[user_id_col].astype(str), user_details[user_name_col]))
            user_id_to_name = lambda x: user_id_to_name_map.get(x, x)

        for _, user_row in user_details.iterrows():
            user_id = user_row[user_id_col]
            user_name = user_id_to_name(user_id)
            user_group_ids = user_groups.get(user_id, [])
            if not user_group_ids:
                continue

            assigned_permissions = set()
            user_assignments = app_role_assignments[app_role_assignments["userId"] == user_id]
            for _, assignment in user_assignments.iterrows():
                permission = role_id_to_permission.get(assignment["roleId"])
                if permission:
                    assigned_permissions.add(permission)

            primary_group_id = user_group_ids[0]
            primary_role = group_to_role.get(primary_group_id, "Unknown")
            expected = expected_permissions.get(primary_role, set())

            excessive = assigned_permissions - expected
            user_mismatches = []
            if excessive:
                user_mismatches.extend([f"Has permission '{perm}', but this is excessive for their assigned role/group ({primary_role})." for perm in excessive])

            for group_id in user_group_ids:
                if group_id in policy_violations:
                    user_mismatches.extend(policy_violations[group_id])

            user_signins = signin_logs[signin_logs["userId"] == user_id]
            accessed_apps = set(user_signins["appDisplayName"].str.lower().unique())
            expected_apps = set()
            for perm in assigned_permissions:
                for app_name, roles in app_to_roles.items():
                    if perm in roles:
                        expected_apps.add(app_name)

            unused_apps = expected_apps - accessed_apps
            for app in unused_apps:
                unused_permissions = app_to_roles.get(app, set()) & assigned_permissions
                for perm in unused_permissions:
                    user_mismatches.append(f"Permission '{perm}' assigned but no activity in app '{app}'")

            if user_mismatches:
                mismatches[user_name] = sorted(user_mismatches)

            # --- SoD check: Example rule ---
            # If user has both 'System Administrator' and 'Sales Enterprise app access', flag as SoD violation
            sod_rules = [
                ("System Administrator", "Sales Enterprise app access")
            ]
            for perm_a, perm_b in sod_rules:
                if perm_a in assigned_permissions and perm_b in assigned_permissions:
                    if user_name not in sod_violations:
                        sod_violations[user_name] = []
                    sod_violations[user_name].append(f"Has both '{perm_a}' and '{perm_b}', which violates SoD rule: No user should have both permissions.")

        logger.info("Permission mismatch and SoD analysis completed")
        return mismatches, sod_violations
    except Exception as e:
        logger.error(f"Error analyzing permission mismatches/SoD: {str(e)}")
        raise 