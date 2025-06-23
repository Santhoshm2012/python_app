import logging
import pandas as pd
from src.utils.config import setup_logging

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

def analyze_permission_trends(audit_logs, signin_logs, user_details, group_memberships, app_roles, app_role_assignments):
    logger.info("Analyzing permission usage trends")
    try:
        trends = {
            "low_usage_permissions": {},
            "unused_roles": {
                "PCS-Related": [],
                "Paramount-Related": [],
                "General": [],
                "Explanation": "Roles listed have no associated activity in audit or sign-in logs over the analyzed period."
            }
        }

        role_id_to_permission = dict(zip(app_roles["roleId"], app_roles["roleName"]))
        group_to_role = dict(zip(group_memberships["groupId"], group_memberships["groupName"]))
        user_groups = group_memberships.groupby("userId")["groupId"].apply(list).to_dict()

        app_to_roles = {}
        for _, role in app_roles.iterrows():
            app_name = role.get("appDisplayName", "Unknown").lower()
            role_name = role["roleName"]
            if app_name not in app_to_roles:
                app_to_roles[app_name] = set()
            app_to_roles[app_name].add(role_name)

        role_usage_audit = {}
        if not audit_logs.empty:
            timestamp_col = "activityDateTime"
            if timestamp_col not in audit_logs.columns:
                logger.error("No timestamp column found in audit_logs. Expected 'activityDateTime'.")
                raise ValueError("No timestamp column found in audit_logs")

            audit_logs[timestamp_col] = pd.to_datetime(
                audit_logs[timestamp_col], format='%Y-%m-%d %H:%M:%S', errors='coerce', utc=True
            )
            invalid_audits = audit_logs[timestamp_col].isna().sum()
            logger.info(f"Invalid activityDateTime entries: {invalid_audits}")

            for user_id in user_details["User ID"]:
                user_group_ids = user_groups.get(user_id, [])
                if not user_group_ids:
                    continue
                primary_group_id = user_group_ids[0]
                role_name = group_to_role.get(primary_group_id, "Unknown")
                user_logs = audit_logs[audit_logs["initiatedByUserId"] == user_id]
                if role_name not in role_usage_audit:
                    role_usage_audit[role_name] = 0
                if not user_logs.empty:
                    role_usage_audit[role_name] += len(user_logs)

        role_usage_signin = {}
        if not signin_logs.empty:
            timestamp_col = "signInDateTime"
            if timestamp_col not in signin_logs.columns:
                logger.error("No timestamp column found in signin_logs. Expected 'signInDateTime'.")
                raise ValueError("No timestamp column found in signin_logs")

            signin_logs[timestamp_col] = pd.to_datetime(
                signin_logs[timestamp_col], format='%Y-%m-%d %H:%M:%S', errors='coerce', utc=True
            )
            invalid_signins = signin_logs[timestamp_col].isna().sum()
            logger.info(f"Invalid signInDateTime entries: {invalid_signins}")

            for user_id in user_details["User ID"]:
                user_group_ids = user_groups.get(user_id, [])
                if not user_group_ids:
                    continue
                primary_group_id = user_group_ids[0]
                role_name = group_to_role.get(primary_group_id, "Unknown")
                user_signins = signin_logs[signin_logs["userId"] == user_id]
                if role_name not in role_usage_signin:
                    role_usage_signin[role_name] = 0
                if not user_signins.empty:
                    role_usage_signin[role_name] += len(user_signins)

        permission_usage = {}
        for user_id in user_details["User ID"]:
            user_signins = signin_logs[signin_logs["userId"] == user_id]
            accessed_apps = set(user_signins["appDisplayName"].str.lower().unique())
            user_assignments = app_role_assignments[app_role_assignments["userId"] == user_id]
            assigned_permissions = set()
            for _, assignment in user_assignments.iterrows():
                permission = role_id_to_permission.get(assignment["roleId"])
                if permission:
                    assigned_permissions.add(permission)

            for perm in assigned_permissions:
                expected_apps = set()
                for app_name, roles in app_to_roles.items():
                    if perm in roles:
                        expected_apps.add(app_name)
                used = bool(expected_apps & accessed_apps)
                if perm not in permission_usage:
                    permission_usage[perm] = {"used": 0, "total": 0}
                permission_usage[perm]["total"] += 1
                if used:
                    permission_usage[perm]["used"] += 1

        for perm, counts in permission_usage.items():
            if counts["total"] > 0:
                usage_rate = counts["used"] / counts["total"]
                if usage_rate < 0.2:
                    trends["low_usage_permissions"][perm] = f"Used by {counts['used']}/{counts['total']} users ({usage_rate*100:.1f}%)"

        all_roles = set(role_usage_audit.keys()) | set(role_usage_signin.keys()) | set(group_to_role.values())
        for role_name in all_roles:
            audit_count = role_usage_audit.get(role_name, 0)
            signin_count = role_usage_signin.get(role_name, 0)
            users_in_role = group_memberships[group_memberships["groupName"] == role_name]["userId"].nunique()
            if users_in_role > 0 and audit_count == 0 and signin_count == 0:
                if "PCS" in role_name:
                    trends["unused_roles"]["PCS-Related"].append(role_name)
                elif "Paramount" in role_name:
                    trends["unused_roles"]["Paramount-Related"].append(role_name)
                else:
                    trends["unused_roles"]["General"].append(role_name)

        if any(trends["unused_roles"][category] for category in ["PCS-Related", "Paramount-Related", "General"]):
            trends["unused_roles"]["Explanation"] = "These roles have no associated activity in audit or sign-in logs over the analyzed period."
        else:
            trends["unused_roles"]["Explanation"] = "No unused roles detected."

        logger.info("Permission usage trends analysis completed")
        return trends
    except Exception as e:
        logger.error(f"Error analyzing permission trends: {str(e)}")
        raise