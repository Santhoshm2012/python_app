import logging
import pandas as pd
from src.utils.config import setup_logging

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

def analyze_access_patterns(context, user_details, group_memberships, app_roles, app_role_assignments, audit_logs, signin_logs):
    """
    Identify underutilized permissions by comparing assigned roles vs. used actions.
    Args:
        context: List of log texts from vectorstore.
        user_details: DataFrame with user details.
        group_memberships, app_roles, app_role_assignments: DataFrames for permission mapping.
        audit_logs, signin_logs: DataFrames for raw log data.
    Returns: Dict of underutilized permissions per user.
    """
    logger.info("Analyzing access patterns")
    try:
        underutilized = {}
        
        # Build group-to-permissions mapping using group_memberships and app_roles
        group_permissions = {}
        for _, group in group_memberships.groupby("groupId"):
            group_id = group["groupId"].iloc[0]
            group_name = group["groupName"].iloc[0]
            users_in_group = group["userId"].tolist()
            assignments = app_role_assignments[app_role_assignments["userId"].isin(users_in_group)]
            perms = set()
            for _, assignment in assignments.iterrows():
                role_id = assignment["roleId"]
                role = app_roles[app_roles["roleId"] == role_id]
                if not role.empty:
                    perms.add(role.iloc[0]["roleName"])
            group_permissions[group_name] = perms

        # Define activity-to-permission mapping (simplified for Dynamics 365 roles)
        activity_to_permission = {
            "sales": "Sales Enterprise app access",
            "customer service": "Customer service app access",
            "outlook": "Dynamics 365 App for Outlook User",
            "admin": "Omnichannel administrator",
            "forecast": "Forecast user"
        }

        # Map app activities to permissions using audit logs
        audit_activity_to_permission = {
            "create": "Create permissions",
            "update": "Update permissions",
            "delete": "Delete permissions",
            "read": "Read permissions"
        }

        for _, row in user_details.iterrows():
            user_id = row["User ID"]
            groups = row["Groups"].split(", ") if row["Groups"] else []
            if not groups:
                logger.debug(f"User {user_id} has no assigned groups, skipping.")
                continue

            # Get assigned permissions (roles) for the user
            assigned_permissions = set()
            for group in groups:
                assigned_permissions.update(group_permissions.get(group, set()))
            user_assignments = app_role_assignments[app_role_assignments["userId"] == user_id]
            for _, assignment in user_assignments.iterrows():
                role_id = assignment["roleId"]
                role = app_roles[app_roles["roleId"] == role_id]
                if not role.empty:
                    assigned_permissions.add(role.iloc[0]["roleName"])

            # Get used permissions (based on audit and sign-in logs)
            used_permissions = set()
            user_audit_logs = audit_logs[audit_logs["initiatedByUserId"] == user_id]
            user_signin_logs = signin_logs[signin_logs["userId"] == user_id]

            # Use audit logs to infer permissions (if action details are available)
            for _, log in user_audit_logs.iterrows():
                action = log.get("actionCode", "").lower()
                for key, perm in audit_activity_to_permission.items():
                    if key in action:
                        used_permissions.add(perm)
                        break

            # Use sign-in logs to infer permissions
            for _, log in user_signin_logs.iterrows():
                app = log["appDisplayName"].lower()
                for key, perm in activity_to_permission.items():
                    if key.lower() in app:
                        used_permissions.add(perm)
                        break

            # Identify underutilized permissions
            unused = assigned_permissions - used_permissions
            if unused:
                underutilized[user_id] = sorted(list(unused))

        logger.info("Access pattern analysis completed")
        return underutilized
    except Exception as e:
        logger.error(f"Error analyzing access patterns: {str(e)}")
        raise