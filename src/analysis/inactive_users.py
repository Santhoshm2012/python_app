import pandas as pd
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

def find_inactive_users(user_details: pd.DataFrame, signin_logs: pd.DataFrame, audit_logs: pd.DataFrame, inactivity_days: int = 30) -> dict:
    try:
        logger.info(f"Columns in signin_logs: {list(signin_logs.columns)}")
        logger.info(f"Columns in audit_logs: {list(audit_logs.columns)}")
        logger.info(f"Columns in user_details: {list(user_details.columns)}")

        user_id_col_signin = None
        possible_user_id_cols = ['userId', 'UserID', 'userid', 'user_id', 'User ID']
        for col in possible_user_id_cols:
            if col in signin_logs.columns:
                user_id_col_signin = col
                break
        
        if user_id_col_signin is None:
            raise KeyError("No user ID column found in signin_logs. Expected one of: " + ", ".join(possible_user_id_cols))

        user_id_col_audit = None
        possible_audit_user_id_cols = ['initiatedByUserId', 'userId', 'UserID', 'userid', 'user_id', 'User ID']
        for col in possible_audit_user_id_cols:
            if col in audit_logs.columns:
                user_id_col_audit = col
                break
        
        if user_id_col_audit is None:
            raise KeyError("No user ID column found in audit_logs. Expected one of: " + ", ".join(possible_audit_user_id_cols))

        user_details_id_col = None
        for col in possible_user_id_cols:
            if col in user_details.columns:
                user_details_id_col = col
                break
        
        if user_details_id_col is None:
            raise KeyError("No user ID column found in user_details. Expected one of: " + ", ".join(possible_user_id_cols))

        # Current date: May 29, 2025, 12:11 PM IST = 06:41 AM UTC
        current_date = pd.Timestamp(datetime(2025, 5, 29, 6, 41), tz='UTC')
        threshold_date = current_date - timedelta(days=inactivity_days)
        
        if not signin_logs.empty:
            signin_logs['signInDateTime'] = pd.to_datetime(
                signin_logs['signInDateTime'], format='%Y-%m-%d %H:%M:%S', errors='coerce', utc=True
            )
            logger.info(f"Sample signInDateTime values: {signin_logs['signInDateTime'].head().tolist()}")
            invalid_signins = signin_logs['signInDateTime'].isna().sum()
            logger.info(f"Invalid signInDateTime entries: {invalid_signins}")
        else:
            logger.warning("Sign-in logs DataFrame is empty.")
            signin_logs['signInDateTime'] = pd.Series(dtype='datetime64[ns, UTC]')
        
        if not audit_logs.empty:
            audit_logs['activityDateTime'] = pd.to_datetime(
                audit_logs['activityDateTime'], format='%Y-%m-%d %H:%M:%S', errors='coerce', utc=True
            )
            logger.info(f"Sample activityDateTime values: {audit_logs['activityDateTime'].head().tolist()}")
            invalid_audits = audit_logs['activityDateTime'].isna().sum()
            logger.info(f"Invalid activityDateTime entries: {invalid_audits}")
        else:
            logger.warning("Audit logs DataFrame is empty.")
            audit_logs['activityDateTime'] = pd.Series(dtype='datetime64[ns, UTC]')

        all_users = set(user_details[user_details_id_col].astype(str).unique())
        
        recent_signins = signin_logs[signin_logs['signInDateTime'] >= threshold_date]
        active_users_signin = set(recent_signins[user_id_col_signin].astype(str).unique())
        
        recent_audit = audit_logs[audit_logs['activityDateTime'] >= threshold_date]
        active_users_audit = set(recent_audit[user_id_col_audit].astype(str).unique())
        
        active_users = active_users_signin | active_users_audit
        
        inactive_users_set = all_users - active_users
        
        inactive_users = {}
        for user_id in inactive_users_set:
            user_signins = signin_logs[signin_logs[user_id_col_signin].astype(str) == user_id]
            user_audit = audit_logs[audit_logs[user_id_col_audit].astype(str) == user_id]
            
            last_signin = user_signins['signInDateTime'].max() if not user_signins.empty else pd.Timestamp.min.tz_localize('UTC')
            last_audit = user_audit['activityDateTime'].max() if not user_audit.empty else pd.Timestamp.min.tz_localize('UTC')
            
            last_activity = max(last_signin, last_audit)
            
            if last_activity == pd.Timestamp.min.tz_localize('UTC'):
                inactive_users[user_id] = f"No activity recorded in the last {inactivity_days} days. Reason: No sign-in or audit activity ever recorded."
            else:
                days_inactive = (current_date - last_activity).days
                activity_type = "sign-in" if last_signin >= last_audit else "audit action"
                inactive_users[user_id] = f"No activity recorded in the last {inactivity_days} days. Reason: Last {activity_type} was {days_inactive} days ago on {last_activity.strftime('%Y-%m-%d')}."
        
        logger.info(f"Found {len(inactive_users)} inactive users out of {len(all_users)} total users.")
        return inactive_users
    
    except Exception as e:
        logger.error(f"Error finding inactive users: {str(e)}")
        return {}