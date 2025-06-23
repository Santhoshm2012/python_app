import os
import pandas as pd
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("analyze_unused_roles")

# File paths
DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
ASSIGNMENTS_FILE = os.path.join(DATA_DIR, 'app_role_assignments.csv')
PRIVILEGES_FILE = os.path.join(DATA_DIR, 'd365_role_privileges.csv')
AUDIT_LOG_FILE = os.path.join(DATA_DIR, 'audit_logs_full_sample.csv')
OUTPUT_FILE = os.path.join(DATA_DIR, 'unused_roles_analysis.csv')

# Load data
assignments = pd.read_csv(ASSIGNMENTS_FILE)
privileges = pd.read_csv(PRIVILEGES_FILE)
audit_logs = pd.read_csv(AUDIT_LOG_FILE)

# Only consider last 90 days
date_col = 'createdon' if 'createdon' in audit_logs.columns else 'activityDateTime'
now = datetime.utcnow()
cutoff = now - timedelta(days=90)
audit_logs[date_col] = pd.to_datetime(audit_logs[date_col], errors='coerce')
audit_logs_90 = audit_logs[audit_logs[date_col] >= cutoff]

# Build privilege lookup by roleId
role_privs = privileges.groupby('roleid').apply(lambda df: set(zip(df['privilegename'], df['privilegetype']))).to_dict()

results = []
for (userId, userName, email), user_roles in assignments.groupby(['userId', 'userName', 'email']):
    for _, role_row in user_roles.iterrows():
        roleId = role_row['roleId']
        roleName = role_row['roleName']
        privs = role_privs.get(roleId, set())
        # For this user, did they perform any action matching any privilege in last 90 days?
        user_logs = audit_logs_90[audit_logs_90['_userid_value'] == userId]
        used = False
        last_used = None
        for _, log in user_logs.iterrows():
            # Try to match entity/action to privilege (very rough: match objecttypecode to privilegename, action to privilegetype)
            entity = str(log.get('objecttypecode', '')).lower()
            action = str(log.get('action', ''))
            for priv_name, priv_type in privs:
                if priv_name and priv_name.lower() in entity:
                    used = True
                    last_used = log[date_col]
                    break
            if used:
                break
        results.append({
            'userId': userId,
            'userName': userName,
            'email': email,
            'roleId': roleId,
            'roleName': roleName,
            'unused': not used,
            'lastUsedDate': last_used if used else ''
        })

out_df = pd.DataFrame(results)
out_df.to_csv(OUTPUT_FILE, index=False)
print(f"Saved unused roles analysis to {OUTPUT_FILE}") 