import pandas as pd
from datetime import datetime, timedelta
import logging
import os

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# File paths (adjust if needed)
AUDIT_LOGS_PATH = os.path.join(os.path.dirname(__file__), '../../data/audit_logs_full_sample.csv')
ROLES_PATH = os.path.join(os.path.dirname(__file__), '../../data/app_roles.csv')
ASSIGNMENTS_PATH = os.path.join(os.path.dirname(__file__), '../../data/app_role_assignments.csv')
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), '../../data/role_usage_heuristic_output.csv')

# Heuristic mapping: role roleName keywords to likely entity names in audit logs
ROLE_ENTITY_MAP = {
    'sales': ['opportunity', 'lead', 'quote', 'order'],
    'customer service': ['case', 'incident'],
    'outlook': ['email', 'activity'],
    'admin': ['systemuser', 'user'],
    'forecast': ['forecast'],
    'marketing': ['campaign', 'marketing'],
    'support': ['support', 'ticket'],
    'scheduler': ['goal', 'schedule'],
    'approvals': ['approval'],
    'pcs': ['pcs'],
    'paramount': ['paramount'],
    # Add more mappings as needed
}

# Load data
def load_data():
    audit_logs = pd.read_csv(AUDIT_LOGS_PATH)
    roles = pd.read_csv(ROLES_PATH)
    assignments = pd.read_csv(ASSIGNMENTS_PATH)
    return audit_logs, roles, assignments

# Map role roleName to likely entity names
def map_role_to_entities(role_name):
    entities = set()
    role_name_lower = role_name.lower()
    for keyword, entity_list in ROLE_ENTITY_MAP.items():
        if keyword in role_name_lower:
            entities.update(entity_list)
    # Fallback: try splitting role roleName and matching to entity
    for part in role_name_lower.replace('-', ' ').replace('_', ' ').split():
        if part in audit_log_entities:
            entities.add(part)
    return list(entities)

def analyze_role_usage(audit_logs, roles, assignments, days=90):
    # Get unique entity names from audit logs
    global audit_log_entities
    audit_log_entities = set(audit_logs['objecttypecode'].dropna().unique())

    # Prepare time window
    audit_logs['createdon'] = pd.to_datetime(audit_logs['createdon'], errors='coerce', utc=True)
    cutoff = pd.Timestamp.utcnow() - timedelta(days=days)
    recent_logs = audit_logs[audit_logs['createdon'] >= cutoff]

    # Prepare output
    results = []

    # Build roleId -> roleName map
    roleid_to_name = dict(zip(roles['roleId'], roles['roleName']))

    # For each user-role assignment
    for _, row in assignments.iterrows():
        user_id = row['userId']
        user_name = row.get('userName', '')
        role_id = row['roleId']
        role_name = row.get('roleName') or roleid_to_name.get(role_id, '')
        if not role_name:
            continue
        entities = map_role_to_entities(role_name)
        if not entities:
            likely_used = 'Unknown (no entity mapping)'
        else:
            # Check if user has any recent log for these entities
            user_logs = recent_logs[(recent_logs['_userid_value'] == user_id) & (recent_logs['objecttypecode'].isin(entities))]
            likely_used = 'Yes' if not user_logs.empty else 'No'
        results.append({
            'userId': user_id,
            'userName': user_name,
            'roleId': role_id,
            'roleName': role_name,
            'likely_used': likely_used,
            'mapped_entities': ','.join(entities) if entities else ''
        })
    df_out = pd.DataFrame(results)
    df_out.to_csv(OUTPUT_PATH, index=False)
    logger.info(f"Analysis complete. Output written to {OUTPUT_PATH}")
    print(df_out['likely_used'].value_counts())
    print(df_out.head(10))

def analyze_role_usage_per_user(audit_logs, roles, assignments, user_details=None, days=90):
    global audit_log_entities
    audit_log_entities = set(audit_logs['objecttypecode'].dropna().unique())
    audit_logs['createdon'] = pd.to_datetime(audit_logs['createdon'], errors='coerce', utc=True)
    cutoff = pd.Timestamp.utcnow() - timedelta(days=days)
    recent_logs = audit_logs[audit_logs['createdon'] >= cutoff]

    # Build roleId -> roleName map
    roleid_to_name = dict(zip(roles['roleId'], roles['roleName']))

    # Group assignments by user
    user_groups = assignments.groupby('userId')
    output_rows = []
    for user_id, group in user_groups:
        user_name = group['userName'].iloc[0] if 'userName' in group else ''
        user_email = ''
        if user_details is not None:
            user_row = user_details[user_details['userId'] == user_id]
            if not user_row.empty:
                user_name = user_row.iloc[0].get('userName', user_name)
                user_email = user_row.iloc[0].get('userEmail', '')
        assigned_roles = []
        used_roles = []
        unused_roles = []
        for _, row in group.iterrows():
            role_id = row['roleId']
            role_name = row.get('roleName') or roleid_to_name.get(role_id, '')
            if not role_name:
                continue
            assigned_roles.append(role_name)
            entities = map_role_to_entities(role_name)
            if not entities:
                continue
            user_logs = recent_logs[(recent_logs['_userid_value'] == user_id) & (recent_logs['objecttypecode'].isin(entities))]
            if not user_logs.empty:
                used_roles.append(role_name)
            else:
                unused_roles.append(role_name)
        output_rows.append({
            'userId': user_id,
            'userName': user_name,
            'userEmail': user_email,
            'assigned_roles': '; '.join(sorted(set(assigned_roles))),
            'used_roles': '; '.join(sorted(set(used_roles))),
            'unused_roles': '; '.join(sorted(set(unused_roles))),
            'assigned_count': len(set(assigned_roles)),
            'used_count': len(set(used_roles)),
            'unused_count': len(set(unused_roles)),
        })
    # --- Ensure all users are included ---
    if user_details is not None:
        all_user_ids = set(user_details['userId'])
        existing_user_ids = set(row['userId'] for row in output_rows)
        for user_id in all_user_ids - existing_user_ids:
            user_row = user_details[user_details['userId'] == user_id].iloc[0]
            output_rows.append({
                'userId': user_id,
                'userName': user_row.get('userName', ''),
                'userEmail': user_row.get('userEmail', ''),
                'assigned_roles': '',
                'used_roles': '',
                'unused_roles': '',
                'assigned_count': 0,
                'used_count': 0,
                'unused_count': 0,
            })
    df_out = pd.DataFrame(output_rows)
    out_path = os.path.join(os.path.dirname(__file__), '../../data/role_usage_per_user_summary.csv')
    df_out.to_csv(out_path, index=False)
    logger.info(f"User-centric summary written to {out_path}")
    print(df_out.head(10))

if __name__ == '__main__':
    audit_logs, roles, assignments = load_data()
    # Try to load user details if available
    user_details_path = os.path.join(os.path.dirname(__file__), '../../data/user_details.csv')
    user_details = None
    if os.path.exists(user_details_path):
        try:
            user_details = pd.read_csv(user_details_path)
        except Exception as e:
            logger.warning(f"Could not load user details: {e}")
    analyze_role_usage_per_user(audit_logs, roles, assignments, user_details, days=90) 