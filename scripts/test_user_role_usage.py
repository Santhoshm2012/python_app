import pandas as pd
import os

# File paths (adjust if needed)
data_dir = os.path.join(os.path.dirname(__file__), '../data')
audit_log_file = os.path.join(data_dir, 'audit_logs_full_sample.csv')
role_assignments_file = os.path.join(data_dir, 'app_role_assignments.csv')
user_details_file = os.path.join(data_dir, 'user_details.csv')

# Load data
print("Loading data...")
audit_logs = pd.read_csv(audit_log_file)
role_assignments = pd.read_csv(role_assignments_file)
user_details = pd.read_csv(user_details_file)

# Input: user email
test_email = input("Enter user email for testing: ").strip().lower()

# Find userId for the email
user_row = user_details[user_details['email'].str.lower() == test_email]
if user_row.empty:
    print(f"No user found with email: {test_email}")
    exit(1)
user_id = user_row.iloc[0]['userId']
user_name = user_row.iloc[0]['userName']
print(f"\nUser: {user_name} ({test_email})\nUserId: {user_id}")

# Get all assigned roles for the user
assigned_roles = role_assignments[role_assignments['userId'] == user_id]['roleName'].dropna().unique().tolist()
print(f"\nAssigned Roles ({len(assigned_roles)}):")
for role in assigned_roles:
    print(f"  - {role}")

# Get all actions/entities performed by the user (from audit log)
user_audit_logs = audit_logs[audit_logs['_userid_value'] == user_id]
print(f"\nAudit Log Actions ({len(user_audit_logs)}):")
if user_audit_logs.empty:
    print("  No actions found in audit log for this user.")
else:
    for idx, row in user_audit_logs.iterrows():
        print(f"  - {row['createdon']} | Entity: {row['objecttypecode']} | Action: {row['action']} | Operation: {row['operation']}")

# Placeholder for mapping logic (to be added later)
print("\n[Mapping logic for used/unused roles can be added here if a mapping table is provided.]") 