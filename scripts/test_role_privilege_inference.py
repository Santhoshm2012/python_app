import pandas as pd

# File paths
log_file = "backend/data/audit_logs_full_sample.csv"

# Hardcoded userId for testing
user_id = "1a695fbd-b4df-eb11-bacb-000d3aba4ed5"

# Load audit log
df = pd.read_csv(log_file)

# Filter for this user
user_logs = df[df["_userid_value"] == user_id]

print(f"Audit log actions for user {user_id}:")
for idx, row in user_logs.iterrows():
    entity = row.get("objecttypecode", "?")
    action = row.get("action", "?")
    createdon = row.get("createdon", "?")
    print(f"- {createdon} | Entity: {entity} | Action: {action}")
    print(f"  [Roles that could have enabled this action: <placeholder, needs mapping table>]") 