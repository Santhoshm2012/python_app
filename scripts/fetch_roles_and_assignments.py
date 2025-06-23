from data_fetcher import fetch_d365_roles, fetch_d365_user_roles

if __name__ == "__main__":
    print("Fetching D365 security roles...")
    roles_df = fetch_d365_roles()
    print(f"Fetched {len(roles_df)} roles. Saved to data/app_roles.csv.")

    print("\nFetching D365 user-role assignments...")
    assignments_df = fetch_d365_user_roles()
    print(f"Fetched {len(assignments_df)} user-role assignments. Saved to data/app_role_assignments.csv.")

    print("\nDone.") 