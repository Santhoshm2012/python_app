import sys
from d365_role_manager import get_user_roles, remove_roles_from_user

def main():
    if len(sys.argv) < 2:
        print("Usage: python remove_d365_user_roles.py <systemuserid> [role1,role2,...]")
        sys.exit(1)
    systemuserid = sys.argv[1]
    if len(sys.argv) > 2:
        # Remove only specified roles
        role_names = sys.argv[2].split(',')
        result = remove_roles_from_user(systemuserid, role_names)
        print(result)
    else:
        # Remove all roles
        from d365_role_manager import get_access_token
        token = get_access_token()
        roles = get_user_roles(systemuserid, token)
        if not roles:
            print("No roles found for this user or failed to fetch roles.")
            sys.exit(0)
        print(f"User has the following roles:")
        for r in roles:
            print(f"- {r['rolename']} (roleid: {r['roleid']})")
        confirm = input("Are you sure you want to remove ALL these roles from the user? (yes/no): ")
        if confirm.strip().lower() != 'yes':
            print("Aborted.")
            sys.exit(0)
        role_names = [r['rolename'] for r in roles]
        result = remove_roles_from_user(systemuserid, role_names)
        print(result)

if __name__ == "__main__":
    main()