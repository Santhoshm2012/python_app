import os
import requests
from azure.identity import ClientSecretCredential
from dotenv import load_dotenv
import logging
from typing import List

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
D365_API_ENDPOINT = os.getenv("D365_API_ENDPOINT", "https://yourorg.crm.dynamics.com")

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("d365_role_manager")

def get_access_token(scope=None):
    if scope is None:
        scope = D365_API_ENDPOINT.rstrip('/') + "/.default"
    credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    token = credential.get_token(scope)
    return token.token

def get_user_roles(systemuserid, token):
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/systemusers({systemuserid})/systemuserroles_association?$select=roleid,name"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    logger.info(f"Fetching roles for user {systemuserid}")
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error(f"Failed to fetch roles: {resp.status_code} {resp.text}")
        return []
    data = resp.json()
    roles = []
    for item in data.get('value', []):
        role = {
            'roleid': item['roleid'],
            'rolename': item['name']
        }
        roles.append(role)
    return roles

def remove_user_role(systemuserid, roleid, token):
    role_url = f"{D365_API_ENDPOINT}/api/data/v9.2/roles({roleid})"
    ref_url = f"{D365_API_ENDPOINT}/api/data/v9.2/systemusers({systemuserid})/systemuserroles_association/$ref?$id={role_url}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    logger.info(f"Removing role {roleid} from user {systemuserid}")
    resp = requests.delete(ref_url, headers=headers)
    if resp.status_code in (204, 200):
        logger.info(f"Removed role {roleid} from user {systemuserid}")
        return True
    else:
        logger.error(f"Failed to remove role {roleid}: {resp.status_code} {resp.text}")
        return False

def remove_roles_from_user(systemuserid: str, role_names: List[str]) -> dict:
    token = get_access_token()
    roles = get_user_roles(systemuserid, token)
    if not roles:
        return {"success": False, "message": "No roles found for this user or failed to fetch roles."}
    # Find roleids for the given role_names
    roles_to_remove = [r for r in roles if r['rolename'] in role_names]
    if not roles_to_remove:
        return {"success": False, "message": "No matching roles to remove."}
    removed = []
    failed = []
    for r in roles_to_remove:
        if remove_user_role(systemuserid, r['roleid'], token):
            removed.append(r['rolename'])
        else:
            failed.append(r['rolename'])
    return {"success": len(failed) == 0, "removed": removed, "failed": failed}

def disable_user_account(systemuserid: str) -> dict:
    """
    Disables a D365 user by setting their 'isdisabled' property to true.
    """
    token = get_access_token()
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/systemusers({systemuserid})"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    data = {"isdisabled": True}
    logger.info(f"Disabling user {systemuserid}")
    resp = requests.patch(url, headers=headers, json=data)
    if resp.status_code in (204, 200):
        logger.info(f"User {systemuserid} disabled successfully.")
        return {"success": True, "userId": systemuserid}
    else:
        logger.error(f"Failed to disable user {systemuserid}: {resp.status_code} {resp.text}")
        return {"success": False, "userId": systemuserid, "error": resp.text}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Disable a D365 user account by systemuserid.")
    parser.add_argument("systemuserid", help="The systemuserid (GUID) of the user to disable.")
    args = parser.parse_args()
    result = disable_user_account(args.systemuserid)
    print(result) 