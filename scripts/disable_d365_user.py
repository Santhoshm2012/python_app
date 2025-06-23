import os
import requests
from azure.identity import ClientSecretCredential
from dotenv import load_dotenv
import logging

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
D365_API_ENDPOINT = os.getenv("D365_API_ENDPOINT", "https://yourorg.crm.dynamics.com")

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("disable_d365_user")

def get_access_token(scope=None):
    if scope is None:
        scope = D365_API_ENDPOINT.rstrip('/') + "/.default"
    credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    token = credential.get_token(scope)
    return token.token

def disable_user_account(systemuserid: str) -> dict:
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