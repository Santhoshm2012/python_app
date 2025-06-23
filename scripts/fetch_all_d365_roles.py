import os
import requests
import pandas as pd
from azure.identity import ClientSecretCredential
from dotenv import load_dotenv
import logging

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
D365_API_ENDPOINT = os.getenv("D365_API_ENDPOINT", "https://yourorg.crm.dynamics.com")

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("fetch_all_d365_roles")

def get_access_token(scope=None):
    if scope is None:
        scope = D365_API_ENDPOINT.rstrip('/') + "/.default"
    credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    token = credential.get_token(scope)
    return token.token

def fetch_all_roles(token):
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/roles?$select=roleid,name,description"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    logger.info(f"Fetching all D365 roles from {url}")
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error(f"Failed to fetch roles: {resp.status_code} {resp.text}")
        return []
    data = resp.json()
    roles = []
    for item in data.get('value', []):
        roles.append({
            'roleid': item.get('roleid'),
            'name': item.get('name'),
            'description': item.get('description', '')
        })
    return roles

def main():
    token = get_access_token()
    roles = fetch_all_roles(token)
    if not roles:
        print("No roles found or failed to fetch roles.")
        return
    print(f"Fetched {len(roles)} roles:")
    for r in roles:
        print(f"- {r['name']} (roleid: {r['roleid']})")
    # Save to CSV
    df = pd.DataFrame(roles)
    df.to_csv("backend/data/d365_roles.csv", index=False)
    print("Saved roles to backend/data/d365_roles.csv")

if __name__ == "__main__":
    main() 