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
D365_API_ENDPOINT = os.getenv("D365_API_ENDPOINT")

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("fetch_d365_role_privileges")

def get_access_token(scope=None):
    if scope is None:
        scope = D365_API_ENDPOINT.rstrip('/') + "/.default"
    credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    token = credential.get_token(scope)
    return token.token

def fetch_all(endpoint, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    results = []
    url = endpoint
    while url:
        logger.info(f"Fetching: {url}")
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error(f"Failed to fetch: {resp.status_code} {resp.text}")
            break
        data = resp.json()
        results.extend(data.get('value', []))
        url = data.get('@odata.nextLink')
    return results

def main():
    token = get_access_token()
    # Fetch all roleprivileges
    roleprivs = fetch_all(f"{D365_API_ENDPOINT}/api/data/v9.2/roleprivileges?$select=roleid,privilegeid", token)
    if not roleprivs:
        print("No roleprivileges found or failed to fetch.")
        return
    # Fetch all privileges
    privs = fetch_all(f"{D365_API_ENDPOINT}/api/data/v9.2/privileges?$select=privilegeid,name,privilegetype", token)
    if not privs:
        print("No privileges found or failed to fetch.")
        return
    # Load roles
    roles_df = pd.read_csv("backend/data/d365_roles.csv")
    roles_dict = dict(zip(roles_df['roleid'], roles_df['name']))
    privs_dict = {p['privilegeid']: p for p in privs}
    all_rows = []
    for rp in roleprivs:
        roleid = rp['roleid']
        privilegeid = rp['privilegeid']
        rolename = roles_dict.get(roleid, '')
        priv = privs_dict.get(privilegeid, {})
        all_rows.append({
            'roleid': roleid,
            'rolename': rolename,
            'privilegeid': privilegeid,
            'privilegename': priv.get('name', ''),
            'privilegetype': priv.get('privilegetype', '')
        })
    if not all_rows:
        print("No role-privilege mappings found.")
        return
    df = pd.DataFrame(all_rows)
    df.to_csv("backend/data/d365_role_privileges.csv", index=False)
    print("Saved role-privilege mapping to backend/data/d365_role_privileges.csv")

if __name__ == "__main__":
    main() 