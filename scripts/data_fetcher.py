import sys
import os

# Add the project root directory to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.insert(0, project_root)

import logging
import os
import sys
import json
import requests
import pandas as pd
import re
from azure.identity import ClientSecretCredential
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from fastapi import FastAPI, HTTPException, Depends
from typing import Dict, List, Optional, Tuple
from src.utils.config import setup_logging
import logging
import os
import requests
import pandas as pd
import re
import json
from azure.identity import ClientSecretCredential
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
from src.utils.config import setup_logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import time
from datetime import timedelta, datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Setup logger
logger = setup_logging()
logger = logging.getLogger("d365")

# Load environment variables
load_dotenv()

# Validate required environment variables
required_env_vars = ["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"]
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    logger.error(f"Missing required environment variables: {missing_vars}")
    raise EnvironmentError(f"Missing required environment variables: {missing_vars}")

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
D365_API_ENDPOINT = os.getenv("D365_API_ENDPOINT", "https://pcsuat1.crm4.dynamics.com")
FETCH_AUDIT_LOGS = os.getenv("FETCH_AUDIT_LOGS", "true").lower() == "true"
FETCH_SIGNIN_LOGS = os.getenv("FETCH_SIGNIN_LOGS", "true").lower() == "true"

# FastAPI app
app = FastAPI(title="Production Access Review API", version="1.0.0")

# Dependency to get access tokens
def get_access_token(scope="https://pcsuat1.crm4.dynamics.com/.default"):
    """Authenticate with Azure AD and get access token."""
    try:
        credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        token = credential.get_token(scope).token
        logger.info(f"Access token obtained for scope {scope}")
        return token
    except Exception as e:
        logger.error(f"Failed to obtain access token for {scope}: {str(e)}")
        raise

# Helper function to fetch a single page of audit logs
def fetch_page_audit_logs(url: str, headers: Dict[str, str], session: requests.Session) -> Tuple[List[Dict], Optional[str]]:
    """Helper function to fetch a single page of audit logs."""
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        json_response = response.json()
        logs = json_response.get("value", [])
        next_url = json_response.get("@odata.nextLink", None)
        return logs, next_url
    except Exception as e:
        logger.error(f"Failed to fetch audit logs page: {str(e)}")
        raise

def fetch_d365_audit_logs() -> pd.DataFrame:
    """Fast fetch of D365 audit logs with parallel processing for the last 90 days."""
    token = get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": "odata.maxpagesize=500000"
    }
    # Calculate the date 90 days ago
    date_90_days_ago = (datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/audits?$select=auditid,createdon&$top=500000&$filter=createdon ge {date_90_days_ago}"
    logger.info(f"Starting fast fetch of D365 audit logs for the last 90 days (since {date_90_days_ago})")
   
    try:
        data = []
        page_urls = [(1, url)]  # (page_number, url)
        batch_size = 50  # Fetch 50 pages at a time
        session = requests.Session()
        session.headers.update(headers)
 
        while page_urls:
            current_batch = page_urls[:batch_size]
            page_urls = page_urls[batch_size:]
 
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                future_to_page = {
                    executor.submit(fetch_page_audit_logs, page_url, headers, session): page_num
                    for page_num, page_url in current_batch
                }
                results = []
                for future in future_to_page:
                    page_num = future_to_page[future]
                    logs, next_url = future.result()
                    logger.debug(f"Retrieved {len(logs)} audit logs in page {page_num}")
                    results.append((page_num, logs, next_url))
 
            # Sort results by page number to maintain order
            results.sort(key=lambda x: x[0])
 
            # Process the results
            for page_num, logs, next_url in results:
                for log in logs:
                    data.append({
                        "auditId": log.get("auditid"),
                        "activityDateTime": log.get("createdon"),
                        "actionCode": None,
                        "initiatedByUserId": None,
                        "targetRecordId": None
                    })
                if next_url:
                    page_urls.append((page_num + 1, next_url))
                    logger.debug(f"Next page URL for page {page_num}: {next_url}")
 
            # Log progress every 10 batches
            if len(data) > 0 and (len(data) // 500000) % 10 == 0:
                logger.info(f"Progress: Fetched {len(data)} audit logs after {page_num} pages")
 
        session.close()
        df = pd.DataFrame(data)
        logger.info(f"Fetched {len(df)} D365 audit logs via Dataverse")
        df.to_csv("data/audit_logs.csv", index=False)
        logger.info("Saved audit logs to data/audit_logs.csv")
        return df
    except Exception as e:
        logger.error(f"Failed to fetch D365 audit logs: {str(e)}")
        try:
            df = pd.read_csv("data/audit_logs.csv")
            logger.info(f"Loaded {len(df)} audit logs from CSV")
            return df
        except FileNotFoundError:
            logger.warning("Fallback CSV data/audit_logs.csv not found, returning empty DataFrame")
            return pd.DataFrame(columns=["auditId", "activityDateTime", "actionCode", "initiatedByUserId",
                                        "targetRecordId"])
 
def fetch_page_signin_logs(url, headers, session):
    """Helper function to fetch a single page of sign-in logs."""
    try:
        response = session.get(url, timeout=(10, 20))
        response.raise_for_status()
        json_response = response.json()
        logs = json_response.get("value", [])
        next_url = json_response.get("@odata.nextLink", None)
        return logs, next_url
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            retry_after = int(e.response.headers.get('Retry-After', 120))
            logger.warning(f"Rate limited on URL {url}, waiting {retry_after} seconds...")
            time.sleep(retry_after)
            # Retry the request
            response = session.get(url, timeout=(10, 20))
            response.raise_for_status()
            json_response = response.json()
            logs = json_response.get("value", [])
            next_url = json_response.get("@odata.nextLink", None)
            return logs, next_url
        else:
            logger.error(f"HTTP error on URL {url}: {str(e)}")
            raise
    except Exception as e:
        logger.error(f"Failed to fetch sign-in logs page {url}: {str(e)}")
        raise
 
def fetch_signin_logs():
    """Fetch D365 sign-in logs for the last 90 days via Microsoft Graph API with optimized parallel processing."""
    token = get_access_token(scope="https://graph.microsoft.com/.default")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": "odata.maxpagesize=1000"
    }
    # Calculate the date 90 days ago
    date_90_days_ago = (datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
    # Filter for Dynamics 365 appId (Dynamics 365 collaboration with Microsoft Teams)
    dynamics_app_id = 'a8adde6c-aeb4-4fd6-9d8f-c2dfdecac60a'
    initial_url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1000&$filter=createdDateTime ge {date_90_days_ago} and appId eq '{dynamics_app_id}'"
    logger.info(f"Starting optimized fetch of Dynamics 365 sign-in logs for the last 90 days (since {date_90_days_ago})")
    logger.info("Throttling limit: 1,000 requests per 10 minutes (~1.67 requests per second)")
 
    try:
        all_data = []
        session = requests.Session()
        session.headers.update(headers)
 
        # Rate limit tracking
        request_count = 0
        burst_start = time.time()
        start_time = time.time()
        processed_records = 0
        page_num = 0
        next_urls = [initial_url]  # Start with the initial URL
        max_workers = 9  # Based on throttling limit: 1.67 req/sec * 5.5 sec/req ≈ 9 workers
        earliest_date = None
        latest_date = None
 
        while next_urls:
            # Fetch pages in parallel, respecting the throttling limit
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {
                    executor.submit(fetch_page_signin_logs, url, headers, session): url
                    for url in next_urls[:max_workers]
                }
                next_urls = next_urls[max_workers:]  # Remove processed URLs
                results = []
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        logs, next_url = future.result()
                        page_num += 1
                        logger.debug(f"Retrieved {len(logs)} sign-in logs in page {page_num}")
                        results.append((page_num, logs, next_url))
                        request_count += 1
                    except Exception as e:
                        logger.error(f"Error fetching page for URL {url}: {str(e)}")
                        raise
 
                # Process the results
                for page_num, logs, next_url in results:
                    page_data = [
                        {
                            "id": log.get("id"),
                            "userId": log.get("userId"),
                            "signInDateTime": log.get("createdDateTime"),
                            "appDisplayName": log.get("appDisplayName"),
                            "appId": log.get("appId"),
                            "locationCity": (log.get("location") or {}).get("city"),
                            "locationCountry": (log.get("location") or {}).get("countryOrRegion"),
                            "ipAddress": log.get("ipAddress"),
                            "browser": (log.get("deviceDetail") or {}).get("browser"),
                            "operatingSystem": (log.get("deviceDetail") or {}).get("operatingSystem"),
                            "statusCode": (log.get("status") or {}).get("errorCode"),
                            "statusMessage": (log.get("status") or {}).get("failureReason")
                        }
                        for log in logs
                    ]
                    # Track earliest and latest sign-in dates
                    for entry in page_data:
                        signin_time = entry.get("signInDateTime")
                        if signin_time:
                            signin_dt = datetime.strptime(signin_time, '%Y-%m-%dT%H:%M:%SZ')
                            if earliest_date is None or signin_dt < earliest_date:
                                earliest_date = signin_dt
                            if latest_date is None or signin_dt > latest_date:
                                latest_date = signin_dt
                    all_data.extend(page_data)
                    processed_records += len(page_data)
                    if next_url:
                        next_urls.append(next_url)
                        logger.debug(f"Next page URL for page {page_num}: {next_url}")
 
            # Rate limit check
            elapsed = time.time() - burst_start
            if request_count >= 950 and elapsed < 600:
                remaining_time = 600 - elapsed
                logger.info(f"Approaching rate limit, waiting {remaining_time:.0f} seconds...")
                time.sleep(remaining_time + 10)
                request_count = 0
                burst_start = time.time()
 
            # Log progress after each batch
            total_elapsed = time.time() - start_time
            burst_elapsed = time.time() - burst_start
            requests_per_min = request_count / (burst_elapsed / 60) if burst_elapsed > 0 else 0
            logger.info(
                f"Progress: {processed_records:,} records | "
                f"Pages: {page_num} | "
                f"Requests: {request_count} | "
                f"Rate: {requests_per_min:.1f} req/min | "
                f"Time: {timedelta(seconds=int(total_elapsed))}"
            )
 
            # Small delay to avoid immediate rate limiting
            time.sleep(0.5)
 
        session.close()
 
        # Log the date range of fetched logs
        if earliest_date and latest_date:
            logger.info(f"Date range of fetched sign-in logs: {earliest_date.strftime('%Y-%m-%dT%H:%M:%SZ')} to {latest_date.strftime('%Y-%m-%dT%H:%M:%SZ')}")
        else:
            logger.warning("No sign-in dates found in the fetched logs.")
 
        # Process final results
        df = pd.DataFrame(all_data)
        if not df.empty:
            df = df.drop_duplicates(subset=["id"], keep="first")
            df.to_csv("data/signin_logs.csv", index=False)
            total_time = time.time() - start_time
            logger.info(f"Fetch completed: {len(df):,} records in {timedelta(seconds=int(total_time))}")
            logger.info(f"Total requests made: {request_count}")
        return df
 
    except Exception as e:
        logger.error(f"Failed to fetch sign-in logs: {str(e)}")
        try:
            df = pd.read_csv("data/signin_logs.csv")
            logger.info(f"Loaded {len(df)} sign-in logs from CSV")
            return df
        except FileNotFoundError:
            logger.warning("Fallback CSV data/signin_logs.csv not found, returning empty DataFrame")
            return pd.DataFrame(columns=["id", "userId", "signInDateTime", "appDisplayName", "appId",
                                        "locationCity", "locationCountry", "ipAddress", "browser",
                                        "operatingSystem", "statusCode", "statusMessage"])

def fetch_entra_users():
    """Fetch all users from Entra ID via Microsoft Graph API."""
    token = get_access_token(scope="https://graph.microsoft.com/.default")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    url = "https://graph.microsoft.com/v1.0/users?$select=id,mail,userPrincipalName"
    users = []
    try:
        while url:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            json_response = response.json()
            users.extend(json_response.get("value", []))
            url = json_response.get("@odata.nextLink", None)
            logger.debug(f"Fetched {len(json_response.get('value', []))} users, next URL: {url}")
        # Create a dictionary mapping Azure AD IDs to user data
        entra_users = {user["id"]: user for user in users}
        logger.info(f"Fetched {len(entra_users)} users from Entra ID")
        return entra_users
    except Exception as e:
        logger.error(f"Failed to fetch Entra ID users: {str(e)}")
        raise


def check_d365_license(azure_ad_id, headers_graph):
    """Check if a user has a D365 license assigned via Microsoft Graph API."""
    if not azure_ad_id:
        logger.debug("No Azure AD ID provided for license check")
        return False

    # D365 license SKUs (updated with actual SKU IDs from License SKU.xlsx)
    D365_LICENSE_SKUS = {
        "Dynamics 365 Finance": "55c9eb4e-c746-45b4-b255-9ab6b19d5c62",
        "Dynamics 365 Customer Service (Trial)": "1e615a51-59db-4807-9957-aa83c3657351",
        "Dynamics 365 Sales Premium (Trial)": "6ec92958-3cc1-49db-95bd-bc6b3798df71",
        "Dynamics 365 Enterprise P1 (IW)": "338148b6-1b11-4102-afb9-f92b6cdc0f8d",
        "Dynamics 365 Sales/Field Service/Customer Service (Sandbox)": "494721b8-1f30-4315-aba6-70ca169358d9",
        "Dynamics 365 Enterprise Customer Service": "749742bf-0d37-4158-a120-33567104deeb",
        "Dynamics 365 Enterprise Sales": "1e1a282c-9c54-43a2-9310-98ef728faace",
    }

    url = f"https://graph.microsoft.com/v1.0/users/{azure_ad_id}/licenseDetails"
    try:
        response = requests.get(url, headers=headers_graph, timeout=10)
        response.raise_for_status()
        license_details = response.json().get("value", [])
        if not license_details:
            logger.debug(f"User {azure_ad_id} has no assigned licenses")
            return False
        # Log all licenses for debugging
        for license in license_details:
            sku_id = license.get("skuId")
            sku_part_number = license.get("skuPartNumber", "Unknown")
            logger.debug(f"User {azure_ad_id} license: skuId={sku_id}, skuPartNumber={sku_part_number}")
            if sku_id in D365_LICENSE_SKUS.values():
                logger.debug(f"User {azure_ad_id} has D365 license: {sku_part_number}")
                return True
        logger.debug(f"User {azure_ad_id} does not have a D365 license")
        return False
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.warning(f"User {azure_ad_id} not found in Entra ID during license check")
            return False
        logger.error(f"Failed to check D365 license for user {azure_ad_id}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Failed to check D365 license for user {azure_ad_id}: {str(e)}")
        return False

def fetch_d365_roles():
    """Fetch D365 security roles via Dataverse API."""
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/roles?$select=roleid,name,componentstate"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        roles = response.json().get("value", [])
        data = []
        for role in roles:
            data.append({
                "roleId": role.get("roleid"),
                "roleName": role.get("name"),
                "componentState": role.get("componentstate")
            })
        df = pd.DataFrame(data)
        logger.info(f"Fetched {len(df)} D365 security roles")
        df.to_csv("data/app_roles.csv", index=False)
        logger.info("Saved security roles to data/app_roles.csv")
        return df
    except Exception as e:
        logger.error(f"Failed to fetch D365 roles: {str(e)}")
        try:
            df = pd.read_csv("data/app_roles.csv")
            logger.info(f"Loaded {len(df)} roles from CSV")
            return df
        except FileNotFoundError:
            logger.warning("Fallback CSV data/app_roles.csv not found, returning empty DataFrame")
            return pd.DataFrame(columns=["roleId", "roleName", "componentState"])

def fetch_d365_user_roles():
    """Fetch D365 user role assignments via Dataverse API."""
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/systemusers?$select=systemuserid,fullname,internalemailaddress,businessunitid&$expand=systemuserroles_association($select=roleid,createdon)"
    logger.debug(f"Fetching user role assignments from URL: {url}")
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        users = response.json().get("value", [])
        data = []
        # Fetch all role IDs and get role names separately
        role_ids = set()
        for user in users:
            for role_assignment in user.get("systemuserroles_association", []):
                role_id = role_assignment.get("roleid")
                if role_id:
                    role_ids.add(role_id)
        # Fetch role names
        role_names = {}
        if role_ids:
            role_url = f"{D365_API_ENDPOINT}/api/data/v9.2/roles?$select=roleid,name&$filter=" + " or ".join([f"roleid eq '{rid}'" for rid in role_ids])
            logger.debug(f"Fetching role names from URL: {role_url}")
            role_response = requests.get(role_url, headers=headers)
            role_response.raise_for_status()
            roles = role_response.json().get("value", [])
            role_names = {role["roleid"]: role["name"] for role in roles}
        # Process user role assignments
        for user in users:
            for role_assignment in user.get("systemuserroles_association", []):
                role_id = role_assignment.get("roleid")
                data.append({
                    "userId": user.get("systemuserid"),
                    "roleId": role_id,
                    "userName": user.get("fullname"),
                    "email": user.get("internalemailaddress"),
                    "businessUnitId": user.get("businessunitid"),
                    "roleName": role_names.get(role_id, "Unknown"),
                    "assignmentDate": role_assignment.get("createdon")
                })
        df = pd.DataFrame(data)
        if len(df) == 0:
            logger.warning("No user role assignments found in Dataverse")
        else:
            logger.info(f"Fetched {len(df)} D365 user role assignments")
            df.to_csv("data/app_role_assignments.csv", index=False)
            logger.info("Saved user role assignments to data/app_role_assignments.csv")
        return df
    except requests.exceptions.HTTPError as e:
        logger.error(f"Failed to fetch D365 user roles: {str(e)}")
        logger.error(f"Response content: {e.response.text}")
        logger.warning("User role assignments may not be available in this environment. Please confirm with the admin.")
        try:
            df = pd.read_csv("data/app_role_assignments.csv")
            logger.info(f"Loaded {len(df)} user role assignments from CSV")
            return df
        except FileNotFoundError:
            logger.warning("Fallback CSV data/app_role_assignments.csv not found, returning empty DataFrame")
            return pd.DataFrame(columns=["userId", "roleId", "userName", "email", "businessUnitId", "roleName", "assignmentDate"])
    except Exception as e:
        logger.error(f"Failed to fetch D365 user roles: {str(e)}")
        logger.warning("User role assignments may not be available in this environment. Please confirm with the admin.")
        try:
            df = pd.read_csv("data/app_role_assignments.csv")
            logger.info(f"Loaded {len(df)} user role assignments from CSV")
            return df
        except FileNotFoundError:
            logger.warning("Fallback CSV data/app_role_assignments.csv not found, returning empty DataFrame")
            return pd.DataFrame(columns=["userId", "roleId", "userName", "email", "businessUnitId", "roleName", "assignmentDate"])

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(requests.exceptions.ConnectionError),
    before_sleep=lambda retry_state: logger.debug(f"Retrying Dataverse API call (attempt {retry_state.attempt_number}) due to connection error...")
)
def fetch_user_details():
    """Fetch user details with manager mapping via Dataverse and Graph APIs, filtering for Entra ID users with D365 licenses."""
    token_d365 = get_access_token()
    token_graph = get_access_token(scope="https://graph.microsoft.com/.default")
    headers_d365 = {"Authorization": f"Bearer {token_d365}", "Accept": "application/json"}
    headers_graph = {"Authorization": f"Bearer {token_graph}", "Accept": "application/json"}
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/systemusers?$select=systemuserid,fullname,internalemailaddress,businessunitid,parentsystemuserid,azureactivedirectoryobjectid,isdisabled"
    logger.debug(f"Fetching user details from URL: {url}")

    try:
        # Step 1: Fetch all users from Entra ID
        entra_users = fetch_entra_users()
        entra_user_ids = set(entra_users.keys())
        logger.info(f"Found {len(entra_user_ids)} users in Entra ID")

        # Step 2: Fetch D365 users
        response = requests.get(url, headers=headers_d365, timeout=30)
        response.raise_for_status()
        users = response.json().get("value", [])
        logger.info(f"Fetched {len(users)} user records from D365")

        data = []  # For users who pass all filters
        no_entra_id_data = []  # For users missing Entra ID
        no_license_data = []  # For users missing D365 license
        users_without_entra_id = 0
        users_without_license = 0

        # Cache systemuser IDs to emails for manager lookup
        user_id_to_email = {}
        for user in users:
            email = user.get("internalemailaddress", "")
            # Fix malformed email by removing any prefix that looks like an Azure AD object ID
            if email and "@" in email:
                email_parts = email.split("@")
                if len(email_parts) == 2:
                    prefix = email_parts[0]
                    domain = email_parts[1]
                    guid_pattern = r'^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}'
                    if re.match(guid_pattern, prefix):
                        actual_email_prefix = re.sub(guid_pattern, "", prefix)
                        email = f"{actual_email_prefix}@{domain}".lstrip()
                        logger.debug(f"Fixed malformed email for user {user.get('systemuserid')}: {user.get('internalemailaddress')} -> {email}")
            user_id_to_email[user.get("systemuserid")] = email

        # Step 3: Filter users based on Entra ID presence and D365 license
        for user in users:
            azure_ad_id = user.get("azureactivedirectoryobjectid", "")
            user_entry = {
                "userId": user.get("systemuserid"),
                "userName": user.get("fullname"),
                "email": user_id_to_email.get(user.get("systemuserid"), ""),
                "businessUnitId": user.get("businessunitid"),
                "azureAdObjectId": azure_ad_id,
                "isDisabled": user.get("isdisabled", False),
                "parentSystemUserId": user.get("parentsystemuserid", "")
            }

            # Filter 1: Check if the user exists in Entra ID
            if not azure_ad_id or azure_ad_id not in entra_user_ids:
                logger.debug(f"User {user.get('systemuserid')} (Azure AD ID: {azure_ad_id}) not found in Entra ID, skipping")
                users_without_entra_id += 1
                no_entra_id_data.append(user_entry)
                continue

            # Filter 2: Check if the user has a D365 license
            has_d365_license = check_d365_license(azure_ad_id, headers_graph)
            if not has_d365_license:
                logger.debug(f"User {user.get('systemuserid')} (Azure AD ID: {azure_ad_id}) does not have a D365 license, skipping")
                users_without_license += 1
                no_license_data.append(user_entry)
                continue

            # If the user passes both filters, proceed with fetching additional details
            email = user_id_to_email.get(user.get("systemuserid"), "")
            logger.debug(f"Processing user {user.get('systemuserid')} with email {email}")
            groups = get_user_groups(azure_ad_id, email, headers_graph, headers_d365)

            # Try to get manager from Dataverse
            manager_id = user.get("parentsystemuserid")
            if manager_id:
                logger.debug(f"Found managerId {manager_id} for user {user.get('systemuserid')}")
                manager_email = get_manager_email(manager_id, headers_d365, user_id_to_email)
            else:
                logger.debug(f"No managerId found in Dataverse for user {user.get('systemuserid')}, falling back to Graph API")
                manager_id, manager_email = get_manager_from_graph(azure_ad_id, email, headers_graph, user_id_to_email)

            if not manager_id and not manager_email:
                logger.warning(f"No manager found for Azure AD ID {azure_ad_id} via Dataverse or Graph API")

            data.append({
                "userId": user.get("systemuserid"),
                "userName": user.get("fullname"),
                "email": email,
                "groupMemberships": groups,
                "businessUnitId": user.get("businessunitid"),
                "managerId": manager_id,
                "managerEmail": manager_email,
                "azureAdObjectId": azure_ad_id
            })

        # Step 4: Log filtering statistics
        logger.info(f"Filtered out {users_without_entra_id} D365 users not present in Entra ID")
        logger.info(f"Filtered out {users_without_license} D365 users without a D365 license")
        logger.info(f"Final user count after filtering: {len(data)}")

        # Step 5: Save the filtered user details and the excluded users
        # Save users who passed all filters
        df = pd.DataFrame(data)
        if len(df) == 0:
            logger.warning("No users found after applying Entra ID and license filters")
        else:
            logger.info(f"Fetched {len(df)} user details after filtering")
            df.to_csv("data/user_details.csv", index=False)
            logger.info("Saved filtered user details to data/user_details.csv")

        # Save users without Entra ID
        df_no_entra_id = pd.DataFrame(no_entra_id_data)
        if len(df_no_entra_id) > 0:
            df_no_entra_id.to_csv("data/users_without_entra_id.csv", index=False)
            logger.info(f"Saved {len(df_no_entra_id)} users without Entra ID to data/users_without_entra_id.csv")

        # Save users without D365 license
        df_no_license = pd.DataFrame(no_license_data)
        if len(df_no_license) > 0:
            df_no_license.to_csv("data/users_without_d365_license.csv", index=False)
            logger.info(f"Saved {len(df_no_license)} users without D365 license to data/users_without_d365_license.csv")

        return df, df_no_entra_id, df_no_license

    except Exception as e:
        logger.error(f"Failed to fetch user details: {str(e)}")
        try:
            df = pd.read_csv("data/user_details.csv")
            df_no_entra_id = pd.read_csv("data/users_without_entra_id.csv") if os.path.exists("data/users_without_entra_id.csv") else pd.DataFrame()
            df_no_license = pd.read_csv("data/users_without_d365_license.csv") if os.path.exists("data/users_without_d365_license.csv") else pd.DataFrame()
            logger.info(f"Loaded {len(df)} user details from CSV")
            return df, df_no_entra_id, df_no_license
        except FileNotFoundError:
            logger.warning("Fallback CSV data/user_details.csv not found, returning empty DataFrames")
            return (pd.DataFrame(columns=["userId", "userName", "email", "groupMemberships", "businessUnitId", 
                                         "managerId", "managerEmail", "azureAdObjectId"]),
                    pd.DataFrame(),
                    pd.DataFrame())
def get_user_groups(azure_ad_id, email, headers_graph, headers_d365):
    """Fetch user group memberships via Graph API."""
    if not azure_ad_id and not email:
        logger.debug(f"No Azure AD ID or email provided for group lookup")
        return None

    # Email validation regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    # Try using azureactivedirectoryobjectid first
    if azure_ad_id:
        url = f"https://graph.microsoft.com/v1.0/users/{azure_ad_id}/memberOf"
        logger.debug(f"Fetching groups for Azure AD ID {azure_ad_id} from URL: {url}")
        try:
            response = requests.get(url, headers=headers_graph)
            response.raise_for_status()
            groups = response.json().get("value", [])
            group_names = ",".join([g.get("displayName") for g in groups]) if groups else None
            logger.debug(f"Groups for Azure AD ID {azure_ad_id}: {group_names}")
            return group_names
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Azure AD ID {azure_ad_id} not found, falling back to email lookup")
            else:
                logger.error(f"Failed to fetch groups for user {azure_ad_id}: {str(e)}")
                return None

    # Fallback to email lookup if Azure AD ID fails or isn't provided
    if email and re.match(email_pattern, email):
        url_by_email = f"https://graph.microsoft.com/v1.0/users?$filter=userPrincipalName eq '{email}'&$select=id"
        logger.debug(f"Fetching user ID by email {email} from URL: {url_by_email}")
        try:
            response = requests.get(url_by_email, headers=headers_graph)
            response.raise_for_status()
            users = response.json().get("value", [])
            if users:
                azure_ad_id = users[0].get("id")
                url_groups = f"https://graph.microsoft.com/v1.0/users/{azure_ad_id}/memberOf"
                logger.debug(f"Fetching groups for Azure AD ID {azure_ad_id} from URL: {url_groups}")
                response = requests.get(url_groups, headers=headers_graph)
                response.raise_for_status()
                groups = response.json().get("value", [])
                group_names = ",".join([g.get("displayName") for g in groups]) if groups else None
                logger.debug(f"Groups for email {email}: {group_names}")
                return group_names
            else:
                logger.debug(f"No user found for email {email}")
                return None
        except Exception as e:
            logger.error(f"Failed to fetch groups by email {email}: {str(e)}")
            return None
    else:
        logger.debug(f"Invalid or missing email for group lookup: {email}")
        return None

def get_manager_email(manager_id, headers, user_id_to_email):
    """Fetch manager email via Dataverse API."""
    if not manager_id:
        return None
    # Check if we already have the email from the initial fetch
    manager_email = user_id_to_email.get(manager_id)
    if manager_email:
        logger.debug(f"Found manager email {manager_email} for managerId {manager_id} in cache")
        return manager_email
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/systemusers({manager_id})?$select=internalemailaddress"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        manager_email = response.json().get("internalemailaddress")
        # Fix malformed email if necessary
        if manager_email and "@" in manager_email:
            email_parts = manager_email.split("@")
            if len(email_parts) == 2:
                prefix = email_parts[0]
                domain = email_parts[1]
                guid_pattern = r'^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}'
                if re.match(guid_pattern, prefix):
                    actual_email_prefix = re.sub(guid_pattern, "", prefix)
                    manager_email = f"{actual_email_prefix}@{domain}".lstrip()
                    logger.debug(f"Fixed malformed manager email for managerId {manager_id}: {manager_email}")
        logger.debug(f"Fetched manager email {manager_email} for managerId {manager_id}")
        return manager_email
    except Exception as e:
        logger.error(f"Failed to fetch manager email for {manager_id}: {str(e)}")
        return None

def get_manager_from_graph(azure_ad_id, email, headers_graph, user_id_to_email):
    """Fetch manager details via Microsoft Graph API as a fallback."""
    if not azure_ad_id and not email:
        logger.debug("No Azure AD ID or email provided for manager lookup")
        return None, None

    # Email validation regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    # Try using azureactivedirectoryobjectid first
    if azure_ad_id:
        # First, verify the user exists
        user_url = f"https://graph.microsoft.com/v1.0/users/{azure_ad_id}?$select=id,mail,userPrincipalName"
        logger.debug(f"Verifying user existence for Azure AD ID {azure_ad_id} from URL: {user_url}")
        try:
            user_response = requests.get(user_url, headers=headers_graph)
            user_response.raise_for_status()
            user_data = user_response.json()
            email = user_data.get("mail") or user_data.get("userPrincipalName")
            logger.debug(f"User {azure_ad_id} found: email={email}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"Failed to verify user {azure_ad_id}: {str(e)}")
            if e.response.status_code == 404:
                logger.warning(f"Azure AD ID {azure_ad_id} not found")
            return None, None

        # Now fetch the manager
        manager_url = f"https://graph.microsoft.com/v1.0/users/{azure_ad_id}/manager"
        logger.debug(f"Fetching manager for Azure AD ID {azure_ad_id} from URL: {manager_url}")
        try:
            response = requests.get(manager_url, headers=headers_graph)
            response.raise_for_status()
            manager = response.json()
            manager_azure_id = manager.get("id")
            manager_email = manager.get("mail") or manager.get("userPrincipalName")
            # Map Azure AD ID back to systemuserid
            manager_id = None
            for user_id, user_email in user_id_to_email.items():
                if user_email == manager_email:
                    manager_id = user_id
                    break
            logger.debug(f"Found manager for Azure AD ID {azure_ad_id}: managerId={manager_id}, email={manager_email}")
            return manager_id, manager_email
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"No manager found for Azure AD ID {azure_ad_id}")
            else:
                logger.error(f"Failed to fetch manager for user {azure_ad_id}: {str(e)}")
            return None, None

    # Fallback to email lookup
    if email and re.match(email_pattern, email):
        url_by_email = f"https://graph.microsoft.com/v1.0/users?$filter=userPrincipalName eq '{email}'&$select=id"
        logger.debug(f"Fetching user ID by email {email} from URL: {url_by_email}")
        try:
            response = requests.get(url_by_email, headers=headers_graph)
            response.raise_for_status()
            users = response.json().get("value", [])
            if users:
                azure_ad_id = users[0].get("id")
                logger.debug(f"Found user by email {email}: Azure AD ID {azure_ad_id}")
                url_manager = f"https://graph.microsoft.com/v1.0/users/{azure_ad_id}/manager"
                logger.debug(f"Fetching manager for Azure AD ID {azure_ad_id} from URL: {url_manager}")
                response = requests.get(url_manager, headers=headers_graph)
                response.raise_for_status()
                manager = response.json()
                manager_azure_id = manager.get("id")
                manager_email = manager.get("mail") or manager.get("userPrincipalName")
                # Map Azure AD ID back to systemuserid
                manager_id = None
                for user_id, user_email in user_id_to_email.items():
                    if user_email == manager_email:
                        manager_id = user_id
                        break
                logger.debug(f"Found manager for email {email}: managerId={manager_id}, email={manager_email}")
                return manager_id, manager_email
            else:
                logger.debug(f"No user found for email {email} in Graph API")
                return None, None
        except Exception as e:
            logger.error(f"Failed to fetch manager by email {email} in Graph API: {str(e)}")
            return None, None
    else:
        logger.debug(f"Invalid or missing email for manager lookup: {email}")
        return None, None


def fetch_conditional_policies():
    """Fetch conditional access policies via Graph API."""
    token = get_access_token(scope="https://graph.microsoft.com/.default")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        policies = response.json().get("value", [])
        data = []
        for policy in policies:
            conditions = policy.get("conditions", {})
            applications = conditions.get("applications", {})
            data.append({
                "policyId": policy.get("id"),
                "policyName": policy.get("displayName"),
                "conditions": json.dumps(conditions),
                "grantControls": json.dumps(policy.get("grantControls", {})),
                "includedApplications": json.dumps(applications.get("includeApplications", [])),
                "excludedApplications": json.dumps(applications.get("excludeApplications", []))
            })
        df = pd.DataFrame(data)
        logger.info(f"Fetched {len(df)} conditional access policies")
        df.to_csv("data/conditional_access_policies.csv", index=False)
        logger.info("Saved conditional access policies to data/conditional_access_policies.csv")
        return df
    except Exception as e:
        logger.error(f"Failed to fetch conditional access policies: {str(e)}")
        try:
            df = pd.read_csv("data/conditional_access_policies.csv")
            logger.info(f"Loaded {len(df)} conditional access policies from CSV")
            return df
        except FileNotFoundError:
            logger.warning("Fallback CSV data/conditional_access_policies.csv not found, returning empty DataFrame")
            return pd.DataFrame(columns=["policyId", "policyName", "conditions", "grantControls", 
                                        "includedApplications", "excludedApplications"])

def fetch_business_units():
    """Fetch business unit hierarchy via Dataverse API."""
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/businessunits?$select=businessunitid,name,parentbusinessunitid"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        units = response.json().get("value", [])
        data = []
        for unit in units:
            parent_id = unit.get("parentbusinessunitid")
            parent_name = get_parent_name(parent_id, headers) if parent_id else None
            data.append({
                "businessUnitId": unit.get("businessunitid"),
                "businessUnitName": unit.get("name"),
                "parentUnitId": parent_id,
                "parentUnitName": parent_name
            })
        df = pd.DataFrame(data)
        logger.info(f"Fetched {len(df)} business units")
        df.to_csv("data/business_units.csv", index=False)
        logger.info("Saved business units to data/business_units.csv")
        return df
    except Exception as e:
        logger.error(f"Failed to fetch business units: {str(e)}")
        try:
            df = pd.read_csv("data/business_units.csv")
            logger.info(f"Loaded {len(df)} business units from CSV")
            return df
        except FileNotFoundError:
            logger.warning("Fallback CSV data/business_units.csv not found, returning empty DataFrame")
            return pd.DataFrame(columns=["businessUnitId", "businessUnitName", "parentUnitId", "parentUnitName"])

def get_parent_name(parent_id, headers):
    """Fetch parent business unit name."""
    if not parent_id:
        return None
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/businessunits({parent_id})?$select=name"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get("name")
    except Exception as e:
        logger.error(f"Failed to fetch parent name for {parent_id}: {str(e)}")
        return None

def load_data():
    """
    Load D365 data via APIs and save to CSVs for access review.
    Returns: audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, app_role_assignments,
             conditional_access_policies, business_units, user_without_entraid, user_without_license
    """
    logger.info("Loading D365 data")
    try:
        # API-based data
        audit_logs = fetch_d365_audit_logs()
        signin_logs = fetch_signin_logs()
        user_details, user_without_entraid, user_without_license = fetch_user_details()
        role_matrix = fetch_d365_roles()
        app_role_assignments = fetch_d365_user_roles()
        conditional_access_policies = fetch_conditional_policies()
        business_units = fetch_business_units()

        # Extract group_memberships from user_details (if needed, otherwise return empty DataFrame)
        group_memberships = pd.DataFrame(user_details[["userId", "groupMemberships"]]) if "groupMemberships" in user_details.columns else pd.DataFrame()

        # app_roles is the same as role_matrix
        app_roles = role_matrix

        logger.info("D365 data loaded successfully")
        return (audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, app_role_assignments, 
                conditional_access_policies, business_units, user_without_entraid, user_without_license)
    except Exception as e:
        logger.error(f"Failed to load D365 data: {str(e)}")
        raise

def fetch_and_save_data():
    """
    Fetch and save D365 data, returning a dict with a 'success' key for programmatic use.
    """
    try:
        (audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, app_role_assignments, 
         conditional_access_policies, business_units, user_without_entraid, user_without_license) = load_data()
        return {
            "success": True,
            "message": "Data fetched and saved successfully",
            "data": {
                "audit_logs_count": len(audit_logs),
                "signin_logs_count": len(signin_logs),
                "user_details_count": len(user_details),
                "role_matrix_count": len(role_matrix),
                "group_memberships_count": len(group_memberships),
                "app_roles_count": len(app_roles),
                "app_role_assignments_count": len(app_role_assignments),
                "conditional_access_policies_count": len(conditional_access_policies),
                "business_units_count": len(business_units),
                "user_without_entraid_count": len(user_without_entraid),
                "user_without_license_count": len(user_without_license)
            }
        }
    except Exception as e:
        logger.error(f"Error in fetch_and_save_data: {str(e)}")
        return {
            "success": False,
            "message": f"Error fetching data: {str(e)}",
            "data": {}
        }

# FastAPI Endpoints
@app.post("/api/v1/fetch-data")
async def fetch_data_endpoint():
    """Endpoint to fetch and save D365 data."""
    try:
        (audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, app_role_assignments, 
         conditional_access_policies, business_units, user_without_entraid, user_without_license) = load_data()
        return {
            "status": "success",
            "message": "Data fetched and saved successfully",
            "data": {
                "audit_logs_count": len(audit_logs),
                "signin_logs_count": len(signin_logs),
                "user_details_count": len(user_details),
                "role_matrix_count": len(role_matrix),
                "group_memberships_count": len(group_memberships),
                "app_roles_count": len(app_roles),
                "app_role_assignments_count": len(app_role_assignments),
                "conditional_access_policies_count": len(conditional_access_policies),
                "business_units_count": len(business_units),
                "user_without_entraid_count": len(user_without_entraid),
                "user_without_license_count": len(user_without_license)
            }
        }
    except Exception as e:
        logger.error(f"Error in fetch-data endpoint: {str(e)}")
        return {
            "status": "error",
            "message": f"Error fetching data: {str(e)}",
            "data": {}
        }

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "message": "API is running"}

# Main script for initial data fetch
if __name__ == "__main__":
    try:
        (audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, app_role_assignments, 
         conditional_access_policies, business_units, user_without_entraid, user_without_license) = load_data()
        print("Audit Logs:")
        print(audit_logs.head().to_string())
        print("Sign-in Logs:")
        print(signin_logs.head().to_string())
        print("User Details:")
        print(user_details.head().to_string())
        print("Role Matrix:")
        print(role_matrix.head().to_string())
        print("Group Memberships:")
        print(group_memberships.head().to_string())
        print("App Roles:")
        print(app_roles.head().to_string())
        print("App Role Assignments:")
        print(app_role_assignments.head().to_string())
        print("Conditional Access Policies:")
        print(conditional_access_policies.head().to_string())
        print("Business Units:")
        print(business_units.head().to_string())
        print("Users without Entra ID:")
        print(user_without_entraid.head().to_string())
        print("Users without D365 License:")
        print(user_without_license.head().to_string())
    except Exception as e:
        logger.error(f"Initial data fetch failed: {str(e)}")
        sys.exit(1)