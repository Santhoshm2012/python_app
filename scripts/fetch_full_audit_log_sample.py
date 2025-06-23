import os
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
import requests
import logging
from concurrent.futures import ThreadPoolExecutor
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("audit_log_sample")

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
D365_API_ENDPOINT = os.getenv("D365_API_ENDPOINT", "https://pcsuat1.crm4.dynamics.com")

def get_access_token(scope="https://pcsuat1.crm4.dynamics.com/.default"):
    try:
        credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        token = credential.get_token(scope).token
        logger.info("Access token obtained for scope %s", scope)
        return token
    except Exception as e:
        logger.error("Failed to obtain access token: %s", str(e))
        raise

def fetch_page_audit_logs(url: str, headers: dict, session: requests.Session):
    try:
        response = session.get(url, timeout=60)
        response.raise_for_status()
        json_response = response.json()
        logs = json_response.get("value", [])
        next_url = json_response.get("@odata.nextLink", None)
        return logs, next_url
    except Exception as e:
        logger.error(f"Failed to fetch audit logs page: {str(e)}")
        raise

def fetch_full_audit_log_sample():
    token = get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": "odata.maxpagesize=5000"
    }
    date_from = (datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f"{D365_API_ENDPOINT}/api/data/v9.2/audits?$top=5000&$filter=createdon ge {date_from}"
    logger.info(f"Starting fast fetch of D365 audit logs for the last 90 days (since {date_from})")

    try:
        data = []
        page_urls = [(1, url)]  # (page_number, url)
        batch_size = 10  # Fetch 10 pages at a time
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
                    logger.info(f"Retrieved {len(logs)} audit logs in page {page_num}")
                    results.append((page_num, logs, next_url))

            # Sort results by page number to maintain order
            results.sort(key=lambda x: x[0])

            # Process the results
            for page_num, logs, next_url in results:
                data.extend(logs)
                if next_url:
                    page_urls.append((page_num + 1, next_url))
                    logger.info(f"Next page URL for page {page_num}: {next_url}")
                else:
                    logger.info(f"No more pages after page {page_num}.")

            # Log progress every 10 batches
            if len(data) > 0 and (len(data) // 5000) % 10 == 0:
                logger.info(f"Progress: Fetched {len(data)} audit logs after {page_num} pages")

        session.close()
        df = pd.DataFrame(data)
        logger.info(f"Fetched {len(df)} D365 audit logs via Dataverse")
        df.to_csv("data/audit_logs_full_sample.csv", index=False)
        logger.info("Saved audit logs to data/audit_logs_full_sample.csv")
        logger.info(f"Columns: {df.columns.tolist()}")
        logger.info(f"Sample rows:\n{df.head(3).to_string()}")
        return df
    except Exception as e:
        logger.error(f"Failed to fetch D365 audit logs: {str(e)}")
        try:
            df = pd.read_csv("data/audit_logs_full_sample.csv")
            logger.info(f"Loaded {len(df)} audit logs from CSV")
            return df
        except FileNotFoundError:
            logger.warning("Fallback CSV data/audit_logs_full_sample.csv not found, returning empty DataFrame")
            return pd.DataFrame()

if __name__ == "__main__":
    fetch_full_audit_log_sample()