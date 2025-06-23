import os
import logging
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError
from datetime import datetime, UTC

def utc_timestamp():
    return datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

def upload_file_to_blob(local_path: str, sas_url: str, dest_blob_path: str) -> bool:
    """
    Upload a file to Azure Blob Storage using SAS URL.
    
    Args:
        local_path: Local path to the file to upload.
        sas_url: SAS URL for the Azure Blob Storage container.
        dest_blob_path: Destination path in the blob storage (e.g., 'filename.csv').
    
    Returns:
        bool: True if upload succeeded, False otherwise.
    """
    logger = logging.getLogger(__name__)
    if not os.path.exists(local_path):
        logger.error(f"File not found: {local_path}")
        return False
    
    try:
        # Initialize BlobServiceClient with SAS URL
        blob_service_client = BlobServiceClient(account_url=sas_url)
        container_client = blob_service_client.get_container_client("accessreview")
        
        # Construct blob name (dest_blob_path is just the filename, e.g., 'analyze.json')
        blob_name = dest_blob_path
        
        logger.info(f"Constructed blob URL: {sas_url.rstrip('?')}/{blob_name}{sas_url[sas_url.index('?'):]}")
        
        # Upload file
        with open(local_path, "rb") as data:
            container_client.upload_blob(name=blob_name, data=data, overwrite=True)
        
        logger.info(f"Uploaded {local_path} to {sas_url.rstrip('?')}/{blob_name}")
        return True
    
    except AzureError as e:
        logger.error(f"Failed to upload {local_path} to {sas_url.rstrip('?')}/{blob_name}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error uploading {local_path}: {str(e)}")
        return False