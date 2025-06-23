from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../scripts'))
from d365_role_manager import remove_roles_from_user
import requests
from azure.identity import ClientSecretCredential
from dotenv import load_dotenv
import logging

router = APIRouter()

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
D365_API_ENDPOINT = os.getenv("D365_API_ENDPOINT", "https://yourorg.crm.dynamics.com")

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("disable_d365_user_api")

class RestrictRolesRequest(BaseModel):
    userId: str
    roles: List[str]

class DisableUserRequest(BaseModel):
    userId: str

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

@router.post("/restrict-roles")
async def restrict_roles(request: RestrictRolesRequest):
    result = remove_roles_from_user(request.userId, request.roles)
    return result

@router.post("/disable-user")
async def disable_user(request: DisableUserRequest):
    result = disable_user_account(request.userId)
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to disable user."))
    return result
