import logging
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
import os
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '../../scripts'))
from d365_role_manager import remove_roles_from_user

from src.core.embeddings import generate_embeddings
from src.core.analysis import run_analysis
# from scripts.data_fetcher import load_data 
# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_data(data_dir):
    logger.info(f"Loading data from CSV files in {data_dir}")
    loaded_data = {}
    try:
        loaded_data["audit_logs"] = pd.read_csv(os.path.join(data_dir, "audit_logs.csv"))
        loaded_data["signin_logs"] = pd.read_csv(os.path.join(data_dir, "signin_logs.csv"))
        loaded_data["user_details"] = pd.read_csv(os.path.join(data_dir, "user_details.csv"))
        # Robustly ensure 'User ID' column exists (case-insensitive)
        cols = [c.lower() for c in loaded_data["user_details"].columns]
        if "userid" in cols:
            idx = cols.index("userid")
            real_col = loaded_data["user_details"].columns[idx]
            loaded_data["user_details"].rename(columns={real_col: "User ID"}, inplace=True)
        if "User ID" not in loaded_data["user_details"].columns:
            raise ValueError("user_details.csv must have a 'User ID' column (or 'userId')")
        loaded_data["app_roles"] = pd.read_csv(os.path.join(data_dir, "app_roles.csv"))
        loaded_data["app_role_assignments"] = pd.read_csv(os.path.join(data_dir, "app_role_assignments.csv"))
        loaded_data["conditional_access_policies"] = pd.read_csv(os.path.join(data_dir, "conditional_access_policies.csv")) if os.path.exists(os.path.join(data_dir, "conditional_access_policies.csv")) else pd.DataFrame()
        loaded_data["business_units"] = pd.read_csv(os.path.join(data_dir, "business_units.csv")) if os.path.exists(os.path.join(data_dir, "business_units.csv")) else pd.DataFrame()

        # Build group_memberships from user_details
        group_memberships_list = []
        if "user_details" in loaded_data:
            for _, row in loaded_data["user_details"].iterrows():
                user_id = row.get("User ID")
                groups = row.get("groupMemberships", "")
                if pd.notna(groups) and groups:
                    for group_name in str(groups).split(","):
                        group_name = group_name.strip()
                        if group_name:
                            group_memberships_list.append({"userId": user_id, "groupId": group_name, "groupName": group_name})
        loaded_data["group_memberships"] = pd.DataFrame(group_memberships_list)

        # Build role_matrix from app_roles
        role_matrix_data = {"role": [], "permissions": []}
        if "app_roles" in loaded_data:
            for _, row in loaded_data["app_roles"].iterrows():
                role_name = row.get("roleName", "Unknown Role")
                # For demo, just use role name as permission
                role_matrix_data["role"].append(role_name)
                role_matrix_data["permissions"].append(role_name)
        loaded_data["role_matrix"] = pd.DataFrame(role_matrix_data)

    except Exception as e:
        logger.error(f"Error loading data: {str(e)}")
        raise
    return (
        loaded_data.get("audit_logs", pd.DataFrame()),
        loaded_data.get("signin_logs", pd.DataFrame()),
        loaded_data.get("user_details", pd.DataFrame()),
        loaded_data.get("role_matrix", pd.DataFrame()),
        loaded_data.get("group_memberships", pd.DataFrame()),
        loaded_data.get("app_roles", pd.DataFrame()),
        loaded_data.get("app_role_assignments", pd.DataFrame()),
        loaded_data.get("conditional_access_policies", pd.DataFrame()),
    )

app = FastAPI()

# --- CORS Middleware ---
# This will allow your frontend at http://localhost:5173 to make requests to the backend.
origins = [
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Endpoint to serve the static analyze.json with CORS headers ---
@app.get("/api/data/analyze.json")
async def serve_analyze_json():
    file_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'analyze.json')
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="analyze.json not found")
    return FileResponse(path=file_path, media_type='application/json')

# Global variables to store loaded data and embeddings
data_store = {}
vectorstore = None

@app.get("/api/v1/fetch-data")
async def fetch_data_endpoint():
    try:
        logger.info("Fetching data using data_fetcher...")
        (audit_logs, signin_logs, user_details, role_matrix, group_memberships, 
         app_roles, app_role_assignments, conditional_access_policies, 
         business_units, user_without_entraid, user_without_license) = fetch_data()
        logger.info("Data fetched successfully")
        return {"message": "Data fetched successfully"}
    except Exception as e:
        logger.error(f"Error fetching data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching data: {str(e)}")

@app.get("/api/v1/load-data")
async def load_data_endpoint():
    try:
        global data_store
        data_store["audit_logs"], data_store["signin_logs"], data_store["user_details"], \
        data_store["role_matrix"], data_store["group_memberships"], data_store["app_roles"], \
        data_store["app_role_assignments"], data_store["conditional_access_policies"] = load_data()
        return {"message": "Data loaded successfully"}
    except Exception as e:
        logger.error(f"Error loading data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error loading data: {str(e)}")

@app.get("/api/v1/generate-embeddings")
async def generate_embeddings_endpoint():
    if not data_store:
        raise HTTPException(status_code=400, detail="Data not loaded. Please load data first.")
    try:
        global vectorstore
        vectorstore = generate_embeddings(
            data_store["audit_logs"],
            data_store["signin_logs"],
            data_store["user_details"],
            data_store["app_role_assignments"]
        )
        return {"message": "Embeddings generated successfully"}
    except Exception as e:
        logger.error(f"Error generating embeddings: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error generating embeddings: {str(e)}")

@app.get("/api/v1/analyze")
async def analyze_endpoint():
    if not data_store:
        raise HTTPException(status_code=400, detail="Data not loaded. Please load data first.")
    if vectorstore is None:
        raise HTTPException(status_code=400, detail="Embeddings not generated. Please generate embeddings first by calling /api/v1/generate-embeddings. Analysis will not run until embeddings are available.")
    try:
        results = await run_analysis(
            vectorstore,
            data_store["user_details"],
            data_store["role_matrix"],
            data_store["group_memberships"],
            data_store["app_roles"],
            data_store["app_role_assignments"],
            data_store["conditional_access_policies"],
            data_store["audit_logs"],
            data_store["signin_logs"]
        )
        return {"results": results}
    except Exception as e:
        logger.error(f"Error running analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error running analysis: {str(e)}")

class RestrictRolesRequest(BaseModel):
    userId: str
    roles: List[str]

@app.post("/api/restrict-roles")
async def restrict_roles(request: RestrictRolesRequest):
    result = remove_roles_from_user(request.userId, request.roles)
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)