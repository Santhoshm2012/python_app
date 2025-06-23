import logging
import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse
import pandas as pd
import os
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from src.core.embeddings import generate_embeddings
from src.core.analysis import run_analysis, map_user_ids_to_names, compute_signin_trends_and_locations
from scripts.data_fetcher import fetch_and_save_data
import sys
import json
from azure.storage.blob import BlobServiceClient
import glob
from datetime import datetime
from src.core.data_loader import load_data as local_load_data
from src.core.embeddings import generate_embeddings as local_generate_embeddings
from src.core.analysis import run_analysis as local_run_analysis
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import os
from src.api.v1 import router as v1_router
load_dotenv()
BLOB_SAS_URL = os.getenv("AZURE_BLOB_SAS_URL")
blob_service_client = BlobServiceClient(account_url=BLOB_SAS_URL)
container_client = blob_service_client.get_container_client("accessreview")

# Existing imports and setup...

# Custom middleware to add CORS headers to StaticFiles responses
class StaticFilesCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/v1/data"):
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
            response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

# Add the custom middleware before CORSMiddleware
# Initialize FastAPI app with metadata for Swagger UI
app = FastAPI(
    title="Production Access Review API",
    description="API for fetching, loading, and analyzing user activity and access data from Dynamics 365 and Entra ID.",
    version="1.0.0",
    docs_url="/docs", 
    redoc_url="/redoc"
)

# Mount static files directory with CORS support
app.mount("/api/v1/data", StaticFiles(directory="data"), name="data")

app.add_middleware(StaticFilesCORSMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# # Initialize FastAPI app with metadata for Swagger UI
# app = FastAPI(
#     title="Production Access Review API",
#     description="API for fetching, loading, and analyzing user activity and access data from Dynamics 365 and Entra ID.",
#     version="1.0.0",
#     docs_url="/docs",
#     redoc_url="/redoc"
# )


# Global variables to store loaded data and embeddings, and analysis results status
data_store = {}
vectorstore = None
analysis_results_available = False

# Pydantic models for request/response validation
class DataLoadResponse(BaseModel):
    status: str
    message: str
    data: Dict[str, Any]

class AnalysisResponse(BaseModel):
    status: str
    results: Dict[str, Any]

class UsersResponse(BaseModel):
    status: str
    users: List[Dict[str, Any]]
    total: int

# Function to load data from CSVs (Paramount logic)
def load_data_from_csv() -> tuple:
    """
    Load CSV files from data/ directory and create a role-permission matrix.
    Returns: audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, 
             app_role_assignments, conditional_access_policies, business_units, user_without_entraid, 
             user_without_license DataFrames.
    """
    logger.info("Loading data from CSV files")
    data_dir = "data"
    
    loaded_data = {}
    data_loaded_success = True

    try:
        # Load available CSV files
        loaded_data["audit_logs"] = pd.read_csv(os.path.join(data_dir, "audit_logs.csv"))
        logger.info(f"Loaded audit_logs with {loaded_data["audit_logs"].shape[0]} rows")

        loaded_data["signin_logs"] = pd.read_csv(os.path.join(data_dir, "signin_logs.csv"))
        logger.info(f"Loaded signin_logs with {loaded_data["signin_logs"].shape[0]} rows")

        loaded_data["user_details"] = pd.read_csv(os.path.join(data_dir, "user_details.csv"))
        logger.info(f"Loaded user_details with {loaded_data["user_details"].shape[0]} rows")

        loaded_data["app_roles"] = pd.read_csv(os.path.join(data_dir, "app_roles.csv"))
        logger.info(f"Loaded app_roles with {loaded_data["app_roles"].shape[0]} rows")

        loaded_data["app_role_assignments"] = pd.read_csv(os.path.join(data_dir, "app_role_assignments.csv"))
        logger.info(f"Loaded app_role_assignments with {loaded_data["app_role_assignments"].shape[0]} rows")

        # Load additional datasets (handle missing files gracefully)
        try:
            loaded_data["conditional_access_policies"] = pd.read_csv(os.path.join(data_dir, "conditional_access_policies.csv"))
        except FileNotFoundError:
            logger.warning("conditional_access_policies.csv not found; proceeding without it.")
            loaded_data["conditional_access_policies"] = pd.DataFrame()

        try:
            loaded_data["business_units"] = pd.read_csv(os.path.join(data_dir, "business_units.csv"))
        except FileNotFoundError:
            logger.warning("business_units.csv not found; proceeding without it.")
            loaded_data["business_units"] = pd.DataFrame()

        try:
            loaded_data["user_without_entraid"] = pd.read_csv(os.path.join(data_dir, "users_without_entra_id.csv"))
        except FileNotFoundError:
            logger.warning("users_without_entra_id.csv not found; proceeding without it.")
            loaded_data["user_without_entraid"] = pd.DataFrame()

        try:
            loaded_data["user_without_license"] = pd.read_csv(os.path.join(data_dir, "users_without_d365_license.csv"))
        except FileNotFoundError:
            logger.warning("users_without_d365_license.csv not found; proceeding without it.")
            loaded_data["user_without_license"] = pd.DataFrame()

        # Basic preprocessing with intelligent handling of missing values
        for df_key in ["audit_logs", "signin_logs", "user_details"]:
            if df_key in loaded_data:
                if df_key == "audit_logs":
                    loaded_data[df_key].fillna({"initiatedByUserId": "unknown", "targetRecordId": "unknown"}, inplace=True)
                elif df_key == "signin_logs":
                    loaded_data[df_key].fillna({
                        "locationCity": "Unknown",
                        "locationCountry": "Unknown",
                        "ipAddress": "Unknown",
                        "browser": "Unknown",
                        "operatingSystem": "Unknown"
                    }, inplace=True)
                elif df_key == "user_details":
                    loaded_data[df_key] = loaded_data[df_key].rename(columns={"userId": "User ID", "userName": "UserName"})
                    loaded_data[df_key].fillna({
                        "groupMemberships": "",
                        "businessUnitId": "Unknown",
                        "managerId": "Unknown",
                        "managerEmail": "Unknown"
                    }, inplace=True)
        
        # Extract group memberships from user_details if available
        if "user_details" in loaded_data:
            group_memberships_list = []
            for _, row in loaded_data["user_details"].iterrows():
                user_id = row["User ID"]
                groups = row["groupMemberships"].split(",") if row["groupMemberships"] else []
                for group_name in groups:
                    group_name = group_name.strip()
                    group_memberships_list.append({"userId": user_id, "groupId": group_name, "groupName": group_name})
            loaded_data["group_memberships"] = pd.DataFrame(group_memberships_list)
            logger.info(f"Created group_memberships with {loaded_data["group_memberships"].shape[0]} rows")

            # Add Groups and Department columns to user_details
            user_groups = loaded_data["group_memberships"].groupby("userId")["groupName"].apply(lambda x: ", ".join(x)).reset_index()
            loaded_data["user_details"] = loaded_data["user_details"].merge(user_groups, left_on="User ID", right_on="userId", how="left")
            loaded_data["user_details"] = loaded_data["user_details"].rename(columns={"groupName": "Groups"})
            loaded_data["user_details"]["Groups"] = loaded_data["user_details"]["Groups"].fillna("")
            loaded_data["user_details"]["Department"] = loaded_data["user_details"]["Groups"].apply(lambda x: x.split(", ")[0] if x else "Unknown")
            loaded_data["user_details"] = loaded_data["user_details"].drop(columns=["userId"], errors="ignore")

        # Enhanced role-permission matrix if app_roles available
        if "app_roles" in loaded_data:
            role_permission_mapping = {
                "Field Service - Dispatcher": ["create_work_order", "assign_technician", "view_field_reports"],
                "Omnichannel administrator": ["manage_channels", "configure_workflows", "view_analytics"],
                "Forecast user": ["create_forecast", "view_forecast", "edit_forecast"],
                "Dynamics 365 App for Outlook User": ["sync_email", "view_calendar", "create_tasks"],
                "Sales Enterprise app access": ["manage_leads", "create_opportunities", "view_sales_reports"]
            }
            
            role_matrix_data = {"role": [], "permissions": []}
            for role_id, role_name in zip(loaded_data["app_roles"]["roleId"], loaded_data["app_roles"]["roleName"]):
                role_matrix_data["role"].append(role_name)
                permissions = role_permission_mapping.get(role_name, [role_name])
                role_matrix_data["permissions"].append(", ".join(permissions))
            loaded_data["role_matrix"] = pd.DataFrame(role_matrix_data)
            logger.info(f"Created role_matrix with {loaded_data["role_matrix"].shape[0]} rows")

        # Validate data consistency if user_details, audit_logs, signin_logs, app_role_assignments available
        if "user_details" in loaded_data and "audit_logs" in loaded_data and "signin_logs" in loaded_data and "app_role_assignments" in loaded_data:
            user_ids = set(loaded_data["user_details"]["User ID"].astype(str))
            audit_initiators = set(loaded_data["audit_logs"]["initiatedByUserId"].astype(str).dropna())
            signin_users = set(loaded_data["signin_logs"]["userId"].astype(str))
            missing_audit_users = audit_initiators - user_ids
            missing_signin_users = signin_users - user_ids
            if missing_audit_users:
                logger.warning(f"Found {len(missing_audit_users)} users in audit_logs not present in user_details: {list(missing_audit_users)[:5]}...")
            if missing_signin_users:
                logger.warning(f"Found {len(missing_signin_users)} users in signin_logs not present in user_details: {list(missing_signin_users)[:5]}...")
            assigned_users = set(loaded_data["app_role_assignments"]["userId"].astype(str))
            missing_assigned_users = assigned_users - user_ids
            if missing_assigned_users:
                logger.warning(f"Found {len(missing_assigned_users)} users in app_role_assignments not present in user_details: {list(missing_assigned_users)[:5]}...")

        logger.info("Data loaded and preprocessed successfully from CSVs")
        return (loaded_data.get("audit_logs", pd.DataFrame()), loaded_data.get("signin_logs", pd.DataFrame()), 
                loaded_data.get("user_details", pd.DataFrame()), loaded_data.get("role_matrix", pd.DataFrame()), 
                loaded_data.get("group_memberships", pd.DataFrame()), loaded_data.get("app_roles", pd.DataFrame()), 
                loaded_data.get("app_role_assignments", pd.DataFrame()), loaded_data.get("conditional_access_policies", pd.DataFrame()), 
                loaded_data.get("business_units", pd.DataFrame()), loaded_data.get("user_without_entraid", pd.DataFrame()), 
                loaded_data.get("user_without_license", pd.DataFrame()))
    except Exception as e:
        logger.error(f"Failed to load data from CSVs: {str(e)}")
        data_loaded_success = False
        raise
    finally:
        # This part won't be reached if an exception is raised and not caught
        pass # Consider adding logic here if needed after load attempt

@app.get("/api/v1/fetch-data", response_model=DataLoadResponse)
async def fetch_data_endpoint():
    logger.info("[fetch-data] Endpoint called")
    global data_store, vectorstore, analysis_results_available
    try:
        logger.info("[fetch-data] Fetching data using scripts/data_fetcher.py...")
        fetch_result = fetch_and_save_data()
        logger.debug(f"[fetch-data] fetch_result: {fetch_result}")
        if not fetch_result.get("success", False):
            logger.error(f"[fetch-data] Data fetch failed: {fetch_result.get('message', 'Unknown error')}")
            raise ValueError(f"Data fetch failed: {fetch_result.get('message', 'Unknown error')}")
        logger.info("[fetch-data] Data fetched successfully, now loading into memory...")
        (audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, app_role_assignments, conditional_access_policies, business_units, user_without_entraid, user_without_license) = load_data_from_csv()
        logger.debug(f"[fetch-data] Loaded data: audit_logs={len(audit_logs)}, signin_logs={len(signin_logs)}, user_details={len(user_details)}")
        data_store = {
            "audit_logs": audit_logs,
            "signin_logs": signin_logs,
            "user_details": user_details,
            "role_matrix": role_matrix,
            "group_memberships": group_memberships,
            "app_roles": app_roles,
            "app_role_assignments": app_role_assignments,
            "conditional_access_policies": conditional_access_policies,
            "business_units": business_units,
            "user_without_entraid": user_without_entraid,
            "user_without_license": user_without_license
        }
        vectorstore = None
        analysis_results_available = False
        logger.info("[fetch-data] Data loaded into memory successfully")
        return DataLoadResponse(
            status="success",
            message="Data fetched, saved, and loaded successfully",
            data={
                "audit_logs_count": len(data_store.get("audit_logs", [])),
                "signin_logs_count": len(data_store.get("signin_logs", [])),
                "user_details_count": len(data_store.get("user_details", [])),
                "role_matrix_count": len(data_store.get("role_matrix", [])),
                "group_memberships_count": len(data_store.get("group_memberships", [])),
                "app_roles_count": len(data_store.get("app_roles", [])),
                "app_role_assignments_count": len(data_store.get("app_role_assignments", [])),
                "conditional_access_policies_count": len(data_store.get("conditional_access_policies", [])),
                "business_units_count": len(data_store.get("business_units", [])),
                "user_without_entraid_count": len(data_store.get("user_without_entraid", [])),
                "user_without_license_count": len(data_store.get("user_without_license", [])),
                "data_loaded": bool(data_store),
                "embeddings_generated": vectorstore is not None,
                "analysis_complete": analysis_results_available
            }
        )
    except Exception as e:
        logger.error(f"[fetch-data] Error fetching data: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching data: {str(e)}")

@app.get("/api/v1/load-data", response_model=DataLoadResponse)
async def load_data_endpoint():
    logger.info("[load-data] Endpoint called")
    global data_store, vectorstore, analysis_results_available
    try:
        (audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, app_role_assignments, conditional_access_policies, business_units, user_without_entraid, user_without_license) = load_data_from_csv()
        logger.debug(f"[load-data] Loaded data: audit_logs={len(audit_logs)}, signin_logs={len(signin_logs)}, user_details={len(user_details)}")
        data_store = {
            "audit_logs": audit_logs,
            "signin_logs": signin_logs,
            "user_details": user_details,
            "role_matrix": role_matrix,
            "group_memberships": group_memberships,
            "app_roles": app_roles,
            "app_role_assignments": app_role_assignments,
            "conditional_access_policies": conditional_access_policies,
            "business_units": business_units,
            "user_without_entraid": user_without_entraid,
            "user_without_license": user_without_license
        }
        vectorstore = None
        analysis_results_available = False
        logger.info("[load-data] Data loaded successfully from CSVs")
        return DataLoadResponse(
            status="success",
            message="Data loaded successfully from CSVs",
            data={
                "audit_logs_count": len(data_store.get("audit_logs", [])),
                "signin_logs_count": len(data_store.get("signin_logs", [])),
                "user_details_count": len(data_store.get("user_details", [])),
                "role_matrix_count": len(data_store.get("role_matrix", [])),
                "group_memberships_count": len(data_store.get("group_memberships", [])),
                "app_roles_count": len(data_store.get("app_roles", [])),
                "app_role_assignments_count": len(data_store.get("app_role_assignments", [])),
                "conditional_access_policies_count": len(data_store.get("conditional_access_policies", [])),
                "business_units_count": len(data_store.get("business_units", [])),
                "user_without_entraid_count": len(data_store.get("user_without_entraid", [])),
                "user_without_license_count": len(data_store.get("user_without_license", [])),
                "data_loaded": bool(data_store),
                "embeddings_generated": vectorstore is not None,
                "analysis_complete": analysis_results_available
            }
        )
    except Exception as e:
        logger.error(f"[load-data] Error loading data from CSVs: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error loading data from CSVs: {str(e)}")

@app.get("/api/v1/generate-embeddings")
async def generate_embeddings_endpoint():
    logger.info("[generate-embeddings] Endpoint called")
    global vectorstore, analysis_results_available
    if not data_store:
        logger.warning("[generate-embeddings] Data not loaded. Please load data first.")
        raise HTTPException(status_code=400, detail="Data not loaded. Please load data first.")
    try:
        logger.info("[generate-embeddings] Generating embeddings...")
        vectorstore = local_generate_embeddings(
            data_store["audit_logs"],
            data_store["signin_logs"],
            data_store["user_details"],
            data_store["app_role_assignments"],
            batch_size=64,
            save_vectorstore=True,
            sample_fraction=1.0
        )
        analysis_results_available = False
        logger.info("[generate-embeddings] Embeddings generated successfully")
        return JSONResponse(
            content={"status": "success", "message": "Embeddings generated successfully", "data_loaded": bool(data_store), "embeddings_generated": vectorstore is not None, "analysis_complete": analysis_results_available},
            status_code=200
        )
    except Exception as e:
        logger.error(f"[generate-embeddings] Error generating embeddings: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error generating embeddings: {str(e)}")
        
@app.get("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_endpoint():
    """
    Run the real analysis pipeline: fetch data, load data, generate embeddings, analyze, and push to blob.
    Also include users without D365 license and without Entra ID in the results.
    """
    try:
        # 1. Fetch and save data
        from scripts.data_fetcher import fetch_and_save_data
        fetch_result = fetch_and_save_data()
        if not fetch_result.get("success", False):
            logger.error(f"[analyze] Data fetch failed: {fetch_result.get('message', 'Unknown error')}")
            raise HTTPException(status_code=500, detail=f"Data fetch failed: {fetch_result.get('message', 'Unknown error')}")
        logger.info("[analyze] Data fetched and saved successfully.")

        # 2. Load data from CSV
        data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
        audit_logs, signin_logs, user_details, role_matrix, group_memberships, app_roles, app_role_assignments, conditional_access_policies, business_units, user_without_entraid, user_without_license = load_data_from_csv()
        logger.info("[analyze] Data loaded from CSV files.")

        # 3. Generate embeddings
        vectorstore = local_generate_embeddings(
            audit_logs,
            signin_logs,
            user_details,
            app_role_assignments,
            batch_size=64,
            save_vectorstore=False
        )
        logger.info("[analyze] Embeddings generated.")

        # 4. Run the real analysis pipeline
        results = await local_run_analysis(
            vectorstore,
            user_details,
            role_matrix,
            group_memberships,
            app_roles,
            app_role_assignments,
            conditional_access_policies,
            audit_logs,
            signin_logs
        )
        logger.info("[analyze] Analysis completed.")

        # --- Map user IDs to names and add sign-in trends/locations ---
        mapped_results = map_user_ids_to_names(results, user_details)
        signin_trends_and_locations = compute_signin_trends_and_locations(signin_logs)
        mapped_results.update(signin_trends_and_locations)

        # 4.1. Add users without D365 license and without Entra ID to results (for API response only)
        users_without_entraid = user_without_entraid.to_dict("records") if not user_without_entraid.empty else []
        users_without_d365_license = user_without_license.to_dict("records") if not user_without_license.empty else []
        # Save only the AI part to analyze.json
        results_to_save = dict(mapped_results)  # shallow copy
        # Add user lists to API response only
        mapped_results["users_without_entraid"] = {
            "count": len(users_without_entraid),
            "users": users_without_entraid
        }
        mapped_results["users_without_d365_license"] = {
            "count": len(users_without_d365_license),
            "users": users_without_d365_license
        }

        # 5. Save the FULL results to backend/data/analyze.json (AI part only)
        output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
        os.makedirs(output_dir, exist_ok=True)  # Ensure the data directory exists
        output_path = os.path.join(output_dir, "analyze.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results_to_save, f, indent=2)
        logger.info(f"[analyze] Analysis results saved to {output_path}")

        # 6. Upload all data and logs to blob storage
        data_files = glob.glob(os.path.join(output_dir, "*"))
        for file_path in data_files:
            blob_path = f"data/{os.path.basename(file_path)}"
            with open(file_path, "rb") as data:
                container_client.upload_blob(name=blob_path, data=data, overwrite=True)
        logs_files = glob.glob("Paramount_Access_Review/logs/*")
        for file_path in logs_files:
            blob_path = f"logs/{os.path.basename(file_path)}"
            with open(file_path, "rb") as data:
                container_client.upload_blob(name=blob_path, data=data, overwrite=True)
        app_log_path = "backend/app.log"
        if os.path.exists(app_log_path):
            blob_path = f"logs/app.log"
            with open(app_log_path, "rb") as data:
                container_client.upload_blob(name=blob_path, data=data, overwrite=True)

        # 7. Return the FULL results as JSON
        return AnalysisResponse(status="success", results=mapped_results)

    except Exception as e:
        logger.error(f"[analyze] Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/v1/users/without-entraid", response_model=UsersResponse)
async def get_users_without_entraid(
    page: int = Query(1, ge=1, description="Page number for pagination"),
    page_size: int = Query(10, ge=1, le=100, description="Number of records per page"),
    search: Optional[str] = Query(None, description="Search by userName or email")
):
    logger.info(f"[users/without-entraid] Endpoint called with page={page}, page_size={page_size}, search={search}")
    if not data_store or "user_without_entraid" not in data_store:
        logger.warning("[users/without-entraid] Data not loaded. Please load data first.")
        raise HTTPException(status_code=400, detail="Data not loaded. Please load data first.")
    try:
        users_df = data_store["user_without_entraid"]
        logger.debug(f"[users/without-entraid] Initial users count: {len(users_df)}")
        if search:
            users_df = users_df[
                users_df["userName"].str.contains(search, case=False, na=False) |
                users_df["email"].str.contains(search, case=False, na=False)
            ]
            logger.debug(f"[users/without-entraid] Filtered users count: {len(users_df)}")
        total = len(users_df)
        start = (page - 1) * page_size
        end = start + page_size
        users_paginated = users_df.iloc[start:end].to_dict("records")
        logger.info(f"[users/without-entraid] Returning {len(users_paginated)} users (total={total})")
        return UsersResponse(status="success", users=users_paginated, total=total)
    except Exception as e:
        logger.error(f"[users/without-entraid] Error retrieving users: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving users without Entra ID: {str(e)}")

@app.get("/api/v1/users/without-d365-license", response_model=UsersResponse)
async def get_users_without_d365_license(
    page: int = Query(1, ge=1, description="Page number for pagination"),
    page_size: int = Query(10, ge=1, le=100, description="Number of records per page"),
    search: Optional[str] = Query(None, description="Search by userName or email")
):
    logger.info(f"[users/without-d365-license] Endpoint called with page={page}, page_size={page_size}, search={search}")
    if not data_store or "user_without_license" not in data_store:
        logger.warning("[users/without-d365-license] Data not loaded. Please load data first.")
        raise HTTPException(status_code=400, detail="Data not loaded. Please load data first.")
    try:
        users_df = data_store["user_without_license"]
        logger.debug(f"[users/without-d365-license] Initial users count: {len(users_df)}")
        if search:
            users_df = users_df[
                users_df["userName"].str.contains(search, case=False, na=False) |
                users_df["email"].str.contains(search, case=False, na=False)
            ]
            logger.debug(f"[users/without-d365-license] Filtered users count: {len(users_df)}")
        total = len(users_df)
        start = (page - 1) * page_size
        end = start + page_size
        users_paginated = users_df.iloc[start:end].to_dict("records")
        logger.info(f"[users/without-d365-license] Returning {len(users_paginated)} users (total={total})")
        return UsersResponse(status="success", users=users_paginated, total=total)
    except Exception as e:
        logger.error(f"[users/without-d365-license] Error retrieving users: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving users without D365 license: {str(e)}")
# Keep the CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Specify frontend origin for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Custom endpoint for analyze.json
@app.get("/api/data/analyze.json")
async def get_analysis_data():
    try:
        analyze_file = os.path.join(os.path.dirname(__file__), "data", "analyze.json")
        if not os.path.exists(analyze_file):
            logger.error("Analysis data file not found")
            raise HTTPException(status_code=404, detail="Analysis data not found")
        
        with open(analyze_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        return JSONResponse(content=data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error serving analysis data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error serving analysis data: {str(e)}")
    except Exception as e:
        logger.error(f"Error serving analysis data: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/analysis")
def get_latest_analysis():
    """
    Return the latest batch-analyzed data from backend/data/analyze.json.
    """
    analysis_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "analyze.json"))
    if not os.path.exists(analysis_path):
        raise HTTPException(status_code=404, detail="analyze.json not found")
    try:
        with open(analysis_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading analyze.json: {str(e)}")

@app.get("/api/data-files")
def list_data_files():
    files = [os.path.basename(f) for f in glob.glob(os.path.join(os.path.dirname(__file__), "data", "*.json"))]
    return {"status": "success", "files": files}

@app.get("/api/data/{filename}")
def get_data_file(filename: str):
    file_path = os.path.join(os.path.dirname(__file__), "data", filename)
    if not os.path.isfile(file_path) or not filename.endswith('.json'):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, media_type='application/json')

# Azure Blob Storage config

# Get blob SAS URL from environment variable
BLOB_SAS_URL = os.getenv("AZURE_BLOB_SAS_URL")
if not BLOB_SAS_URL:
    logger.warning("AZURE_BLOB_SAS_URL not set in environment")
else:
    blob_service_client = BlobServiceClient(account_url=BLOB_SAS_URL)
    container_client = blob_service_client.get_container_client("accessreview")

# Add these imports at the top with your existing imports
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import requests
import asyncio

# Setup CORS middleware to allow frontend to access backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the data directory to serve JSON files
app.mount("/api/v1/data", StaticFiles(directory="data"), name="data")

# Create a background scheduler
scheduler = BackgroundScheduler()

# Function to trigger the analyze endpoint
async def scheduled_analysis():
    try:
        logger.info("Running scheduled analysis task")
        # Make a request to the analyze endpoint
        response = requests.get("http://localhost:8000/api/v1/analyze")
        if response.status_code == 200:
            logger.info("Scheduled analysis completed successfully")
        else:
            logger.error(f"Scheduled analysis failed with status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Error in scheduled analysis: {str(e)}")

# Function to start the scheduler
def start_scheduler():
    # Schedule the analysis to run every 12 hours
    scheduler.add_job(
        lambda: asyncio.run(scheduled_analysis()),
        trigger=IntervalTrigger(hours=12),
        id="scheduled_analysis",
        name="Run analysis every 12 hours",
        replace_existing=True
    )
    scheduler.start()
    logger.info("Scheduler started - Analysis will run every 12 hours")

# Add a startup event to start the scheduler when the app starts
@app.on_event("startup")
def on_startup():
    start_scheduler()
    logger.info("FastAPI application started")

# Add a shutdown event to shut down the scheduler when the app stops
@app.on_event("shutdown")
def on_shutdown():
    scheduler.shutdown()
    logger.info("FastAPI application shutdown")

app.include_router(v1_router, prefix="/api/v1")

if __name__ == "__main__":
    """
    Run the FastAPI app using Uvicorn.
    """
    try:
        logger.info("Starting FastAPI server with Uvicorn")
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info",
            workers=1
        )
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        raise