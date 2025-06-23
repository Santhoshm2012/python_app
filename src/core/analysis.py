import os
import json
import streamlit as st
from langchain_openai import AzureChatOpenAI
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Dict
import pandas as pd
import logging
import asyncio
import aiohttp
import time
from src.utils.config import setup_logging, load_config
from src.analysis.access_pattern import analyze_access_patterns
from src.analysis.anomaly_detector import detect_anomalies
from src.analysis.permission_mismatch import find_permission_mismatches_and_sod
from src.analysis.permission_trends import analyze_permission_trends
from src.analysis.inactive_users import find_inactive_users
from dotenv import load_dotenv
from src.utils.azure_blob import upload_file_to_blob, utc_timestamp
import glob
import subprocess
import numpy as np

# Load environment variables from .env file
load_dotenv()

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

# Helper function to check if running in Streamlit context
def is_streamlit_running():
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        return get_script_run_ctx() is not None
    except ImportError:
        return False

# Helper function for safe JSON parsing
def safe_parse_json(raw_response):
    try:
        return json.loads(raw_response)
    except json.JSONDecodeError as e:
        logger.warning(f"JSON parsing error: {str(e)}. Attempting to fix unterminated string.")
        last_valid = raw_response[:e.pos]
        try:
            return json.loads(last_valid + "}")
        except:
            logger.error(f"Failed to parse even after truncation: {raw_response}")
            return {}

# Validate input DataFrames
def validate_dataframes(
    user_details: pd.DataFrame,
    role_matrix: pd.DataFrame,
    group_memberships: pd.DataFrame,
    app_roles: pd.DataFrame,
    app_role_assignments: pd.DataFrame,
    conditional_access_policies: pd.DataFrame,
    audit_logs: pd.DataFrame,
    signin_logs: pd.DataFrame
):
    logger.info("Validating input DataFrames")
    
    # Check for required columns
    required_columns = {
        "user_details": ["User ID"],
        "role_matrix": ["role", "permissions"],
        "group_memberships": ["userId", "groupId"],
        "app_roles": ["roleId"],
        "app_role_assignments": ["userId", "roleId"],
        "audit_logs": ["activityDateTime", "initiatedByUserId"],
        "signin_logs": ["signInDateTime", "userId"]
    }
    
    for df_name, df in [
        ("user_details", user_details),
        ("role_matrix", role_matrix),
        ("group_memberships", group_memberships),
        ("app_roles", app_roles),
        ("app_role_assignments", app_role_assignments),
        ("audit_logs", audit_logs),
        ("signin_logs", signin_logs)
    ]:
        if df.empty:
            logger.warning(f"{df_name} DataFrame is empty")
        missing_cols = [col for col in required_columns.get(df_name, []) if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns in {df_name}: {missing_cols}")
    
    # Parse timestamps
    if not audit_logs.empty:
        audit_logs["activityDateTime"] = pd.to_datetime(audit_logs["activityDateTime"], errors="coerce", utc=True)
        invalid_timestamps = audit_logs["activityDateTime"].isna().sum()
        if invalid_timestamps > 0:
            logger.warning(f"Found {invalid_timestamps} invalid activityDateTime entries in audit_logs")
    
    if not signin_logs.empty:
        signin_logs["signInDateTime"] = pd.to_datetime(signin_logs["signInDateTime"], errors="coerce", utc=True)
        invalid_timestamps = signin_logs["signInDateTime"].isna().sum()
        if invalid_timestamps > 0:
            logger.warning(f"Found {invalid_timestamps} invalid signInDateTime entries in signin_logs")

class AnalysisState(TypedDict):
    query: str
    context: List[str]
    user_details: pd.DataFrame
    role_matrix: pd.DataFrame
    group_memberships: pd.DataFrame
    app_roles: pd.DataFrame
    app_role_assignments: pd.DataFrame
    conditional_access_policies: pd.DataFrame
    audit_logs: pd.DataFrame
    signin_logs: pd.DataFrame
    results: dict

class SequentialLLMProcessor:
    """Handle sequential processing of LLM requests with Azure OpenAI"""
    
    def __init__(self, config: Dict):
        self.config = config
        
    async def process_chunk_async(self, session: aiohttp.ClientSession, 
                                  chunk_data: Dict, chunk_id: int, 
                                  prompt_template: str, chunk_type: str = "findings") -> Dict:
        """Process a single chunk asynchronously"""
        try:
            start_time = time.time()
            logger.info(f"Processing {chunk_type} chunk {chunk_id} with data size: {len(str(chunk_data))} bytes")
            
            headers = {
                "Content-Type": "application/json",
                "api-key": self.config["AZURE_OPENAI_API_KEY"]
            }
            
            if chunk_type == "findings":
                user_message = prompt_template.format(**chunk_data)
            else:  # recommendations
                user_message = prompt_template.format(**chunk_data)
            
            payload = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security analyst. Always respond with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": user_message
                    }
                ],
                "max_tokens": 4000,
                "temperature": 0,
                "response_format": {"type": "json_object"}
            }
            
            url = f"{self.config['AZURE_OPENAI_ENDPOINT']}/openai/deployments/{self.config['AZURE_OPENAI_DEPLOYMENT_NAME']}/chat/completions?api-version={self.config['AZURE_OPENAI_API_VERSION']}"
            
            logger.debug(f"Sending request for {chunk_type} chunk {chunk_id}")
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    processing_time = time.time() - start_time
                    logger.info(f"{chunk_type.capitalize()} chunk {chunk_id} completed in {processing_time:.2f}s")
                    return {
                        "chunk_id": chunk_id,
                        "content": result["choices"][0]["message"]["content"],
                        "success": True,
                        "processing_time": processing_time
                    }
                elif response.status == 429:
                    logger.warning(f"Rate limit hit for {chunk_type} chunk {chunk_id}, retrying after 30s delay...")
                    await asyncio.sleep(30)  # Increased delay for rate limit
                    return await self.process_chunk_async(session, chunk_data, chunk_id, prompt_template, chunk_type)
                else:
                    error_text = await response.text()
                    logger.error(f"HTTP {response.status} for {chunk_type} chunk {chunk_id}: {error_text}")
                    return {
                        "chunk_id": chunk_id,
                        "error": f"HTTP {response.status}: {error_text}",
                        "success": False
                    }
                    
        except Exception as e:
            logger.error(f"Error processing {chunk_type} chunk {chunk_id}: {str(e)}")
            return {
                "chunk_id": chunk_id,
                "error": str(e),
                "success": False
            }
    
    async def process_chunks_sequentially(self, chunks_data: List[Dict], 
                                          prompt_template: str, 
                                          chunk_type: str = "findings",
                                          max_retries: int = 3) -> List[Dict]:
        """Process multiple chunks sequentially with retry logic"""
        timeout = aiohttp.ClientTimeout(total=1800, connect=60, sock_connect=60, sock_read=300)  # Increased timeouts
        connector = aiohttp.TCPConnector(limit=1)  # Single connection to avoid rate limiting
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            results = []
            
            for i, chunk_data in enumerate(chunks_data):
                chunk_id = i + 1
                retries = 0
                while retries <= max_retries:
                    logger.info(f"Attempt {retries + 1}/{max_retries + 1} for {chunk_type} chunk {chunk_id}")
                    result = await self.process_chunk_async(session, chunk_data, chunk_id, prompt_template, chunk_type)
                    if result.get("success", False):
                        results.append(result)
                        break
                    retries += 1
                    logger.warning(f"Retry {retries}/{max_retries} for {chunk_type} chunk {chunk_id} due to: {result.get('error')}")
                    await asyncio.sleep(2)
                
                if not result.get("success", False):
                    logger.error(f"Failed to process {chunk_type} chunk {chunk_id} after {max_retries} retries")
                    results.append(result)
            
            return results

def truncate_description(text: str, max_length: int = 50) -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

def chunk_dict(data: Dict, chunk_size: int, all_keys: List[str]) -> List[Dict]:
    keys = list(set(all_keys))
    chunks = []
    for i in range(0, len(keys), chunk_size):
        chunk_keys = keys[i:i + chunk_size]
        chunk = {k: data.get(k, []) if isinstance(data.get(k), list) else data.get(k, {}) for k in chunk_keys}
        chunks.append(chunk)
    return chunks

def calculate_chunk_size(total_users: int) -> int:
    if total_users < 500:
        return 100
    elif total_users < 1000:
        return 200
    else:
        return 500

def calculate_recommendation_chunk_size(total_users: int) -> int:
    if total_users < 500:
        return 50
    elif total_users < 1000:
        return 30
    else:
        return 20

def map_user_ids_to_names(results: dict, user_details: pd.DataFrame) -> dict:
    """
    Map all userId keys in results to userName using user_details DataFrame.
    Also replaces userId mentions in recommendations/details with userName.
    """
    # Build userId -> userName mapping
    user_id_col = None
    user_name_col = None
    for col in ['userId', 'User ID']:
        if col in user_details.columns:
            user_id_col = col
            break
    for col in ['userName', 'UserName', 'Display Name', 'Name']:
        if col in user_details.columns:
            user_name_col = col
            break
    if not user_id_col or not user_name_col:
        return results  # fallback: do nothing
    user_id_to_name = dict(zip(user_details[user_id_col].astype(str), user_details[user_name_col]))

    def map_keys(d):
        return {user_id_to_name.get(k, k): v for k, v in d.items()}

    mapped = dict(results)
    for key in ["underutilized", "inactive", "mismatches", "anomalies"]:
        if key in mapped and isinstance(mapped[key], dict):
            mapped[key] = map_keys(mapped[key])
    # Fix recommendations
    if "recommendations" in mapped and isinstance(mapped["recommendations"], list):
        for rec in mapped["recommendations"]:
            for uid, uname in user_id_to_name.items():
                if uid in rec.get("details", ""):
                    rec["details"] = rec["details"].replace(uid, uname)
    return mapped


def compute_signin_trends_and_locations(signin_logs: pd.DataFrame) -> dict:
    """
    Compute sign-in trends (per day) and most frequent sign-in locations per user.
    Returns a dict with 'sign_in_trends' and 'sign_in_locations'.
    """
    trends = []
    locations = {}
    if not signin_logs.empty:
        # Trends: sign-ins per day
        signin_logs['signInDateTime'] = pd.to_datetime(signin_logs['signInDateTime'], errors='coerce', utc=True)
        per_day = signin_logs.dropna(subset=['signInDateTime']).groupby(signin_logs['signInDateTime'].dt.date).size()
        for date, count in per_day.items():
            trends.append({"date": str(date), "signins": int(count)})
        # Locations: most frequent per user
        loc_counts = signin_logs.groupby(['userId', 'locationCity', 'locationCountry']).size().reset_index(name='count')
        for user_id in loc_counts['userId'].unique():
            user_locs = loc_counts[loc_counts['userId'] == user_id]
            if not user_locs.empty:
                top = user_locs.sort_values('count', ascending=False).iloc[0]
                locations[user_id] = f"{top['locationCity']}, {top['locationCountry']}"
    return {"sign_in_trends": trends, "sign_in_locations": locations}

async def run_analysis(vectorstore, user_details, role_matrix, group_memberships, app_roles, app_role_assignments, conditional_access_policies, audit_logs, signin_logs):
    logger.info("Initializing Azure OpenAI LLM")
    try:
        config = load_config()
        
        required_vars = [
            "AZURE_OPENAI_API_KEY",
            "AZURE_OPENAI_ENDPOINT",
            "AZURE_OPENAI_DEPLOYMENT_NAME",
            "AZURE_OPENAI_API_VERSION"
        ]
        missing_vars = [var for var in required_vars if not config.get(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

        # Validate DataFrames
        validate_dataframes(
            user_details, role_matrix, group_memberships, app_roles,
            app_role_assignments, conditional_access_policies, audit_logs, signin_logs
        )

        # --- PATCH: Ensure 'Groups' column exists in user_details ---
        if "Groups" not in user_details.columns:
            # Build a mapping from userId to list of group names
            user_to_groups = group_memberships.groupby("userId")["groupName"].apply(lambda x: ", ".join(sorted(set(x.dropna())))).to_dict()
            user_details["Groups"] = user_details["User ID"].map(user_to_groups).fillna("")
        # --- END PATCH ---

        # Log user ID counts before filtering
        logger.info(f"Columns in user_details: {list(user_details.columns)}")
        logger.info(f"Columns in signin_logs: {list(signin_logs.columns)}")
        logger.info(f"Columns in audit_logs: {list(audit_logs.columns)}")
        logger.info(f"Columns in app_role_assignments: {list(app_role_assignments.columns)}")
        logger.info(f"Columns in app_roles: {list(app_roles.columns)}")

        # Handle NaN values in user ID columns
        user_ids_user_details = set(user_details['User ID'].dropna().astype(str))
        user_ids_signin = set(signin_logs['userId'].dropna().astype(str))
        user_ids_audit = set(audit_logs['initiatedByUserId'].dropna().astype(str))
        
        app_role_user_id_column = 'userId'  # Align with main.py
        if app_role_user_id_column not in app_role_assignments.columns:
            logger.error(f"'{app_role_user_id_column}' column not found in app_role_assignments. Available columns: {list(app_role_assignments.columns)}")
            user_ids_app_roles = set()
        else:
            user_ids_app_roles = set(app_role_assignments[app_role_user_id_column].dropna().astype(str))
        
        all_user_ids_set = user_ids_user_details | user_ids_signin | user_ids_audit | user_ids_app_roles
        logger.info(f"User IDs from user_details: {len(user_ids_user_details)}")
        logger.info(f"User IDs from signin_logs: {len(user_ids_signin)}")
        logger.info(f"User IDs from audit_logs: {len(user_ids_audit)}")
        logger.info(f"User IDs from app_role_assignments: {len(user_ids_app_roles)}")
        logger.info(f"Total unique user IDs: {len(all_user_ids_set)}")

        # Initialize sequential processor
        sequential_processor = SequentialLLMProcessor(config)

        llm = AzureChatOpenAI(
            azure_endpoint=config["AZURE_OPENAI_ENDPOINT"],
            api_key=config["AZURE_OPENAI_API_KEY"],
            deployment_name=config["AZURE_OPENAI_DEPLOYMENT_NAME"],
            api_version=config["AZURE_OPENAI_API_VERSION"],
            temperature=0,
            model_kwargs={"response_format": {"type": "json_object"}}
        )
        
        def retrieve(state: AnalysisState):
            logger.info("Retrieving relevant documents from vectorstore")
            try:
                docs = vectorstore.similarity_search(state["query"], k=10)
                return {"context": [doc.page_content for doc in docs]}
            except Exception as e:
                logger.error(f"Error retrieving documents: {str(e)}", exc_info=True)
                raise
        
        async def analyze(state: AnalysisState):
            logger.info("Starting analysis")
            try:
                underutilized = analyze_access_patterns(
                    state["context"],
                    state["user_details"],
                    state["group_memberships"],
                    state["app_roles"],
                    state["app_role_assignments"],
                    state["audit_logs"],
                    state["signin_logs"]
                )
                # PATCH: Format underutilized as in reference output, using best display name
                user_details_df = state["user_details"]
                display_name_col = None
                for col in ["Display Name", "Name", "Email"]:
                    if col in user_details_df.columns:
                        display_name_col = col
                        break
                if display_name_col:
                    logger.info(f"Using '{display_name_col}' as display name for underutilized output.")
                    user_id_to_name = dict(zip(user_details_df["User ID"], user_details_df[display_name_col]))
                else:
                    logger.info("No display name column found, using User ID as name.")
                    user_id_to_name = dict(zip(user_details_df["User ID"], user_details_df["User ID"]))
                formatted_underutilized = {}
                for user_id, perms in underutilized.items():
                    user_name = user_id_to_name.get(user_id, user_id)
                    formatted_underutilized[user_name] = [f"{perm}: No usage in 90 days" for perm in perms]
                underutilized = formatted_underutilized
                anomalies = detect_anomalies(
                    state["context"],
                    vectorstore,
                    state["signin_logs"],
                    state["user_details"]
                )
                mismatches, sod_violations = find_permission_mismatches_and_sod(
                    state["user_details"],
                    state["role_matrix"],
                    state["group_memberships"],
                    state["app_roles"],
                    state["app_role_assignments"],
                    state["conditional_access_policies"],
                    state["signin_logs"]
                )
                trends = analyze_permission_trends(
                    state["audit_logs"],
                    state["signin_logs"],
                    state["user_details"],
                    state["group_memberships"],
                    state["app_roles"],
                    state["app_role_assignments"]
                )
                logger.info("Analyzing inactive users")
                inactive = find_inactive_users(
                    state["user_details"],
                    state["signin_logs"],
                    state["audit_logs"],
                    inactivity_days=30
                )

                all_user_ids = set()
                for data in [underutilized, anomalies, mismatches, trends.get("low_usage_permissions", []), inactive]:
                    all_user_ids.update(data.keys())
                if app_role_user_id_column in app_role_assignments.columns:
                    all_user_ids.update(app_role_assignments[app_role_user_id_column].dropna().astype(str))
                all_user_ids = list(all_user_ids)
                logger.info(f"Total unique user IDs after analysis: {len(all_user_ids)}")

                simplified_anomalies = {user_id: truncate_description(desc) for user_id, desc in anomalies.items()}
                simplified_mismatches = {user_id: truncate_description(desc) for user_id, desc in mismatches.items()}
                simplified_inactive = {user_id: truncate_description(desc) for user_id, desc in inactive.items()}

                user_context = {}
                for _, row in state["user_details"].iterrows():
                    user_id = row["User ID"]
                    if pd.isna(user_id):
                        continue
                    user_id = str(user_id)
                    user_context[user_id] = row.get("Department", "Unknown")

                app_roles_id_column = 'roleId' if 'roleId' in app_roles.columns else 'id'
                app_roles_name_column = 'roleName' if 'roleName' in app_roles.columns else 'displayName'
                app_role_assignments_role_id_column = 'roleId' if 'roleId' in app_role_assignments.columns else 'appRoleId'

                if app_roles_id_column not in app_roles.columns:
                    logger.error(f"Required column '{app_roles_id_column}' not found in app_roles. Available columns: {list(app_roles.columns)}")
                    app_roles_dict = {}
                elif app_roles_name_column not in app_roles.columns:
                    logger.error(f"Required column '{app_roles_name_column}' not found in app_roles. Available columns: {list(app_roles.columns)}")
                    app_roles_dict = {}
                else:
                    app_roles_dict = app_roles.set_index(app_roles_id_column)[app_roles_name_column].to_dict()

                if app_role_assignments_role_id_column not in app_role_assignments.columns:
                    logger.error(f"Required column '{app_role_assignments_role_id_column}' not found in app_role_assignments. Available columns: {list(app_role_assignments.columns)}")
                else:
                    for _, row in app_role_assignments.iterrows():
                        user_id = row[app_role_user_id_column] if app_role_user_id_column in app_role_assignments.columns else None
                        if not user_id or pd.isna(user_id):
                            continue
                        user_id = str(user_id)
                        role_id = row[app_role_assignments_role_id_column]
                        role_name = app_roles_dict.get(role_id, "Unknown Role")
                        if user_id not in user_context:
                            user_context[user_id] = f"App Role: {role_name}"
                        else:
                            user_context[user_id] += f", App Role: {role_name}"

                if is_streamlit_running():
                    st.subheader("Preliminary Findings")
                    st.write(f"**Total Users Analyzed**: {len(all_user_ids)}")
                    st.write(f"**Anomalies Detected**: {len(simplified_anomalies)}")
                    st.write(f"**Inactive Users**: {len(simplified_inactive)}")
                    st.write("Full analysis in progress...")

                combined_results = None
                if is_streamlit_running() and "combined_results" in st.session_state:
                    logger.info("Loading combined results from session state")
                    combined_results = st.session_state.combined_results
                if combined_results is None:
                    logger.info("Starting sequential processing of findings")
                    
                    findings_template = """You are a senior security analyst. Your description to response should be very precise. Based on the following:
Underutilized: {underutilized}
Anomalies: {anomalies}
Mismatches: {mismatches}
Trends: {trends}
Inactive: {inactive}
User context: {user_context}

Return a JSON with detailed findings:
- "underutilized": map user IDs to list of unused permissions with explanations
- "anomalies": map user IDs to detailed anomaly descriptions (e.g., "Unusual sign-in from unknown location")
- "mismatches": map user IDs to mismatch descriptions with explanations
- "trends": include "low_usage_permissions" (string) and "unused_roles" (categorized)
- "inactive": map user IDs to inactivity descriptions with reasons

If data is missing (e.g., no sign-in logs for a user), use the user_context to infer potential issues (e.g., "No sign-in activity, but user has role X which suggests potential risk").

Example:
{{
    "underutilized": {{"user_001": ["perm1: No usage in 90 days"]}},
    "anomalies": {{"user_001": "Unusual sign-in from unknown location on 2025-05-01"}},
    "mismatches": {{"user_001": "Assigned PCS BU Manager role but in Support department"}},
    "trends": {{
        "low_usage_permissions": "Permissions underutilized across IT department...",
        "unused_roles": {{
            "PCS-Related": ["PCS Employees"],
            "Paramount-Related": ["Paramount"],
            "General": ["AdminAgents"],
            "Explanation": "No activity in 90 days."
        }}
    }},
    "inactive": {{"user_001": "No sign-in in 30 days, last activity on 2025-04-01"}}
}}"""

                    chunk_size = calculate_chunk_size(len(all_user_ids))
                    logger.info(f"Using chunk size: {chunk_size} for {len(all_user_ids)} users")

                    trends_low_usage = trends.get("low_usage_permissions", {})
                    trends_unused_roles = trends.get("unused_roles", [])

                    underutilized_chunks = chunk_dict(underutilized, chunk_size, all_user_ids)
                    anomalies_chunks = chunk_dict(simplified_anomalies, chunk_size, all_user_ids)
                    mismatches_chunks = chunk_dict(simplified_mismatches, chunk_size, all_user_ids)
                    trends_chunks_low_usage = chunk_dict(trends_low_usage, chunk_size, all_user_ids)
                    inactive_chunks = chunk_dict(simplified_inactive, chunk_size, all_user_ids)
                    user_context_chunks = chunk_dict(user_context, chunk_size, all_user_ids)

                    chunks_data = []
                    for i, (underutilized_chunk, anomalies_chunk, mismatches_chunk, trends_chunk_low_usage, inactive_chunk, user_context_chunk) in enumerate(zip(
                        underutilized_chunks, anomalies_chunks, mismatches_chunks, trends_chunks_low_usage, inactive_chunks, user_context_chunks
                    )):
                        trends_chunk = {
                            "low_usage_permissions": trends_chunk_low_usage,
                            "unused_roles": trends_unused_roles
                        }
                        chunks_data.append({
                            "underutilized": underutilized_chunk,
                            "anomalies": anomalies_chunk,
                            "mismatches": mismatches_chunk,
                            "trends": trends_chunk,
                            "inactive": inactive_chunk,
                            "user_context": user_context_chunk
                        })

                    logger.info(f"Processing {len(chunks_data)} chunks sequentially")
                    
                    if is_streamlit_running():
                        progress_bar = st.progress(0)
                        progress_text = st.empty()
                    else:
                        progress_bar = None
                        progress_text = None
                    
                    start_time = time.time()
                    
                    total_chunks = len(chunks_data)
                    completed_chunks = 0
                    results = await sequential_processor.process_chunks_sequentially(
                        chunks_data, findings_template, "findings", max_retries=3
                    )
                    
                    combined_results = {
                        "underutilized": {},
                        "anomalies": {},
                        "mismatches": {},
                        "trends": {
                            "low_usage_permissions": "No trends detected.",
                            "unused_roles": {
                                "PCS-Related": [],
                                "Paramount-Related": [],
                                "General": [],
                                "Explanation": "No unused roles detected."
                            }
                        },
                        "inactive": {},
                        "recommendations": [],
                        "sod_violations": sod_violations
                    }
                    
                    successful_chunks = 0
                    expected_keys = ["underutilized", "anomalies", "mismatches", "trends", "inactive"]
                    for result in results:
                        if not result.get("success", False):
                            logger.error(f"Chunk {result['chunk_id']} failed: {result.get('error', 'Unknown error')}")
                            continue
                        
                        try:
                            parsed_results = safe_parse_json(result["content"])
                            logger.info(f"LLM response parsed successfully for chunk {result['chunk_id']}")
                            
                            missing_keys = [key for key in expected_keys if key not in parsed_results]
                            if missing_keys:
                                logger.error(f"Missing expected keys {missing_keys} in chunk {result['chunk_id']} response: {parsed_results}")
                                combined_results["recommendations"].append({
                                    "priority": "Low",
                                    "action": "Error",
                                    "details": f"Missing keys {missing_keys} in chunk {result['chunk_id']} response"
                                })
                                continue
                            
                            if not isinstance(parsed_results["underutilized"], dict):
                                logger.error(f"Invalid underutilized data in chunk {result['chunk_id']}: {parsed_results['underutilized']}")
                                continue
                            if not isinstance(parsed_results["anomalies"], dict):
                                logger.error(f"Invalid anomalies data in chunk {result['chunk_id']}: {parsed_results['anomalies']}")
                                continue
                            if not isinstance(parsed_results["mismatches"], dict):
                                logger.error(f"Invalid mismatches data in chunk {result['chunk_id']}: {parsed_results['mismatches']}")
                                continue
                            if not isinstance(parsed_results["trends"], dict):
                                logger.error(f"Invalid trends data in chunk {result['chunk_id']}: {parsed_results['trends']}")
                                continue
                            if not isinstance(parsed_results["inactive"], dict):
                                logger.error(f"Invalid inactive data in chunk {result['chunk_id']}: {parsed_results['inactive']}")
                                continue
                            
                            combined_results["underutilized"].update(parsed_results["underutilized"])
                            for user_id, desc in parsed_results["anomalies"].items():
                                combined_results["anomalies"][user_id] = anomalies.get(user_id, desc)
                            combined_results["mismatches"].update(parsed_results["mismatches"])
                            if "trends" in parsed_results:
                                combined_results["trends"]["low_usage_permissions"] = parsed_results["trends"].get("low_usage_permissions", "No trends detected.")
                                combined_results["trends"]["unused_roles"] = parsed_results["trends"].get("unused_roles", {})
                            combined_results["inactive"].update(parsed_results["inactive"])
                            successful_chunks += 1
                            
                            completed_chunks += 1
                            progress = min(completed_chunks / total_chunks, 0.95)
                            if is_streamlit_running():
                                progress_bar.progress(progress)
                                progress_text.text(f"Processing findings sequentially... ({int(progress * 100)}%)")
                            else:
                                logger.info(f"Processed {completed_chunks}/{total_chunks} chunks ({int(progress * 100)}%)")
                            
                        except Exception as e:
                            logger.error(f"Unexpected error processing chunk {result['chunk_id']}: {str(e)}")
                            combined_results["recommendations"].append({
                                "priority": "Low",
                                "action": "Error",
                                "details": f"Unexpected error in chunk {result['chunk_id']}: {str(e)}"
                            })
                    
                    if is_streamlit_running():
                        progress_bar.progress(1.0)
                        progress_text.text("Sequential Processing completed!")
                    else:
                        logger.info("Sequential Processing completed!")
                    
                    processing_time = time.time() - start_time
                    logger.info(f"Sequential processing completed in {processing_time:.2f}s")
                    logger.info(f"Successfully processed {successful_chunks}/{len(results)} chunks")
                    
                    if successful_chunks == 0:
                        raise RuntimeError("No chunks processed successfully; cannot proceed with analysis")
                    
                    if is_streamlit_running():
                        st.session_state.combined_results = combined_results

                logger.info("Starting sequential processing of recommendations")
                
                recommendations_template = """You are a security analyst. Based on the findings:
Underutilized: {underutilized}
Anomalies: {anomalies}
Mismatches: {mismatches}
Trends: {trends}
Inactive: {inactive}
User context: {user_context}

Return a JSON with recommendations:
- "recommendations": list of {{"priority": "High/Medium/Low", "action", "details"}}

Prioritize:
- High: Anomalies (unusual locations/frequent sign-ins)
- Medium: Mismatches/underutilized permissions (role creep)
- Low: Inactive users/unused roles

Example:
{{
    "recommendations": [
        {{"priority": "High", "action": "Investigate", "details": "Verify sign-ins for user_001 (Dept: IT)."}},
        {{"priority": "Medium", "action": "Address Mismatch", "details": "Remove PCS BU Manager from user_001 (Dept: Support)."}},
        {{"priority": "Low", "action": "Review Inactive", "details": "Consider disabling user_001."}}
    ]
}}
If none, return:
{{
    "recommendations": [{{"priority": "Low", "action": "No Action", "details": "No issues detected."}}]
}}"""

                recommendation_chunk_size = calculate_recommendation_chunk_size(len(all_user_ids))
                logger.info(f"Using recommendation chunk size: {recommendation_chunk_size} for {len(all_user_ids)} users")

                underutilized_chunks = chunk_dict(combined_results["underutilized"], recommendation_chunk_size, all_user_ids)
                anomalies_chunks = chunk_dict(combined_results["anomalies"], recommendation_chunk_size, all_user_ids)
                mismatches_chunks = chunk_dict(combined_results["mismatches"], recommendation_chunk_size, all_user_ids)
                trends_chunks_low_usage = chunk_dict({"low_usage": combined_results["trends"]["low_usage_permissions"]}, recommendation_chunk_size, ["low_usage"])
                inactive_chunks = chunk_dict(combined_results["inactive"], recommendation_chunk_size, all_user_ids)
                user_context_chunks = chunk_dict(user_context, recommendation_chunk_size, all_user_ids)

                logger.info("Validating recommendation chunks data")
                recommendation_chunks_data = []
                for i, (underutilized_chunk, anomalies_chunk, mismatches_chunk, trends_chunk_low_usage, inactive_chunk, user_context_chunk) in enumerate(zip(
                    underutilized_chunks, anomalies_chunks, mismatches_chunks, trends_chunks_low_usage, inactive_chunks, user_context_chunks
                )):
                    trends_chunk = {
                        "low_usage_permissions": trends_chunk_low_usage.get("low_usage", "No trends detected."),
                        "unused_roles": combined_results["trends"]["unused_roles"]
                    }
                    chunk_data = {
                        "underutilized": underutilized_chunk,
                        "anomalies": anomalies_chunk,
                        "mismatches": mismatches_chunk,
                        "trends": trends_chunk,
                        "inactive": inactive_chunk,
                        "user_context": user_context_chunk
                    }
                    for key, value in chunk_data.items():
                        if not isinstance(value, dict):
                            logger.error(f"Invalid data for {key} in recommendation chunk {i+1}: {value}")
                            raise ValueError(f"Invalid data for {key} in recommendation chunk {i+1}: expected dict, got {type(value)}")
                    recommendation_chunks_data.append(chunk_data)

                if not recommendation_chunks_data:
                    logger.warning("No recommendation chunks generated; skipping recommendations phase")
                    combined_results["recommendations"] = [{
                        "priority": "Low",
                        "action": "No Action",
                        "details": "No data available for generating recommendations."
                    }]
                    return {"results": combined_results}

                if is_streamlit_running():
                    recommendations_progress = st.progress(0)
                    recommendations_text = st.empty()
                else:
                    recommendations_progress = None
                    recommendations_text = None
                
                logger.info("Running sequential recommendations processing")
                total_recommendation_chunks = len(recommendation_chunks_data)
                completed_recommendation_chunks = 0
                recommendations_results = await sequential_processor.process_chunks_sequentially(
                    recommendation_chunks_data, recommendations_template, "recommendations", max_retries=3
                )
                
                all_recommendations = []
                for result in recommendations_results:
                    if not result.get("success", False):
                        logger.error(f"Recommendation chunk {result['chunk_id']} failed: {result.get('error', 'Unknown error')}")
                        all_recommendations.append({
                            "priority": "Low",
                            "action": "Error",
                            "details": f"Failed to process recommendation chunk {result['chunk_id']}: {result.get('error', 'Unknown error')}"
                        })
                        continue
                    
                    try:
                        parsed_results = safe_parse_json(result["content"])
                        recommendations = parsed_results.get("recommendations", [])
                        if not isinstance(recommendations, list):
                            logger.error(f"Invalid recommendations format in chunk {result['chunk_id']}: {parsed_results}")
                            all_recommendations.append({
                                "priority": "Low",
                                "action": "Error",
                                "details": f"Invalid recommendations format in chunk {result['chunk_id']}"
                            })
                            continue
                        all_recommendations.extend(recommendations)
                    except Exception as e:
                        logger.error(f"Unexpected error processing recommendations for chunk {result['chunk_id']}: {str(e)}")
                        all_recommendations.append({
                            "priority": "Low",
                            "action": "Error",
                            "details": f"Unexpected error in recommendations for chunk {result['chunk_id']}: {str(e)}"
                        })
                    
                    completed_recommendation_chunks += 1
                    progress = min(completed_recommendation_chunks / total_recommendation_chunks, 0.95)
                    if is_streamlit_running():
                        recommendations_progress.progress(progress)
                        recommendations_text.text(f"Processing recommendations sequentially... ({int(progress * 100)}%)")
                    else:
                        logger.info(f"Processed {completed_recommendation_chunks}/{total_recommendation_chunks} recommendation chunks ({int(progress * 100)}%)")

                if is_streamlit_running():
                    recommendations_progress.progress(1.0)
                    recommendations_text.text("Recommendations processing completed!")
                    recommendations_progress.empty()
                    recommendations_text.empty()
                else:
                    logger.info("Recommendations processing completed!")
                
                unique_recommendations = []
                seen = set()
                for rec in all_recommendations:
                    if not isinstance(rec, dict) or "priority" not in rec or "action" not in rec or "details" not in rec:
                        logger.error(f"Invalid recommendation format: {rec}")
                        continue
                    rec_tuple = (rec["priority"], rec["action"], rec["details"])
                    if rec_tuple not in seen:
                        seen.add(rec_tuple)
                        unique_recommendations.append(rec)
                        
                combined_results["recommendations"] = unique_recommendations if unique_recommendations else [{
                    "priority": "Low",
                    "action": "No Action",
                    "details": "No recommendations generated."
                }]
                
                logger.info(f"Analysis completed successfully with {len(unique_recommendations)} recommendations")
                # --- PATCH: Upload all data files to Azure Blob Storage after analysis ---
                data_dir = os.path.join(os.path.dirname(__file__), "../../data")
                data_dir = os.path.abspath(data_dir)
                sas_url = os.getenv("AZURE_BLOB_SAS_URL")
                logger.info(f"[BLOB DEBUG] sas_url: {sas_url}")
                if sas_url:
                    files_to_upload = glob.glob(os.path.join(data_dir, "*"))
                    logger.info(f"[BLOB DEBUG] files_to_upload: {files_to_upload}")
                    if not files_to_upload:
                        logger.warning("[BLOB DEBUG] No files found in data_dir for upload.")
                    for file_path in files_to_upload:
                        if os.path.isfile(file_path):
                            fname = os.path.basename(file_path)
                            dest_blob_path = fname  # No container name, no timestamp
                            logger.info(f"Uploading {file_path} to blob as {dest_blob_path}")
                            upload_file_to_blob(file_path, sas_url, dest_blob_path)
                else:
                    logger.warning("[BLOB DEBUG] AZURE_BLOB_SAS_URL not set; skipping blob upload.")
                # --- END PATCH ---

                # After all analysis is done, before returning/saving results:
                # 1. Map user IDs to names
                # 2. Add sign-in trends/locations
                combined_results = map_user_ids_to_names(combined_results, user_details)
                signin_trends_and_locations = compute_signin_trends_and_locations(signin_logs)
                combined_results.update(signin_trends_and_locations)

                # --- AI-Driven SoD Analysis ---
                sod_prompt = '''You are a security and compliance expert. Given the following user-permission-role assignments, identify any combinations of permissions or roles that should not be held by the same user (Segregation of Duties, SoD rules). For each rule, explain why it is risky. Then, list any users who violate these rules.

Return a JSON with:
- "rules": list of {"rule": str, "explanation": str}
- "violations": {user_name: [list of violated rules]}

Example:
{
  "rules": [
    {"rule": "No user should have both 'System Administrator' and 'Sales Enterprise app access'", "explanation": "Combining admin and sales access increases risk of fraud."}
  ],
  "violations": {
    "John Doe": ["No user should have both 'System Administrator' and 'Sales Enterprise app access'"]
  }
}
'''
                # Summarize user-permission-role assignments
                # --- PATCH: Robust userId column detection ---
                user_id_col = None
                for col in ['userId', 'User ID']:
                    if col in user_details.columns:
                        user_id_col = col
                        break
                if not user_id_col:
                    logger.warning("Could not find userId column in user_details for SoD analysis.")
                user_permissions = {}
                for _, details in user_details.iterrows():
                    name = details.get('userName') or details.get('User Name') or details.get('Display Name') or details.get('Name') or details.get('email') or details.get('User ID')
                    user_id = details.get(user_id_col) if user_id_col else None
                    perms = set()
                    if user_id is not None and 'userId' in app_role_assignments.columns:
                        assignments = app_role_assignments[app_role_assignments['userId'] == user_id]
                        for _, row in assignments.iterrows():
                            role_id = row.get('roleId')
                            if role_id and role_id in app_roles['roleId'].values:
                                role_name = app_roles[app_roles['roleId'] == role_id]['roleName'].values[0]
                                perms.add(role_name)
                    user_permissions[name] = list(perms)
                sod_input = {"user_permissions": user_permissions}
                sod_llm_payload = {
                    "messages": [
                        {"role": "system", "content": "You are a security and compliance expert. Always respond with valid JSON."},
                        {"role": "user", "content": sod_prompt + "\n" + json.dumps(sod_input)}
                    ],
                    "max_tokens": 2000,
                    "temperature": 0,
                    "response_format": {"type": "json_object"}
                }
                # Use AzureChatOpenAI or your LLM client
                try:
                    sod_llm = AzureChatOpenAI(
                        azure_endpoint=config["AZURE_OPENAI_ENDPOINT"],
                        api_key=config["AZURE_OPENAI_API_KEY"],
                        deployment_name=config["AZURE_OPENAI_DEPLOYMENT_NAME"],
                        api_version=config["AZURE_OPENAI_API_VERSION"],
                        temperature=0,
                        model_kwargs={"response_format": {"type": "json_object"}}
                    )
                    sod_response = sod_llm.invoke(sod_llm_payload["messages"])
                    sod_analysis = safe_parse_json(sod_response["content"])
                except Exception as e:
                    logger.error(f"Error running LLM SoD analysis: {str(e)}")
                    sod_analysis = {"rules": [], "violations": {}, "error": str(e)}
                # Save in results
                combined_results["sod_analysis"] = sod_analysis

                # --- User Role Usage Analysis from CSV ---
                def load_role_usage_summary():
                    csv_path = os.path.join(os.path.dirname(__file__), '../../data/role_usage_per_user_summary.csv')
                    # If file does not exist or is empty, generate it by running the script
                    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
                        script_path = os.path.join(os.path.dirname(__file__), '../analysis/role_usage_heuristic.py')
                        script_dir = os.path.dirname(os.path.abspath(script_path))
                        logger.info(f"Generating {csv_path} by running {script_path} with cwd={script_dir}")
                        subprocess.run(['python', script_path], check=True, cwd=script_dir)
                    df = pd.read_csv(csv_path)
                    if df.empty or len(df.columns) == 0:
                        logger.error(f"Role usage summary file is empty or has no columns: {csv_path}")
                        return {}
                    df = df.replace({np.nan: None})
                    summary = {}
                    for _, row in df.iterrows():
                        summary[row['userId']] = {
                            "userName": row.get("userName", None),
                            "userEmail": row.get("userEmail", None),
                            "assigned_roles": row.get("assigned_roles", None),
                            "used_roles": row.get("used_roles", None),
                            "unused_roles": row.get("unused_roles", None),
                            "assigned_count": row.get("assigned_count", 0),
                            "used_count": row.get("used_count", 0),
                            "unused_count": row.get("unused_count", 0),
                        }
                    return summary
                combined_results["user_role_usage"] = load_role_usage_summary()
                return {"results": combined_results}
                
            except Exception as e:
                logger.error(f"Error during analysis: {str(e)}", exc_info=True)
                raise

        workflow = StateGraph(AnalysisState)
        workflow.add_node("retrieve", retrieve)
        workflow.add_node("analyze", analyze)
        workflow.set_entry_point("retrieve")
        workflow.add_edge("retrieve", "analyze")
        workflow.add_edge("analyze", END)
        
        app = workflow.compile()
        query = "Analyze user activity for suspicious behavior and permission issues"
        result = await app.ainvoke({
            "query": query,
            "context": [],
            "user_details": user_details,
            "role_matrix": role_matrix,
            "group_memberships": group_memberships,
            "app_roles": app_roles,
            "app_role_assignments": app_role_assignments,
            "conditional_access_policies": conditional_access_policies,
            "audit_logs": audit_logs,
            "signin_logs": signin_logs,
            "results": {}
        })
        return result["results"]
        
    except Exception as e:
        logger.error(f"Failed to run analysis: {str(e)}", exc_info=True)
        raise