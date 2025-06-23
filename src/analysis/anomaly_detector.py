import logging
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
from collections import Counter
from src.utils.config import setup_logging
from math import radians, cos, sin, asin, sqrt

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

def get_user_location_profile(signin_logs: pd.DataFrame, user_id: str) -> dict:
    user_signins = signin_logs[signin_logs["userId"] == user_id]
    if user_signins.empty:
        return {"most_frequent": "Unknown", "frequency": 0}
    
    locations = user_signins.groupby(["locationCity", "locationCountry"]).size().reset_index(name="Count")
    total_signins = len(user_signins)
    if locations.empty:
        return {"most_frequent": "Unknown", "frequency": 0}
    
    most_frequent = locations.sort_values("Count", ascending=False).iloc[0]
    location_str = f"{most_frequent['locationCity']}, {most_frequent['locationCountry']}"
    frequency = most_frequent["Count"] / total_signins
    return {"most_frequent": location_str, "frequency": frequency}

def get_user_signin_times(signin_logs: pd.DataFrame, user_id: str) -> dict:
    user_signins = signin_logs[signin_logs["userId"] == user_id]
    if user_signins.empty:
        return {"hours": [], "typical_hours": "Unknown"}
    
    signin_hours = pd.to_datetime(user_signins["signInDateTime"], errors='coerce').dt.hour
    hours_list = [hour for hour in signin_hours if pd.notna(hour)]
    
    if not hours_list:
        logger.debug(f"No valid sign-in hours for user {user_id}")
        return {"hours": [], "typical_hours": "Unknown"}
    
    hour_counts = Counter(hours_list)
    total_signins = len(hours_list)
    cumulative_freq = 0
    typical_hours = []
    for hour, count in hour_counts.most_common():
        if pd.isna(hour):
            continue
        typical_hours.append(int(hour))
        cumulative_freq += count / total_signins
        if cumulative_freq >= 0.6:
            break
    
    if not typical_hours:
        logger.debug(f"No typical hours identified for user {user_id}")
        return {"hours": hours_list, "typical_hours": "Unknown"}
    
    typical_hours.sort()
    typical_hours_str = f"{typical_hours[0]}:00" if len(typical_hours) == 1 else f"{min(typical_hours)}:00 to {max(typical_hours)}:00"
    return {"hours": hours_list, "typical_hours": typical_hours_str}

def create_comprehensive_user_mapping(user_details: pd.DataFrame, signin_logs: pd.DataFrame, vectorstore_metadata: list) -> tuple:
    """
    Create comprehensive user mapping from all available sources with improved handling
    Includes mapping via azureAdObjectId to userId in signin_logs
    Returns: (user_mapping, user_department, missing_users_info)
    """
    user_mapping = {}
    user_department = {}
    missing_users_info = []
    azure_to_user_id = {}  # Mapping from azureAdObjectId to userId in user_details
    
    # Step 1: Standardize user ID column names across all sources
    def standardize_id(user_id):
        if pd.isna(user_id):
            return None
        return str(user_id).strip().lower()
    
    # Step 2: Create mapping from user_details with robust column detection
    username_columns = ['UserName', 'userName', 'Username', 'username', 'DisplayName', 'displayName', 'Name', 'name']
    email_columns = ['email', 'Email', 'emailAddress', 'EmailAddress', 'mail', 'Mail', 'userPrincipalName']
    dept_columns = ['Department', 'department', 'Dept', 'dept', 'Division', 'division']
    
    # Find the best ID column in user_details
    user_id_column = None
    for col in ['User ID', 'userId', 'user_id', 'UserID', 'ID', 'id', 'azureAdObjectId']:
        if col in user_details.columns:
            user_id_column = col
            break
    
    if not user_id_column:
        raise ValueError("No valid user ID column found in user_details")
    
    logger.info(f"Using '{user_id_column}' as primary user ID column")
    
    # Process user_details and create azureAdObjectId to userId mapping
    for _, row in user_details.iterrows():
        user_id = standardize_id(row[user_id_column])
        if not user_id or user_id == 'nan':
            continue
            
        # Map azureAdObjectId to userId if available
        if 'azureAdObjectId' in row and not pd.isna(row['azureAdObjectId']):
            azure_id = standardize_id(row['azureAdObjectId'])
            if azure_id and azure_id != 'nan':
                azure_to_user_id[azure_id] = user_id
                logger.debug(f"Mapped azureAdObjectId {azure_id} to userId {user_id}")
            
        # Find username from multiple possible columns
        username = None
        username_source = None
        for col in username_columns:
            if col in row and not pd.isna(row[col]) and str(row[col]).strip().lower() not in ['', 'nan']:
                username = str(row[col]).strip()
                username_source = f"user_details.{col}"
                break
        
        # Fallback to email if no username found
        if not username:
            for col in email_columns:
                if col in row and not pd.isna(row[col]) and str(row[col]).strip().lower() not in ['', 'nan']:
                    username = str(row[col]).split('@')[0].replace('.', ' ').title()
                    username_source = f"user_details.{col} (email)"
                    break
        
        # Final fallback to user ID
        if not username:
            username = f"User-{user_id[:8]}"
            username_source = "user_id_fallback"
        
        # Get department
        department = "Unknown"
        for col in dept_columns:
            if col in row and not pd.isna(row[col]) and str(row[col]).strip().lower() not in ['', 'nan']:
                department = str(row[col]).strip()
                break
                
        user_mapping[user_id] = username
        user_department[user_id] = department

    # Step 3: Collect all unique user IDs from all sources
    all_user_ids = set(user_mapping.keys())
    signin_user_ids = set()
    
    # From signin logs, attempt to map via azureAdObjectId
    if not signin_logs.empty and 'userId' in signin_logs.columns:
        signin_logs['original_userId'] = signin_logs['userId']  # Preserve original for reference
        signin_logs['userId'] = signin_logs['userId'].apply(standardize_id)
        
        # Map signin_logs userId to user_details userId via azureAdObjectId
        signin_logs['mapped_userId'] = signin_logs['userId'].map(azure_to_user_id)
        successful_mappings = signin_logs['mapped_userId'].notna().sum()
        logger.info(f"Successfully mapped {successful_mappings} signin_logs userIds to user_details userIds via azureAdObjectId")
        
        # Use mapped userId where available, otherwise fall back to original
        signin_logs['userId'] = signin_logs['mapped_userId'].combine_first(signin_logs['original_userId'])
        signin_user_ids = set(signin_logs['userId'].dropna().unique())
        all_user_ids.update(signin_user_ids)
    
    # From vectorstore metadata
    vectorstore_user_ids = set()
    for meta in vectorstore_metadata:
        user_id = standardize_id(meta.get("userId"))
        if user_id:
            # Also attempt to map vectorstore userId via azureAdObjectId
            mapped_id = azure_to_user_id.get(user_id, user_id)
            vectorstore_user_ids.add(mapped_id)
    all_user_ids.update(vectorstore_user_ids)
    
    # Step 4: Handle missing users (present in logs/vectorstore but not in user_details)
    missing_user_ids = all_user_ids - set(user_mapping.keys())
    
    logger.info(f"Total mapped users: {len(user_mapping)}")
    logger.info(f"Total users in signin logs: {len(signin_user_ids) if not signin_logs.empty else 0}")
    logger.info(f"Total users in vectorstore: {len(vectorstore_user_ids)}")
    logger.info(f"Missing users (not in user_details): {len(missing_user_ids)}")
    
    # Create reasonable names for missing users
    for user_id in missing_user_ids:
        # Try to extract name from ID format
        if '@' in user_id:  # Looks like email
            username = user_id.split('@')[0].replace('.', ' ').title()
        elif '-' in user_id and len(user_id) > 20:  # Looks like GUID
            username = f"Unknown-{user_id[:8]}"
        else:
            username = f"User-{user_id[:8]}"
            
        user_mapping[user_id] = username
        user_department[user_id] = "Unknown"
        missing_users_info.append({
            'user_id': user_id,
            'generated_username': username,
            'source': 'signin_logs' if user_id in signin_user_ids else 'vectorstore'
        })
    
    # Log sample mappings
    logger.info("Sample user mappings:")
    for i, (uid, name) in enumerate(list(user_mapping.items())[:5]):
        logger.info(f"  {uid} -> {name} (dept: {user_department.get(uid, 'Unknown')})")
    
    if missing_users_info:
        logger.info(f"Generated names for {len(missing_users_info)} missing users")
        for info in missing_users_info[:5]:
            logger.info(f"  Missing user: {info['user_id']} -> {info['generated_username']}")
    
    return user_mapping, user_department, missing_users_info

def haversine(lat1, lon1, lat2, lon2):
    # Calculate the great circle distance between two points on the earth (specified in decimal degrees)
    # Returns distance in kilometers
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    # Haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    r = 6371  # Radius of earth in kilometers
    return c * r

# Simple city/country to lat/lon mapping for demo (expand as needed)
CITY_COORDS = {
    ("Dubayy", "AE"): (25.276987, 55.296249),
    ("Dubai", "AE"): (25.276987, 55.296249),
    ("Abu Zaby", "AE"): (24.453884, 54.377343),
    ("Gurgaon", "IN"): (28.459497, 77.026634),
    ("Bengaluru", "IN"): (12.971599, 77.594566),
    ("Delhi", "IN"): (28.613939, 77.209023),
    ("Kolkata", "IN"): (22.572646, 88.363895),
    ("Mumbai", "IN"): (19.076090, 72.877426),
    ("Singapore", "SG"): (1.352083, 103.819836),
    ("Agra", "IN"): (27.176670, 78.008072),
    ("Sembakkam", "IN"): (12.9116, 80.1978),
    ("Kathmandu", "NP"): (27.7172, 85.3240),
    ("Kolhapur", "IN"): (16.7050, 74.2433),
    ("Unknown", "Unknown"): (0, 0),
    # Add more as needed
}

def get_lat_lon(city, country):
    return CITY_COORDS.get((city, country), (None, None))

def detect_anomalies(context: list, vectorstore, signin_logs: pd.DataFrame, user_details: pd.DataFrame) -> dict:
    logger.info("Detecting anomalies")
    anomalies = {}

    try:
        # Log DataFrame details
        logger.info("=== USER DATA VALIDATION ===")
        logger.info(f"User details shape: {user_details.shape}")
        logger.info(f"User details columns: {user_details.columns.tolist()}")
        logger.info(f"Signin logs shape: {signin_logs.shape}")
        logger.info(f"Signin logs columns: {signin_logs.columns.tolist()}")

        # Parse timestamps
        if not signin_logs.empty:
            signin_logs['signInDateTime'] = pd.to_datetime(
                signin_logs['signInDateTime'], errors='coerce', utc=True
            )
            invalid_signins = signin_logs['signInDateTime'].isna().sum()
            logger.info(f"Invalid signInDateTime entries: {invalid_signins}")
            if invalid_signins > 0:
                logger.warning(f"Sample invalid entries: {signin_logs[signin_logs['signInDateTime'].isna()][['userId', 'signInDateTime']].head().to_dict()}")
                if invalid_signins > 0.5 * len(signin_logs):
                    logger.error("Over 50% of signInDateTime entries invalid. Exporting for analysis.")
                    signin_logs[signin_logs['signInDateTime'].isna()].to_csv("data/invalid_signin_logs.csv", index=False)
        else:
            logger.warning("Sign-in logs DataFrame is empty.")

        # Step 1: Retrieve documents from vectorstore and extract metadata
        docs = vectorstore.similarity_search("suspicious activity", k=1000)
        if not docs:
            logger.info("No relevant documents found in vectorstore")

        # Extract embeddings and metadata
        embeddings = []
        metadata_list = []
        user_roles = {}
        for doc in docs:
            meta = doc.metadata
            if "embedding" not in meta:
                logger.debug(f"Document missing embedding: {meta}")
                continue
            embeddings.append(meta["embedding"])
            metadata_list.append(meta)
            
            user_id = str(meta.get("userId", "unknown")).strip().lower()
            if user_id != "unknown":
                role = meta.get("appRole", "Unknown Role")
                user_roles.setdefault(user_id, []).append(role)

        # Step 2: Create comprehensive user mapping
        user_mapping, user_department, missing_users_info = create_comprehensive_user_mapping(
            user_details, signin_logs, metadata_list
        )

        # Log mapping statistics
        logger.info(f"=== USER MAPPING STATISTICS ===")
        logger.info(f"Successfully mapped {len(user_mapping)} users")
        if missing_users_info:
            logger.info(f"Generated names for {len(missing_users_info)} users not found in user_details")
            for info in missing_users_info[:5]:  # Show first 5 examples
                logger.info(f"  {info['user_id']} -> {info['generated_username']} (from {info['source']})")

        embeddings = np.array(embeddings) if embeddings else np.array([])

        # Step 3: Isolation Forest for anomaly detection
        if embeddings.size > 0 and len(embeddings) >= 10:
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            labels = iso_forest.fit_predict(embeddings)
            
            for label, meta in zip(labels, metadata_list):
                if label == -1:
                    user_id = str(meta.get("userId", "unknown")).strip().lower()
                    if user_id != "unknown":
                        username = user_mapping.get(user_id, f"Unknown-User-{user_id}")
                        department = user_department.get(user_id, "Unknown")
                        roles = user_roles.get(user_id, ["Unknown Role"])
                        description = (
                            f"User {username} has an unusual activity pattern (Roles: {', '.join(roles)}, Department: {department}). "
                            f"Details: {meta.get('anomaly_description', 'Unusual activity pattern')}"
                        )
                        if username in anomalies:
                            anomalies[username] += f"; {description}"
                        else:
                            anomalies[username] = description
        else:
            logger.info("Too few embeddings for clustering; skipping Isolation Forest")

        # Step 4: Frequent sign-in detection
        if not signin_logs.empty:
            user_signins = signin_logs.groupby("userId").size().reset_index(name="signInCount")
            if not user_signins.empty:
                avg_signins = user_signins["signInCount"].mean()
                std_signins = user_signins["signInCount"].std() if len(user_signins) > 1 else 0
                threshold = max(avg_signins + 2 * std_signins, 3)

                for _, row in user_signins.iterrows():
                    user_id = str(row["userId"]).strip().lower()
                    signin_count = row["signInCount"]
                    if signin_count > threshold:
                        username = user_mapping.get(user_id, f"Unknown-User-{user_id}")
                        description = (
                            f"User {username} had {int(signin_count)} sign-ins (avg: {avg_signins:.1f}, threshold: {threshold:.1f}) in the period."
                        )
                        if username in anomalies:
                            anomalies[username] += f"; {description}"
                        else:
                            anomalies[username] = description

        # Step 5: Detect unusual locations
        if not signin_logs.empty:
            for user_id in signin_logs["userId"].unique():
                user_id = str(user_id).strip().lower()
                user_signins = signin_logs[signin_logs["userId"] == user_id]
                location_profile = get_user_location_profile(signin_logs, user_id)
                most_frequent_location = location_profile["most_frequent"]
                frequency = location_profile["frequency"]
                username = user_mapping.get(user_id, f"Unknown-User-{user_id}")
                # department = user_department.get(user_id, "Unknown")

                if frequency >= 0.5:
                    for _, signin in user_signins.iterrows():
                        if pd.isna(signin['signInDateTime']):
                            continue
                        signin_location = f"{signin['locationCity']}, {signin['locationCountry']}"
                        if signin_location != most_frequent_location and signin_location != "Unknown, Unknown":
                            description = (
                                f"User usually signs in from {most_frequent_location} ({frequency*100:.1f}%), "
                                f"but on {signin['signInDateTime']:%Y-%m-%d} signed in from {signin_location}."
                            )
                            if username in anomalies:
                                anomalies[username] += f"; {description}"
                            else:
                                anomalies[username] = description

        # Step 6 (NEW): Flag new country sign-ins
        if not signin_logs.empty:
            for user_id in signin_logs["userId"].unique():
                user_id = str(user_id).strip().lower()
                user_signins = signin_logs[signin_logs["userId"] == user_id].sort_values("signInDateTime")
                username = user_mapping.get(user_id, f"Unknown-User-{user_id}")
                seen_countries = set()
                prev_device = None
                device_change_flagged = False
                for idx, signin in user_signins.iterrows():
                    country = signin.get("locationCountry", "Unknown")
                    # New country sign-in
                    if country not in seen_countries and len(seen_countries) > 0 and country != "Unknown":
                        description = (
                            f"New country sign-in detected: User {username} signed in from {country} for the first time on {signin['signInDateTime']:%Y-%m-%d %H:%M}."
                        )
                        if username in anomalies:
                            anomalies[username] += f"; {description}"
                        else:
                            anomalies[username] = description
                    seen_countries.add(country)
                    # Device change anomaly
                    device = signin.get("deviceId") or signin.get("userAgent")
                    if prev_device is not None and device and device != prev_device and not device_change_flagged:
                        description = (
                            f"Device change detected: User {username} signed in from a new device ({device}) on {signin['signInDateTime']:%Y-%m-%d %H:%M}. Previous device: {prev_device}."
                        )
                        if username in anomalies:
                            anomalies[username] += f"; {description}"
                        else:
                            anomalies[username] = description
                        device_change_flagged = True  # Only flag once per user per run
                    if device:
                        prev_device = device

        # Step 6b: Rapid sign-in failures
        if not signin_logs.empty and ("signInStatus" in signin_logs.columns or "status" in signin_logs.columns):
            status_col = "signInStatus" if "signInStatus" in signin_logs.columns else "status"
            for user_id in signin_logs["userId"].unique():
                user_id = str(user_id).strip().lower()
                user_signins = signin_logs[(signin_logs["userId"] == user_id) & (signin_logs[status_col].astype(str).str.lower().str.contains("fail"))].sort_values("signInDateTime")
                username = user_mapping.get(user_id, f"Unknown-User-{user_id}")
                times = list(user_signins["signInDateTime"])
                for i in range(len(times) - 2):
                    t0, t1, t2 = times[i], times[i+1], times[i+2]
                    if pd.notna(t0) and pd.notna(t2) and (t2 - t0).total_seconds() <= 600:  # 10 minutes
                        description = (
                            f"Rapid sign-in failures detected: User {username} had 3 or more failed sign-ins within 10 minutes (starting {t0:%Y-%m-%d %H:%M})."
                        )
                        if username in anomalies:
                            anomalies[username] += f"; {description}"
                        else:
                            anomalies[username] = description
                        break  # Only flag once per user per run

        # Step 7: Detect users without sign-in activity
        all_users = set(user_mapping.keys())
        users_with_signins = {str(uid).strip().lower() for uid in signin_logs["userId"].unique()} if not signin_logs.empty else set()
        vectorstore_users = set(user_roles.keys())
        all_users.update(vectorstore_users)

        for user_id in all_users:
            user_id = str(user_id).strip().lower()
            username = user_mapping.get(user_id, f"Unknown-User-{user_id}")
            department = user_department.get(user_id, "Unknown")
            roles = user_roles.get(user_id, ["Unknown Role"])

            if user_id not in users_with_signins:
                high_privilege_roles = [r for r in roles if "Admin" in r or "Manager" in r]
                if high_privilege_roles:
                    description = (
                        f"User {username} has no sign-in activity but holds high-privilege roles: {', '.join(high_privilege_roles)}. Potential dormant account risk."
                    )
                    if username in anomalies:
                        anomalies[username] += f"; {description}"
                    else:
                        anomalies[username] = description

            # Check for Azure AD sync issues (only for users in user_details)
            user_id_column = None
            for col in ['User ID', 'userId', 'user_id', 'UserID', 'ID', 'id']:
                if col in user_details.columns:
                    user_id_column = col
                    break
                    
            if user_id_column and user_id in user_mapping:
                user_data = user_details[user_details[user_id_column] == user_id]
                if not user_data.empty and ('azureAdObjectId' not in user_data.columns or pd.isna(user_data['azureAdObjectId'].iloc[0])):
                    description = (
                        f"User {username} is missing an Azure AD object ID (Roles: {', '.join(roles)}). Potential Azure AD sync issue."
                    )
                    if username in anomalies:
                        anomalies[username] += f"; {description}"
                    else:
                        anomalies[username] = description

        # Step 8: Impossible travel detection
        if not signin_logs.empty:
            for user_id in signin_logs["userId"].unique():
                user_id = str(user_id).strip().lower()
                user_signins = signin_logs[signin_logs["userId"] == user_id].sort_values("signInDateTime")
                username = user_mapping.get(user_id, f"Unknown-User-{user_id}")
                prev_time = None
                prev_city = None
                prev_country = None
                prev_lat = None
                prev_lon = None
                for _, signin in user_signins.iterrows():
                    if pd.isna(signin["signInDateTime"]):
                        continue
                    city = signin.get("locationCity", "Unknown")
                    country = signin.get("locationCountry", "Unknown")
                    lat, lon = get_lat_lon(city, country)
                    curr_time = signin["signInDateTime"]
                    if prev_time and lat is not None and lon is not None and prev_lat is not None and prev_lon is not None:
                        time_diff = (curr_time - prev_time).total_seconds() / 3600.0  # in hours
                        distance = haversine(prev_lat, prev_lon, lat, lon)
                        # If distance > 1000km and time_diff < 4 hours, flag as impossible travel
                        if distance > 1000 and time_diff < 4:
                            description = (
                                f"Impossible travel detected: User {username} signed in at {prev_city}, {prev_country} at {prev_time.strftime('%Y-%m-%d %H:%M')} "
                                f"and then at {city}, {country} at {curr_time.strftime('%Y-%m-%d %H:%M')} (distance: {distance:.0f} km, time diff: {time_diff:.1f}h)."
                            )
                            if username in anomalies:
                                anomalies[username] += f"; {description}"
                            else:
                                anomalies[username] = description
                    prev_time = curr_time
                    prev_city = city
                    prev_country = country
                    prev_lat = lat
                    prev_lon = lon

        logger.info(f"Detected {len(anomalies)} anomalies")
        
        # Log some examples of successful mappings
        logger.info("=== ANOMALY MAPPING EXAMPLES ===")
        for i, (username, description) in enumerate(list(anomalies.items())[:3]):
            logger.info(f"Example {i+1}: {username} -> {description[:100]}...")
        
        return anomalies

    except Exception as e:
        logger.error(f"Error detecting anomalies: {str(e)}")
        raise