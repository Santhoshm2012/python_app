import logging
import pandas as pd
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_community.document_loaders import DataFrameLoader
import os
import time
import torch
import faiss
import numpy as np
import gc
import psutil
from src.utils.config import setup_logging
from typing import List, Dict, Any
import traceback

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

# Custom docstore as a fallback for InMemoryDocstore
class SimpleDocstore:
    def __init__(self, docs_dict):
        self._docs = docs_dict

    def search(self, id):
        return self._docs.get(id, None)

# Attempt to import InMemoryDocstore
try:
    from langchain_core.stores import InMemoryDocstore
    logger.info("Successfully imported InMemoryDocstore from langchain_core.stores")
except ImportError:
    try:
        from langchain_community.vectorstores.utils import InMemoryDocstore
        logger.warning("Imported InMemoryDocstore from langchain_community.vectorstores.utils (older LangChain version detected)")
    except ImportError:
        logger.warning("Could not import InMemoryDocstore; using SimpleDocstore as fallback")
        InMemoryDocstore = None

def log_memory_usage():
    """Log current memory usage."""
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    logger.info(f"Memory usage: RSS={mem_info.rss / 1024**2:.2f} MB, VMS={mem_info.vms / 1024**2:.2f} MB")

def calculate_nlist(num_vectors: int) -> int:
    """
    Dynamically calculate the number of clusters (nlist) for FAISS IndexIVFFlat based on dataset size.
    """
    if num_vectors < 10000:
        return 10
    elif num_vectors < 100000:
        return 50
    else:
        return 100

def get_user_location_history(signin_logs: pd.DataFrame) -> Dict[str, str]:
    """
    Precompute the most frequent sign-in location for all users to optimize metadata generation.
    
    Args:
        signin_logs (pd.DataFrame): Sign-in logs DataFrame.
    
    Returns:
        Dict[str, str]: Mapping of user_id to their most frequent location.
    """
    logger.info("Precomputing user location history for all users")
    start_time = time.time()
    
    # Group by userId and location, count occurrences
    location_counts = (
        signin_logs.groupby(["userId", "locationCity", "locationCountry"])
        .size()
        .reset_index(name="Count")
    )
    
    # Find the most frequent location per user
    idx = location_counts.groupby("userId")["Count"].idxmax()
    most_frequent = location_counts.loc[idx]
    user_locations = {
        row["userId"]: f"{row['locationCity']}, {row['locationCountry']}"
        for _, row in most_frequent.iterrows()
    }
    
    # Handle users with no sign-ins
    all_users = set(signin_logs["userId"])
    for user_id in all_users:
        if user_id not in user_locations:
            user_locations[user_id] = "Unknown"
    
    logger.info(f"Precomputed location history in {time.time() - start_time:.2f} seconds")
    return user_locations

def generate_embeddings(
    audit_logs: pd.DataFrame,
    signin_logs: pd.DataFrame,
    user_details: pd.DataFrame,
    app_role_assignments: pd.DataFrame,
    batch_size: int = 64,
    save_vectorstore: bool = True,
    sample_fraction: float = 1.0
) -> FAISS:
    """
    Generate embeddings for logs and store in FAISS with optimizations for performance and memory usage.
    
    Args:
        audit_logs (pd.DataFrame): DataFrame containing audit logs.
        signin_logs (pd.DataFrame): DataFrame containing sign-in logs.
        user_details (pd.DataFrame): DataFrame containing user details.
        app_role_assignments (pd.DataFrame): DataFrame containing app role assignments.
        batch_size (int): Batch size for embedding generation (default: 64).
        save_vectorstore (bool): Whether to save the vectorstore to disk (default: True).
        sample_fraction (float): Fraction of logs to sample for embedding (default: 1.0, range: 0.0–1.0).
    
    Returns:
        FAISS: FAISS vectorstore containing the embeddings.
    """
    logger.info("Starting embedding generation")
    total_start_time = time.time()

    try:
        # Validate inputs
        if not 0.0 <= sample_fraction <= 1.0:
            raise ValueError(f"sample_fraction must be between 0.0 and 1.0, got {sample_fraction}")
        logger.info(f"Using sample_fraction={sample_fraction:.2f} ({sample_fraction*100:.1f}%)")

        if not isinstance(batch_size, int) or batch_size <= 0:
            raise ValueError(f"batch_size must be a positive integer, got {batch_size}")
        logger.info(f"Using batch_size={batch_size}")

        # Step 1: Initialize Hugging Face embeddings with GPU support if available
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Using device: {device}")
        
        init_start_time = time.time()
        embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/paraphrase-MiniLM-L3-v2",
            model_kwargs={"device": device},
            encode_kwargs={"batch_size": batch_size}
        )
        init_time = time.time() - init_start_time
        logger.info(f"Initialized Hugging Face embeddings with batch_size={batch_size}")
        logger.info(f"Embedding initialization took {init_time:.2f} seconds")
        log_memory_usage()

        # Step 2: Create embedding text using vectorized operations
        logger.info("Creating embedding text for logs")
        text_start_time = time.time()

        # Sample the DataFrames if sample_fraction < 1.0
        total_audit_logs = len(audit_logs)
        total_signin_logs = len(signin_logs)
        if sample_fraction < 1.0:
            logger.info(f"Sampling {sample_fraction*100:.1f}% of audit_logs ({total_audit_logs} rows) and signin_logs ({total_signin_logs} rows)")
            audit_logs = audit_logs.sample(frac=sample_fraction, random_state=42).copy()
            signin_logs = signin_logs.sample(frac=sample_fraction, random_state=42).copy()
            logger.info(f"After sampling: audit_logs={len(audit_logs)} rows, signin_logs={len(signin_logs)} rows")
        else:
            logger.info(f"Using all logs: audit_logs={total_audit_logs} rows, signin_logs={total_signin_logs} rows")
            audit_logs = audit_logs.copy()
            signin_logs = signin_logs.copy()

        # Precompute user location history to optimize metadata generation
        user_locations = get_user_location_history(signin_logs)

        # Map user IDs to departments from user_details
        user_departments = dict(zip(user_details["User ID"].astype(str), user_details.get("Department", "Unknown")))

        # Map user IDs to roles from app_role_assignments
        user_roles = {}
        if "userId" in app_role_assignments.columns and "roleId" in app_role_assignments.columns:
            for _, row in app_role_assignments.iterrows():
                user_id = str(row["userId"])
                role_id = str(row["roleId"])
                user_roles.setdefault(user_id, []).append(role_id)

        # Vectorized operation for audit_logs
        audit_logs["embedding_text"] = (
            "Action at " + audit_logs["activityDateTime"].astype(str) +
            " (Initiated by: " + audit_logs["initiatedByUserId"].astype(str) +
            ", Target: " + audit_logs["targetRecordId"].astype(str) +
            ", Department: " + audit_logs["initiatedByUserId"].map(user_departments).fillna("Unknown") + ")"
        )
        audit_logs["metadata"] = audit_logs.apply(
            lambda row: {
                "type": "audit_log",
                "auditId": row["auditId"],
                "userId": row.get("initiatedByUserId", "unknown"),
                "activityDateTime": row["activityDateTime"],
                "anomaly_description": f"Suspicious audit activity by user {row.get('initiatedByUserId', 'unknown')} on {row['activityDateTime']}",
                "department": user_departments.get(row.get("initiatedByUserId", "unknown"), "Unknown"),
                "roles": user_roles.get(row.get("initiatedByUserId", "unknown"), [])
            },
            axis=1
        )

        # Vectorized operation for signin_logs with enhanced anomaly description
        signin_logs["embedding_text"] = (
            signin_logs["userId"].astype(str) + " signed in to " +
            signin_logs["appDisplayName"].astype(str) + " at " +
            signin_logs["signInDateTime"].astype(str) + " from " +
            signin_logs["locationCity"].astype(str) + ", " +
            signin_logs["locationCountry"].astype(str) +
            " (IP: " + signin_logs["ipAddress"].astype(str) +
            ", Browser: " + signin_logs["browser"].astype(str) +
            ", Status: " + signin_logs["statusMessage"].astype(str) +
            ", Department: " + signin_logs["userId"].map(user_departments).fillna("Unknown") + ")"
        )
        signin_logs["metadata"] = signin_logs.apply(
            lambda row: {
                "type": "signin_log",
                "id": row["id"],
                "userId": row["userId"],
                "signInDateTime": row["signInDateTime"],
                "locationCity": row.get("locationCity", "Unknown"),
                "locationCountry": row.get("locationCountry", "Unknown"),
                "anomaly_description": (
                    f"Sign-in by user {row['userId']} from {row.get('locationCity', 'Unknown')}, {row.get('locationCountry', 'Unknown')}"
                    f" at {row['signInDateTime']}. Typical location: {user_locations.get(row['userId'], 'Unknown')}"
                ),
                "department": user_departments.get(row["userId"], "Unknown"),
                "roles": user_roles.get(row["userId"], [])
            },
            axis=1
        )
        
        text_end_time = time.time()
        logger.info(f"Text generation took {text_end_time - text_start_time:.2f} seconds")
        log_memory_usage()

        # Step 3: Convert DataFrames to documents
        logger.info("Converting DataFrames to documents")
        docs_start_time = time.time()
        
        audit_docs = DataFrameLoader(audit_logs, page_content_column="embedding_text").load()
        signin_docs = DataFrameLoader(signin_logs, page_content_column="embedding_text").load()

        # Add metadata to documents
        for doc, metadata in zip(audit_docs, audit_logs["metadata"]):
            doc.metadata = metadata
        for doc, metadata in zip(signin_docs, signin_logs["metadata"]):
            doc.metadata = metadata

        all_docs = audit_docs + signin_docs
        logger.info(f"Total documents to embed: {len(all_docs)}")
        docs_end_time = time.time()
        logger.info(f"Document conversion took {docs_end_time - docs_start_time:.2f} seconds")
        log_memory_usage()

        # Step 4: Generate embeddings in chunks to optimize memory usage
        logger.info("Generating embeddings in chunks")
        embed_start_time = time.time()
        
        texts = [doc.page_content for doc in all_docs]
        chunk_size = 5000  # Process 5000 documents at a time
        embedded_vectors = []
        
        for i in range(0, len(texts), chunk_size):
            chunk_texts = texts[i:i + chunk_size]
            logger.info(f"Embedding chunk {i//chunk_size + 1}/{(len(texts) + chunk_size - 1)//chunk_size} ({len(chunk_texts)} documents)")
            chunk_embeddings = embeddings.embed_documents(chunk_texts)
            embedded_vectors.extend(chunk_embeddings)
            # Clear memory after each chunk
            del chunk_texts
            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            log_memory_usage()
        
        # Clear texts to free memory
        del texts
        gc.collect()
        
        embed_end_time = time.time()
        logger.info(f"Embedding generation took {embed_end_time - embed_start_time:.2f} seconds")
        log_memory_usage()

        # Step 5: Create FAISS vectorstore with embeddings in metadata
        logger.info("Generating FAISS vectorstore")
        faiss_start_time = time.time()

        # Convert embedded vectors to a numpy array with float32 to save memory
        embedded_vectors = np.array(embedded_vectors, dtype=np.float32)
        dimension = embedded_vectors.shape[1]  # Embedding dimension (384 for paraphrase-MiniLM-L3-v2)

        # Dynamically calculate nlist
        nlist = calculate_nlist(len(embedded_vectors))
        logger.info(f"Using nlist={nlist} for FAISS IndexIVFFlat with {len(embedded_vectors)} vectors")

        # Create and train FAISS index
        quantizer = faiss.IndexFlatL2(dimension)
        index = faiss.IndexIVFFlat(quantizer, dimension, nlist, faiss.METRIC_L2)
        index.train(embedded_vectors)
        index.add(embedded_vectors)

        # Add embeddings to document metadata
        docs_with_metadata = []
        for i, (doc, embedding) in enumerate(zip(all_docs, embedded_vectors)):
            metadata = doc.metadata if doc.metadata else {}
            metadata.update({
                "embedding": embedding.tolist()  # Store embedding in metadata as a list
            })
            new_doc = doc.__class__(page_content=doc.page_content, metadata=metadata)
            docs_with_metadata.append(new_doc)

        # Create docstore
        if InMemoryDocstore is not None:
            docstore = InMemoryDocstore({str(i): doc for i, doc in enumerate(docs_with_metadata)})
        else:
            logger.warning("Using SimpleDocstore as a fallback due to missing InMemoryDocstore")
            docstore = SimpleDocstore({str(i): doc for i, doc in enumerate(docs_with_metadata)})
        
        index_to_docstore_id = {i: str(i) for i in range(len(docs_with_metadata))}
        vectorstore = FAISS(
            embedding_function=embeddings.embed_query,  # Pass the embed_query method as embedding_function
            index=index,
            docstore=docstore,
            index_to_docstore_id=index_to_docstore_id
        )

        # Save the vectorstore (optional)
        if save_vectorstore:
            os.makedirs("vector_db", exist_ok=True)
            vectorstore.save_local("vector_db/faiss_index")
            logger.info("Saved FAISS vectorstore to disk")
        else:
            logger.info("Skipping saving vectorstore to disk.")
        
        faiss_end_time = time.time()
        logger.info(f"FAISS vectorstore creation took {faiss_end_time - faiss_start_time:.2f} seconds")
        log_memory_usage()

        # Step 6: Drop temporary columns from DataFrames
        audit_logs.drop(columns=["embedding_text", "metadata"], inplace=True, errors="ignore")
        signin_logs.drop(columns=["embedding_text", "metadata"], inplace=True, errors="ignore")

        total_time = time.time() - total_start_time
        logger.info(f"Total embedding generation took {total_time:.2f} seconds")
        return vectorstore

    except Exception as e:
        logger.error(f"Failed to generate embeddings: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise