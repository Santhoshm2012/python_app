from dotenv import load_dotenv
import os
import logging

def setup_logging():
    """
    Set up logging configuration for the application.
    Logs to both file (app.log) and console.
    """
    logger = logging.getLogger()
    if not logger.handlers:  # Avoid duplicate handlers
        logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler("app.log")
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))
        logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))
        logger.addHandler(console_handler)
    
    return logger

def load_config():
    """
    Load environment variables from .env file.
    Returns: Dict of config values.
    """
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Loading environment variables")
    
    try:
        load_dotenv()
        config = {
            "AZURE_OPENAI_API_KEY": os.getenv("AZURE_OPENAI_API_KEY"),
            "AZURE_OPENAI_ENDPOINT": os.getenv("AZURE_OPENAI_ENDPOINT"),
            "AZURE_OPENAI_DEPLOYMENT_NAME": os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"),
            "AZURE_OPENAI_API_VERSION": os.getenv("AZURE_OPENAI_API_VERSION")
        }
        logger.info("Environment variables loaded successfully")
        return config
    except Exception as e:
        logger.error(f"Failed to load environment variables: {str(e)}")
        raise