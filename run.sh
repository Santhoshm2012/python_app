#!/bin/bash

echo "Running data fetcher..."
cd "$(dirname "$0")"  # Change to the project root directory
python scripts/data_fetcher.py

if [ $? -eq 0 ]; then
    echo "Data fetcher completed successfully. Starting FastAPI server..."
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
else
    echo "Data fetcher failed. Please check the logs for details."
    exit 1
fi