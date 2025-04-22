import uuid
import threading
import sqlite3
import json
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from scan import scan_host
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
security = HTTPBearer()
master_key = os.getenv("MASTER_KEY", "default_master_key")

class ScanRequest(BaseModel):
    host: str
    ports: str = "1-1024"

def get_db():
    conn = sqlite3.connect("scanner.db", check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS APIKeys (
            api_key TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ScanResults (
            uid TEXT PRIMARY KEY,
            host TEXT,
            ports TEXT,
            result JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    return conn

def validate_api_key(api_key: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT api_key FROM APIKeys WHERE api_key = ?", (api_key,))
    return cursor.fetchone() is not None

@app.post("/generate-api-key")
async def generate_api_key(
    auth: HTTPAuthorizationCredentials = Depends(security)
):
    if auth.credentials != master_key:  # Validate from header [[6]]
        raise HTTPException(status_code=403, detail="Invalid master key")
    
    new_key = str(uuid.uuid4())
    conn = get_db()
    conn.execute("INSERT INTO APIKeys (api_key) VALUES (?)", (new_key,))
    conn.commit()
    return {"api_key": new_key}

@app.post("/scan")
async def start_scan(
    scan_request: ScanRequest,
    auth: HTTPAuthorizationCredentials = Depends(security)
):
    if not validate_api_key(auth.credentials):
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    uid = str(uuid.uuid4())
    thread = threading.Thread(
        target=perform_scan,
        args=(uid, scan_request.host, scan_request.ports)
    )
    thread.start()
    return {"uid": uid}

def perform_scan(uid: str, host: str, ports: str):
    result = scan_host(host, ports)
    conn = get_db()
    conn.execute(
        "INSERT INTO ScanResults (uid, host, ports, result) VALUES (?, ?, ?, ?)",
        (uid, host, ports, json.dumps(result))
    )
    conn.commit()

@app.get("/results/{uid}")
async def get_results(
    uid: str,
    auth: HTTPAuthorizationCredentials = Depends(security)
):
    if not validate_api_key(auth.credentials):
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT result FROM ScanResults WHERE uid = ?", (uid,))
    result = cursor.fetchone()
    
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found or scanning")
    
    return json.loads(json.loads(result[0]))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
