import time
import redis
import requests
import json
import random
import csv
import os
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from backend.ai_guard import analyze_risk_with_ai
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Smart AI Rate Limiter")

# --- CONFIGURATION ---
AUDIT_LOG_FILE = "security_audit.csv"

# --- REDIS CONNECTION ---
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_password = os.getenv("REDIS_PASSWORD", None)
use_ssl = redis_host != "localhost"

try:
    redis_client = redis.Redis(
        host=redis_host,
        port=int(os.getenv("REDIS_PORT", 6379)),
        password=redis_password,
        ssl=use_ssl,
        db=0,
        decode_responses=True,
        socket_timeout=5
    )
    redis_client.ping()
    print("✅ Connected to Redis")
except Exception as e:
    print(f"⚠️ Redis Connection Failed: {e}")
    redis_client = None


def get_ip_location(ip_address):
    # 1. Define Mock Locations (Used for Localhost & Docker IPs)
    mock_locations = [
        {"lat": 40.7128, "lon": -74.0060, "city": "New York, US"},
        {"lat": 51.5074, "lon": -0.1278, "city": "London, UK"},
        {"lat": 35.6895, "lon": 139.6917, "city": "Tokyo, JP"},
        {"lat": 19.0760, "lon": 72.8777, "city": "Mumbai, IN"},
        {"lat": 55.7558, "lon": 37.6173, "city": "Moscow, RU"},
        {"lat": 1.3521, "lon": 103.8198, "city": "Singapore, SG"},
        {"lat": -33.8688, "lon": 151.2093, "city": "Sydney, AU"},
    ]

    # 2. Try to get Real Location
    try:
        # Skip lookup for private Docker ranges (172.x, 192.168.x, 10.x, 127.x) to save time
        if ip_address.startswith(("127.", "172.", "192.168.", "10.", "::1")):
            return random.choice(mock_locations)

        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
        data = response.json()
        
        if data['status'] == 'success':
            return {
                "lat": data['lat'], 
                "lon": data['lon'], 
                "city": f"{data['city']}, {data['countryCode']}"
            }
    except Exception:
        pass # If API fails, fall through to simulation

    # 3. FALLBACK: If real lookup failed (or it's a Docker IP), use a Mock Location
    # This ensures the map ALWAYS has data to show.
    return random.choice(mock_locations)

# --- HELPER 2: LOG TO CSV (COMPLIANCE) ---
def log_security_event_csv(ip, reason, location_data):
    """Appends blocked attacks to a CSV file for permanent auditing."""
    file_exists = os.path.isfile(AUDIT_LOG_FILE)
    with open(AUDIT_LOG_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Timestamp", "IP Address", "Attack Type", "Location", "Action"])
        
        city = location_data.get("city", "Unknown")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([timestamp, ip, reason, city, "BLOCKED"])

# --- MIDDLEWARE (THE BRAIN) ---
@app.middleware("http")
async def smart_rate_limit(request: Request, call_next):
    # 0. Skip logging endpoints to prevent loops
    if request.url.path in ["/logs", "/banned", "/unblock", "/docs", "/openapi.json"]:
        return await call_next(request)

    client_ip = request.client.host
    rate_key = f"rate_limit:{client_ip}"
    ban_key = f"ban:{client_ip}"

    # 1. Check if Banned (Fastest Check)
    if redis_client and redis_client.exists(ban_key):
        reason = redis_client.get(ban_key)
        return JSONResponse(status_code=403, content={"detail": f"Access Denied: Banned for {reason}"})

    # 2. Rate Limiting
    request_count = 1
    if redis_client:
        request_count = redis_client.incr(rate_key)
        if request_count == 1:
            redis_client.expire(rate_key, 60)

    # 3. Security Logic
    status = "ALLOWED"
    risk_score = "SAFE"
    should_ban = False

    # RULE A: DDoS Protection
    if request_count > 50: 
        should_ban = True
        risk_score = "DDOS_HIGH_RATE"

    # RULE B: AI Analysis (Only for POST requests)
    elif request.method == "POST":
        # Read body safely
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="ignore")
        
        # Restore body for the actual endpoint
        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request._receive = receive
        
        # AI Check
        print(f"⚠️ Analyzing {client_ip}...")
        risk_score = analyze_risk_with_ai(body_text)
        if risk_score != "SAFE":
            should_ban = True

    # 4. Handle Ban
    if should_ban:
        status = "BLOCKED"
        if redis_client:
            redis_client.setex(ban_key, 3600, risk_score) # Ban for 1 hour

    # 5. UNIFIED LOGGING (For Dashboard & CSV)
    if redis_client:
        loc_data = get_ip_location(client_ip)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": client_ip,
            "path": request.url.path,
            "status": status,
            "risk_score": risk_score,
            "city": loc_data.get("city", "Unknown"),
            "lat": loc_data.get("lat", 0),
            "lon": loc_data.get("lon", 0)
        }
        
        # Push to Redis List (Keep last 100 entries)
        redis_client.lpush("dashboard_logs", json.dumps(log_entry))
        redis_client.ltrim("dashboard_logs", 0, 99)

        if status == "BLOCKED":
            log_security_event_csv(client_ip, risk_score, loc_data)
            print(f"🚫 BLOCKED {client_ip}: {risk_score}")

    # 6. Return Response
    if should_ban:
        code = 429 if risk_score == "DDOS_HIGH_RATE" else 403
        return JSONResponse(status_code=code, content={"detail": f"Blocked by AI. Reason: {risk_score}"})

    response = await call_next(request)
    return response

# --- ENDPOINTS ---

@app.get("/")
def home():
    return {"message": "System is ONLINE. AI Guard Active."}

class LoginRequest(BaseModel):
    username: str
    password: str = "optional"

@app.post("/login")
def login_endpoint(data: LoginRequest):
    return {
        "status": "success", 
        "message": f"Welcome, {data.username}! You passed the AI security check.",
        "risk_level": "SAFE"
    }

@app.get("/logs")
def get_dashboard_logs():
    """Fetches the last 100 logs from Redis for the Streamlit UI."""
    if not redis_client:
        return []
    raw_logs = redis_client.lrange("dashboard_logs", 0, 99)
    parsed_logs = []
    for log in raw_logs:
        try:
            parsed_logs.append(json.loads(log))
        except:
            continue
    return parsed_logs

# --- BAN MANAGEMENT ---

@app.get("/banned")
def get_banned_ips():
    """Returns a list of currently banned IPs and their reasons."""
    if not redis_client:
        return []
    
    ban_keys = redis_client.keys("ban:*")
    banned_users = []
    
    for key in ban_keys:
        ip = key.split(":")[1]
        reason = redis_client.get(key)
        ttl = redis_client.ttl(key)
        
        banned_users.append({
            "ip": ip,
            "reason": reason,
            "time_remaining": f"{ttl}s"
        })
    return banned_users

class UnblockRequest(BaseModel):
    ip: str

@app.post("/unblock")
def unblock_ip(data: UnblockRequest):
    """Manually unbans an IP address."""
    if not redis_client:
        return {"status": "error", "message": "Redis unavailable"}
    
    redis_client.delete(f"ban:{data.ip}")
    redis_client.delete(f"rate_limit:{data.ip}") # Reset rate limit too
    
    print(f"✅ Manually Unblocked IP: {data.ip}")
    return {"status": "success", "message": f"IP {data.ip} unblocked successfully."}