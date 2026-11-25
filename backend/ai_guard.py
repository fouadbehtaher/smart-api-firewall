import os
import hashlib
import redis
from google import genai
from dotenv import load_dotenv

from backend.signatures import detect_signature

load_dotenv()

# --- CONFIGURATION ---
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = int(os.getenv("REDIS_PORT", 6379))
redis_password = os.getenv("REDIS_PASSWORD", None)

# CRITICAL FIX: Enable SSL if using Cloud Redis (Upstash)
use_ssl = redis_host != "localhost"

redis_client = redis.Redis(
    host=redis_host,
    port=redis_port,
    password=redis_password,
    ssl=use_ssl,  # <--- This prevents "Connection closed by server"
    decode_responses=True
)

api_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=api_key) if api_key else None

KNOWN_THREATS = {"SQL_INJECTION", "XSS_ATTACK", "COMMAND_INJECTION", "MALWARE", "SAFE"}

def analyze_risk_with_ai(payload: str) -> str:
    if not payload:
        return "SAFE"

    # 0. LOCAL SIGNATURES FIRST: no API call, no cache, cannot be talked out of it
    local_verdict = detect_signature(payload)
    if local_verdict:
        return local_verdict

    # 1. GENERATE FINGERPRINT (Hash)
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    cache_key = f"ai_verdict:{payload_hash}"

    # 2. CHECK REDIS MEMORY
    try:
        cached_verdict = redis_client.get(cache_key)
        if cached_verdict:
            print(f"🧠 AI Memory Recall: {payload[:15]}... -> {cached_verdict}")
            return cached_verdict
    except Exception as e:
        print(f"⚠️ Redis Error (Skipping Cache): {e}")

    # 3. ASK THE AI
    if not client: return "SAFE"
    
    print(f"🤖 New Threat? Asking AI about: {payload[:15]}...")
    prompt = (
        f"Analyze payload: ```{payload}```\n"
        f"Classify strictly as: {', '.join(KNOWN_THREATS)}.\n"
        f"Reply ONLY with the category."
    )

    try:
        # Use the specific model that works for you
        response = client.models.generate_content(
            model='gemini-2.5-flash-lite', 
            contents=prompt
        )
        
        ai_verdict = response.text.strip().upper()
        ai_verdict = ai_verdict.replace(".", "").replace(" ", "_")

        if ai_verdict not in KNOWN_THREATS:
            ai_verdict = "SAFE"

        # 4. SAVE TO MEMORY (Cache for 24 hours)
        try:
            redis_client.setex(cache_key, 86400, ai_verdict)
        except Exception as e:
            print(f"⚠️ Failed to cache verdict: {e}")
        
        return ai_verdict

    except Exception as e:
        print(f"⚠️ AI Unavailable: {e}")
        return "SAFE"
