# 🛡️ AI-Enhanced Web Application Firewall (WAF)

![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Redis](https://img.shields.io/badge/redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Google%20Gemini-8E75B2?style=for-the-badge&logo=google%20bard&logoColor=white)

> **A Next-Generation API Security Platform.** > Combines the speed of **Redis** caching with the intelligence of **Google Gemini 2.0** to detect and block semantic cyberattacks (SQLi, XSS, Command Injection) in real-time.

---

## 🚀 Overview
Traditional firewalls rely on static "Regular Expressions" (Regex) which are easily bypassed by obfuscated attacks. This project implements a **Hybrid Security Engine**:

1.  **Local Signatures (Redis):** Instantly blocks known malicious payloads (<1ms latency).
2.  **Generative AI (Gemini 2.0):** Analyzes unknown/complex payloads to detect *intent* rather than just patterns.
3.  **Adaptive Ban System:** Automatically bans IPs engaging in DDoS or malicious behavior, with a UI to manage/unblock them.

## ✨ Key Features
* **🧠 AI Threat Detection:** Uses LLMs to understand context (e.g., distinguishing between a SQL query and a SQL injection).
* **⚡ Zero-Latency Caching:** "Learns" from AI verdicts. Once a threat is detected, the signature is cached in Redis for instant blocking next time.
* **🐳 Fully Dockerized:** One-command deployment for both Backend and Dashboard.
* **🌍 Live Threat Map:** Visualizes attacker locations in real-time on an interactive map.
* **⚔️ Attack Simulator:** Built-in "Hacker UI" to safely test vulnerabilities (SQLi, XSS) against the firewall.
* **🛡️ Ban Manager:** Admin interface to view active bans, remaining time, and manually **unblock IPs**.
* **📝 Compliance Ready:** Auto-generates CSV audit logs for security post-mortems.

---

## 🏗️ Architecture

graph TD
    User[User / Attacker] -->|POST /login| Firewall[🛡️ FastAPI Firewall]
    
    subgraph "Hybrid Security Engine"
        Firewall -->|1. Check Cache| Redis[(Redis Memory)]
        Redis -- "Known Threat?" --> Decision{Verdict}
        
        Decision -- "Yes (Hit)" --> Block[⛔ Block Instantly]
        Decision -- "No (Miss)" --> AI[🤖 Google Gemini 2.0]
        
        AI -->|2. Analyze Intent| AI_Verdict{Is Malicious?}
        AI_Verdict -- "Yes" --> UpdateCache[3. Cache Signature]
        AI_Verdict -- "No" --> Pass[✅ Allow Traffic]
        
        UpdateCache --> Block
    end
    
    subgraph "Observability"
        Block -.->|Log| Dashboard[📊 Streamlit Dashboard]
        Pass -.->|Log| Dashboard
        Dashboard -->|Read| Redis
    end

| Component | Tech Stack | Role |
| :--- | :--- | :--- |
| **Backend API** | FastAPI (Python) | Intercepts traffic, manages rate limits, calls AI. |
| **Brain** | Google Gemini 2.0 Flash | Analyzes payloads for malicious intent. |
| **Memory** | Redis (Upstash) | Caches verdicts, stores rate limits, tracks bans. |
| **Dashboard** | Streamlit | Real-time monitoring, Maps, and Ban Management. |
| **Infrastructure** | Docker Compose | Orchestrates the entire stack. |

---

## 🐳 Quick Start (Docker)
*Prerequisite: Docker Desktop installed.*

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/your-username/smart-api-firewall.git](https://github.com/your-username/smart-api-firewall.git)
    cd smart-api-firewall
    ```

2.  **Configure Environment**
    Create a `.env` file in the root directory:
    ```env
    # Redis Configuration (Use Upstash or Local)
    REDIS_HOST=your-redis-endpoint
    REDIS_PORT=6379
    REDIS_PASSWORD=your-redis-password

    # Google AI Configuration
    GEMINI_API_KEY=your-gemini-api-key
    ```

3.  **Run with Docker Compose**
    ```bash
    docker compose up --build
    ```

4.  **Access the App**
    * **🛡️ Security Dashboard:** [http://localhost:8501](http://localhost:8501)
    * **🔌 API Backend:** [http://localhost:8000](http://localhost:8000)

---

## 🕹️ How to Use the Dashboard

The Dashboard (Port 8501) is divided into two tabs:

### Tab 1: ⚔️ Attack Simulator
Use this interface to act like a hacker and test the firewall.
* **Safe Request:** Enter `alice` -> Result: `✅ ACCESS GRANTED`
* **SQL Injection:** Enter `' OR '1'='1` -> Result: `🛡️ BLOCKED BY FIREWALL`
* **XSS Attack:** Enter `<script>alert(1)</script>` -> Result: `🛡️ BLOCKED BY FIREWALL`

### Tab 2: 📊 Admin Dashboard
Monitor the defense system in action.
* **Live Map:** See where requests are coming from (Simulated for Docker traffic).
* **Audit Logs:** View a table of recent traffic with Risk Scores.
* **Ban Manager:** View currently banned IPs. Select an IP and click **"Unlock IP"** to restore access.
* **Download:** Export logs to CSV for reporting.

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/login` | The protected endpoint. Analyzing body for threats. |
| `GET` | `/logs` | Fetches recent security logs for the dashboard. |
| `GET` | `/banned` | Lists all currently banned IPs and remaining ban time. |
| `POST` | `/unblock` | Manually removes a ban for a specific IP. |

---

## 🔮 Future Roadmap
- [ ] **Email Alerts:** Send notifications to Admins when High-Risk threats are detected.
- [ ] **Custom Fine-Tuning:** Train a smaller LLM specifically on SQLi datasets for faster local inference.
- [ ] **Kubernetes Support:** Helm charts for scaling the backend.

---

## 👨‍💻 Author
**AswinDas**
* [LinkedIn](https://linkedin.com/in/aswindas-c)
* [GitHub](https://github.com/aswindas-c)

built with ❤️ and ☕ using Python.