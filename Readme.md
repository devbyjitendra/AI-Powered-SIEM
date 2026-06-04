# 🛡️ AI-Powered SIEM Platform

A next-generation, premium Security Information and Event Management (SIEM) system built using **FastAPI** (Backend) and **React** (Frontend). This project features centralized logging, real-time threat detection, an automated event correlation engine, incident ticket escalation, and a security analyst chat assistant powered by **Google Gemini AI**.

---

## 🌟 Key Features

*   **⚡ High-Performance API Gateway**: Powered by FastAPI, offering standard RESTful endpoints for log ingestion, alert triage, incident case ticket management, and detection rule orchestration.
*   **📡 Real-Time WebSockets**: Instantly stream correlated threat alerts to security analysts as soon as they are triggered.
*   **🧠 Gemini AI Security Analyst**:
    *   **Automated Incident Playbooks**: Generate localized investigation steps, mitigation strategies, and summaries for critical alerts.
    *   **Interactive Chat Assistant**: Query the AI analyst directly from the dashboard to answer complex threat triage questions.
*   **📊 Premium Interactive Dashboard**:
    *   **Glassmorphism Theme**: A sleek, dark-mode visual aesthetic built with harmonic HSL colors and Outfit/Inter typography.
    *   **Events Over Time Chart**: Line graphs visualizing historical trends of raw security events vs. correlated high-priority alerts.
    *   **Geographical Threat Map**: Leaflet-based world map plotting real-time threat sources and security alert hot spots.
    *   **Active KPI Counters**: Track total ingested events, alerts, and cases with dynamic risk metrics.
*   **🧩 Automated Correlation Engine**: Regex-based log parser executing rule matches (e.g. Auth Brute Force, SQL Injections, XSS Script Injections, Port Scanning) to automatically generate alerts.
*   **⚙️ Local DB Backup & Size Pruning**: Built-in automatic size pruning (retains latest 1,000 logs and 500 alerts) to ensure instant query performance (sub-100ms `/stats` latency) and prevent disk bloat.
*   **🤖 Integrated Simulator Daemon**: Simulates realistic enterprise environments, generating benign diurnal traffic patterns interweaved with SQL Injection, brute-force, or malware contact attacks.

---

## 📁 Project Structure

```bash
AI-Powered-SIEM/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/  # APIs for logs, alerts, cases, and rules
│   │   ├── core/              # Config, DB connections, and logging
│   │   ├── models/            # SQLAlchemy schemas & Pydantic models
│   │   └── services/          # AI Analyst, Correlation Engine, WebSockets
│   ├── requirements.txt       # Python backend dependencies
│   └── Dockerfile             # Multi-stage production container setup
│
├── frontend/
│   ├── src/
│   │   ├── components/        # React components (Map, Charts, Playbooks, Chat)
│   │   ├── services/          # API & WebSocket service configurations
│   │   ├── App.jsx            # Main app shell & global state orchestrator
│   │   └── index.css          # Central HSL variable styling system
│   ├── vite.config.js         # Frontend asset bundler
│   └── package.json           # Frontend packages & dev scripts
│
├── simulator_daemon.py        # Log generator script mimicking live attacks
├── docker-compose.yml         # Container orchestration profile
├── Readme.md                  # System documentation (This file)
└── siem_database.db           # Local database (when running SQLite)
```

---

## 🚀 Getting Started

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/devbyjitendra/AI-Powered-SIEM.git
cd AI-Powered-SIEM
```

### 2️⃣ Configure Environment Variables (`.env`)
Create a `.env` file in the root workspace folder:
```env
APP_NAME="AI-Powered SIEM"
DEBUG=True
GEMINI_API_KEY="YOUR_GOOGLE_GEMINI_API_KEY"
DATABASE_URL="sqlite:///./siem_database.db"
ALLOWED_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
```

---

### 3️⃣ Backend Setup (FastAPI)

1. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

2. Install python dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. Run the development API server:
   ```bash
   cd backend
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
   The backend API will start at: `http://127.0.0.1:8000`
   * Swagger Documentation: `http://127.0.0.1:8000/docs`
   * ReDoc Documentation: `http://127.0.0.1:8000/redoc`

---

### 4️⃣ Frontend Setup (Vite + React)

1. Open a new terminal window in the `frontend` folder:
   ```bash
   cd frontend
   ```

2. Install node dependencies:
   ```bash
   npm install
   ```

3. Start the Vite React development server:
   ```bash
   npm run dev
   ```
   The web portal will open at: `http://127.0.0.1:5173`

---

### 5️⃣ Launch the Simulator Daemon

To feed live data into the platform, run the simulator from the root project directory:
```bash
python simulator_daemon.py --attack-ratio 1.0 --interval 2
```
*   `--attack-ratio`: Ratio of security logs that represent malicious attack events (0.0 to 1.0).
*   `--interval`: Speed of log ingestion in seconds.

---

## 🐳 Docker Deployment

To spin up the entire application stack in containerized mode (Frontend + Backend):
```bash
docker-compose up --build
```
*   **Frontend Web App**: `http://localhost:80`
*   **Backend REST Gateway**: `http://localhost:8000`

---

## 👨‍💻 Author

**Jitendra Kumar**
*   Cybersecurity Specialist & Backend Engineer
*   Passionate about centralizing security architectures with state-of-the-art AI.
