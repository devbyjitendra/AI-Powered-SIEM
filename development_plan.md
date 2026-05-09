# 📅 40-Day AI-Powered SIEM Development Plan

This document outlines a structured, 40-day step-by-step roadmap to build a production-ready, Google-Ready AI-Powered Security Information and Event Management (SIEM) system. The frontend will precisely match the dark-themed dashboard design, and the backend will support robust log ingestion, signature/rule-based detection, anomaly analysis, and Gemini-based AI insights.

---

## 🏛️ Project Architecture
- **Backend**: Python, FastAPI, SQLite (development) / PostgreSQL (production), SQLAlchemy ORM, WebSockets, Pytest.
- **Frontend**: React (Vite), Tailwind CSS (for layout and modern styling), Chart.js or Recharts, Lucide Icons, and React Vector Maps / custom SVG maps.
- **AI Integration**: Google Generative AI (Gemini) SDK.

---

## 🗺️ 40-Day Roadmap

### 📂 Phase 1: Project Architecture & Database Design (Days 1–5)
*   **Day 1**: Initialize repository, establish workspace structure (`backend/` and `frontend/`), configure environment setups (`.env`, `.gitignore`).
*   **Day 2**: Design the Database schema for logs, alerts, correlation rules, and cases.
*   **Day 3**: Implement Database connection manager, migrations (SQLAlchemy & Alembic setup), and base model definitions.
*   **Day 4**: Write the configuration module (`config.py`) and set up standard Google-style JSON logging.
*   **Day 5**: Build the `/health` and status endpoints. Write initial unit tests for database connection sanity.

### 📥 Phase 2: Log Ingestion API & Parsing Pipeline (Days 6–10)
*   **Day 6**: Build the Pydantic schemas for structured log payloads (following Google Cloud Logging format).
*   **Day 7**: Create the log ingestion API endpoint `/api/v1/logs/ingest` supporting bulk ingestion.
*   **Day 8**: Implement the Log Parser parser middleware (extracting geo-IP context, user agents, and normalizer).
*   **Day 9**: Write background worker tasks using Python's `asyncio` to queue logs for asynchronous parsing.
*   **Day 10**: Write unit tests for log parser validation, rate-limiting, and bad payload handling.

### ⚡ Phase 3: Rule-Based Correlation & Threat Detection Engine (Days 11–15)
*   **Day 11**: Create detection rule models, load default security rules (SSH Brute Force, SQL Injection, Port Scan).
*   **Day 12**: Implement the in-memory Correlation Engine to track events by IP and User within window intervals.
*   **Day 13**: Code detection logic for: Brute Force login (e.g. 5 failed login attempts in 60s from same IP).
*   **Day 14**: Code detection logic for: Web Application Attacks (regex patterns for SQL Injection, XSS) and Port Scanning patterns.
*   **Day 15**: Implement automatic Alert generation from detection rules, storing them in the Database. Run verification tests.

### 🎨 Phase 4: Core Frontend Shell & Visual Framework (Days 16–20)
*   **Day 16**: Scaffold the React/Vite frontend. Setup theme colors (Deep Slates, Neon Cyan/Purple) and font family (Inter/Outfit).
*   **Day 17**: Develop the Left Sidebar Navigation (Dashboard, Alerts, Incidents, UEBA, Log Management, etc.) matching the reference design layout.
*   **Day 18**: Build the Top Header containing the Search Bar, "Ask AI" action button, Notification Badge, and Theme toggle.
*   **Day 19**: Create the main Dashboard Grid layout and mock up the four key KPI metrics cards (Total Events, Alerts, Incidents, Critical Incidents).
*   **Day 20**: Implement glassmorphism styles and card layouts. Write snapshot tests for frontend components.

### 📈 Phase 5: Interactive Visualizations & Frontend Data Views (Days 21–25)
*   **Day 21**: Integrate Recharts/Chart.js and implement the "Events Over Time" line chart with custom glowing styles.
*   **Day 22**: Build the "Top Alert Categories" donut chart and detailed legend breakdown.
*   **Day 23**: Build the "World Map - Threat Activity" using SVG/interactive maps showing geographical hot spots.
*   **Day 24**: Implement the "Top Threat Sources" table displaying IP Addresses, Countries, Events, and Risk Scores.
*   **Day 25**: Implement the "Recent Alerts" table showing real-time security events.

### 🔌 Phase 6: Real-Time Communication (WebSockets) & Ingest Simulation (Days 26–30)
*   **Day 26**: Implement the WebSocket Server endpoint `/api/v1/alerts/ws` in FastAPI to stream new alerts.
*   **Day 27**: Connect React frontend to the Alert WebSocket, enabling toast notifications and live updates.
*   **Day 28**: Create the interactive "Log Generator (Simulator) Panel" in the frontend to trigger test attacks.
*   **Day 29**: Hook up the simulator to the backend to generate live attacks (SSH brute force, SQL injection) and verify real-time alert UI rendering.
*   **Day 30**: Optimize frontend performance: introduce virtualization for high-frequency logs and handle connection dropouts.

### 🤖 Phase 7: Gemini AI Security Analyst Integration (Days 31–35)
*   **Day 31**: Configure Google Generative AI SDK on the backend and implement Gemini API connection handlers.
*   **Day 32**: Design structured prompt templates for security analysis (supplying raw logs, triggered rule metadata, and system context).
*   **Day 33**: Implement structured JSON parsing from Gemini for threat classification, description, and remediation playbooks.
*   **Day 34**: Build the "AI Insights" dashboard feed and the "Consult Gemini" interactive panel on the frontend.
*   **Day 35**: Implement backend caching of Gemini responses to minimize latency and control API token costs.

### 🛡️ Phase 8: Advanced Modules, Settings & Production Hardening (Days 36–40)
*   **Day 36**: Develop the Case Management system (creating incidents, status flow, assigning analysts).
*   **Day 37**: Implement the threat intelligence feed integration (auto-flagging known malicious IPs).
*   **Day 38**: Add settings configuration panels (toggle rules, customize alert severity, set Gemini model options).
*   **Day 39**: Create the Docker infrastructure (`Dockerfile` for backend, `Dockerfile` for frontend, `docker-compose.yml` orchestrating all containers).
*   **Day 40**: Final system integration testing, comprehensive walkthrough documentation, and resume-ready deployment preparation.
