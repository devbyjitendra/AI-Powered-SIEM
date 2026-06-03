# 🚨 AI-Powered SIEM Backend

A modern Security Information and Event Management (SIEM) backend built using FastAPI.  
This project focuses on centralized logging, event monitoring, alert generation, and security analysis.

---

## ✨ Features

- ⚡ FastAPI based backend
- 📡 RESTful API architecture
- 📝 Centralized logging system
- 🔐 Security event monitoring
- ❤️ Health check endpoints
- 🐳 Docker support
- ⚙️ Environment based configuration
- 🧩 Modular and scalable structure
- 🧪 API testing support
- 📊 Future dashboard integration

---

# 🛠️ Tech Stack

| Technology | Purpose          |
| ---------- | ---------------- |
| Python     | Backend Language |
| FastAPI    | API Framework    |
| PostgreSQL | Database         |
| SQLAlchemy | ORM              |
| Docker     | Containerization |
| Pydantic   | Data Validation  |
| Uvicorn    | ASGI Server      |

---

# 📁 Project Structure

```bash
AI-Powered-SIEM/
├── backend/
│   ├── app/                  # FastAPI Application Core
│   ├── tests/                # Pytest Suite
│   ├── Dockerfile            # Backend Container Config
│   └── requirements.txt      # Python Dependencies
│
├── frontend/
│   ├── src/                  # React Dashboard Components & Hooks
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json          # Node Dependencies
│   └── Dockerfile            # Nginx Multi-stage Container Config
│
├── docker-compose.yml        # Multi-container Orchestration
├── development_plan.md       # Roadmap & Acceleration Schedule
├── progress.md               # Day-by-Day Milestone Tracker
└── Readme.md                 # Documentation
```

---

# 🚀 Getting Started

## 1️⃣ Clone Repository

```bash
git clone https://github.com/devbyjitendra/AI-Powered-SIEM.git
cd AI-Powered-SIEM
```

---

## 2️⃣ Create Virtual Environment

```bash
python -m venv venv
```

### ▶️ Activate Virtual Environment

### Windows

```bash
venv\Scripts\activate
```

### Linux / Mac

```bash
source venv/bin/activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r backend/requirements.txt
```

---

# ⚙️ Environment Variables

Create a `.env` file in the root directory.

## Example

```env
APP_NAME="AI-Powered SIEM"
DEBUG=True
DATABASE_URL=sqlite:///./siem_database.db
GEMINI_API_KEY=your_google_gemini_api_key_here
ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

---

# ▶️ Run Development Server

```bash
cd backend
uvicorn app.main:app --reload
```

Server will start at:

```txt
http://127.0.0.1:8000
```

---

# 📚 API Documentation

Once the server is running:

| Documentation | URL                         |
| ------------- | --------------------------- |
| Swagger UI    | http://127.0.0.1:8000/docs  |
| ReDoc         | http://127.0.0.1:8000/redoc |

---

# 🐳 Docker Setup

Build and run the multi-container environment:

```bash
docker-compose up --build
```

Access services at:

| Component | Port / URL |
| --------- | ---------- |
| Frontend Dashboard | [http://localhost](http://localhost) (Port 80) |
| Backend API Server | [http://localhost:8000](http://localhost:8000) (Port 8000) |


---

# 🧪 Running Tests

```bash
pytest
```

---

# 🎯 Current Development Goals

- [ ] Log ingestion pipeline
- [ ] Authentication & Authorization
- [ ] Alert management system
- [ ] Threat detection rules
- [ ] Dashboard integration
- [ ] Real-time monitoring
- [ ] Event correlation engine

---

# 🤝 Contributing

Contributions are welcome.

If you'd like to contribute:

1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Open a Pull Request

---

# 📌 Future Improvements

- Kafka integration
- Elasticsearch support
- Redis caching
- WebSocket alerts
- AI-based anomaly detection
- Role Based Access Control (RBAC)

---

# 📄 License

This project is currently intended for learning, development, and research purposes.

---

# 👨‍💻 Author

### Jitendra Kumar

- Cybersecurity Enthusiast
- Backend Developer
- AI & Security Learner

---

# ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub.
