# LAN Monitor - Network Device Monitoring Web Application

## Project Overview
A web application for monitoring devices on your local network, inspired by NetAlertX.

### Features
- Real-time device discovery using ARP scanning
- Device connection/disconnection monitoring
- Detailed device information (IP, MAC, hostname, vendor, etc.)
- Modern, responsive UI with dark/light themes
- WebSocket-based real-time updates

### Tech Stack
- **Backend**: Python 3.11+ with FastAPI
- **Frontend**: Next.js 14 with React, TypeScript, Tailwind CSS
- **Database**: SQLite with SQLAlchemy ORM
- **Network Scanning**: scapy, python-nmap
- **Real-time**: WebSockets

### Project Structure
```
lanmon/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── api/            # API routes
│   │   ├── core/           # Core configuration
│   │   ├── db/             # Database models and connection
│   │   ├── scanner/        # Network scanning modules
│   │   ├── services/       # Business logic
│   │   └── main.py         # Application entry point
│   ├── requirements.txt
│   └── pyproject.toml
├── frontend/               # Next.js frontend
│   ├── src/
│   │   ├── app/           # App router pages
│   │   ├── components/    # React components
│   │   ├── lib/           # Utilities and API client
│   │   └── types/         # TypeScript types
│   ├── package.json
│   └── tailwind.config.ts
└── README.md
```

### Development Commands
- Backend: `cd backend && uvicorn app.main:app --reload`
- Frontend: `cd frontend && npm run dev`

### Environment Variables
- `DATABASE_URL`: SQLite database path (default: sqlite:///./lanmon.db)
- `SCAN_INTERVAL`: Network scan interval in seconds (default: 60)
- `NEXT_PUBLIC_API_URL`: Backend API URL for frontend
