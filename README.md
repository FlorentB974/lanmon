# LAN Monitor

A modern, real-time network device monitoring application inspired by [NetAlertX](https://github.com/jokob-sk/NetAlertX).

![LAN Monitor](https://via.placeholder.com/800x400?text=LAN+Monitor+Dashboard)

## Features

- 🔍 **Device Discovery**: Automatic detection of devices on your local network using ARP scanning
- 📡 **Real-time Updates**: WebSocket-based live updates when devices connect or disconnect
- 📊 **Dashboard Statistics**: Overview of online/offline devices, new discoveries, and activity
- 🏷️ **Device Management**: Customize names, add notes, and categorize your devices
- ⭐ **Favorites**: Mark important devices for quick access
- 📜 **Connection History**: Track device connection/disconnection events
- 🌙 **Modern Dark UI**: Sleek, responsive interface with glass-morphism effects

## Tech Stack

### Backend
- **Framework**: FastAPI (Python 3.11+)
- **Database**: SQLite with SQLAlchemy ORM
- **Network Scanning**: Scapy, python-nmap
- **Real-time**: WebSocket support

### Frontend
- **Framework**: Next.js 14 with React 18
- **Styling**: Tailwind CSS with custom design system
- **Animations**: Framer Motion
- **Icons**: Lucide React

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+
- macOS, Linux, or Windows with WSL

### Backend Setup

```bash
cd backend

# Create virtual environment (use Python 3.12 for best compatibility)
python3.12 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server (requires sudo for network scanning)
sudo .venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run the development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Configuration

### Backend Environment Variables

Create a `.env` file in the `backend` directory:

```env
DATABASE_URL=sqlite+aiosqlite:///./lanmon.db
SCAN_INTERVAL=60
DEBUG=true
```

### Frontend Environment Variables

Create a `.env.local` file in the `frontend` directory:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List all devices |
| GET | `/api/devices/{id}` | Get device by ID |
| PATCH | `/api/devices/{id}` | Update device |
| DELETE | `/api/devices/{id}` | Delete device |
| GET | `/api/devices/{id}/events` | Get device events |
| GET | `/api/dashboard/stats` | Get dashboard statistics |
| POST | `/api/scan/trigger` | Trigger network scan |
| GET | `/api/scan/sessions` | Get scan history |
| WS | `/ws` | WebSocket for real-time updates |

## Network Scanning

The application uses multiple methods to discover devices:

1. **Scapy ARP Scan**: Primary method using raw ARP requests
2. **arp-scan**: Fallback command-line tool
3. **System ARP Table**: Last resort using cached ARP entries

> **Note**: Network scanning typically requires elevated privileges (sudo/admin).

## Screenshots

### Dashboard
![Dashboard](https://via.placeholder.com/800x400?text=Dashboard+View)

### Device Details
![Device Details](https://via.placeholder.com/800x400?text=Device+Details+Modal)

## Development

### Project Structure

```
lanmon/
├── backend/
│   ├── app/
│   │   ├── api/           # API routes and schemas
│   │   ├── core/          # Configuration
│   │   ├── db/            # Database models
│   │   ├── scanner/       # Network scanning
│   │   └── main.py        # Application entry
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/           # Next.js pages
│   │   ├── components/    # React components
│   │   ├── lib/           # Utilities and API
│   │   └── types/         # TypeScript types
│   └── package.json
└── README.md
```

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

## Troubleshooting

### Permission Denied for Scanning

Network scanning requires elevated privileges:
```bash
# Run with sudo
sudo uvicorn app.main:app --reload

# Or grant capabilities (Linux)
sudo setcap cap_net_raw=eip $(which python)
```

### No Devices Found

1. Ensure you're on the same network segment as target devices
2. Check if your firewall allows ARP traffic
3. Verify the subnet configuration in settings

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [NetAlertX](https://github.com/jokob-sk/NetAlertX) for inspiration
- [Scapy](https://scapy.net/) for network packet manipulation
- [FastAPI](https://fastapi.tiangolo.com/) for the excellent API framework
