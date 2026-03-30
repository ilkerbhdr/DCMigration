# DC Migration Port Mapping Tool

A web-based network infrastructure management tool designed for **data center migration** projects. Connects to network switches and firewalls via SSH, collects port information in real-time, and provides a comprehensive suite of tools for planning, executing, and verifying DC migrations.

## Features

### Port Mapping & Export
- Collect port status, description, VLAN, LLDP neighbors, MAC addresses from multiple switches simultaneously
- IP range support (`192.168.1.10-15`, `192.168.1.20-25` or comma-separated)
- Firewall ARP table integration for MAC-to-IP resolution
- Reverse DNS lookup for hostname discovery (parallel, 20 threads)
- Export to Excel with color-coded status, filters, and freeze panes
- Port-Channel member detection and mapping

### Live Table
- Real-time Excel-like view of all switch ports in the browser
- Automatic polling with change detection and highlighting
- Recently changed rows float to the top with visual indicators
- Per-port tagging (persistent, survives restarts)
- Advanced filtering with AND/OR logic across all columns
- Truncated display for ports with many MAC/IP entries (expandable popup)
- SFP type information per port

### Real-Time Port Monitor
- Multi-switch simultaneous monitoring via SSE (Server-Sent Events)
- Instant detection when a cable is plugged/unplugged (port up/down)
- Sound alerts on port changes
- Change log with tagging and bulk tagging
- Snapshot comparison (before/after)
- CSV export of change history
- Webhook notifications (Microsoft Teams, Slack, generic)

### Network Topology Visualization
- Interactive graph powered by Cytoscape.js
- Automatic device classification from hostname patterns (spine, leaf, mgmt, firewall, server, storage)
- Hierarchical layout (dagre) or force-directed layout (cose)
- Color-coded links (fiber = blue, copper = orange, LAG = thick)
- Hover to highlight connected neighbors, click for detail panel
- Export to PNG or SVG
- Data from live session, last collection, or any saved baseline

### Dashboard
- Overview of all monitored switches with port statistics
- Baseline management (save, compare, delete)
- Switch group definitions for quick access
- Webhook configuration and testing
- Audit log with event filtering
- Auto-refresh on configurable interval

### SFP Inventory
- Collect SFP/transceiver types from all switch ports
- Snapshot before/after migration
- Side-by-side comparison highlighting changes (added, removed, changed SFPs)

### Baseline & Diff
- Save full port mapping as a baseline before migration
- Compare any two baselines to detect changes in status, VLAN, LLDP, description
- Topology diff showing new/removed/changed LLDP adjacencies

## Architecture

```
Browser (N users) ──► Flask App ──► SQLite DB (data/port_map.db)
    ▲                    │
    │ SSE               SSH (Netmiko)
    │                    │
    └── Real-time ◄─────► Switches / Firewalls
        updates          Firewalls (ARP)
```

- **Backend**: Python / Flask with threaded server
- **Database**: SQLite with WAL mode (thread-safe)
- **SSH**: Netmiko (multi-vendor support)
- **Frontend**: Vanilla JS, Inter font, custom CSS design system
- **Graphs**: Cytoscape.js + dagre for topology visualization
- **Multi-user**: Single monitor session shared via SSE broadcast; all data persisted in DB

## Quick Start

### Prerequisites
- Python 3.9+
- Network access to switches via SSH (Arista EOS or Cisco Nexus)

### Local Development

```bash
git clone https://github.com/ilkerbhdr/DCmigration.git
cd DCmigration
pip install -r requirements.txt
python run.py
```

Open `http://localhost:5000` in your browser.

### Docker

```bash
docker build -t dcmigration .
docker run -d -p 5000:5000 -v ./data:/app/data dcmigration
```

### Docker Compose

```bash
docker-compose up -d
```

### Kubernetes (K3s / Rancher)

1. Build and push image to your registry
2. Create a PersistentVolumeClaim (`1Gi`, `ReadWriteOnce`)
3. Deploy with volume mounted at `/app/data`
4. Create Ingress with path prefix (app supports `/migration` prefix)

See `k8s/` directory for example manifests.

## Configuration

### URL Prefix

The application supports a URL prefix for reverse proxy / ingress setups. By default it runs under `/migration/`:

```
https://your-domain.com/migration/           → Dashboard
https://your-domain.com/migration/port-mapping → Port Mapping
https://your-domain.com/migration/live        → Live Table
https://your-domain.com/migration/monitor     → Monitor
https://your-domain.com/migration/topology    → Topology
https://your-domain.com/migration/sfp         → SFP Check
```

### Credential Profiles

Store SSH credentials as reusable profiles (saved in SQLite DB). Profiles are shared across all pages and users.

### Switch Groups

Define groups of switches (e.g., "4th Floor Spine Switches") for quick selection across Dashboard, Port Mapping, and Monitor pages.

### Webhooks

Configure Microsoft Teams, Slack, or generic webhook URLs to receive notifications when port changes are detected during monitoring.

## Project Structure

```
DCmigration/
├── app.py                 # Flask routes and API endpoints
├── database.py            # SQLite schema, migrations, CRUD operations
├── monitor_session.py     # Background thread for real-time monitoring
├── switch_collector.py    # SSH data collection (show interfaces, LLDP, MAC, VLAN)
├── port_monitor.py        # Lightweight port status polling
├── firewall_collector.py  # Firewall ARP table collection
├── dns_resolver.py        # Parallel reverse DNS lookups
├── excel_exporter.py      # Excel file generation (openpyxl)
├── webhook_notifier.py    # Teams/Slack/generic webhook sender
├── audit_log.py           # Event logging (legacy, migrated to DB)
├── run.py                 # Application entry point
├── wsgi.py                # Gunicorn WSGI entry point
├── requirements.txt       # Python dependencies
├── Dockerfile             # Container build
├── docker-compose.yml     # Docker Compose configuration
├── .dockerignore
├── templates/
│   ├── dashboard.html     # Dashboard & settings page
│   ├── index.html         # Port mapping & collection page
│   ├── live.html          # Live table (real-time Excel view)
│   ├── monitor.html       # Port change monitor
│   ├── topology.html      # Network topology visualization
│   └── sfp.html           # SFP inventory & comparison
├── static/
│   ├── style.css          # Shared design system
│   └── common.js          # Shared JS utilities & navigation
└── data/
    ├── port_map.db        # SQLite database (auto-created)
    └── exports/           # Generated Excel files
```

## Supported Devices

| Device | Connection | Data Collected |
|--------|-----------|----------------|
| Arista EOS switches | SSH (Netmiko) | Ports, status, VLAN, LLDP, MAC, SFP, Port-Channel, error counters |
| Cisco Nexus switches | SSH (Netmiko) | Ports, status, VLAN, LLDP, CDP, MAC, SFP, Port-Channel, error counters |
| PAN-OS firewalls | SSH (Netmiko) | ARP table (MAC → IP mapping) |
| FortiGate firewalls | SSH (Netmiko) | ARP table (MAC → IP mapping) |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/profiles` | List credential profiles |
| POST | `/api/profiles` | Create/update profile |
| POST | `/collect` | Collect port data (SSE stream) |
| GET | `/api/dashboard/summary` | Switch overview |
| POST | `/api/monitor/start` | Start monitoring session |
| GET | `/api/monitor/stream` | SSE stream for real-time updates |
| GET | `/api/live/ports` | Get all live port data |
| POST | `/api/live/tag` | Tag a port (persistent) |
| POST | `/api/baseline/save` | Save baseline |
| POST | `/api/baseline/diff` | Compare two baselines |
| GET | `/api/topology/data` | Get topology graph data |
| POST | `/api/sfp/collect` | Collect SFP inventory |
| GET | `/api/webhooks` | List webhooks |
| GET | `/api/audit-log` | Get audit log entries |

## Data Persistence

All data is stored in a single SQLite database (`data/port_map.db`):

- Credential profiles
- Switch groups
- Monitor sessions, port changes, tags
- Live port data (survives restarts)
- Baselines and snapshots
- SFP snapshots
- Webhook configurations
- Audit log

When running in Docker/K8s, mount `/app/data` as a persistent volume.

## Browser Support

Tested on modern browsers (Chrome, Firefox, Edge). Requires JavaScript enabled.

## Security Notes

- SSH credentials are stored in plaintext in SQLite. Suitable for internal/lab use.
- No user authentication — all users share the same session.
- Designed for internal network use, not public internet exposure.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
