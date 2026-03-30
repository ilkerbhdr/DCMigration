# Contributing

Thank you for your interest in contributing to the DC Migration Port Mapping Tool!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone <your-fork-url>`
3. Install dependencies: `pip install -r requirements.txt`
4. Run locally: `python run.py`
5. Open `http://localhost:5000` in your browser

## Development

### Project Structure

- `app.py` — Flask routes and API endpoints (Blueprint under `/migration`)
- `database.py` — SQLite schema, migrations, all CRUD operations
- `monitor_session.py` — Background thread for SSH polling and SSE broadcast
- `switch_collector.py` — Arista EOS SSH commands and output parsing
- `templates/` — HTML pages (each page is self-contained with inline JS)
- `static/style.css` — Shared CSS design system
- `static/common.js` — Shared JS utilities (topbar, escape, colors, audio)

### Key Patterns

- **Database**: All data goes through `database.py` functions (`db_*` prefix). Thread-safe with `threading.RLock`.
- **SSE**: Real-time updates use Server-Sent Events. `monitor_session.py` manages a single background thread; multiple browser clients share the same stream via `register_client()` / `unregister_client()`.
- **Frontend**: Vanilla JavaScript, no build step. Each page loads `common.js` for shared utilities and renders the topbar with `renderTopbar('page-id')`.

### Adding a New Page

1. Add route in `app.py`: `@bp.route("/your-page")`
2. Create `templates/your-page.html` following existing patterns
3. Add to topbar in `static/common.js` `renderTopbar()` pages array
4. Use shared CSS classes from `static/style.css`

### Adding a New API Endpoint

1. Add route in `app.py` before `app.register_blueprint(bp)`
2. Use `db_*` functions from `database.py` for data access
3. Return JSON with `jsonify()`

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature description
fix: resolve specific issue
refactor: code improvement without behavior change
style: CSS/UI changes
chore: build, config, dependency changes
docs: documentation updates
```

## Pull Requests

1. Create a feature branch from `main`
2. Make your changes
3. Test locally with Docker: `docker-compose up -d --build`
4. Submit a PR with a clear description of what changed and why

## Testing

Currently the project uses manual testing. When testing:

- Test with at least 2 browser tabs to verify multi-user sync
- Test page refresh to verify data persistence
- Test with Docker build to catch import/path issues
- Verify SSH commands work against actual Arista switches

## Reporting Issues

When reporting bugs, please include:

- Browser and version
- Steps to reproduce
- Console errors (F12 → Console)
- Pod logs if running in K8s: `kubectl logs <pod-name>`

## Code Style

- Python: Standard PEP 8
- JavaScript: No framework, vanilla JS
- CSS: Use CSS variables from `style.css` design system
- HTML: Minimal inline styles, prefer shared CSS classes
