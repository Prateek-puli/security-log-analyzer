"""Local dashboard server. Run with Python; no additional packages required."""
from contextlib import contextmanager
import json
import sqlite3
import sys
import webbrowser
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from analyzer import analyze

ROOT = Path(__file__).parent
DB_PATH = ROOT / 'analysis.db'
PAGE_PATH = ROOT / 'index.html'
PORT = 8501            # updated in main() if 8501 is busy
MAX_BODY = 5_000_000   # bytes
MAX_SCANS = 100        # older scans are deleted automatically

SUMMARY_COLUMNS = {'events': 'INTEGER', 'alerts': 'INTEGER', 'high': 'INTEGER', 'skipped': 'INTEGER'}


def summarize(result):
    return dict(events=len(result['events']), alerts=len(result['alerts']),
                high=sum(a['severity'] == 'High' for a in result['alerts']), skipped=result.get('skipped', 0))


@contextmanager
def database():
    db = sqlite3.connect(DB_PATH)
    try:
        with db:
            db.execute('CREATE TABLE IF NOT EXISTS analyses (id INTEGER PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP, result TEXT)')
            existing = {row[1] for row in db.execute('PRAGMA table_info(analyses)')}
            missing = [name for name in SUMMARY_COLUMNS if name not in existing]
            for name in missing:
                db.execute(f'ALTER TABLE analyses ADD COLUMN {name} {SUMMARY_COLUMNS[name]}')
            # Backfill summary columns for scans saved by older versions (runs once).
            for scan_id, raw in db.execute('SELECT id, result FROM analyses WHERE events IS NULL').fetchall():
                db.execute('UPDATE analyses SET events=:events, alerts=:alerts, high=:high, skipped=:skipped WHERE id=:id',
                           dict(summarize(json.loads(raw)), id=scan_id))
            yield db
    finally:
        db.close()


def read_settings(data):
    """Validate the settings sent by the browser. Raises ValueError with a readable message."""
    def number(key, low, high, label, default=None):
        value = data.get(key, default)
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise ValueError(f'{label} must be a whole number.') from None
        if not low <= value <= high:
            raise ValueError(f'{label} must be between {low} and {high}.')
        return value

    base = data.get('threshold', 5)
    settings = dict(
        failures=number('failures', 2, 100, 'Failed-login threshold', base),
        users=number('users', 2, 100, 'Distinct-account threshold', base),
        success=number('success', 2, 100, 'Success-after-failures threshold', base),
        minutes=number('minutes', 1, 1440, 'Time window'),
        year=number('year', 1970, 2100, 'Log year'),
    )
    allowlist = data.get('allowlist', [])
    if isinstance(allowlist, str):
        allowlist = allowlist.replace(',', '\n').splitlines()
    if not isinstance(allowlist, list) or len(allowlist) > 100:
        raise ValueError('The allowlist can contain up to 100 entries.')
    settings['allowlist'] = [str(x).strip() for x in allowlist if str(x).strip()]
    return settings


class Handler(BaseHTTPRequestHandler):
    def reply(self, body, status=200, kind='application/json'):
        body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def error(self, message, status=400):
        self.reply(json.dumps({'error': message}), status)

    def trusted(self):
        """Only answer requests addressed to this local server.

        Checking Host blocks DNS-rebinding attacks (a website pointing its own
        domain at 127.0.0.1 to read your saved logs). Checking Origin blocks other
        websites from making your browser send requests here.
        """
        allowed = {f'127.0.0.1:{PORT}', f'localhost:{PORT}'}
        if self.headers.get('Host') not in allowed:
            self.error('Requests must use http://127.0.0.1 on this computer.', 403)
            return False
        origin = self.headers.get('Origin')
        if origin and origin not in {f'http://{host}' for host in allowed}:
            self.error('Cross-site requests are not allowed.', 403)
            return False
        return True

    def scan_id(self):
        try:
            return int(self.path.rsplit('/', 1)[1])
        except ValueError:
            self.error('Invalid scan ID')
            return None

    def do_GET(self):
        if not self.trusted():
            return
        if self.path == '/':
            self.reply(PAGE_PATH.read_text(encoding='utf-8'), kind='text/html')
        elif self.path == '/history':
            with database() as db:
                rows = db.execute(f'SELECT id, created_at, events, alerts, high FROM analyses ORDER BY id DESC LIMIT {MAX_SCANS}').fetchall()
            self.reply(json.dumps([dict(id=r[0], created_at=r[1], events=r[2], alerts=r[3], high=r[4]) for r in rows]))
        elif self.path.startswith('/history/'):
            scan_id = self.scan_id()
            if scan_id is None:
                return
            with database() as db:
                row = db.execute('SELECT id, created_at, result FROM analyses WHERE id = ?', (scan_id,)).fetchone()
            if row is None:
                return self.error('Saved scan not found', 404)
            self.reply(json.dumps(dict(id=row[0], created_at=row[1], result=json.loads(row[2]))))
        elif self.path == '/sample':
            self.reply((ROOT / 'sample.log').read_text(encoding='utf-8'), kind='text/plain')
        else:
            self.error('Not found', 404)

    def do_POST(self):
        if not self.trusted():
            return
        if self.path != '/analyze':
            return self.error('Not found', 404)
        if not self.headers.get('Content-Type', '').startswith('application/json'):
            return self.error('Send settings as JSON.', 415)
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > MAX_BODY:
                raise ValueError('Choose a log file smaller than 5 MB.')
            data = json.loads(self.rfile.read(length) or b'{}')
            text = data.get('text', '')
            if not isinstance(text, str) or not text.strip():
                raise ValueError('Paste or upload some log lines first.')
            settings = read_settings(data)
            result = analyze(text, minutes=settings['minutes'], year=settings['year'], failures=settings['failures'],
                             users=settings['users'], success=settings['success'], allowlist=settings['allowlist'])
            result['settings'] = settings
            result['source_text'] = text
            result['source_name'] = str(data.get('name') or '')[:200]
            with database() as db:
                cursor = db.execute('INSERT INTO analyses (result, events, alerts, high, skipped) VALUES (:result, :events, :alerts, :high, :skipped)',
                                    dict(summarize(result), result=json.dumps(result)))
                scan_id = cursor.lastrowid
                db.execute('DELETE FROM analyses WHERE id NOT IN (SELECT id FROM analyses ORDER BY id DESC LIMIT ?)', (MAX_SCANS,))
            result['id'] = scan_id
            self.reply(json.dumps(result))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            self.error(str(exc))

    def do_DELETE(self):
        if not self.trusted():
            return
        if self.path == '/history':
            with database() as db:
                count = db.execute('DELETE FROM analyses').rowcount
            return self.reply(json.dumps({'deleted': count}))
        if not self.path.startswith('/history/'):
            return self.error('Not found', 404)
        scan_id = self.scan_id()
        if scan_id is None:
            return
        with database() as db:
            count = db.execute('DELETE FROM analyses WHERE id = ?', (scan_id,)).rowcount
        if not count:
            return self.error('Saved scan not found', 404)
        self.reply(json.dumps({'deleted': count}))


class Server(ThreadingHTTPServer):
    # On Windows, SO_REUSEADDR lets two programs share a port, which would hide
    # the "port busy" error and send requests to the wrong app.
    allow_reuse_address = sys.platform != 'win32'
    daemon_threads = True


def main():
    global PORT
    for port in range(8501, 8511):  # fall back to the next free port if 8501 is busy
        try:
            server = Server(('127.0.0.1', port), Handler)
            break
        except OSError:
            continue
    else:
        raise SystemExit('Ports 8501-8510 are all in use. Close another copy of the app and try again.')
    PORT = port
    url = f'http://127.0.0.1:{PORT}'
    print(f'Security Log Analyzer: {url} (Ctrl+C to stop)')
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nDashboard stopped.')
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
