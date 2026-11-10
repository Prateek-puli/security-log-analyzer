"""SSH log parsing and explainable, time-window-based detection.

Parsing
-------
Each recognized line becomes an event with a time, user, source IP, and status
(Failed or Accepted). The source IP is always taken from the *end* of the line
(" from <ip> port <n> ...") and validated with the ipaddress module. sshd writes
attacker-supplied usernames into the log verbatim, so a username such as
"x from 10.0.0.1" must never be able to change which IP gets blamed.

sshd often writes several lines for one attempt (for example "Invalid user ..."
followed by "Failed password for invalid user ..."). Lines that only repeat an
attempt are marked secondary and dropped when the same sshd process (PID) also
logged a primary Failed/Accepted line, so attempts are not double counted.

Detection
---------
Rules run over a rolling time window per source IP. Each rule raises one alert
per burst: while matching events keep arriving within the window the same alert
grows; after a quiet gap longer than the window, a new alert starts.
"""
import ipaddress
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone

TAIL = r' from (?P<ip>\S+) port \d+'

# Primary lines: one per authentication attempt. The greedy (?P<user>.*) makes
# the regex use the LAST " from <ip> port <n>" in the line, which is the part
# sshd appends itself, not the attacker-controlled username.
PRIMARY = re.compile(
    r'(?P<status>Failed|Accepted) (?P<method>\S+) for (?:invalid user )?(?P<user>.*)'
    + TAIL + r'(?: ssh2)?(?:: .*)?\s*$')

# Secondary lines: also describe failed attempts, but often duplicate a primary line.
SECONDARY = [
    ('Invalid user', re.compile(r'Invalid user (?P<user>.*)' + TAIL + r'\s*$')),
    ('Connection closed before authentication', re.compile(
        r'(?:Connection closed|Disconnected) by (?:authenticating|invalid) user (?P<user>.*) (?P<ip>\S+) port \d+ \[preauth\]\s*$')),
    ('PAM authentication failure', re.compile(
        r'pam_unix\(sshd:auth\): authentication failure;.*\brhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?\s*$')),
]

PID = re.compile(r'\b(?P<host>\S+) sshd\[(?P<pid>\d+)\]:')
SYSLOG_STAMP = re.compile(r'^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d')
ISO_STAMP = re.compile(r'^\d{4}-\d\d-\d\dT\S+')

RULE_FAILURES = 'Repeated failed logins'
RULE_USERS = 'Multiple accounts targeted'
RULE_SUCCESS = 'Success after repeated failures'


def parse_allowlist(entries):
    """Turn ['10.0.0.0/8', '192.0.2.5'] into network objects. Raises ValueError for bad entries."""
    networks = []
    for entry in entries or []:
        entry = entry.strip()
        if entry:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                raise ValueError(f'Allowlist entry "{entry}" is not an IP address or CIDR range.') from None
    return networks


def parse_time(line, year):
    """Return (naive UTC-or-local datetime, kind) for a log line, or (None, None)."""
    iso = ISO_STAMP.match(line)
    if iso:
        stamp = datetime.fromisoformat(iso.group().replace('Z', '+00:00'))
        if stamp.tzinfo:  # convert offsets to UTC so mixed-timezone logs sort correctly
            stamp = stamp.astimezone(timezone.utc).replace(tzinfo=None)
        return stamp, 'iso'
    syslog = SYSLOG_STAMP.match(line)
    if syslog:
        return datetime.strptime(f'{year} {syslog.group()}', '%Y %b %d %H:%M:%S'), 'syslog'
    return None, None


def match_line(line):
    """Return (status, user, ip, kind, primary) for an SSH auth line, or None."""
    match = PRIMARY.search(line)
    if match:
        kind = f"{match['status']} {match['method']}"
        return match['status'], match['user'], match['ip'], kind, True
    for kind, pattern in SECONDARY:
        match = pattern.search(line)
        if match:
            return 'Failed', match['user'] or '(unknown)', match['ip'], kind, False
    return None


def parse(text, year=2026):
    """Parse log text into sorted events. Returns (events, skipped_count)."""
    events, skipped = [], 0
    last_syslog = None
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        found = match_line(line)
        if not found:
            skipped += 1
            continue
        status, user, ip, kind, primary = found
        try:
            ip = str(ipaddress.ip_address(ip))
            stamp, stamp_kind = parse_time(line, year)
        except ValueError:
            stamp = None
        if stamp is None:
            skipped += 1
            continue
        if stamp_kind == 'syslog':
            # Syslog lines carry no year. If time jumps back by more than a month
            # (e.g. Dec 31 -> Jan 1), assume the log rolled into the next year.
            if last_syslog and stamp < last_syslog - timedelta(days=30):
                year += 1
                stamp = stamp.replace(year=year)
            last_syslog = stamp
        pid = PID.search(line)
        events.append(dict(
            time=stamp.isoformat(), user=user, ip=ip, status=status, kind=kind,
            line=line_no, raw=line, _dt=stamp, _primary=primary,
            _pid=(pid['host'], pid['pid']) if pid else None))

    # Drop secondary lines that repeat an attempt already logged by the same sshd process.
    primary_pids = {e['_pid'] for e in events if e['_primary'] and e['_pid']}
    events = [e for e in events if e['_primary'] or e['_pid'] is None or e['_pid'] not in primary_pids]
    events.sort(key=lambda e: (e['_dt'], e['line']))
    return events, skipped


class Detector:
    """Rolling-window rules for one analysis."""

    def __init__(self, failures, users, success, minutes):
        self.failures, self.users, self.success = failures, users, success
        self.window = timedelta(minutes=minutes)
        self.minutes = minutes
        self.recent = defaultdict(deque)     # ip -> failed events inside the window
        self.open = {}                       # (ip, rule, user) -> alert still growing
        self.alerts = []

    def feed(self, event):
        now, ip = event['_dt'], event['ip']
        recent = self.recent[ip]
        while recent and now - recent[0]['_dt'] > self.window:
            recent.popleft()
        if event['status'] == 'Failed':
            recent.append(event)
            if len(recent) >= self.failures:
                self.raise_alert(RULE_FAILURES, 'Medium', event, list(recent))
            distinct = {e['user'] for e in recent}
            if len(distinct) >= self.users:
                self.raise_alert(RULE_USERS, 'High', event, list(recent))
        else:
            same_user = [e for e in recent if e['user'] == event['user']]
            if len(same_user) >= self.success:
                self.raise_alert(RULE_SUCCESS, 'High', event, same_user + [event], user=event['user'])

    def raise_alert(self, rule, severity, event, evidence, user=None):
        key = (event['ip'], rule, user)
        alert = self.open.get(key)
        if alert and event['_dt'] - alert['_end'] <= self.window:
            seen = {e['line'] for e in alert['_evidence']}
            alert['_evidence'] += [e for e in evidence if e['line'] not in seen]
            alert['_end'] = event['_dt']
            return
        alert = dict(rule=rule, severity=severity, ip=event['ip'], _evidence=list(evidence), _end=event['_dt'])
        self.open[key] = alert
        self.alerts.append(alert)

    def results(self):
        out = []
        for alert in self.alerts:
            evidence = alert.pop('_evidence')
            end = alert.pop('_end')
            failed = [e for e in evidence if e['status'] == 'Failed']
            users = sorted({e['user'] for e in evidence})
            start = evidence[0]['_dt']
            span = max(1, round((end - start).total_seconds() / 60))
            if alert['rule'] == RULE_SUCCESS:
                text = f'{len(failed)} failed logins for "{users[0]}", then a successful login.'
            elif alert['rule'] == RULE_USERS:
                text = f'{len(failed)} failed logins across {len(users)} different accounts.'
            else:
                text = f'{len(failed)} failed logins.'
            text += f' Burst lasted about {span} min (window {self.minutes} min). Review the source and account activity.'
            out.append(dict(alert, time=start.isoformat(), end=end.isoformat(), count=len(failed),
                            users=users, explanation=text, lines=[e['line'] for e in evidence],
                            evidence=[public(e) for e in evidence]))
        out.sort(key=lambda a: (a['severity'] != 'High', a['time']))
        return out


def public(event):
    return {k: v for k, v in event.items() if not k.startswith('_')}


def analyze(text, threshold=5, minutes=5, year=2026, *, failures=None, users=None,
            success=None, allowlist=None):
    """Parse and analyze SSH logs.

    `threshold` is the default for every rule; `failures`, `users`, and `success`
    override it per rule. `allowlist` is a list of IPs/CIDR ranges to ignore
    during detection (their events are still listed).
    """
    networks = parse_allowlist(allowlist)
    events, skipped = parse(text, year)
    detector = Detector(failures or threshold, users or threshold, success or threshold, minutes)
    for event in events:
        address = ipaddress.ip_address(event['ip'])
        event['allowlisted'] = any(address in net for net in networks)
        if not event['allowlisted']:
            detector.feed(event)
    alerts = detector.results()
    return dict(events=[public(e) for e in events], alerts=alerts, skipped=skipped)
