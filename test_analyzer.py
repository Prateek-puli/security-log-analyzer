import unittest
from pathlib import Path
from analyzer import analyze

SAMPLE = Path(__file__).with_name('sample.log').read_text()


def failed(n, ip='192.0.2.1', user='a', start_minute=0, step_seconds=10, day=16):
    """Build n syslog 'Failed password' lines from one IP."""
    lines = []
    for i in range(n):
        total = start_minute * 60 + i * step_seconds
        lines.append(f'Oct {day} {total // 3600:02}:{total // 60 % 60:02}:{total % 60:02} host sshd[{1000 + i}]: '
                     f'Failed password for {user} from {ip} port 22 ssh2')
    return '\n'.join(lines)


class DetectionTests(unittest.TestCase):
    def test_sample(self):
        result = analyze(SAMPLE)
        self.assertEqual(len(result['events']), 12)
        self.assertEqual(len(result['alerts']), 4)
        self.assertEqual(result['skipped'], 0)
        rules = {(a['rule'], a['ip']) for a in result['alerts']}
        self.assertIn(('Success after repeated failures', '203.0.113.50'), rules)
        self.assertIn(('Multiple accounts targeted', '198.51.100.20'), rules)

    def test_outside_window(self):
        lines = '\n'.join(f'Oct 16 {hour:02}:00:00 host sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2' for hour in range(6))
        self.assertEqual(analyze(lines)['alerts'], [])

    def test_unrecognized(self):
        self.assertEqual(analyze('unrelated log line')['skipped'], 1)

    def test_other_account_success(self):
        text = SAMPLE.replace('Accepted password for admin', 'Accepted password for bob')
        self.assertFalse(any(a['rule'] == 'Success after repeated failures' for a in analyze(text)['alerts']))


class ParsingTests(unittest.TestCase):
    def test_username_cannot_spoof_source_ip(self):
        # sshd logs the attacker's username verbatim, including spaces.
        line = 'Oct 16 09:00:00 host sshd[1]: Failed password for invalid user x from 10.9.9.9 port 1 from 203.0.113.7 port 4242 ssh2'
        event = analyze(line)['events'][0]
        self.assertEqual(event['ip'], '203.0.113.7')
        self.assertEqual(event['user'], 'x from 10.9.9.9 port 1')

    def test_invalid_ip_is_skipped(self):
        result = analyze('Oct 16 09:00:00 host sshd[1]: Failed password for a from not-an-ip port 22 ssh2')
        self.assertEqual((result['events'], result['skipped']), ([], 1))

    def test_more_formats(self):
        text = '\n'.join([
            'Oct 16 09:00:00 host sshd[1]: Failed keyboard-interactive/pam for root from 192.0.2.1 port 22 ssh2',
            'Oct 16 09:00:01 host sshd[2]: Accepted publickey for bob from 192.0.2.2 port 22 ssh2: ED25519 SHA256:abc',
            'Oct 16 09:00:02 host sshd[3]: Invalid user guest from 192.0.2.3 port 22',
            'Oct 16 09:00:03 host sshd[4]: Connection closed by authenticating user root 192.0.2.4 port 22 [preauth]',
            'Oct 16 09:00:04 host sshd[5]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.5  user=carol',
            'Oct 16 09:00:05 host sshd[6]: Failed password for dave from 2001:db8::1 port 22 ssh2',
        ])
        events = analyze(text)['events']
        self.assertEqual([e['ip'] for e in events], ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.5', '2001:db8::1'])
        self.assertEqual([e['status'] for e in events], ['Failed', 'Accepted', 'Failed', 'Failed', 'Failed', 'Failed'])
        self.assertEqual(events[4]['user'], 'carol')

    def test_duplicate_lines_for_one_attempt_count_once(self):
        text = '\n'.join([
            'Oct 16 09:00:00 host sshd[7]: Invalid user guest from 192.0.2.3 port 22',
            'Oct 16 09:00:01 host sshd[7]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.3',
            'Oct 16 09:00:02 host sshd[7]: Failed password for invalid user guest from 192.0.2.3 port 22 ssh2',
        ])
        events = analyze(text)['events']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['kind'], 'Failed password')

    def test_timezone_offsets_are_converted_to_utc(self):
        text = '\n'.join([
            '2026-10-16T10:00:00+02:00 host sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2',  # 08:00 UTC
            '2026-10-16T09:00:00Z host sshd[2]: Failed password for b from 192.0.2.1 port 22 ssh2',
        ])
        events = analyze(text)['events']
        self.assertEqual([e['time'] for e in events], ['2026-10-16T08:00:00', '2026-10-16T09:00:00'])
        self.assertEqual(events[0]['user'], 'a')

    def test_year_rollover(self):
        text = '\n'.join([
            'Dec 31 23:59:00 host sshd[1]: Failed password for a from 192.0.2.1 port 22 ssh2',
            'Jan  1 00:01:00 host sshd[2]: Failed password for a from 192.0.2.1 port 22 ssh2',
        ])
        times = [e['time'] for e in analyze(text, year=2025)['events']]
        self.assertEqual(times, ['2025-12-31T23:59:00', '2026-01-01T00:01:00'])


class RuleTests(unittest.TestCase):
    def test_separate_bursts_get_separate_alerts(self):
        text = failed(5, start_minute=0) + '\n' + failed(5, start_minute=120)
        alerts = analyze(text)['alerts']
        self.assertEqual(len(alerts), 2)
        self.assertEqual([a['count'] for a in alerts], [5, 5])

    def test_one_long_burst_is_one_alert(self):
        alerts = analyze(failed(30, step_seconds=60))['alerts']  # one attempt per minute for 30 minutes
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['count'], 30)

    def test_per_rule_thresholds(self):
        text = '\n'.join(failed(1, user=u, start_minute=i) for i, u in enumerate('abc'))
        rules = {a['rule'] for a in analyze(text, failures=10, users=3)['alerts']}
        self.assertEqual(rules, {'Multiple accounts targeted'})

    def test_allowlist(self):
        result = analyze(SAMPLE, allowlist=['203.0.113.0/24'])
        self.assertTrue(all(a['ip'] != '203.0.113.50' for a in result['alerts']))
        self.assertTrue(any(e['allowlisted'] for e in result['events']))
        with self.assertRaises(ValueError):
            analyze(SAMPLE, allowlist=['not-an-ip'])


if __name__ == '__main__':
    unittest.main()
