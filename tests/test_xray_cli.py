# SPDX-License-Identifier: GPL-3.0-or-later
"""offline audit smoke tests against the built executable."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    exe = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'server.json'
        cfg = {
            'protocol': 'vless', 'port': 443,
            'settings': {'decryption': 'none', 'flow': 'xtls-rprx-vision',
                         'users': [{'id': 'TEST_SECRET_UUID'}]},
            'streamSettings': {'method': 'raw', 'security': 'tls'},
        }

        def run(expected, as_json=True):
            args = [exe, 'audit-config', str(path), '--json' if as_json else '--no-color']
            result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', timeout=15)
            assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
            assert 'TEST_SECRET_UUID' not in result.stdout
            return json.loads(result.stdout) if as_json else result.stdout

        path.write_text(json.dumps(cfg), encoding='utf-8')
        report = run(0)
        assert report['protocols'][0]['flow'] == 'vision'
        assert report['protocols'][0]['vision_users'] == 1
        assert report['network_confirmed'] is False
        assert report['runtime_validated'] is False
        assert 'flow=vision' in run(0, False)

        cfg['streamSettings']['method'] = 'quic'
        path.write_text(json.dumps(cfg), encoding='utf-8')
        report = run(65)
        assert report['ok'] is True
        assert report['compatibility_errors'] > 0
        assert report['tspu_tier'] == 'UNKNOWN'
        assert any(f['tag'] == 'removed-transport' for f in report['findings'])
        assert 'compatibility errors:' in run(65, False)

        path.write_text('{invalid', encoding='utf-8')
        assert run(64)['ok'] is False
        path.unlink()
        assert run(64)['ok'] is False
        path.write_bytes(b' ' * (16 * 1024 * 1024 + 1))
        assert run(64)['ok'] is False
    print('xray audit CLI: passed')


if __name__ == '__main__':
    main()
