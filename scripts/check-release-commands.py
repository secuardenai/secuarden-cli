#!/usr/bin/env python3
"""Check documented command syntax without executing setup, capture, or uploads."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
args = parser.parse_args()
binary = args.binary.resolve()
source = Path(__file__).resolve().parent.parent
commands = set()
for page in (source / 'docs-site/src/content/docs').rglob('*.md'):
    for line in page.read_text().splitlines():
        if line.startswith('secuarden '):
            commands.add(tuple(shlex.split(line)[1:]))
if not commands:
    raise SystemExit('No documentation command examples found')
with tempfile.TemporaryDirectory(prefix='secuarden-release-check-') as temp:
    env = dict(os.environ, HOME=temp, GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL=os.devnull)
    failures = []
    for command in sorted(commands):
        argv = list(command)
        if '--help' not in argv:
            argv.append('--help')
        result = subprocess.run([str(binary), *argv], cwd=temp, env=env,
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            failures.append('secuarden ' + ' '.join(command) + '\n' + result.stderr)
    # Also evaluate a pure, read-only feature command. A version label alone
    # must not stand in for the feature surface promised by this release.
    result = subprocess.run([str(binary), 'attestation', 'contracts'], cwd=temp,
                            env=env, text=True, capture_output=True, timeout=30)
    if result.returncode:
        failures.append('attestation contracts unavailable: ' + result.stderr)
    else:
        contracts = json.loads(result.stdout)
        if {c['adapter'] for c in contracts} != {'claude-code', 'codex'}:
            failures.append('Expected Claude Code and Codex capture contracts')
    if failures:
        raise SystemExit('\n\n'.join(failures))
print(f'Passed {len(commands)} documentation command-help checks and embedded contract output.')
print('No hooks, live-agent delivery, or remote services were exercised.')
