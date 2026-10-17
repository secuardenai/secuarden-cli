#!/usr/bin/env python3
"""Render actual CLI output from explicitly synthetic hook input, without live agents."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, default=HERE.parent.parent)
args = parser.parse_args()
source = args.source.resolve()

def run(argv, **kwargs):
    result = subprocess.run([str(x) for x in argv], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout

with tempfile.TemporaryDirectory(prefix='secuarden-demo-', dir='/private/tmp') as temporary:
    work = Path(temporary)
    home, repo, frames = work / 'home', work / 'repository', work / 'frames'
    for p in (home / '.claude', repo / 'src/auth', frames, work / 'bin'):
        p.mkdir(parents=True, exist_ok=True)
    (home / '.claude/settings.json').write_text('{}\n')
    (repo / 'src/auth/middleware.ts').write_text('export function middleware(request, next) {\n  return next(request)\n}\n')
    (repo / '.env.example').write_text('DEMO_VALUE=placeholder\n')
    binary = work / 'bin/secuarden'
    build_env = dict(os.environ, GOCACHE='/private/tmp/secuarden-demo-go-cache', CGO_ENABLED='0')
    run(['go', 'build', '-ldflags', '-X github.com/secuardenai/secuarden-cli/cmd.Version=demo',
         '-o', binary, './cmd/secuarden'], cwd=source, env=build_env)
    # Child processes alone use a disposable home; never change the caller's shell.
    env = {'HOME': str(home), 'USER': 'demo', 'LOGNAME': 'demo',
           'PATH': str(binary.parent) + ':' + os.environ['PATH'],
           'TMPDIR': str(work), 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': str(home / '.gitconfig'), 'NO_COLOR': '1', 'TERM': 'dumb'}
    def local(*argv, **kwargs):
        return run(argv, cwd=repo, env=env, **kwargs)
    local('git', 'init', '-q')
    local('git', 'symbolic-ref', 'HEAD', 'refs/heads/main')
    local('git', 'config', 'user.name', 'Demo Developer')
    local('git', 'config', 'user.email', 'developer@example.invalid')
    local('git', 'remote', 'add', 'origin', 'https://example.invalid/acme/demo-repository.git')
    local('git', 'add', '.')
    local('git', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Demo baseline')
    transcript = []
    number = 0
    def screen(title, command, output, note, excerpt=False):
        global number
        # Only display paths are abbreviated; stored evidence is left untouched.
        output = output.replace(str(repo), '/demo/repository').replace(str(home), '/demo/home')
        output = re.sub(r'\x1b\[[0-9;]*m', '', output).rstrip()
        transcript.append(f'{title}\n$ {command}\n{output}\n{note}\n')
        lines = []
        displayed = output
        if excerpt:
            displayed = '\n'.join(output.splitlines()[:12]) + '\n\n[Setup excerpt; full output in transcript.txt]\nLive capture verification is pending.'
        for line in displayed.splitlines():
            lines.extend(textwrap.wrap(line, width=100, replace_whitespace=False,
                                       drop_whitespace=False) or [''])
        pages = [lines[i:i+21] for i in range(0, len(lines), 21)] or [[]]
        for page, body in enumerate(pages, 1):
            number += 1
            suffix = f' ({page}/{len(pages)})' if len(pages) > 1 else ''
            content = '\n'.join([title + suffix, 'SYNTHETIC HOOK REPLAY | current CLI output | local only', '',
                                 '$ ' + command, '', *body, '', note])
            (frames / f'{number:02}.txt').write_text(content + '\n')
    output = local(binary, 'init', '--repo', '.', '--agent', 'claude-code', '--scope', 'repo', '--receipt-mode', 'explicit')
    screen('01 / SET UP REPOSITORY CAPTURE', 'secuarden init --repo . --agent claude-code --scope repo --receipt-mode explicit',
           output, 'Setup is configured. A replay does not establish live runtime delivery.', excerpt=True)
    commands = [('01-session-start.json', 'session-start'), ('02-read.json', 'pre-tool-use'),
                ('02-read-post.json', 'post-tool-use'), ('03-sensitive-read.json', 'pre-tool-use'),
                ('03-sensitive-read-post.json', 'post-tool-use'), ('04-edit.json', 'pre-tool-use'),
                ('04-edit-post.json', 'post-tool-use'), ('05-command-pre.json', 'pre-tool-use'),
                ('06-command-post.json', 'post-tool-use'), ('07-mcp.json', 'pre-tool-use'),
                ('07-mcp-post.json', 'post-tool-use'), ('08-session-end.json', 'session-end')]
    for filename, hook in commands:
        payload = json.loads((HERE / 'fixtures' / filename).read_text())
        payload['cwd'] = str(repo)
        if filename == '04-edit-post.json':
            path = repo / 'src/auth/middleware.ts'
            path.write_text(path.read_text().replace('return next(request)', 'return validate(request, next)'))
        local(binary, 'hook', hook, input=json.dumps(payload))
    screen('02 / WHAT DID THE AGENT TOUCH?', 'secuarden events --last 8',
           local(binary, 'events', '--last', '8'),
           'Fixture outcomes include a reported failing test command and a sensitive file read.')
    screen('03 / INVESTIGATE SENSITIVE ACCESS', 'secuarden events --sensitive --last 4',
           local(binary, 'events', '--sensitive', '--last', '4'),
           'The demo .env.example contains only a placeholder. No real secrets are used.')
    screen('04 / REVIEW THE SESSION', 'secuarden report --since 24h --limit 2',
           local(binary, 'report', '--since', '24h', '--limit', '2'),
           'Reported outcomes are evidence from hook payloads, not independently run tests.')
    integrity = json.loads(local(binary, 'verify', '--json'))
    assert integrity.get('valid') is True, integrity
    screen('05 / CHECK THE STORED EVIDENCE', 'secuarden verify', local(binary, 'verify'),
           'Hash verification checks stored records; it does not prove complete capture.')
    bom = local(binary, 'bom', '--since', '24h')
    json.loads(bom)
    text = '\n'.join(transcript)
    forbidden = [str(Path.home()), str(source), os.environ.get('USER', '')]
    for value in forbidden:
        if len(value) > 3 and value in text:
            raise RuntimeError('Host identity or path found in display output')
    if re.search(r'AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}', text):
        raise RuntimeError('Credential-like text found in display output')
    output = HERE / 'secuarden-terminal-demo.gif'
    run(['swift', '-module-cache-path', '/private/tmp/secuarden-demo-swift-cache',
         HERE / 'render.swift', frames, output])
    assert output.stat().st_size < 5_000_000, 'GIF exceeds 5 MB'
    (HERE / 'transcript.txt').write_text(text)
    print(f'Generated {number} frames ({output.stat().st_size:,} bytes).')
    print('Verified real capture storage, hash integrity, and JSON AI-BOM export.')
    print('Synthetic replay only: no agent launched, no SaaS sync, no host settings changed.')
