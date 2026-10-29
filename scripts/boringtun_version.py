#!/usr/bin/env python3
"""Read-only version/notes checks against immutable source snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

import boringtun_release_policy as policy

INTENT = 'packaging/boringtun/release-intent.json'
BASELINE = '60f5f278c2f7c0e91b96b898ef887dd859ec9887'
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')


def require(value, message):
    if not value:
        raise policy.PolicyError(message)


def semver(value):
    require(type(value) is str and len(value) <= 32 and VERSION.fullmatch(value), 'invalid stable semantic version')
    return tuple(map(int, value.split('.')))


def read_data(read, path):
    raw = read(path)
    require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024, 'missing or oversized source file: ' + path)
    return raw


def check_versions(read):
    library = tomllib.loads(read_data(read, 'boringtun/Cargo.toml').decode())
    cli = tomllib.loads(read_data(read, 'boringtun-cli/Cargo.toml').decode())
    lock = tomllib.loads(read_data(read, 'Cargo.lock').decode())
    value = library['package']['version']
    semver(value)
    require(cli['package']['version'] == value and cli['dependencies']['boringtun']['version'] == value
            and cli['dependencies']['boringtun']['path'] == '../boringtun', 'Cargo packages/dependency versions disagree')
    for name in ('boringtun', 'boringtun-cli'):
        packages = [p for p in lock['package'] if p['name'] == name]
        require(len(packages) == 1 and packages[0]['version'] == value and 'source' not in packages[0],
                'Cargo.lock workspace version mismatch or duplicate: ' + name)
    return value


def notes(read, value):
    semver(value)
    raw = read_data(read, f'docs/releases/{value}.md')
    require(len(raw) <= 20000, 'release notes exceed 20 KB')
    text = raw.decode('utf-8').replace('\r\n', '\n').strip()
    require(text and not any(marker in text for marker in ('<', '>', 'descriptor_sha256=', 'RELEASE.json(base64)='))
            and all(ord(c) >= 32 or c == '\n' for c in text), 'unsafe release notes or reserved metadata marker')
    require('## Compatibility & upgrade notes\n' in text, 'release notes need Compatibility & upgrade notes')
    return text


def check_transition(read_base, read_source, changed_paths):
    before, after = check_versions(read_base), check_versions(read_source)
    notice_policy = policy.load_json(read_data(read_source, 'packaging/boringtun/notice-policy.json'))
    require(type(notice_policy) is dict, 'notice policy must be an object')
    reviewed_locks = notice_policy.get('source_lock_sha256')
    require(type(reviewed_locks) is list and
            hashlib.sha256(read_data(read_source, 'Cargo.lock')).hexdigest() in reviewed_locks,
            'Cargo.lock checksum missing from reviewed notice policy')
    raw = read_data(read_source, INTENT)
    require(len(raw) <= 4096 and raw != read_base(INTENT), 'each PR must update its release intent')
    intent = policy.load_json(raw)
    policy._keys(intent, 'schema bump base_version version reason', 'release intent')
    require(type(intent['schema']) is int and intent['schema'] == 1, 'unsupported release intent')
    require(intent['base_version'] == before and intent['version'] == after,
            'stale release intent: refresh against the actual base version')
    require(type(intent['reason']) is str and 10 <= len(intent['reason'].strip()) <= 1000, 'explain the version choice')
    major, minor, patch = semver(before)
    expected = {'patch': (major, minor, patch + 1), 'minor': (major, minor + 1, 0), 'none': (major, minor, patch)}
    require(intent['bump'] in expected and semver(after) == expected[intent['bump']], 'version does not match explicit bump')
    require(type(changed_paths) is list and changed_paths and all(type(p) is str for p in changed_paths), 'missing changed paths')
    require(INTENT in changed_paths, 'release intent is not changed by this PR')
    if intent['bump'] == 'none':
        require(all(p == INTENT or p in ('README.md', 'CHANGELOG.md') or p.startswith(('docs/', 'tests/'))
                    for p in changed_paths), 'none is restricted to documentation and tests')
    else:
        require(semver(after) >= (0, 8, 0), 'new releases start at 0.8.0')
        notes(read_source, after)
        require(f'docs/releases/{after}.md' in changed_paths, 'release notes must be reviewed in this PR')
    return intent


def git_reader(root, ref):
    require(re.fullmatch(r'[0-9a-f]{40}', ref), 'Git snapshot must be a full commit SHA')
    def read(path):
        result = subprocess.run(['git', '-C', str(root), 'show', f'{ref}:{path}'], capture_output=True)
        if result.returncode:
            if path == INTENT:
                return None
            raise policy.PolicyError('cannot read Git snapshot: ' + path)
        return result.stdout
    return read


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, help='exact current base commit')
    parser.add_argument('--source', required=True, help='exact candidate or merge commit')
    args = parser.parse_args(argv)
    try:
        root = Path(__file__).resolve().parents[1]
        read_base, read_source = git_reader(root, args.base), git_reader(root, args.source)
        result = subprocess.run(['git', '-C', str(root), 'diff', '--no-renames', '--name-only', '-z', args.base, args.source],
                                check=True, capture_output=True)
        paths = result.stdout.decode().rstrip('\0').split('\0')
        print(json.dumps(check_transition(read_base, read_source, paths), sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as exc:
        print('Release intent blocked: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
