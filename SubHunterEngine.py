"""Validation, module orchestration and output. No terminal dependencies."""

import ipaddress
from pathlib import Path
import re
from time import monotonic

import requests

from moduls.crt import run_crt
from moduls.dns import run_dns
from moduls.vhost import run_vhost


def normalize_domain(value):
    """Return a lowercase ASCII hostname, rejecting URLs and IP addresses."""
    value = value.strip().rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as error:
        raise ValueError('Invalid domain name.') from error
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2:
        raise ValueError('Enter a domain such as example.com, without a URL or port.')
    for label in labels:
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
            raise ValueError('Invalid domain label; use a domain without a URL or port.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Use a domain name, not an IP address.')


def select_modules(crt=False, dns=False, vhost=False):
    selected = []
    if crt:
        selected.append('CRT')
    if dns:
        selected.append('DNS')
    if vhost:
        selected.append('VHOST')
    return selected or ['CRT', 'DNS', 'VHOST']


def filter_results(values, target):
    results = set()
    for value in values:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if value.startswith('*.'):
            value = value[2:]
        try:
            domain = normalize_domain(value)
        except ValueError:
            continue
        if domain.endswith('.' + target):
            results.add(domain)
    return results


def read_wordlist(path, target):
    """Accept relative labels or full in-scope names, one per line."""
    candidates = set()
    with Path(path).expanduser().open(encoding='utf-8-sig') as source:
        for line in source:
            word = line.strip().lower().rstrip('.')
            if not word or word.startswith('#') or word == target:
                continue
            if not word.endswith('.' + target):
                word += '.' + target
            if '*' not in word:
                candidates.update(filter_results([word], target))
    if not candidates:
        raise ValueError('The wordlist contains no valid candidates.')
    return sorted(candidates)


def run_scan(target, wordlist=None, crt=False, dns=False, vhost=False,
             output=None, callback=None, user_agent=None):
    """Callback receives (module, state, detail, seconds, count)."""
    target = normalize_domain(target)
    selected = select_modules(crt, dns, vhost)
    candidates = []
    if 'DNS' in selected or 'VHOST' in selected:
        if not wordlist:
            raise ValueError('DNS and VHost require a wordlist. Use -w <wordlist>.')
        candidates = read_wordlist(wordlist, target)

    results = set()
    reports = {}
    for name in ['CRT', 'DNS', 'VHOST']:
        if name not in selected:
            reports[name] = {'state': 'SKIPPED', 'seconds': 0, 'count': 0, 'detail': 'Disabled'}
            if callback:
                callback(name, 'SKIPPED', 'Disabled', 0, 0)
            continue
        started = monotonic()
        notes = []

        def progress(detail, count=0):
            if detail.startswith('Partial results:'):
                notes.append(detail)
            if callback:
                callback(name, 'RUNNING', detail, monotonic() - started, count)

        progress('Starting')
        found = set()
        try:
            if name == 'CRT':
                found = run_crt(target, progress, user_agent=user_agent)
            elif name == 'DNS':
                found = run_dns(target, candidates, progress)
            elif name == 'VHOST':
                found = run_vhost(target, candidates, progress, user_agent=user_agent)
            found = filter_results(found, target)
            results.update(found)
            state = 'SUCCESS' if found else 'EMPTY'
            detail = '; '.join(notes)
        except (TimeoutError, requests.Timeout) as error:
            state, detail = 'TIMEOUT', str(error)
        except Exception as error:
            state, detail = 'FAILED', str(error)
        elapsed = monotonic() - started
        reports[name] = {'state': state, 'seconds': elapsed, 'count': len(found), 'detail': detail}
        if callback:
            callback(name, state, detail, elapsed, len(found))

    ordered = sorted(results)
    saved_path = None
    failed = any(report['state'] in ('FAILED', 'TIMEOUT') for report in reports.values())
    if output and (ordered or not failed):
        destination = Path(output).expanduser().resolve()
        destination.write_text(''.join(domain + '\n' for domain in ordered), encoding='utf-8')
        saved_path = str(destination)
    return {'target': target, 'results': ordered, 'modules': reports, 'output': saved_path}
