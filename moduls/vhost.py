"""Compare Host-header responses against two random baseline hosts."""

from concurrent.futures import ThreadPoolExecutor
from difflib import SequenceMatcher
import re
from time import monotonic
from uuid import uuid4

import requests


def response_signature(url, hostname, user_agent=None):
    """Read a bounded body sample; never follow redirects off the target."""
    headers = {'Host': hostname, 'User-Agent': 'SubHunter/1.0' if user_agent is None else user_agent}
    with requests.get(url, headers=headers,
                      timeout=(3, 5), allow_redirects=False, stream=True) as response:
        if response.status_code == 429 or response.status_code >= 500:
            response.raise_for_status()
        body = bytearray()
        started = monotonic()
        for chunk in response.iter_content(1024):
            body.extend(chunk)
            if len(body) >= 16384:
                break
            if monotonic() - started > 10:
                raise TimeoutError('VHost body sample exceeded its time budget.')
        text = bytes(body[:16384]).decode('utf-8', errors='replace').lower()
        location = response.headers.get('Location', '').lower()
        text = text.replace(hostname.lower(), '<host>')
        location = location.replace(hostname.lower(), '<host>')
        # Ignore common volatile timestamps, counters and request identifiers.
        text = re.sub(r'\b[0-9a-f]{16,}\b|\d+', '<value>', text)
        text = re.sub(r'\s+', ' ', text)
        return response.status_code, location, text


def similar(first, second):
    return (first[:2] == second[:2]
            and SequenceMatcher(None, first[2], second[2]).ratio() >= 0.90)


def run_vhost(target, candidates, progress=None, user_agent=None) -> set[str]:
    if progress:
        progress('Connecting via HTTPS and checking default responses')
    baseline_host = f'{uuid4().hex}.{target}'
    try:
        url = f'https://{target}/'
        baseline = response_signature(url, baseline_host, user_agent)
    except (requests.RequestException, TimeoutError):
        if progress:
            progress('HTTPS unavailable; trying HTTP')
        url = f'http://{target}/'
        try:
            baseline = response_signature(url, baseline_host, user_agent)
        except requests.Timeout as error:
            raise TimeoutError('VHost target timed out over HTTPS and HTTP.') from error
        except requests.RequestException as error:
            raise RuntimeError(f'VHost target unreachable over HTTPS and HTTP: {error}') from error
    second = response_signature(url, f'{uuid4().hex}.{target}', user_agent)
    if not similar(baseline, second):
        raise RuntimeError('VHost default responses are unstable; cannot reliably compare candidates.')

    def check(hostname):
        try:
            response = response_signature(url, hostname, user_agent)
            if similar(response, baseline) or similar(response, second):
                return False, None
            confirmation = response_signature(url, hostname, user_agent)
            distinct = (similar(response, confirmation)
                        and not similar(confirmation, baseline)
                        and not similar(confirmation, second))
            return distinct, None
        except (requests.Timeout, TimeoutError):
            return False, 'timeout'
        except requests.RequestException:
            return False, 'request failed'

    results = set()
    errors = []
    completed = 0
    with ThreadPoolExecutor(max_workers=4) as pool:
        for offset in range(0, len(candidates), 16):
            batch = candidates[offset:offset + 16]
            for hostname, (distinct, error) in zip(batch, pool.map(check, batch)):
                if distinct:
                    results.add(hostname)
                if error:
                    errors.append(error)
                completed += 1
                if progress:
                    progress(f'{completed}/{len(candidates)} candidates; {len(errors)} request errors', completed)
    if errors and not results:
        if all(error == 'timeout' for error in errors):
            raise TimeoutError(f'VHost scan incomplete: {len(errors)} timed-out candidates.')
        raise RuntimeError(f'VHost scan incomplete: {len(errors)} failed candidates.')
    if errors and progress:
        progress(f'Partial results: {len(errors)} VHost request errors', completed)
    return results
