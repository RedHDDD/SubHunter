"""Certificate transparency enumeration using crt.sh."""

import requests


def run_crt(target, progress=None, user_agent=None) -> set[str]:
    """Two attempts at most; read timeouts are inactivity limits, not deadlines."""
    headers = {'User-Agent': user_agent} if user_agent is not None else None
    for attempt in range(2):
        if progress:
            progress(f'Loading crt.sh (attempt {attempt + 1}/2; connect 5s, read 12s)')
        try:
            with requests.get('https://crt.sh/', params={'q': '%.' + target, 'output': 'json'},
                              timeout=(5, 12), headers=headers) as response:
                response.raise_for_status()
                try:
                    data = response.json()
                except ValueError as error:
                    raise RuntimeError('crt.sh returned invalid or missing JSON.') from error
            break
        except (requests.Timeout, requests.ConnectionError) as error:
            if attempt == 1:
                if isinstance(error, requests.Timeout):
                    raise TimeoutError('crt.sh timed out after two attempts.') from error
                raise RuntimeError(f'crt.sh connection failed after two attempts: {error}') from error
            if progress:
                progress('crt.sh is slow or unavailable; retrying once')
        except requests.HTTPError as error:
            status = error.response.status_code
            if attempt == 0 and status in (429, 500, 502, 503, 504):
                if progress:
                    progress(f'crt.sh HTTP {status}; retrying once')
                continue
            raise RuntimeError(f'crt.sh HTTP {status}; request failed.') from error

    if not isinstance(data, list):
        raise RuntimeError('crt.sh returned an unexpected JSON structure.')
    results = set()
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get('name_value'), str):
            raise RuntimeError('crt.sh returned a malformed certificate entry.')
        results.update(entry['name_value'].splitlines())
    if progress:
        progress(f'Received {len(data)} certificate entries', len(data))
    return results
