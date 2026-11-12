"""Bounded A/AAAA enumeration with conservative wildcard checks."""

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import dns.exception
import dns.resolver


def resolve_candidate(hostname):
    """Return addresses, CNAME destinations and lookup problems."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    addresses, aliases, problems = set(), set(), []
    for record_type in ('A', 'AAAA'):
        try:
            answer = resolver.resolve(hostname, record_type, search=False)
            addresses.update(str(record) for record in answer)
            canonical = str(answer.canonical_name).rstrip('.').lower()
            if canonical != hostname:
                aliases.add(canonical)
        except dns.resolver.NXDOMAIN:
            break
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.Timeout:
            problems.append('timeout')
        except dns.resolver.NoNameservers:
            problems.append('nameservers unavailable')
    return addresses, aliases, problems


def run_dns(target, candidates, progress=None) -> set[str]:
    if progress:
        progress('Checking wildcard DNS')
    first = resolve_candidate(f'{uuid4().hex}.{target}')
    second = resolve_candidate(f'{uuid4().hex}.{target}')
    wildcard_aliases = first[1] & second[1]
    wildcard_addresses = first[0] & second[0]
    if first[0] and second[0] and progress:
        progress('Wildcard DNS detected; shared IPs alone will not exclude names')

    results = set()
    errors = []
    completed = 0
    # Small batches bound both the thread count and pending work.
    with ThreadPoolExecutor(max_workers=8) as pool:
        for offset in range(0, len(candidates), 32):
            batch = candidates[offset:offset + 32]
            for hostname, answer in zip(batch, pool.map(resolve_candidate, batch)):
                addresses, aliases, problems = answer
                errors.extend(problems)
                matches_wildcard = (aliases and aliases <= wildcard_aliases
                                    and addresses and addresses <= wildcard_addresses)
                if addresses and not matches_wildcard:
                    results.add(hostname)
                completed += 1
                if progress:
                    progress(f'{completed}/{len(candidates)} candidates; {len(errors)} lookup errors', completed)
    if errors and not results:
        if all(error == 'timeout' for error in errors):
            raise TimeoutError(f'DNS scan incomplete: {len(errors)} timed-out lookups.')
        raise RuntimeError(f'DNS scan incomplete: {len(errors)} lookup errors.')
    if errors and progress:
        progress(f'Partial results: {len(errors)} DNS lookup errors', completed)
    return results
