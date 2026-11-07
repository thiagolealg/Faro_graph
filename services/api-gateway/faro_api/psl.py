"""Deterministic Public Suffix List parser (including PRIVATE rules).

The packaged snapshot is deliberately offline and versioned. It needs routine
updates to avoid stale suffix decisions; unknown suffixes use the PSL wildcard.
"""
from __future__ import annotations

from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=1)
def _rules() -> tuple[set[str], set[str], set[str]]:
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    content = files('faro_api').joinpath('data/public_suffix_list.dat').read_text(encoding='utf-8')
    for line in content.splitlines():
        rule = line.strip().lower()
        if not rule or rule.startswith('//'):
            continue
        if rule.startswith('!'):
            exceptions.add(rule[1:])
        elif rule.startswith('*.'):
            wildcards.add(rule[2:])
        else:
            rules.add(rule)
    return rules, wildcards, exceptions


def suffix_length(hostname: str) -> int:
    parts = hostname.lower().split('.')
    rules, wildcards, exceptions = _rules()
    match = 1  # PSL implicit wildcard rule: '*'.
    for index in range(len(parts)):
        candidate = '.'.join(parts[index:])
        if candidate in exceptions:
            return len(parts) - index - 1
        if candidate in rules:
            match = max(match, len(parts) - index)
        if index > 0 and candidate in wildcards:
            match = max(match, len(parts) - index + 1)
    return match


def registrable_domain(hostname: str) -> str | None:
    labels = hostname.lower().split('.')
    suffix = suffix_length(hostname)
    if len(labels) <= suffix:
        return None
    return '.'.join(labels[-(suffix + 1):])
