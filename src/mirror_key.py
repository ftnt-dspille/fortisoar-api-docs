"""A throwaway API key with exactly the JWT user's roles and teams.

Comparing a JWT with some other API key measures two things at once: the auth
method and that key's RBAC. A key with no team gets 403 on every write, and a
key on different teams cannot see the same records, so its failures look like
"API keys are not supported". `mirror_api_key` mints a key that matches the
JWT user, so the auth method is the only difference, and revokes it after.

    with mirror_api_key(jwt_client) as key:
        ...  # Authorization: API-KEY <key>
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager

from pyfsr import FortiSOAR

PREFIX = "authprobe-mirror-"
#: A mirror key older than this is a crashed run's leftover. Younger ones may
#: belong to a run still in progress (live_test and auth_probe can overlap).
STALE_AFTER_S = 6 * 3600


def _grants(client: FortiSOAR) -> tuple[list[str], list[str]]:
    me = client.request("GET", "/api/3/actors/current").json()
    person = client.request("GET", me["@id"], params={"$relationships": "true"}).json()

    def uuids(rel: list) -> list[str]:
        return [(x if isinstance(x, str) else x["@id"]).rsplit("/", 1)[-1] for x in rel or []]

    return uuids(person.get("roles")), uuids(person.get("teams"))


def remove(client: FortiSOAR, binding: dict) -> None:
    """Delete a mirror key's binding and revoke its user."""
    client.api_keys.delete(binding["uuid"])
    user = binding.get("userId")
    if user:
        client.api_users.revoke(user.rsplit("/", 1)[-1])


def sweep(client: FortiSOAR) -> int:
    """Remove mirror keys a crashed run left behind (never one a live run is using)."""
    cutoff = time.time() - STALE_AFTER_S
    stale = [k for k in client.api_keys.list()
             if str(k.get("name", "")).startswith(PREFIX) and (k.get("createDate") or 0) < cutoff]
    for binding in stale:
        remove(client, binding)
    return len(stale)


def mint(client: FortiSOAR) -> tuple[dict, str]:
    """A new mirror key: ``(binding, plaintext)``. Pair with :func:`remove`."""
    roles, teams = _grants(client)
    return client.api_keys.ensure_usable(name=PREFIX + secrets.token_hex(4), roles=roles, teams=teams)


@contextmanager
def mirror_api_key(client: FortiSOAR) -> Iterator[str]:
    """Yield the plaintext of a new API key with the JWT user's roles and teams; revoke it on exit."""
    sweep(client)
    binding, key = mint(client)
    try:
        yield key
    finally:
        remove(client, binding)
