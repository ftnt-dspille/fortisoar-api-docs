"""Single source of truth for secret-bearing field names.

`live_test._scrub` redacts these from captured examples; `spec_health.check_secrets`
fails the build if an unredacted one survives. Kept in one module so the two
consumers can't drift apart. Matching is case-insensitive.

Scope is deliberately secret MATERIAL, not identifiers: the agent AMQP
`username`/`vhost` and credential `loginid` name an account rather than
authenticate as one, and several are plain display names (`userName` on a
person/alert) or documented sample logins (`csadmin`) whose paired `password`
is already redacted here -- blanking them would only degrade the reference. The
agent's AMQP username (`user_<hash>`) is still scrubbed, by value pattern in
`live_test` (`_AMQP_IDENT_RE`), so the credential-linked identifier goes without
touching display names.
"""

import re

SECRET_PLACEHOLDER = "<redacted-secret>"

# Stored normalized (lower-cased, `_`/`-` stripped) so `api_key`, `apiKey` and
# `apikey` all collapse to one entry; `is_secret_key` normalizes the same way.
# Exact-match, not suffix-match: a `...key` suffix would wrongly catch benign
# `publickey`/`sortkey` fields. The encrypted-value net below covers anything
# this list misses that actually holds FortiSOAR secret material.
_SECRET_KEYS_NORMALIZED = frozenset((
    "encryptionkey", "password", "passwd", "passphrase", "enablepassword",
    "vhost", "apikey", "token", "accesstoken", "refreshtoken", "authtoken",
    "authorization", "clientsecret", "secret", "secretkey", "privatekey",
))

# FortiSOAR's encrypted-value envelope: `<prefix>.0x<keyid>.<base64>` (agent
# encryptionKey, connector enable_password, and other at-rest secrets all share
# it). Matching by VALUE catches secret material in any field, named or not --
# the safety net behind the field-name list above.
ENCRYPTED_VALUE_RE = re.compile(r"[A-Za-z0-9]{5,}\.0x[0-9A-Fa-f]{4,}\.[A-Za-z0-9+/]{20,}={0,2}")


def is_secret_key(key: object) -> bool:
    """True if `key` names a secret-bearing field (case- and separator-insensitive)."""
    return (isinstance(key, str)
            and key.lower().replace("_", "").replace("-", "") in _SECRET_KEYS_NORMALIZED)


def looks_encrypted(value: object) -> bool:
    """True if `value` is a string carrying a FortiSOAR encrypted secret."""
    return isinstance(value, str) and ENCRYPTED_VALUE_RE.search(value) is not None
