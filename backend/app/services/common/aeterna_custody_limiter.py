"""Atomic, shared, fail-closed limits for custody validation requests."""

import hashlib

from redis.exceptions import RedisError

from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.services.common.aeterna_security import (
    IdentityKeyUnavailable,
    get_identity_keys,
    ip_lookup,
)
from app.services.common.redis import redis_client

WINDOW_SECONDS = 60
IP_REQUEST_LIMIT = 30
DEVICE_REQUEST_LIMIT = 10
COUNTER_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {count, redis.call('TTL', KEYS[1])}
"""


class AeternaCustodyLimiter:
    """Apply IP before database work and device limits after signature validation."""

    def __init__(self, redis=None, key_provider=get_identity_keys):
        self.key_provider = key_provider
        self.redis = redis if redis is not None else redis_client.redis

    async def check(self, scope, identity, request_id):
        try:
            lookup = (
                ip_lookup(self.key_provider(), identity).hex()
                if scope == "ip"
                else hashlib.sha256(identity.encode("utf-8")).hexdigest()
            )
            count, ttl = await self.redis.eval(
                COUNTER_SCRIPT, 1, f"aeterna:custody:{scope}:{lookup}", WINDOW_SECONDS
            )
        except (RedisError, IdentityKeyUnavailable):
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", request_id
            ) from None
        limit = IP_REQUEST_LIMIT if scope == "ip" else DEVICE_REQUEST_LIMIT
        if count > limit:
            raise AeternaProtocolException(
                429,
                "auth.rate_limited",
                request_id,
                retry_after_seconds=max(1, min(WINDOW_SECONDS, ttl)),
            )


def get_aeterna_custody_limiter():
    return AeternaCustodyLimiter(
        redis=redis_client.redis, key_provider=get_identity_keys
    )
