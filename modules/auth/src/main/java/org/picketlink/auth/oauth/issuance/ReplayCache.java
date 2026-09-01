package org.picketlink.auth.oauth.issuance;

import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory jti replay cache with time-based eviction. */
public final class ReplayCache {

    private final ConcurrentHashMap<String, Long> seen = new ConcurrentHashMap<>();
    private final Clock clock;

    public ReplayCache(Clock clock) {
        this.clock = clock;
    }

    /**
     * Records the token id and reports whether it was already seen.
     *
     * @return true if the id is new (not a replay)
     */
    public boolean checkAndStore(String tokenId, Duration retention) {
        long now = clock.instant().toEpochMilli();
        evictExpired(now, retention.toMillis());
        Long previous = seen.putIfAbsent(tokenId, now);
        return previous == null;
    }

    private void evictExpired(long now, long retentionMillis) {
        // Guard against unbounded growth without a background thread; cheap enough at token-endpoint rates.
        if (seen.size() < 1024) {
            return;
        }
        for (java.util.Iterator<java.util.Map.Entry<String, Long>> it = seen.entrySet().iterator(); it.hasNext();) {
            java.util.Map.Entry<String, Long> entry = it.next();
            if (now - entry.getValue() > retentionMillis) {
                it.remove();
            }
        }
    }
}
