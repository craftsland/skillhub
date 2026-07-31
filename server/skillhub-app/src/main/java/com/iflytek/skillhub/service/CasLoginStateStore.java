package com.iflytek.skillhub.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

/**
 * Stores CAS browser state in Redis and consumes it atomically across
 * application instances.
 */
@Component
public class CasLoginStateStore {

    private static final String KEY_PREFIX =
            "skillhub:auth:cas:state:";
    private static final String PENDING_PREFIX = "P:";
    private static final String REPLAY_MARKER = "R";
    private static final String INVALID_MARKER = "E";
    private static final Pattern STATE_PATTERN =
            Pattern.compile("[A-Za-z0-9_-]{32,128}");
    private static final DefaultRedisScript<String> CONSUME_SCRIPT =
            new DefaultRedisScript<>(
                    """
                    local value = redis.call('GET', KEYS[1])
                    if not value then
                      return nil
                    end
                    if value == 'R' then
                      return 'R'
                    end
                    if string.sub(value, 1, 2) ~= 'P:' then
                      return 'E'
                    end
                    local ttl = redis.call('PTTL', KEYS[1])
                    if ttl <= 0 then
                      redis.call('DEL', KEYS[1])
                      return nil
                    end
                    redis.call('SET', KEYS[1], 'R', 'PX', ttl)
                    return value
                    """,
                    String.class);

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Autowired
    public CasLoginStateStore(
            StringRedisTemplate redisTemplate,
            ObjectMapper objectMapper) {
        this(redisTemplate, objectMapper, Clock.systemUTC());
    }

    CasLoginStateStore(
            StringRedisTemplate redisTemplate,
            ObjectMapper objectMapper,
            Clock clock) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    void save(
            String sessionId,
            String state,
            String providerCode,
            String serviceUrl,
            String returnTo,
            Duration ttl) {
        requireSessionAndState(sessionId, state);
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new CasLoginStateStoreException();
        }
        CasLoginState loginState = new CasLoginState(
                providerCode,
                serviceUrl,
                returnTo,
                clock.instant().plus(ttl));
        try {
            redisTemplate.opsForValue().set(
                    key(sessionId, state),
                    PENDING_PREFIX
                            + objectMapper.writeValueAsString(loginState),
                    ttl);
        } catch (RuntimeException
                | JsonProcessingException exception) {
            throw new CasLoginStateStoreException();
        }
    }

    ConsumeResult consume(
            String sessionId,
            String state) {
        if (!validSessionAndState(sessionId, state)) {
            return ConsumeResult.notFound();
        }
        String serialized;
        try {
            serialized = redisTemplate.execute(
                    CONSUME_SCRIPT,
                    List.of(key(sessionId, state)));
        } catch (RuntimeException exception) {
            throw new CasLoginStateStoreException();
        }
        if (serialized == null) {
            return ConsumeResult.notFound();
        }
        if (REPLAY_MARKER.equals(serialized)) {
            return ConsumeResult.replayed();
        }
        if (INVALID_MARKER.equals(serialized)
                || !serialized.startsWith(PENDING_PREFIX)) {
            throw new CasLoginStateStoreException();
        }
        try {
            CasLoginState loginState = objectMapper.readValue(
                    serialized.substring(PENDING_PREFIX.length()),
                    CasLoginState.class);
            if (!loginState.expiresAt().isAfter(clock.instant())) {
                return ConsumeResult.notFound();
            }
            return ConsumeResult.consumed(loginState);
        } catch (RuntimeException
                | JsonProcessingException exception) {
            throw new CasLoginStateStoreException();
        }
    }

    private void requireSessionAndState(
            String sessionId,
            String state) {
        if (!validSessionAndState(sessionId, state)) {
            throw new CasLoginStateStoreException();
        }
    }

    private boolean validSessionAndState(
            String sessionId,
            String state) {
        return sessionId != null
                && !sessionId.isBlank()
                && state != null
                && STATE_PATTERN.matcher(state).matches();
    }

    private String key(
            String sessionId,
            String state) {
        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(
                    (sessionId + "\n" + state)
                            .getBytes(StandardCharsets.UTF_8));
            return KEY_PREFIX + HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new CasLoginStateStoreException();
        }
    }

    record CasLoginState(
            String providerCode,
            String serviceUrl,
            String returnTo,
            Instant expiresAt
    ) {
        CasLoginState {
            Objects.requireNonNull(
                    providerCode,
                    "providerCode");
            Objects.requireNonNull(
                    serviceUrl,
                    "serviceUrl");
            Objects.requireNonNull(
                    expiresAt,
                    "expiresAt");
            if (providerCode.isBlank()
                    || serviceUrl.isBlank()) {
                throw new IllegalArgumentException(
                        "CAS state fields must not be blank");
            }
        }
    }

    enum ConsumeStatus {
        CONSUMED,
        NOT_FOUND,
        REPLAYED
    }

    record ConsumeResult(
            ConsumeStatus status,
            CasLoginState state
    ) {
        private static ConsumeResult consumed(
                CasLoginState state) {
            return new ConsumeResult(
                    ConsumeStatus.CONSUMED,
                    Objects.requireNonNull(state, "state"));
        }

        private static ConsumeResult notFound() {
            return new ConsumeResult(
                    ConsumeStatus.NOT_FOUND,
                    null);
        }

        private static ConsumeResult replayed() {
            return new ConsumeResult(
                    ConsumeStatus.REPLAYED,
                    null);
        }
    }

    static final class CasLoginStateStoreException
            extends RuntimeException {

        private CasLoginStateStoreException() {
            super("CAS_LOGIN_STATE_STORE_FAILURE");
        }
    }
}
