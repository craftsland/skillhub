package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

class CasLoginStateStoreTest {

    private static final Instant NOW =
            Instant.parse("2026-07-31T00:00:00Z");
    private static final String SESSION_ID =
            "session-secret";
    private static final String STATE =
            "abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-";

    @Test
    void savesHashedKeyAndConsumesStateAtomically() {
        StringRedisTemplate redis = mock(
                StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values =
                mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        ObjectMapper objectMapper = new ObjectMapper()
                .findAndRegisterModules();
        CasLoginStateStore store = new CasLoginStateStore(
                redis,
                objectMapper,
                Clock.fixed(NOW, ZoneOffset.UTC));
        Duration ttl = Duration.ofMinutes(5);

        store.save(
                SESSION_ID,
                STATE,
                "cas-main",
                "https://skill.example/api/v1/auth/cas/cas-main/callback"
                        + "?state="
                        + STATE,
                "/dashboard",
                ttl);

        ArgumentCaptor<String> key =
                ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> serialized =
                ArgumentCaptor.forClass(String.class);
        verify(values).set(
                key.capture(),
                serialized.capture(),
                org.mockito.ArgumentMatchers.eq(ttl));
        assertThat(key.getValue())
                .startsWith("skillhub:auth:cas:state:")
                .doesNotContain(SESSION_ID)
                .doesNotContain(STATE);
        assertThat(serialized.getValue()).startsWith("P:");

        when(redis.execute(
                org.mockito.ArgumentMatchers
                        .<RedisScript<String>>any(),
                eq(List.of(key.getValue()))))
                .thenReturn(serialized.getValue())
                .thenReturn("R")
                .thenReturn((String) null);

        CasLoginStateStore.ConsumeResult consumed =
                store.consume(SESSION_ID, STATE);
        assertThat(consumed.status())
                .isEqualTo(
                        CasLoginStateStore.ConsumeStatus.CONSUMED);
        assertThat(consumed.state())
                .extracting(
                        CasLoginStateStore.CasLoginState::providerCode,
                        CasLoginStateStore.CasLoginState::returnTo)
                .containsExactly("cas-main", "/dashboard");
        assertThat(store.consume(SESSION_ID, STATE).status())
                .isEqualTo(
                        CasLoginStateStore.ConsumeStatus.REPLAYED);
        assertThat(store.consume(SESSION_ID, STATE).status())
                .isEqualTo(
                        CasLoginStateStore.ConsumeStatus.NOT_FOUND);
    }

    @Test
    void rejectsExpiredOrMalformedStateWithoutReturningIt() throws Exception {
        StringRedisTemplate redis = mock(
                StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values =
                mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        ObjectMapper objectMapper = new ObjectMapper()
                .findAndRegisterModules();
        CasLoginStateStore store = new CasLoginStateStore(
                redis,
                objectMapper,
                Clock.fixed(NOW, ZoneOffset.UTC));
        String expired = objectMapper.writeValueAsString(
                new CasLoginStateStore.CasLoginState(
                        "cas-main",
                        "https://skill.example/callback",
                        null,
                        NOW.minusSeconds(1)));
        when(redis.execute(
                org.mockito.ArgumentMatchers
                        .<RedisScript<String>>any(),
                anyList()))
                .thenReturn("P:" + expired);

        assertThat(store.consume(SESSION_ID, STATE).status())
                .isEqualTo(
                        CasLoginStateStore.ConsumeStatus.NOT_FOUND);
        assertThat(store.consume(
                SESSION_ID,
                "not valid").status())
                .isEqualTo(
                        CasLoginStateStore.ConsumeStatus.NOT_FOUND);
    }

    @Test
    void failsClosedWhenRedisCannotPersistOrConsumeState() {
        StringRedisTemplate redis = mock(
                StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values =
                mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        CasLoginStateStore store = new CasLoginStateStore(
                redis,
                new ObjectMapper().findAndRegisterModules(),
                Clock.fixed(NOW, ZoneOffset.UTC));
        org.mockito.Mockito.doThrow(
                        new IllegalStateException("redis unavailable"))
                .when(values)
                .set(
                        anyString(),
                        anyString(),
                        org.mockito.ArgumentMatchers.any(
                                Duration.class));

        assertThatThrownBy(() -> store.save(
                SESSION_ID,
                STATE,
                "cas-main",
                "https://skill.example/callback",
                null,
                Duration.ofMinutes(5)))
                .isInstanceOf(
                        CasLoginStateStore
                                .CasLoginStateStoreException.class);

        when(redis.execute(
                org.mockito.ArgumentMatchers
                        .<RedisScript<String>>any(),
                anyList()))
                .thenThrow(new IllegalStateException(
                        "redis unavailable"));
        assertThatThrownBy(
                () -> store.consume(SESSION_ID, STATE))
                .isInstanceOf(
                        CasLoginStateStore
                                .CasLoginStateStoreException.class);
    }
}
