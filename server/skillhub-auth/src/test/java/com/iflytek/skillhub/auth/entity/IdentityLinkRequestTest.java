package com.iflytek.skillhub.auth.entity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class IdentityLinkRequestTest {

    private static final Instant CREATED_AT =
            Instant.parse("2026-07-31T08:00:00Z");
    private static final String STATE_HASH = "a".repeat(64);

    @Test
    void linkRequestRequiresNoTargetBindingAndStartsPending() {
        IdentityLinkRequest request = new IdentityLinkRequest(
                UUID.randomUUID(),
                "usr_1",
                IdentityLinkOperation.LINK,
                "github",
                null,
                STATE_HASH,
                CREATED_AT.plusSeconds(600),
                CREATED_AT);

        assertThat(request.getStatus())
                .isEqualTo(
                        IdentityLinkRequestStatus
                                .PENDING_REAUTHENTICATION);
        assertThat(request.getTargetBindingId()).isNull();
    }

    @Test
    void unlinkRequestRequiresTargetBinding() {
        assertThatThrownBy(() ->
                new IdentityLinkRequest(
                        UUID.randomUUID(),
                        "usr_1",
                        IdentityLinkOperation.UNLINK,
                        "github",
                        null,
                        STATE_HASH,
                        CREATED_AT.plusSeconds(600),
                        CREATED_AT))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requestCanOnlyBeReauthenticatedAndCompletedOnce() {
        IdentityLinkRequest request = request();
        request.markReauthenticated(
                "local-password",
                CREATED_AT.plusSeconds(10));
        request.complete(CREATED_AT.plusSeconds(20));

        assertThat(request.getStatus())
                .isEqualTo(IdentityLinkRequestStatus.COMPLETED);
        assertThatThrownBy(() ->
                request.complete(CREATED_AT.plusSeconds(30)))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() ->
                request.markReauthenticated(
                        "local-password",
                        CREATED_AT.plusSeconds(30)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void expiredRequestCannotReturnToAnActiveState() {
        IdentityLinkRequest request = request();
        request.expire(CREATED_AT.plusSeconds(600));

        assertThat(request.getStatus())
                .isEqualTo(IdentityLinkRequestStatus.EXPIRED);
        assertThatThrownBy(() ->
                request.markReauthenticated(
                        "local-password",
                        CREATED_AT.plusSeconds(601)))
                .isInstanceOf(IllegalStateException.class);
    }

    private IdentityLinkRequest request() {
        return new IdentityLinkRequest(
                UUID.randomUUID(),
                "usr_1",
                IdentityLinkOperation.LINK,
                "github",
                null,
                STATE_HASH,
                CREATED_AT.plusSeconds(600),
                CREATED_AT);
    }
}
