package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.entity.IdentityLinkOperation;
import com.iflytek.skillhub.auth.entity.IdentityLinkRequestStatus;
import com.iflytek.skillhub.auth.local.LocalAuthService;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IdentityLinkIntentServiceTest {

    @Mock
    private IdentityLinkTransaction transaction;

    @Mock
    private LocalAuthService localAuthService;

    @Test
    void localReauthenticationValidatesIntentBeforeCheckingPassword() {
        IdentityLinkIntentService service =
                new IdentityLinkIntentService(
                        transaction,
                        localAuthService);
        IdentityLinkActor actor = actor();
        UUID intentId = UUID.randomUUID();
        IdentityLinkIntent pending = intent(
                intentId,
                IdentityLinkRequestStatus.PENDING_REAUTHENTICATION);
        IdentityLinkIntent ready = intent(
                intentId,
                IdentityLinkRequestStatus.READY);
        when(transaction.getIntent(actor, intentId))
                .thenReturn(pending);
        when(transaction.markLocalReauthenticated(
                actor,
                intentId))
                .thenReturn(ready);

        IdentityLinkIntent result = service.reauthenticateLocal(
                actor,
                intentId,
                "current-password");

        assertThat(result).isSameAs(ready);
        InOrder order = inOrder(
                transaction,
                localAuthService);
        order.verify(transaction).getIntent(actor, intentId);
        order.verify(localAuthService).reauthenticate(
                actor.userId(),
                "current-password");
        order.verify(transaction).markLocalReauthenticated(
                actor,
                intentId);
    }

    @Test
    void consumedIntentDoesNotCheckPassword() {
        IdentityLinkIntentService service =
                new IdentityLinkIntentService(
                        transaction,
                        localAuthService);
        IdentityLinkActor actor = actor();
        UUID intentId = UUID.randomUUID();
        when(transaction.getIntent(actor, intentId))
                .thenReturn(intent(
                        intentId,
                        IdentityLinkRequestStatus.READY));

        assertThatThrownBy(() ->
                service.reauthenticateLocal(
                        actor,
                        intentId,
                        "current-password"))
                .isInstanceOfSatisfying(
                        IdentityLinkException.class,
                        exception -> assertThat(
                                exception.getReasonCode())
                                .isEqualTo(
                                        IdentityLinkFailureCode
                                                .ALREADY_CONSUMED));

        verifyNoInteractions(localAuthService);
        verify(transaction, never())
                .markLocalReauthenticated(actor, intentId);
    }

    private IdentityLinkActor actor() {
        return new IdentityLinkActor(
                "usr_1",
                "local",
                "session-nonce",
                new IdentityLoginContext(
                        "req-1",
                        "203.0.113.9",
                        "Identity Link Test"));
    }

    private IdentityLinkIntent intent(
            UUID intentId,
            IdentityLinkRequestStatus status) {
        return new IdentityLinkIntent(
                intentId,
                IdentityLinkOperation.LINK,
                status,
                "github",
                null,
                Instant.parse("2026-07-31T08:10:00Z"));
    }
}
