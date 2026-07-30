package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserStatus;
import org.junit.jupiter.api.Test;

class AccountLoginGuardTest {

    private final AccountLoginGuard guard = new AccountLoginGuard();

    @Test
    void allowsActiveInteractiveAccount() {
        assertThat(guard.evaluateInteractive(user(UserStatus.ACTIVE)))
                .isEqualTo(AccountLoginDecision.ALLOWED);
    }

    @Test
    void classifiesAllBlockedInteractiveAccountStates() {
        assertThat(guard.evaluateInteractive(user(UserStatus.PENDING)))
                .isEqualTo(AccountLoginDecision.PENDING);
        assertThat(guard.evaluateInteractive(user(UserStatus.DISABLED)))
                .isEqualTo(AccountLoginDecision.DISABLED);
        assertThat(guard.evaluateInteractive(user(UserStatus.MERGED)))
                .isEqualTo(AccountLoginDecision.MERGED);
        assertThat(guard.evaluateInteractive(
                UserAccount.systemAccount("system_1", "system", null, null)))
                .isEqualTo(AccountLoginDecision.SYSTEM_ACCOUNT);
    }

    private static UserAccount user(UserStatus status) {
        UserAccount user = new UserAccount(
                "usr_1",
                "alice",
                "alice@example.com",
                null);
        user.setStatus(status);
        return user;
    }
}
