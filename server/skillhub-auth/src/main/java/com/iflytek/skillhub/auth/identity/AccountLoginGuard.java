package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.util.Objects;
import org.springframework.stereotype.Service;

/**
 * Central account-state guard for interactive local and federated login.
 */
@Service
public class AccountLoginGuard {

    public AccountLoginDecision evaluateInteractive(UserAccount user) {
        Objects.requireNonNull(user, "user");
        if (user.isSystemAccount()) {
            return AccountLoginDecision.SYSTEM_ACCOUNT;
        }
        return switch (user.getStatus()) {
            case ACTIVE -> AccountLoginDecision.ALLOWED;
            case PENDING -> AccountLoginDecision.PENDING;
            case DISABLED -> AccountLoginDecision.DISABLED;
            case MERGED -> AccountLoginDecision.MERGED;
        };
    }
}
