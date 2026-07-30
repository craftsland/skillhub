package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.entity.IdentityBinding;
import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.domain.namespace.GlobalNamespaceMembershipService;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short database transaction that preserves the existing identity-binding and
 * provisioning behavior behind the unified core facade.
 */
@Service
class IdentityResolutionTransaction {

    private static final String ACCOUNT_PENDING = "ACCOUNT_PENDING";

    private final IdentityBindingRepository bindingRepository;
    private final UserAccountRepository userRepository;
    private final GlobalNamespaceMembershipService membershipService;
    private final AccountLoginGuard accountLoginGuard;
    private final PlatformPrincipalFactory principalFactory;

    IdentityResolutionTransaction(
            IdentityBindingRepository bindingRepository,
            UserAccountRepository userRepository,
            GlobalNamespaceMembershipService membershipService,
            AccountLoginGuard accountLoginGuard,
            PlatformPrincipalFactory principalFactory) {
        this.bindingRepository = bindingRepository;
        this.userRepository = userRepository;
        this.membershipService = membershipService;
        this.accountLoginGuard = accountLoginGuard;
        this.principalFactory = principalFactory;
    }

    @Transactional
    public IdentityLoginOutcome resolve(
            IdentityAssertion assertion,
            UserStatus initialStatus) {
        IdentityBinding binding = bindingRepository
                .findByProviderCodeAndSubject(
                        assertion.provider().providerCode(),
                        assertion.primarySubject().value())
                .orElse(null);
        if (binding != null) {
            return resolveExisting(assertion, binding);
        }
        return createAccount(assertion, initialStatus);
    }

    private IdentityLoginOutcome resolveExisting(
            IdentityAssertion assertion,
            IdentityBinding binding) {
        UserAccount user = userRepository.findById(binding.getUserId())
                .orElseThrow(() -> new IllegalStateException(
                        "User not found for identity binding"));
        AccountLoginDecision decision =
                accountLoginGuard.evaluateInteractive(user);
        if (decision == AccountLoginDecision.PENDING) {
            return new IdentityLoginOutcome.PendingApproval(ACCOUNT_PENDING);
        }
        requireAllowed(decision);

        synchronizeCompatibilityProfile(user, assertion.profile());
        user = userRepository.save(user);
        return new IdentityLoginOutcome.Authenticated(
                principalFactory.create(
                        user,
                        assertion.provider().providerCode()),
                false,
                false);
    }

    private IdentityLoginOutcome createAccount(
            IdentityAssertion assertion,
            UserStatus initialStatus) {
        ExternalProfile profile = assertion.profile();
        UserAccount user = new UserAccount(
                "usr_" + UUID.randomUUID(),
                profile.displayName(),
                trustedEmail(profile).orElse(null),
                profile.avatarUrl().map(Object::toString).orElse(null));
        user.setStatus(initialStatus);
        user = userRepository.save(user);

        if (initialStatus == UserStatus.ACTIVE) {
            membershipService.ensureMember(user.getId());
        }
        bindingRepository.save(new IdentityBinding(
                user.getId(),
                assertion.provider().providerCode(),
                assertion.primarySubject().value(),
                profile.displayName()));

        if (initialStatus == UserStatus.PENDING) {
            return new IdentityLoginOutcome.PendingApproval(ACCOUNT_PENDING);
        }
        requireAllowed(accountLoginGuard.evaluateInteractive(user));
        return new IdentityLoginOutcome.Authenticated(
                principalFactory.create(
                        user,
                        assertion.provider().providerCode()),
                true,
                true);
    }

    private void synchronizeCompatibilityProfile(
            UserAccount user,
            ExternalProfile profile) {
        user.setDisplayName(profile.displayName());
        trustedEmail(profile).ifPresent(user::setEmail);
        profile.avatarUrl()
                .map(Object::toString)
                .ifPresent(user::setAvatarUrl);
    }

    private Optional<String> trustedEmail(ExternalProfile profile) {
        return profile.email()
                .filter(claim -> claim.assurance().isVerifiedOrAuthoritative())
                .map(EmailClaim::value);
    }

    private void requireAllowed(AccountLoginDecision decision) {
        IdentityFailureCode failureCode = switch (decision) {
            case ALLOWED -> null;
            case PENDING -> IdentityFailureCode.ACCOUNT_PENDING;
            case DISABLED -> IdentityFailureCode.ACCOUNT_DISABLED;
            case MERGED -> IdentityFailureCode.ACCOUNT_MERGED;
            case SYSTEM_ACCOUNT ->
                    IdentityFailureCode.SYSTEM_ACCOUNT_FORBIDDEN;
        };
        if (failureCode != null) {
            throw new IdentityCoreException(failureCode);
        }
    }
}
