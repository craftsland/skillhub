package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.rbac.PlatformRoleDefaults;
import com.iflytek.skillhub.auth.repository.UserRoleBindingRepository;
import com.iflytek.skillhub.domain.user.UserAccount;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

/**
 * Builds the shared serializable principal snapshot from platform-owned user
 * and role data.
 */
@Service
public class PlatformPrincipalFactory {

    private final UserRoleBindingRepository roleBindingRepository;

    public PlatformPrincipalFactory(
            UserRoleBindingRepository roleBindingRepository) {
        this.roleBindingRepository = roleBindingRepository;
    }

    public PlatformPrincipal create(
            UserAccount user,
            String authenticationProvider) {
        Objects.requireNonNull(user, "user");
        Objects.requireNonNull(authenticationProvider, "authenticationProvider");
        if (authenticationProvider.isBlank()) {
            throw new IllegalArgumentException(
                    "Authentication provider must not be blank");
        }

        Set<String> roles = roleBindingRepository.findByUserId(user.getId())
                .stream()
                .map(binding -> binding.getRole().getCode())
                .collect(Collectors.toSet());
        roles = PlatformRoleDefaults.withDefaultUserRole(roles);

        return new PlatformPrincipal(
                user.getId(),
                user.getDisplayName(),
                user.getEmail(),
                user.getAvatarUrl(),
                authenticationProvider,
                roles);
    }
}
