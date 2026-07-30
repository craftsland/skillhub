package com.iflytek.skillhub.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.entity.Role;
import com.iflytek.skillhub.auth.entity.UserRoleBinding;
import com.iflytek.skillhub.auth.repository.UserRoleBindingRepository;
import com.iflytek.skillhub.domain.user.UserAccount;
import java.util.List;
import org.junit.jupiter.api.Test;

class PlatformPrincipalFactoryTest {

    @Test
    void defaultsToUserRoleWhenNoExplicitBindingExists() {
        UserRoleBindingRepository repository =
                mock(UserRoleBindingRepository.class);
        when(repository.findByUserId("usr_1")).thenReturn(List.of());
        PlatformPrincipalFactory factory =
                new PlatformPrincipalFactory(repository);

        var principal = factory.create(user(), "github");

        assertThat(principal.userId()).isEqualTo("usr_1");
        assertThat(principal.displayName()).isEqualTo("alice");
        assertThat(principal.oauthProvider()).isEqualTo("github");
        assertThat(principal.platformRoles()).containsExactly("USER");
    }

    @Test
    void usesExplicitPlatformRolesWhenPresent() {
        UserRoleBindingRepository repository =
                mock(UserRoleBindingRepository.class);
        Role role = mock(Role.class);
        when(role.getCode()).thenReturn("AUDITOR");
        when(repository.findByUserId("usr_1"))
                .thenReturn(List.of(new UserRoleBinding("usr_1", role)));
        PlatformPrincipalFactory factory =
                new PlatformPrincipalFactory(repository);

        var principal = factory.create(user(), "local");

        assertThat(principal.oauthProvider()).isEqualTo("local");
        assertThat(principal.platformRoles()).containsExactly("AUDITOR");
    }

    private static UserAccount user() {
        return new UserAccount(
                "usr_1",
                "alice",
                "alice@example.com",
                "https://avatars.example/alice.png");
    }
}
