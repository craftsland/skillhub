package com.iflytek.skillhub.auth.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Principal;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PlatformPrincipalTest {

    @Test
    void exposesStablePlatformUserIdAsPrincipalName() {
        PlatformPrincipal principal = new PlatformPrincipal(
                "usr_stable",
                "Display Name",
                "user@example.com",
                null,
                "github",
                Set.of("USER"));

        assertThat(principal).isInstanceOf(Principal.class);
        assertThat(principal.getName()).isEqualTo("usr_stable");
    }
}
