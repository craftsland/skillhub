package com.iflytek.skillhub.auth.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PassiveAuthenticationRequestTest {

    @Test
    void copiesAndNormalizesHeadersWithoutExposingMutableState() {
        ArrayList<String> values = new ArrayList<>(
                List.of("first"));
        Map<String, List<String>> headers =
                new LinkedHashMap<>();
        headers.put("X-Identity-Assertion", values);
        headers.put(
                "x-identity-assertion",
                List.of("second"));

        PassiveAuthenticationRequest request =
                new PassiveAuthenticationRequest(
                        "post",
                        "/api/v1/auth/session/bootstrap",
                        "source=portal",
                        "203.0.113.9",
                        headers);
        values.add("mutated");
        headers.clear();

        assertThat(request.method()).isEqualTo("POST");
        assertThat(request.headerValues("X-IDENTITY-ASSERTION"))
                .containsExactly("first", "second");
        assertThat(request.headers())
                .containsOnlyKeys("x-identity-assertion");
        assertThatThrownBy(() ->
                request.headers().put("other", List.of("value")))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsMissingTransportIdentity() {
        assertThatThrownBy(() ->
                new PassiveAuthenticationRequest(
                        " ",
                        "/bootstrap",
                        null,
                        null,
                        Map.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("method");
        assertThatThrownBy(() ->
                new PassiveAuthenticationRequest(
                        "POST",
                        " ",
                        null,
                        null,
                        Map.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("URI");
    }
}
