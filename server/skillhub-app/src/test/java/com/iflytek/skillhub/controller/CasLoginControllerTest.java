package com.iflytek.skillhub.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.service.CasLoginAppService;
import com.iflytek.skillhub.service.CasLoginFailure;
import com.iflytek.skillhub.service.CasLoginFlowException;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;

class CasLoginControllerTest {

    private final CasLoginAppService loginAppService =
            mock(CasLoginAppService.class);
    private final CasLoginController controller =
            new CasLoginController(loginAppService);

    @Test
    void loginRedirectsOnlyToApplicationServiceTarget() {
        MockHttpServletRequest request =
                new MockHttpServletRequest();
        URI target = URI.create(
                "https://cas.example/login?service=opaque");
        when(loginAppService.begin(
                "cas-main",
                "/dashboard",
                request)).thenReturn(target);

        var response = controller.login(
                "cas-main",
                "/dashboard",
                request);

        assertThat(response.getStatusCode())
                .isEqualTo(HttpStatus.FOUND);
        assertThat(response.getHeaders().getLocation())
                .isEqualTo(target);
    }

    @Test
    void callbackMapsStableFailureWithoutReflectingTicketOrState() {
        MockHttpServletRequest request =
                new MockHttpServletRequest();
        when(loginAppService.complete(
                "cas-main",
                "ST-secret",
                "state-secret",
                request)).thenThrow(
                        new CasLoginFlowException(
                                CasLoginFailure.VALIDATION_FAILED));

        var response = controller.callback(
                "cas-main",
                "ST-secret",
                "state-secret",
                request);

        assertThat(response.getStatusCode())
                .isEqualTo(HttpStatus.FOUND);
        assertThat(response.getHeaders().getLocation())
                .hasToString(
                        "/login?reason=casValidationFailed");
        assertThat(response.getHeaders().getLocation().toString())
                .doesNotContain("ST-secret")
                .doesNotContain("state-secret");
    }

    @Test
    void callbackMapsReplayToDedicatedCredentialFreeReason() {
        MockHttpServletRequest request =
                new MockHttpServletRequest();
        when(loginAppService.complete(
                "cas-main",
                "ST-replayed",
                "state-replayed",
                request)).thenThrow(
                        new CasLoginFlowException(
                                CasLoginFailure.REPLAY_DETECTED));

        var response = controller.callback(
                "cas-main",
                "ST-replayed",
                "state-replayed",
                request);

        assertThat(response.getHeaders().getLocation())
                .hasToString(
                        "/login?reason=casReplayDetected");
        assertThat(response.getHeaders().getLocation().toString())
                .doesNotContain("ST-replayed")
                .doesNotContain("state-replayed");
    }
}
