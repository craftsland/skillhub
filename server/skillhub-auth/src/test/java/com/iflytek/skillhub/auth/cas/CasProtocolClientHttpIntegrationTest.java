package com.iflytek.skillhub.auth.cas;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.web.util.UriComponentsBuilder;

class CasProtocolClientHttpIntegrationTest {

    private static final String STATE =
            "abcdefghijklmnopqrstuvwxyz0123456789_ABCD";

    private HttpServer server;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(
                new InetSocketAddress(
                        InetAddress.getLoopbackAddress(),
                        0),
                0);
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void validatesWithTheRealTransportAndExactServiceQuery()
            throws IOException {
        AtomicReference<String> rawQuery = new AtomicReference<>();
        server.createContext(
                "/cas/p3/serviceValidate",
                exchange -> {
                    rawQuery.set(exchange.getRequestURI().getRawQuery());
                    respond(
                            exchange,
                            200,
                            """
                            {
                              "serviceResponse": {
                                "authenticationSuccess": {
                                  "user": "alice"
                                }
                              }
                            }
                            """);
                });

        CasProtocolClient client = client(1024);
        String service = client.begin(
                "cas-main",
                STATE).serviceUrl();

        CasAuthenticationExchange authentication = client.validate(
                "cas-main",
                "ST-real-transport",
                service);

        assertThat(authentication.principal()).isEqualTo("alice");
        var query = UriComponentsBuilder
                .fromUriString("http://localhost/?" + rawQuery.get())
                .build()
                .getQueryParams();
        assertThat(query.getFirst("ticket"))
                .isEqualTo("ST-real-transport");
        assertThat(decode(query.getFirst("service")))
                .isEqualTo(service);
        assertThat(query.getFirst("format")).isEqualTo("JSON");
    }

    @Test
    void realTransportNeverFollowsRedirects() throws IOException {
        AtomicInteger redirectedRequests = new AtomicInteger();
        server.createContext(
                "/cas/p3/serviceValidate",
                exchange -> {
                    exchange.getResponseHeaders().add(
                            "Location",
                            "/cas/redirected");
                    exchange.sendResponseHeaders(302, -1);
                    exchange.close();
                });
        server.createContext(
                "/cas/redirected",
                exchange -> {
                    redirectedRequests.incrementAndGet();
                    respond(
                            exchange,
                            200,
                            """
                            {
                              "serviceResponse": {
                                "authenticationSuccess": {
                                  "user": "redirected"
                                }
                              }
                            }
                            """);
                });

        CasProtocolClient client = client(1024);

        assertThatThrownBy(() -> client.validate(
                "cas-main",
                "ST-no-redirect",
                client.begin("cas-main", STATE).serviceUrl()))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);
        assertThat(redirectedRequests).hasValue(0);
    }

    @Test
    void realTransportRejectsOversizedResponses() {
        server.createContext(
                "/cas/p3/serviceValidate",
                exchange -> respond(
                        exchange,
                        200,
                        "x".repeat(1025)));

        CasProtocolClient client = client(1024);

        assertThatThrownBy(() -> client.validate(
                "cas-main",
                "ST-oversized",
                client.begin("cas-main", STATE).serviceUrl()))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);
    }

    private CasProtocolClient client(int maximumResponseBytes) {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setAllowInsecureForTesting(true);
        properties.setServerUrl(
                "http://127.0.0.1:"
                        + server.getAddress().getPort()
                        + "/cas");
        properties.setServiceUrl(
                "http://skillhub.test/api/v1/auth/cas/cas-main/callback");
        properties.setMaxResponseBytes(maximumResponseBytes);
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles("test");
        return new CasProtocolClient(
                new CasProviderConfiguration(
                        properties,
                        environment),
                new ObjectMapper());
    }

    private void respond(
            HttpExchange exchange,
            int status,
            String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (var body = exchange.getResponseBody()) {
            body.write(bytes);
        }
    }

    private String decode(String value) {
        return URLDecoder.decode(
                value,
                StandardCharsets.UTF_8);
    }
}
