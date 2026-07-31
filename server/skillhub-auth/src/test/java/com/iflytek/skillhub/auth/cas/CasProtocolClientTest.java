package com.iflytek.skillhub.auth.cas;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.web.util.UriComponentsBuilder;

class CasProtocolClientTest {

    private static final String STATE =
            "abcdefghijklmnopqrstuvwxyz0123456789_ABCD";
    private static final Instant AUTHENTICATED_AT =
            Instant.parse("2026-07-31T00:00:00Z");

    @Test
    void beginsWithCoreGeneratedLoginRouteAndExactStateBoundService() {
        CasProtocolClient client = client((uri, connect, read, maximum) ->
                new CasProtocolClient.CasValidationResponse(
                        500,
                        ""));

        CasLoginInitiation initiation =
                client.begin("cas-main", STATE);

        assertThat(initiation.serviceUrl()).isEqualTo(
                "https://skillhub.example.com/api/v1/auth/cas/cas-main/callback?state="
                        + STATE);
        assertThat(initiation.loginUri().getPath())
                .isEqualTo("/cas/login");
        assertThat(UriComponentsBuilder
                .fromUri(initiation.loginUri())
                .build()
                .getQueryParams()
                .getFirst("service"))
                .satisfies(value -> assertThat(decode(value))
                        .isEqualTo(initiation.serviceUrl()));
    }

    @Test
    void validatesCas30JsonAgainstTheExactServiceUrl() {
        AtomicReference<URI> requested = new AtomicReference<>();
        CasProtocolClient client = client((uri, connect, read, maximum) -> {
            requested.set(uri);
            return new CasProtocolClient.CasValidationResponse(
                    200,
                    """
                    {
                      "serviceResponse": {
                        "authenticationSuccess": {
                          "user": "alice",
                          "attributes": {
                            "cn": "Alice",
                            "memberOf": ["engineering", "reviewers"]
                          }
                        }
                      }
                    }
                    """);
        });
        String service = client.begin(
                "cas-main",
                STATE).serviceUrl();

        CasAuthenticationExchange exchange = client.validate(
                "cas-main",
                "ST-123",
                service);

        assertThat(exchange.principal()).isEqualTo("alice");
        assertThat(exchange.attributes().get("memberOf"))
                .containsExactly("engineering", "reviewers");
        assertThat(exchange.authenticatedAt())
                .isEqualTo(AUTHENTICATED_AT);
        var query = UriComponentsBuilder
                .fromUri(requested.get())
                .build()
                .getQueryParams();
        assertThat(query.getFirst("ticket")).isEqualTo("ST-123");
        assertThat(decode(query.getFirst("service")))
                .isEqualTo(service);
        assertThat(query.getFirst("format")).isEqualTo("JSON");
    }

    @Test
    void parsesCas20XmlAndPreservesRepeatedAttributes() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setProtocolVersion("2.0");
        CasProtocolClient client = client(
                properties,
                (uri, connect, read, maximum) ->
                        new CasProtocolClient.CasValidationResponse(
                                200,
                                """
                                <?xml version="1.0" encoding="UTF-8"?>
                                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                                  <cas:authenticationSuccess>
                                    <cas:user>alice</cas:user>
                                    <cas:attributes>
                                      <cas:memberOf>engineering</cas:memberOf>
                                      <cas:memberOf>reviewers</cas:memberOf>
                                    </cas:attributes>
                                  </cas:authenticationSuccess>
                                </cas:serviceResponse>
                                """));

        CasAuthenticationExchange exchange = client.validate(
                "cas-main",
                "ST-20",
                client.begin("cas-main", STATE).serviceUrl());

        assertThat(exchange.attributes().get("memberOf"))
                .containsExactly("engineering", "reviewers");
    }

    @Test
    void cas30AcceptsStandardsCompatibleXmlFallback() {
        CasProtocolClient client = client((uri, connect, read, maximum) ->
                new CasProtocolClient.CasValidationResponse(
                        200,
                        """
                        <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                          <cas:authenticationSuccess>
                            <cas:user>alice</cas:user>
                          </cas:authenticationSuccess>
                        </cas:serviceResponse>
                        """));

        assertThat(client.validate(
                "cas-main",
                "ST-xml",
                client.begin("cas-main", STATE).serviceUrl())
                .principal()).isEqualTo("alice");
    }

    @Test
    void invalidStateBoundServiceNeverReachesTheCasServer() {
        AtomicReference<URI> requested = new AtomicReference<>();
        CasProtocolClient client = client((uri, connect, read, maximum) -> {
            requested.set(uri);
            return new CasProtocolClient.CasValidationResponse(
                    200,
                    "");
        });

        assertThatThrownBy(() -> client.validate(
                "cas-main",
                "ST-123",
                "https://evil.example/callback?state=" + STATE))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);
        assertThat(requested.get()).isNull();
    }

    @Test
    void classifiesCasFailuresWithoutLeakingTicket() {
        CasProtocolClient client = client((uri, connect, read, maximum) ->
                new CasProtocolClient.CasValidationResponse(
                        200,
                        """
                        {
                          "serviceResponse": {
                            "authenticationFailure": {
                              "code": "INVALID_TICKET",
                              "description": "ticket rejected"
                            }
                          }
                        }
                        """));

        assertThatThrownBy(() -> client.validate(
                "cas-main",
                "ST-secret-value",
                client.begin("cas-main", STATE).serviceUrl()))
                .isInstanceOf(ProviderAuthenticationException.class)
                .hasMessage(
                        ProviderAuthenticationFailureCode
                                .UPSTREAM_INVALID_CREDENTIALS
                                .name())
                .hasMessageNotContaining("ST-secret-value")
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_CREDENTIALS);
    }

    @Test
    void rejectsXxeBeforeIdentityMapping() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setProtocolVersion("2.0");
        CasProtocolClient client = client(
                properties,
                (uri, connect, read, maximum) ->
                        new CasProtocolClient.CasValidationResponse(
                                200,
                                """
                                <?xml version="1.0"?>
                                <!DOCTYPE serviceResponse [
                                  <!ENTITY xxe SYSTEM "file:///etc/passwd">
                                ]>
                                <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
                                  <cas:authenticationSuccess>
                                    <cas:user>&xxe;</cas:user>
                                  </cas:authenticationSuccess>
                                </cas:serviceResponse>
                                """));

        assertThatThrownBy(() -> client.validate(
                "cas-main",
                "ST-xxe",
                client.begin("cas-main", STATE).serviceUrl()))
                .isInstanceOf(ProviderAuthenticationException.class)
                .hasMessageNotContaining("root:")
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);
    }

    @Test
    void rejectsWrongXmlNamespaceAndOversizedPrincipal() {
        CasProperties properties =
                CasTestConfiguration.validProperties();
        properties.setProtocolVersion("2.0");
        CasProtocolClient wrongNamespace = client(
                properties,
                (uri, connect, read, maximum) ->
                        new CasProtocolClient.CasValidationResponse(
                                200,
                                """
                                <serviceResponse xmlns="https://evil.example/cas">
                                  <authenticationSuccess>
                                    <user>alice</user>
                                  </authenticationSuccess>
                                </serviceResponse>
                                """));

        assertThatThrownBy(() -> wrongNamespace.validate(
                "cas-main",
                "ST-wrong-namespace",
                wrongNamespace.begin(
                        "cas-main",
                        STATE).serviceUrl()))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);

        CasProtocolClient oversizedPrincipal = client(
                (uri, connect, read, maximum) ->
                        new CasProtocolClient.CasValidationResponse(
                                200,
                                """
                                {
                                  "serviceResponse": {
                                    "authenticationSuccess": {
                                      "user": "%s"
                                    }
                                  }
                                }
                                """.formatted("x".repeat(4097))));

        assertThatThrownBy(() -> oversizedPrincipal.validate(
                "cas-main",
                "ST-oversized-principal",
                oversizedPrincipal.begin(
                        "cas-main",
                        STATE).serviceUrl()))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);
    }

    @Test
    void mapsHttpAndMalformedResponseFailures() {
        CasProtocolClient unavailable = client(
                (uri, connect, read, maximum) ->
                        new CasProtocolClient.CasValidationResponse(
                                503,
                                ""));
        String service = unavailable.begin(
                "cas-main",
                STATE).serviceUrl();

        assertThatThrownBy(() -> unavailable.validate(
                "cas-main",
                "ST-503",
                service))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_UNAVAILABLE);

        CasProtocolClient malformed = client(
                (uri, connect, read, maximum) ->
                        new CasProtocolClient.CasValidationResponse(
                                200,
                                "{\"unexpected\":true}"));

        assertThatThrownBy(() -> malformed.validate(
                "cas-main",
                "ST-malformed",
                malformed.begin(
                        "cas-main",
                        STATE).serviceUrl()))
                .isInstanceOf(ProviderAuthenticationException.class)
                .extracting("reasonCode")
                .isEqualTo(ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);
    }

    private CasProtocolClient client(
            CasProtocolClient.CasValidationTransport transport) {
        return client(
                CasTestConfiguration.validProperties(),
                transport);
    }

    private CasProtocolClient client(
            CasProperties properties,
            CasProtocolClient.CasValidationTransport transport) {
        return new CasProtocolClient(
                CasTestConfiguration.configuration(properties),
                new ObjectMapper(),
                transport,
                Clock.fixed(
                        AUTHENTICATED_AT,
                        ZoneOffset.UTC));
    }

    private String decode(String value) {
        return URLDecoder.decode(
                value,
                StandardCharsets.UTF_8);
    }
}
