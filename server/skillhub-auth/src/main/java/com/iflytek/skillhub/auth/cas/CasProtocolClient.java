package com.iflytek.skillhub.auth.cas;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationException;
import com.iflytek.skillhub.auth.provider.ProviderAuthenticationFailureCode;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.net.ssl.SSLException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * CAS redirect construction and service-ticket validation.
 *
 * <p>The implementation intentionally does not use Apereo's URL-based
 * validator because that client logs the full validation URL and response at
 * DEBUG level. The URL contains the one-time service ticket. This client keeps
 * transport, parsing and failures credential-free while preserving CAS
 * 2.0/3.0 protocol behavior.</p>
 */
@Component
public final class CasProtocolClient implements CasBrowserClient {

    private static final int MAX_TICKET_LENGTH = 2048;
    private static final int MAX_SERVICE_LENGTH = 4096;
    private static final int MAX_ATTRIBUTE_COUNT = 128;
    private static final int MAX_VALUES_PER_ATTRIBUTE = 32;
    private static final int MAX_ATTRIBUTE_VALUE_LENGTH = 4096;
    private static final String CAS_NAMESPACE =
            "http://www.yale.edu/tp/cas";
    private static final Pattern STATE_PATTERN =
            Pattern.compile("[A-Za-z0-9_-]{32,128}");

    private final CasProviderConfiguration configuration;
    private final ObjectMapper objectMapper;
    private final CasValidationTransport transport;
    private final Clock clock;

    @Autowired
    CasProtocolClient(
            CasProviderConfiguration configuration,
            ObjectMapper objectMapper) {
        this(
                configuration,
                objectMapper,
                JdkCasValidationTransport::exchange,
                Clock.systemUTC());
    }

    CasProtocolClient(
            CasProviderConfiguration configuration,
            ObjectMapper objectMapper,
            CasValidationTransport transport,
            Clock clock) {
        this.configuration = configuration;
        this.objectMapper = objectMapper;
        this.transport = transport;
        this.clock = clock;
    }

    @Override
    public CasLoginInitiation begin(
            String providerCode,
            String state) {
        CasProviderConfiguration.ResolvedCasProvider resolved =
                requireProvider(providerCode);
        if (state == null
                || !STATE_PATTERN.matcher(state).matches()) {
            throw invalidResponse();
        }

        String serviceUrl = resolved.serviceUri().toASCIIString()
                + "?state="
                + state;
        URI loginEndpoint = appendPath(
                resolved.serverUri(),
                "/login");
        URI loginUri = UriComponentsBuilder
                .fromUri(loginEndpoint)
                .queryParam("service", serviceUrl)
                .build()
                .encode()
                .toUri();
        return new CasLoginInitiation(
                loginUri,
                serviceUrl,
                resolved.stateTtl());
    }

    @Override
    public CasAuthenticationExchange validate(
            String providerCode,
            String ticket,
            String expectedServiceUrl) {
        CasProviderConfiguration.ResolvedCasProvider resolved =
                requireProvider(providerCode);
        requireTicket(ticket);
        requireExpectedService(resolved, expectedServiceUrl);

        URI endpoint = appendPath(
                resolved.serverUri(),
                resolved.protocolVersion().validationPath());
        UriComponentsBuilder validationUri =
                UriComponentsBuilder.fromUri(endpoint)
                        .queryParam("ticket", ticket)
                        .queryParam("service", expectedServiceUrl);
        if (resolved.protocolVersion().jsonPreferred()) {
            validationUri.queryParam("format", "JSON");
        }

        CasValidationResponse response;
        try {
            response = transport.exchange(
                    validationUri.build().encode().toUri(),
                    resolved.connectTimeout(),
                    resolved.readTimeout(),
                    resolved.maximumResponseBytes());
        } catch (CasTransportFailure failure) {
            throw new ProviderAuthenticationException(
                    failure.reasonCode());
        }

        requireSuccessStatus(response.statusCode());
        if (response.body() == null || response.body().isBlank()) {
            throw invalidResponse();
        }
        return parseResponse(
                resolved.protocolVersion(),
                response.body());
    }

    private CasProviderConfiguration.ResolvedCasProvider requireProvider(
            String providerCode) {
        CasProviderConfiguration.ResolvedCasProvider resolved;
        try {
            resolved = configuration.requireResolved();
        } catch (RuntimeException exception) {
            throw new ProviderAuthenticationException(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_MISCONFIGURED);
        }
        if (!resolved.providerCode().equals(providerCode)) {
            throw new ProviderAuthenticationException(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_MISCONFIGURED);
        }
        return resolved;
    }

    private void requireTicket(String ticket) {
        if (ticket == null
                || ticket.isBlank()
                || ticket.length() > MAX_TICKET_LENGTH
                || ticket.chars().anyMatch(character ->
                        Character.isISOControl(character)
                                || Character.isWhitespace(character))) {
            throw new ProviderAuthenticationException(
                    ProviderAuthenticationFailureCode
                            .UPSTREAM_INVALID_CREDENTIALS);
        }
    }

    private void requireExpectedService(
            CasProviderConfiguration.ResolvedCasProvider resolved,
            String expectedServiceUrl) {
        if (expectedServiceUrl == null
                || expectedServiceUrl.length() > MAX_SERVICE_LENGTH) {
            throw invalidResponse();
        }
        UriComponents expected;
        try {
            expected = UriComponentsBuilder
                    .fromUriString(expectedServiceUrl)
                    .build();
        } catch (RuntimeException exception) {
            throw invalidResponse();
        }
        URI base = resolved.serviceUri();
        if (!base.getScheme().equals(expected.getScheme())
                || !base.getHost().equals(expected.getHost())
                || base.getPort() != expected.getPort()
                || !base.getPath().equals(expected.getPath())
                || expected.getFragment() != null
                || expected.getQueryParams().size() != 1
                || expected.getQueryParams().get("state") == null
                || expected.getQueryParams().get("state").size() != 1
                || !STATE_PATTERN.matcher(expected.getQueryParams()
                        .getFirst("state")).matches()) {
            throw invalidResponse();
        }
    }

    private void requireSuccessStatus(int statusCode) {
        if (statusCode >= 200 && statusCode < 300) {
            return;
        }
        ProviderAuthenticationFailureCode code;
        if (statusCode == 401) {
            code = ProviderAuthenticationFailureCode
                    .UPSTREAM_INVALID_CREDENTIALS;
        } else if (statusCode == 403) {
            code = ProviderAuthenticationFailureCode
                    .UPSTREAM_ACCESS_DENIED;
        } else if (statusCode >= 500) {
            code = ProviderAuthenticationFailureCode
                    .UPSTREAM_UNAVAILABLE;
        } else {
            code = ProviderAuthenticationFailureCode
                    .UPSTREAM_INVALID_RESPONSE;
        }
        throw new ProviderAuthenticationException(code);
    }

    private CasAuthenticationExchange parseResponse(
            CasProtocolVersion protocolVersion,
            String response) {
        try {
            String stripped = response.stripLeading();
            if (protocolVersion.jsonPreferred()
                    && stripped.startsWith("{")) {
                return parseJson(response);
            }
            if (stripped.startsWith("<")) {
                return parseXml(response);
            }
            throw invalidResponse();
        } catch (CasAuthenticationFailure failure) {
            throw new ProviderAuthenticationException(
                    failureCode(failure.code()));
        } catch (ProviderAuthenticationException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidResponse();
        }
    }

    private CasAuthenticationExchange parseJson(String response) {
        JsonNode root;
        try {
            root = objectMapper.readTree(response);
        } catch (JsonProcessingException exception) {
            throw invalidResponse();
        }
        JsonNode serviceResponse = root.path("serviceResponse");
        JsonNode success =
                serviceResponse.path("authenticationSuccess");
        JsonNode failure =
                serviceResponse.path("authenticationFailure");
        if (!success.isMissingNode() && !failure.isMissingNode()) {
            throw invalidResponse();
        }
        if (!failure.isMissingNode()) {
            throw new CasAuthenticationFailure(
                    textValue(failure.path("code"), "UNKNOWN"));
        }
        if (!success.isObject()) {
            throw invalidResponse();
        }
        String principal = requiredText(success.path("user"));
        Map<String, List<String>> attributes =
                parseJsonAttributes(success.path("attributes"));
        return new CasAuthenticationExchange(
                principal,
                attributes,
                clock.instant());
    }

    private Map<String, List<String>> parseJsonAttributes(
            JsonNode attributesNode) {
        if (attributesNode.isMissingNode() || attributesNode.isNull()) {
            return Map.of();
        }
        if (!attributesNode.isObject()
                || attributesNode.size() > MAX_ATTRIBUTE_COUNT) {
            throw invalidResponse();
        }
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        attributesNode.fields().forEachRemaining(entry -> {
            JsonNode raw = entry.getValue();
            List<String> values = new ArrayList<>();
            if (raw.isValueNode() && !raw.isNull()) {
                values.add(scalarValue(raw));
            } else if (raw.isArray()
                    && raw.size() <= MAX_VALUES_PER_ATTRIBUTE) {
                raw.forEach(value -> {
                    if (!value.isValueNode() || value.isNull()) {
                        throw invalidResponse();
                    }
                    values.add(scalarValue(value));
                });
            } else {
                throw invalidResponse();
            }
            attributes.put(entry.getKey(), List.copyOf(values));
        });
        return Map.copyOf(attributes);
    }

    private String scalarValue(JsonNode node) {
        String value = node.asText();
        if (value.length() > MAX_ATTRIBUTE_VALUE_LENGTH) {
            throw invalidResponse();
        }
        return value;
    }

    private CasAuthenticationExchange parseXml(String response) {
        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();
        configureSecureXml(factory);
        try {
            var builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new StrictXmlErrorHandler());
            var document = builder.parse(
                    new InputSource(new StringReader(response)));
            Element root = document.getDocumentElement();
            if (root == null
                    || !"serviceResponse".equals(
                            root.getLocalName())
                    || !CAS_NAMESPACE.equals(
                            root.getNamespaceURI())) {
                throw invalidResponse();
            }
            List<Element> successes = childElements(
                    root,
                    "authenticationSuccess");
            List<Element> failures = childElements(
                    root,
                    "authenticationFailure");
            if (!successes.isEmpty() && !failures.isEmpty()) {
                throw invalidResponse();
            }
            if (!failures.isEmpty()) {
                throw new CasAuthenticationFailure(
                        failures.getFirst().getAttribute("code"));
            }
            if (successes.size() != 1) {
                throw invalidResponse();
            }
            Element success = successes.getFirst();
            List<Element> users = childElements(success, "user");
            if (users.size() != 1) {
                throw invalidResponse();
            }
            String principal = users.getFirst().getTextContent();
            if (principal == null
                    || principal.isBlank()
                    || principal.length()
                    > MAX_ATTRIBUTE_VALUE_LENGTH) {
                throw invalidResponse();
            }
            List<Element> attributesElements =
                    childElements(success, "attributes");
            if (attributesElements.size() > 1) {
                throw invalidResponse();
            }
            Map<String, List<String>> attributes =
                    attributesElements.isEmpty()
                            ? Map.of()
                            : parseXmlAttributes(
                                    attributesElements.getFirst());
            return new CasAuthenticationExchange(
                    principal,
                    attributes,
                    clock.instant());
        } catch (CasAuthenticationFailure failure) {
            throw failure;
        } catch (ProviderAuthenticationException exception) {
            throw exception;
        } catch (Exception exception) {
            throw invalidResponse();
        }
    }

    private void configureSecureXml(
            DocumentBuilderFactory factory) {
        factory.setNamespaceAware(true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        try {
            factory.setFeature(
                    XMLConstants.FEATURE_SECURE_PROCESSING,
                    true);
            factory.setFeature(
                    "http://apache.org/xml/features/disallow-doctype-decl",
                    true);
            factory.setFeature(
                    "http://xml.org/sax/features/external-general-entities",
                    false);
            factory.setFeature(
                    "http://xml.org/sax/features/external-parameter-entities",
                    false);
            factory.setFeature(
                    "http://apache.org/xml/features/nonvalidating/load-external-dtd",
                    false);
            factory.setAttribute(
                    XMLConstants.ACCESS_EXTERNAL_DTD,
                    "");
            factory.setAttribute(
                    XMLConstants.ACCESS_EXTERNAL_SCHEMA,
                    "");
        } catch (ParserConfigurationException
                | IllegalArgumentException exception) {
            throw invalidResponse();
        }
    }

    private Map<String, List<String>> parseXmlAttributes(
            Element attributesElement) {
        Map<String, List<String>> attributes =
                new LinkedHashMap<>();
        for (Element element : childElements(attributesElement, null)) {
            String name = element.getLocalName();
            String value = element.getTextContent();
            if (name == null
                    || value == null
                    || value.length() > MAX_ATTRIBUTE_VALUE_LENGTH) {
                throw invalidResponse();
            }
            List<String> existing = attributes.getOrDefault(
                    name,
                    List.of());
            if (existing.size() >= MAX_VALUES_PER_ATTRIBUTE) {
                throw invalidResponse();
            }
            List<String> values = new ArrayList<>(existing);
            values.add(value);
            attributes.put(name, List.copyOf(values));
            if (attributes.size() > MAX_ATTRIBUTE_COUNT) {
                throw invalidResponse();
            }
        }
        return Map.copyOf(attributes);
    }

    private List<Element> childElements(
            Element parent,
            String localName) {
        List<Element> elements = new ArrayList<>();
        for (Node node = parent.getFirstChild();
                node != null;
                node = node.getNextSibling()) {
            if (node instanceof Element element
                    && (localName == null
                    || localName.equals(element.getLocalName())
                    && CAS_NAMESPACE.equals(
                            element.getNamespaceURI()))) {
                elements.add(element);
            }
        }
        return elements;
    }

    private String requiredText(JsonNode node) {
        if (!node.isTextual()
                || node.textValue().isBlank()
                || node.textValue().length()
                > MAX_ATTRIBUTE_VALUE_LENGTH) {
            throw invalidResponse();
        }
        return node.textValue();
    }

    private String textValue(
            JsonNode node,
            String fallback) {
        return node.isTextual() && !node.textValue().isBlank()
                ? node.textValue()
                : fallback;
    }

    private ProviderAuthenticationFailureCode failureCode(
            String casCode) {
        if ("INVALID_TICKET".equals(casCode)) {
            return ProviderAuthenticationFailureCode
                    .UPSTREAM_INVALID_CREDENTIALS;
        }
        if ("INVALID_SERVICE".equals(casCode)
                || "INVALID_REQUEST".equals(casCode)) {
            return ProviderAuthenticationFailureCode
                    .UPSTREAM_MISCONFIGURED;
        }
        if ("UNAUTHORIZED_SERVICE".equals(casCode)) {
            return ProviderAuthenticationFailureCode
                    .UPSTREAM_ACCESS_DENIED;
        }
        return ProviderAuthenticationFailureCode
                .UPSTREAM_UNAVAILABLE;
    }

    private URI appendPath(URI base, String path) {
        String value = base.toASCIIString();
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return URI.create(value + path);
    }

    private ProviderAuthenticationException invalidResponse() {
        return new ProviderAuthenticationException(
                ProviderAuthenticationFailureCode
                        .UPSTREAM_INVALID_RESPONSE);
    }

    @FunctionalInterface
    interface CasValidationTransport {

        CasValidationResponse exchange(
                URI uri,
                Duration connectTimeout,
                Duration readTimeout,
                int maximumResponseBytes);
    }

    record CasValidationResponse(
            int statusCode,
            String body
    ) {
    }

    private static final class CasAuthenticationFailure
            extends RuntimeException {

        private final String code;

        private CasAuthenticationFailure(String code) {
            super("CAS_AUTHENTICATION_FAILURE");
            this.code = code == null || code.isBlank()
                    ? "UNKNOWN"
                    : code;
        }

        private String code() {
            return code;
        }
    }

    private static final class CasTransportFailure
            extends RuntimeException {

        private final ProviderAuthenticationFailureCode reasonCode;

        private CasTransportFailure(
                ProviderAuthenticationFailureCode reasonCode) {
            super(reasonCode.name());
            this.reasonCode = reasonCode;
        }

        private ProviderAuthenticationFailureCode reasonCode() {
            return reasonCode;
        }
    }

    private static final class JdkCasValidationTransport {

        private JdkCasValidationTransport() {
        }

        private static CasValidationResponse exchange(
                URI uri,
                Duration connectTimeout,
                Duration readTimeout,
                int maximumResponseBytes) {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(connectTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(readTimeout)
                    .header("Accept", "application/json, application/xml")
                    .GET()
                    .build();
            try {
                HttpResponse<InputStream> response = client.send(
                        request,
                        HttpResponse.BodyHandlers.ofInputStream());
                try (InputStream body = response.body()) {
                    byte[] bytes = body.readNBytes(
                            maximumResponseBytes + 1);
                    if (bytes.length > maximumResponseBytes) {
                        throw new CasTransportFailure(
                                ProviderAuthenticationFailureCode
                                        .UPSTREAM_INVALID_RESPONSE);
                    }
                    return new CasValidationResponse(
                            response.statusCode(),
                            new String(
                                    bytes,
                                    StandardCharsets.UTF_8));
                }
            } catch (CasTransportFailure failure) {
                throw failure;
            } catch (HttpTimeoutException
                    | ConnectException exception) {
                throw new CasTransportFailure(
                        ProviderAuthenticationFailureCode
                                .UPSTREAM_UNAVAILABLE);
            } catch (IOException exception) {
                if (hasTlsCause(exception)) {
                    throw new CasTransportFailure(
                            ProviderAuthenticationFailureCode
                                    .TLS_VALIDATION_FAILED);
                }
                throw new CasTransportFailure(
                        ProviderAuthenticationFailureCode
                                .UPSTREAM_UNAVAILABLE);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new CasTransportFailure(
                        ProviderAuthenticationFailureCode
                                .UPSTREAM_UNAVAILABLE);
            }
        }

        private static boolean hasTlsCause(Throwable failure) {
            for (Throwable current = failure;
                    current != null;
                    current = current.getCause()) {
                if (current instanceof SSLException) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final class StrictXmlErrorHandler
            implements ErrorHandler {

        @Override
        public void warning(SAXParseException exception)
                throws SAXException {
            throw exception;
        }

        @Override
        public void error(SAXParseException exception)
                throws SAXException {
            throw exception;
        }

        @Override
        public void fatalError(SAXParseException exception)
                throws SAXException {
            throw exception;
        }
    }
}
