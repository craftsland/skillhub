package com.iflytek.skillhub.observability;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.transport.Kind;
import io.micrometer.observation.transport.ReceiverContext;
import io.micrometer.observation.transport.SenderContext;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Propagates tracing and request correlation across asynchronous message transports.
 *
 * <p>The message carrier owns transport metadata. Business payloads remain independent from
 * Micrometer, OpenTelemetry, MDC, and a concrete tracing backend.</p>
 */
@Component
public class MessageObservationSupport {

    public static final String REQUEST_ID_FIELD = "skillhub.request_id";

    private static final Set<String> OWNED_TRANSPORT_FIELDS = Set.of(
            REQUEST_ID_FIELD,
            "traceparent",
            "tracestate",
            "baggage"
    );

    private final ObservationRegistry observationRegistry;
    private final RequestIdAccessor requestIdAccessor;

    public MessageObservationSupport(
            ObservationRegistry observationRegistry,
            RequestIdAccessor requestIdAccessor
    ) {
        this.observationRegistry = observationRegistry;
        this.requestIdAccessor = requestIdAccessor;
    }

    /**
     * Observes a message publish operation and injects the current transport context.
     */
    public <C, T> T observePublish(
            String messagingSystem,
            String destination,
            C carrier,
            MessageCarrierAdapter<C> carrierAdapter,
            Supplier<T> action
    ) {
        validateArguments(messagingSystem, destination, carrier, action);
        Objects.requireNonNull(carrierAdapter, "carrierAdapter must not be null");
        OWNED_TRANSPORT_FIELDS.forEach(field -> carrierAdapter.remove(carrier, field));
        String requestId = requestIdAccessor.current();
        if (RequestIdAccessor.isValid(requestId)) {
            carrierAdapter.set(carrier, REQUEST_ID_FIELD, requestId);
        }

        SenderContext<C> senderContext = new SenderContext<>(carrierAdapter, Kind.PRODUCER);
        senderContext.setCarrier(carrier);
        senderContext.setRemoteServiceName(messagingSystem);
        return observe(
                "skillhub.message.publish",
                destination + " publish",
                messagingSystem,
                destination,
                "publish",
                senderContext,
                action
        );
    }

    /**
     * Extracts a message transport context and observes processing inside its scope.
     */
    public <C, T> T observeProcess(
            String messagingSystem,
            String destination,
            C carrier,
            MessageCarrierAdapter<C> carrierAdapter,
            Supplier<T> action
    ) {
        validateArguments(messagingSystem, destination, carrier, action);
        Objects.requireNonNull(carrierAdapter, "carrierAdapter must not be null");
        ReceiverContext<C> receiverContext = new ReceiverContext<>(carrierAdapter, Kind.CONSUMER);
        receiverContext.setCarrier(carrier);
        receiverContext.setRemoteServiceName(messagingSystem);

        String propagatedRequestId = carrierAdapter.get(carrier, REQUEST_ID_FIELD);
        RequestIdAccessor.Scope requestIdScope = requestIdAccessor.openNullable(
                RequestIdAccessor.isValid(propagatedRequestId) ? propagatedRequestId : null
        );
        try (requestIdScope) {
            return observe(
                    "skillhub.message.process",
                    destination + " process",
                    messagingSystem,
                    destination,
                    "process",
                    receiverContext,
                    action
            );
        }
    }

    /**
     * Marks the currently active message Observation as failed when processing handles the
     * exception without rethrowing it.
     */
    public void recordCurrentError(Throwable error) {
        Objects.requireNonNull(error, "error must not be null");
        Observation currentObservation = observationRegistry.getCurrentObservation();
        if (currentObservation != null) {
            currentObservation.error(error);
        }
    }

    private <T> T observe(
            String observationName,
            String contextualName,
            String messagingSystem,
            String destination,
            String operation,
            Observation.Context transportContext,
            Supplier<T> action
    ) {
        Observation observation = Observation
                .createNotStarted(observationName, () -> transportContext, observationRegistry)
                .contextualName(contextualName)
                .lowCardinalityKeyValue("messaging.system", messagingSystem)
                .lowCardinalityKeyValue("messaging.operation.type", operation)
                .highCardinalityKeyValue("messaging.destination.name", destination)
                .start();
        try (Observation.Scope ignored = observation.openScope()) {
            return action.get();
        } catch (RuntimeException | Error error) {
            observation.error(error);
            throw error;
        } finally {
            observation.stop();
        }
    }

    private void validateArguments(
            String messagingSystem,
            String destination,
            Object carrier,
            Supplier<?> action
    ) {
        if (messagingSystem == null || messagingSystem.isBlank()) {
            throw new IllegalArgumentException("messagingSystem must not be blank");
        }
        if (destination == null || destination.isBlank()) {
            throw new IllegalArgumentException("destination must not be blank");
        }
        Objects.requireNonNull(carrier, "carrier must not be null");
        Objects.requireNonNull(action, "action must not be null");
    }
}
