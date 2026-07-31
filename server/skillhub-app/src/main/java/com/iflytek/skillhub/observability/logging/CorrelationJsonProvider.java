package com.iflytek.skillhub.observability.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import com.fasterxml.jackson.core.JsonGenerator;
import net.logstash.logback.composite.AbstractJsonProvider;

import java.io.IOException;
import java.util.Map;

/**
 * Writes only the approved correlation fields from MDC.
 */
final class CorrelationJsonProvider extends AbstractJsonProvider<ILoggingEvent> {

    private static final String REQUEST_ID_KEY = "requestId";
    private static final String TRACE_ID_KEY = "traceId";
    private static final String SPAN_ID_KEY = "spanId";
    private static final String EXTERNAL_TRACE_ID_KEY = "tid";

    @Override
    public void writeTo(JsonGenerator generator, ILoggingEvent event) throws IOException {
        Map<String, String> mdc = event.getMDCPropertyMap();
        if (mdc == null || mdc.isEmpty()) {
            return;
        }

        writeIfPresent(generator, "request.id", mdc.get(REQUEST_ID_KEY));
        writeIfPresent(
                generator,
                "trace.id",
                firstPresent(mdc.get(TRACE_ID_KEY), mdc.get(EXTERNAL_TRACE_ID_KEY))
        );
        writeIfPresent(generator, "span.id", mdc.get(SPAN_ID_KEY));
    }

    private String firstPresent(String preferred, String fallback) {
        return isPresent(preferred) ? preferred : fallback;
    }

    private void writeIfPresent(JsonGenerator generator, String fieldName, String value)
            throws IOException {
        if (isPresent(value)) {
            generator.writeStringField(fieldName, value);
        }
    }

    private boolean isPresent(String value) {
        return value != null && !value.isBlank();
    }
}
