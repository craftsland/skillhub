package com.iflytek.skillhub.observability;

import io.micrometer.observation.transport.Propagator;

/**
 * Adapts transport-specific message headers to the common observation boundary.
 */
public interface MessageCarrierAdapter<C>
        extends Propagator.Getter<C>, Propagator.Setter<C> {

    /**
     * Removes every value associated with a transport header.
     */
    void remove(C carrier, String key);
}
