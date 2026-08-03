package com.iflytek.skillhub.stream;

import com.iflytek.skillhub.observability.MessageCarrierAdapter;

import java.util.Map;

/**
 * Adapts Redis Stream field maps to the transport-neutral message observation boundary.
 */
final class RedisStreamMessageCarrier {

    static final String MESSAGING_SYSTEM = "redis";

    static final MessageCarrierAdapter<Map<String, String>> ADAPTER =
            new MessageCarrierAdapter<>() {
                @Override
                public String get(Map<String, String> carrier, String key) {
                    return carrier.get(key);
                }

                @Override
                public void set(Map<String, String> carrier, String key, String value) {
                    carrier.put(key, value);
                }

                @Override
                public void remove(Map<String, String> carrier, String key) {
                    carrier.remove(key);
                }
            };

    private RedisStreamMessageCarrier() {
    }
}
