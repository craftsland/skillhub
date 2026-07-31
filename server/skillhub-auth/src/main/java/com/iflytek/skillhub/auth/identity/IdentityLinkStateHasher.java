package com.iflytek.skillhub.auth.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

@Component
final class IdentityLinkStateHasher {

    String hash(String rawState) {
        if (rawState == null || rawState.isBlank()) {
            throw new IllegalArgumentException(
                    "Identity link state must not be blank");
        }
        return HexFormat.of().formatHex(
                sha256(rawState.getBytes(StandardCharsets.UTF_8)));
    }

    boolean matches(String rawState, String expectedHash) {
        if (rawState == null || expectedHash == null) {
            return false;
        }
        byte[] actual = sha256(rawState.getBytes(StandardCharsets.UTF_8));
        byte[] expected;
        try {
            expected = HexFormat.of().parseHex(expectedHash);
        } catch (IllegalArgumentException exception) {
            return false;
        }
        return MessageDigest.isEqual(actual, expected);
    }

    private byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable",
                    exception);
        }
    }
}
