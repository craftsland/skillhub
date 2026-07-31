package com.iflytek.skillhub.auth.merge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

@Component
final class AccountMergeStateHasher {

    String hash(String rawState) {
        if (rawState == null || rawState.isBlank()) {
            throw new IllegalArgumentException(
                    "Account merge state must not be blank");
        }
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256")
                            .digest(rawState.getBytes(
                                    StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable",
                    exception);
        }
    }

    boolean matches(
            String rawState,
            String expectedHash) {
        if (rawState == null || expectedHash == null) {
            return false;
        }
        byte[] expected;
        try {
            expected = HexFormat.of().parseHex(expectedHash);
        } catch (IllegalArgumentException exception) {
            return false;
        }
        return MessageDigest.isEqual(
                digest(rawState),
                expected);
    }

    private byte[] digest(String rawState) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(rawState.getBytes(
                            StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable",
                    exception);
        }
    }
}
