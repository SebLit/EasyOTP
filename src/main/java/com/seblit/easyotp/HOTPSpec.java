package com.seblit.easyotp;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import java.util.Arrays;
import java.util.Objects;

/**
 * Specifies secret and length for HOTP calculation conform with RFC4226
 */
public class HOTPSpec {

    /**
     * Minimum length of an OTP
     * */
    public static final int MIN_OTP_LENGTH = 6;
    /**
     * Maximum length of an OTP
     * */
    public static final int MAX_OTP_LENGTH = 8;
    /**
     * Minimum byte count of the secret
     * */
    public static final int MIN_SECRET_BYTES = 16;
    private final byte[] secret;
    private final int length;

    /**
     * Creates a new spec
     *
     * @throws IllegalArgumentException if the secret is too short (min 16 bytes) or the length is not within 6 - 8
     * @see #MIN_OTP_LENGTH
     * @see #MAX_OTP_LENGTH
     * @see #MIN_SECRET_BYTES
     */
    public HOTPSpec(@NotNull byte[] secret, @Range(from = 6, to = 8) int length) {
        if (secret.length < MIN_SECRET_BYTES) {
            throw new IllegalArgumentException("Secret too short. Byte count must be >= 16");
        }
        if (length < MIN_OTP_LENGTH || length > MAX_OTP_LENGTH) {
            throw new IllegalArgumentException("Length not within valid range 6-8");
        }
        this.secret = secret;
        this.length = length;
    }

    byte[] getSecret() {
        return secret;
    }

    public int getLength() {
        return length;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HOTPSpec hotpSpec = (HOTPSpec) o;
        return length == hotpSpec.length && Arrays.equals(secret, hotpSpec.secret);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(length);
        result = 31 * result + Arrays.hashCode(secret);
        return result;
    }
}
