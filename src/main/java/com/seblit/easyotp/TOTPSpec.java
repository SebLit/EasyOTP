package com.seblit.easyotp;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import java.util.Objects;

/**
 * Specifies secret, length, algorithm and period TOTP calculation conform with RFC6238
 * */
public class TOTPSpec extends HOTPSpec {

    private final Algorithm algorithm;
    private final int period;
    private final long periodMillis;

    /**
     * Creates a new spec
     *
     * @throws IllegalArgumentException if the secret is too short (min 16 bytes), the length is not within 6 - 8 or period is less than 1 second
     * @see #MIN_OTP_LENGTH
     * @see #MAX_OTP_LENGTH
     * @see #MIN_SECRET_BYTES
     */
    public TOTPSpec(@NotNull byte[] secret, @Range(from = 6, to = 8) int length, @NotNull Algorithm algorithm, @Range(from = 1, to = Integer.MAX_VALUE) int period) {
        this(secret, length, algorithm, period, period * 1000L);
    }

    /**
     * Creates a new spec
     *
     * @throws IllegalArgumentException if the secret is too short (min 16 bytes), the length is not within 6 - 8 or period is less than 1 second
     * @see #MIN_OTP_LENGTH
     * @see #MAX_OTP_LENGTH
     * @see #MIN_SECRET_BYTES
     */
    public TOTPSpec(@NotNull byte[] secret, @Range(from = 6, to = 8) int length, @NotNull Algorithm algorithm, @Range(from = 1, to = Long.MAX_VALUE) long periodMillis) {
        this(secret, length, algorithm, (int) (periodMillis / 1000), periodMillis);
    }

    private TOTPSpec(byte[] secret, int length, Algorithm algorithm, int period, long periodMillis) {
        super(secret, length);
        if (period < 1) {
            throw new IllegalArgumentException("Period must be > 1 second");
        }
        this.algorithm = algorithm;
        this.period = period;
        this.periodMillis = periodMillis;
    }

    @NotNull
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public int getPeriod() {
        return period;
    }

    public long getPeriodMillis() {
        return periodMillis;
    }

    @Override
    public boolean equals(Object o) {
        if (!super.equals(o)) return false;
        TOTPSpec totpSpec = (TOTPSpec) o;
        return period == totpSpec.period && periodMillis == totpSpec.periodMillis && algorithm == totpSpec.algorithm;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), algorithm, period, periodMillis);
    }

    public enum Algorithm {
        SHA1("HmacSHA1"), SHA256("HmacSHA256"), SHA512("HmacSHA512");

        private final String algorithmName;

        Algorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        String getAlgorithmName() {
            return algorithmName;
        }
    }
}
