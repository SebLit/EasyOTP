package com.seblit.easyotp;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Generator for HOTPs conform to RFC4226 or TOTPs conform to RFC6238
 * */
public class OTPGenerator {

    private static final int MASK_BYTE = 0xFF;
    private static final int MASK_LOWER_BITS = 0x0F;
    private static final int MASK_OMIT_MSB = 0x7F;

    /**
     * Generates an RFC4226 conform HOTP based on the provided {@link HOTPSpec} and counter
     * @throws NoSuchAlgorithmException if HmacSHA1 initialization should fail
     * @throws InvalidKeyException if the secret should be unsuitable as a key for HmacSHA1
     * @return the generated OTP. Leading zeros will be filled in to match the {@link HOTPSpec}s length requirement
     * */
    public String generate(@NotNull HOTPSpec spec, @Range(from = 0, to = Long.MAX_VALUE) long counter) throws NoSuchAlgorithmException, InvalidKeyException {
        return generate(spec, TOTPSpec.Algorithm.SHA1, counter);
    }

    /**
     * Generates an RFC6238 conform TOTP based on the provided {@link TOTPSpec} and utc time
     * @throws NoSuchAlgorithmException if initialization of the specified hmac algorithm should fail
     * @throws InvalidKeyException if the secret should be unsuitable as a key for the specified hmac algorithm
     * @return the generated OTP. Leading zeros will be filled in to match the {@link TOTPSpec}s length requirement
     * */
    public String generate(@NotNull TOTPSpec spec, long utcTimeMillis) throws NoSuchAlgorithmException, InvalidKeyException {
        long counter = utcTimeMillis / spec.getPeriodMillis();
        return generate(spec, spec.getAlgorithm(), counter);
    }

    private String generate(HOTPSpec spec, TOTPSpec.Algorithm algorithm, long counter) throws NoSuchAlgorithmException, InvalidKeyException {
        String algorithmName = algorithm.getAlgorithmName();
        Mac mac = Mac.getInstance(algorithmName);
        SecretKeySpec keySpec = new SecretKeySpec(spec.getSecret(), algorithmName);
        byte[] counterBytes = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();
        mac.init(keySpec);
        byte[] hmac = mac.doFinal(counterBytes);

        int offset = hmac[hmac.length - 1] & MASK_LOWER_BITS;
        int binaryCode = (hmac[offset] & MASK_OMIT_MSB) << 24
                | (hmac[offset + 1] & MASK_BYTE) << 16
                | (hmac[offset + 2] & MASK_BYTE) << 8
                | (hmac[offset + 3] & MASK_BYTE);

        int otp = binaryCode % (int) Math.pow(10, spec.getLength());
        return String.format("%0" + spec.getLength() + "d", otp);
    }

}
