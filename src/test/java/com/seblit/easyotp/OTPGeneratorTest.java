package com.seblit.easyotp;

import org.junit.Test;

import static org.junit.Assert.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class OTPGeneratorTest {

    private final static byte[] TEST_SECRET = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private final static int TEST_LENGTH = 6;
    private final static int TEST_PERIOD = 30;
    private final static long TEST_UTC_TIME = 9000;
    private final static long TEST_COUNTER = 100;

    private final static String RESULT_HOTP = "358214";
    private final static String RESULT_TOTP_SHA_1 = "957890";

    @Test
    public void testGenerate_hotp() throws NoSuchAlgorithmException, InvalidKeyException {
        HOTPSpec spec = new HOTPSpec(TEST_SECRET, TEST_LENGTH);
        String result = new OTPGenerator().generate(spec, TEST_COUNTER);
        assertEquals(RESULT_HOTP, result);
    }

    @Test
    public void testGenerate_totp() throws NoSuchAlgorithmException, InvalidKeyException {
        TOTPSpec spec = new TOTPSpec(TEST_SECRET, TEST_LENGTH, TOTPSpec.Algorithm.SHA1, TEST_PERIOD);
        String result = new OTPGenerator().generate(spec, TEST_UTC_TIME);
        assertEquals(RESULT_TOTP_SHA_1, result);
    }

    @Test
    public void testGenerate_fillLeadingZero() throws NoSuchAlgorithmException, InvalidKeyException {
        String expectedOTP = "005350";
        HOTPSpec spec = new HOTPSpec(TEST_SECRET, TEST_LENGTH);
        String result = new OTPGenerator().generate(spec, 235);
        assertEquals(expectedOTP, result);
    }

    @Test
    public void testGenerate_algorithmSHA256() throws NoSuchAlgorithmException, InvalidKeyException {
        String expectedOTP = "755289";
        TOTPSpec spec = new TOTPSpec(TEST_SECRET, TEST_LENGTH, TOTPSpec.Algorithm.SHA256, TEST_PERIOD);
        String result = new OTPGenerator().generate(spec, TEST_UTC_TIME);
        assertEquals(expectedOTP, result);
    }

    @Test
    public void testGenerate_algorithmSHA512() throws NoSuchAlgorithmException, InvalidKeyException {
        String expectedOTP = "067078";
        TOTPSpec spec = new TOTPSpec(TEST_SECRET, TEST_LENGTH, TOTPSpec.Algorithm.SHA512, TEST_PERIOD);
        String result = new OTPGenerator().generate(spec, TEST_UTC_TIME);
        assertEquals(expectedOTP, result);
    }

    @Test
    public void testGenerate_customLength() throws NoSuchAlgorithmException, InvalidKeyException {
        String expectedOTP = "87358214";
        HOTPSpec spec = new HOTPSpec(TEST_SECRET, 8);
        String result = new OTPGenerator().generate(spec, TEST_COUNTER);
        assertEquals(expectedOTP, result);
    }

}
