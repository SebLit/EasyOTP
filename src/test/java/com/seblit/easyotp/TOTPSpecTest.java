package com.seblit.easyotp;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

public class TOTPSpecTest {
    private final byte[] TEST_SECRET = new byte[16];
    private final int TEST_LENGTH = 6;
    private final int TEST_PERIOD_SECONDS = 30;
    private final long TEST_PERIOD_MILLIS = TEST_PERIOD_SECONDS * 1000L;
    private final TOTPSpec.Algorithm TEST_ALGORITHM = TOTPSpec.Algorithm.SHA512;

    @Before
    public void setup() {
        new SecureRandom().nextBytes(TEST_SECRET);
    }

    @Test
    public void testInit_seconds() {
        TOTPSpec spec = new TOTPSpec(TEST_SECRET, TEST_LENGTH, TEST_ALGORITHM, TEST_PERIOD_SECONDS);
        assertArrayEquals(TEST_SECRET, spec.getSecret());
        assertEquals(TEST_LENGTH, spec.getLength());
        assertEquals(TEST_ALGORITHM, spec.getAlgorithm());
        assertEquals(TEST_PERIOD_SECONDS, spec.getPeriod());
        assertEquals(TEST_PERIOD_MILLIS, spec.getPeriodMillis());
    }

    @Test
    public void testInit_millis() {
        TOTPSpec spec = new TOTPSpec(TEST_SECRET, TEST_LENGTH, TEST_ALGORITHM, TEST_PERIOD_MILLIS);
        assertArrayEquals(TEST_SECRET, spec.getSecret());
        assertEquals(TEST_LENGTH, spec.getLength());
        assertEquals(TEST_ALGORITHM, spec.getAlgorithm());
        assertEquals(TEST_PERIOD_SECONDS, spec.getPeriod());
        assertEquals(TEST_PERIOD_MILLIS, spec.getPeriodMillis());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInit_secretTooSmall() {
        new TOTPSpec(new byte[15], TEST_LENGTH, TEST_ALGORITHM, TEST_PERIOD_SECONDS);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInit_lengthTooSmall() {
        new TOTPSpec(TEST_SECRET, 5, TEST_ALGORITHM, TEST_PERIOD_SECONDS);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInit_lengthTooLarge() {
        new TOTPSpec(TEST_SECRET, 9, TEST_ALGORITHM, TEST_PERIOD_SECONDS);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInit_periodTooSmall() {
        new TOTPSpec(TEST_SECRET, TEST_LENGTH, TEST_ALGORITHM, 0);
    }

    @Test
    public void testEquals() {
        TOTPSpec spec1 = new TOTPSpec(TEST_SECRET, TEST_LENGTH, TEST_ALGORITHM, TEST_PERIOD_SECONDS);
        TOTPSpec spec2 = new TOTPSpec(TEST_SECRET, TEST_LENGTH, TEST_ALGORITHM, TEST_PERIOD_SECONDS);
        TOTPSpec spec3 = new TOTPSpec(TEST_SECRET, 8, TEST_ALGORITHM, TEST_PERIOD_SECONDS);
        TOTPSpec spec4 = new TOTPSpec(new byte[128], TEST_LENGTH, TEST_ALGORITHM, TEST_PERIOD_SECONDS);
        TOTPSpec spec5 = new TOTPSpec(new byte[128], TEST_LENGTH, TOTPSpec.Algorithm.SHA1, TEST_PERIOD_SECONDS);
        TOTPSpec spec6 = new TOTPSpec(new byte[128], TEST_LENGTH, TEST_ALGORITHM, 5);
        assertEquals(spec1, spec2);
        assertNotEquals(spec1, spec3);
        assertNotEquals(spec1, spec4);
        assertNotEquals(spec1, spec5);
        assertNotEquals(spec1, spec6);
    }

}
