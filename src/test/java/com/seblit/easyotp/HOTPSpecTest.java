package com.seblit.easyotp;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

public class HOTPSpecTest {

    private final byte[] TEST_SECRET = new byte[16];
    private final int TEST_LENGTH = 6;

    @Before
    public void setup() {
        new SecureRandom().nextBytes(TEST_SECRET);
    }

    @Test
    public void testInit() {
        HOTPSpec spec = new HOTPSpec(TEST_SECRET, TEST_LENGTH);
        assertArrayEquals(TEST_SECRET, spec.getSecret());
        assertEquals(TEST_LENGTH, spec.getLength());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInit_secretTooSmall() {
        new HOTPSpec(new byte[15], TEST_LENGTH);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInit_lengthTooSmall() {
        new HOTPSpec(TEST_SECRET, 5);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInit_lengthTooLarge() {
        new HOTPSpec(TEST_SECRET, 9);
    }

    @Test
    public void testEquals() {
        HOTPSpec spec1 = new HOTPSpec(TEST_SECRET, TEST_LENGTH);
        HOTPSpec spec2 = new HOTPSpec(TEST_SECRET, TEST_LENGTH);
        HOTPSpec spec3 = new HOTPSpec(TEST_SECRET, 8);
        HOTPSpec spec4 = new HOTPSpec(new byte[128], TEST_LENGTH);
        assertEquals(spec1, spec2);
        assertNotEquals(spec1, spec3);
        assertNotEquals(spec1, spec4);
    }

}
