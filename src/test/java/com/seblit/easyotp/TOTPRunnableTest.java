package com.seblit.easyotp;


import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

public class TOTPRunnableTest {

    private static final String TEST_OTP = "someOTP";

    private TOTPSpec mockedSpec;
    private TOTPRunnable.Callback mockedCallback;
    private TOTPRunnable.ErrorCallback mockedErrorCallback;
    private OTPGenerator mockedGenerator;

    @Before
    public void setup() throws NoSuchAlgorithmException, InvalidKeyException {
        mockedCallback = mock(TOTPRunnable.Callback.class);
        mockedErrorCallback = mock(TOTPRunnable.ErrorCallback.class);
        mockedGenerator = mock(OTPGenerator.class);
        mockedSpec = mock(TOTPSpec.class);
        when(mockedSpec.getPeriodMillis()).thenReturn(1000L);
        when(mockedGenerator.generate(same(mockedSpec), anyLong())).thenReturn(TEST_OTP);
    }

    @Test
    public void testRun() throws InterruptedException {
        ArgumentCaptor<String> otpCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<TOTPSpec> specCaptor = ArgumentCaptor.forClass(TOTPSpec.class);
        TOTPRunnable runnable = new TOTPRunnable(mockedSpec, mockedCallback, mockedErrorCallback, mockedGenerator);
        doAnswer(invocationOnMock -> {
            runnable.cancel();
            return null;
        }).when(mockedCallback).onOTPChanged(otpCaptor.capture(), specCaptor.capture(), anyLong());

        executeAndWait(runnable);

        assertEquals(TEST_OTP, otpCaptor.getValue());
        assertEquals(mockedSpec, specCaptor.getValue());
    }

    @Test
    public void testCancel() throws InterruptedException {
        TOTPRunnable runnable = new TOTPRunnable(mockedSpec, mockedCallback, mockedErrorCallback, mockedGenerator);
        doAnswer(invocationOnMock -> {
            runnable.cancel();
            return null;
        }).when(mockedCallback).onOTPChanged(any(String.class), same(mockedSpec), anyLong());

        executeAndWait(runnable);

        verify(mockedCallback, times(1)).onOTPChanged(any(String.class), any(TOTPSpec.class), anyLong());

        reset(mockedCallback);
        executeAndWait(runnable);

        verify(mockedCallback, never()).onOTPChanged(any(String.class), any(TOTPSpec.class), anyLong());
    }

    @Test
    public void testCallback_multiple() throws InterruptedException {
        TOTPRunnable runnable = new TOTPRunnable(mockedSpec, mockedCallback, mockedErrorCallback, mockedGenerator);
        doAnswer(invocationOnMock -> {
            doAnswer(invocationOnMock1 -> {
                runnable.cancel();
                return null;
            }).when(mockedCallback).onOTPChanged(any(String.class), same(mockedSpec), anyLong());
            return null;
        }).when(mockedCallback).onOTPChanged(any(String.class), same(mockedSpec), anyLong());

        executeAndWait(runnable);

        verify(mockedCallback, times(2)).onOTPChanged(any(String.class), same(mockedSpec), anyLong());
    }

    @Test
    public void testErrorCallback_none() throws NoSuchAlgorithmException, InvalidKeyException, InterruptedException {
        when(mockedGenerator.generate(same(mockedSpec), anyLong())).thenThrow(NoSuchAlgorithmException.class);
        TOTPRunnable runnable = new TOTPRunnable(mockedSpec, mockedCallback, null, mockedGenerator);
        Thread t = new Thread(() -> {
            try {
                runnable.run();
                fail();
            } catch (RuntimeException ex) {
                assertEquals(RuntimeException.class, ex.getClass());
            }
        });

        t.start();
        t.join();
    }

    @Test
    public void testErrorCallback_true() throws NoSuchAlgorithmException, InvalidKeyException, InterruptedException {
        when(mockedErrorCallback.onError(any(Throwable.class), any(TOTPSpec.class), anyLong())).thenReturn(true);
        when(mockedGenerator.generate(same(mockedSpec), anyLong())).thenThrow(NoSuchAlgorithmException.class);
        TOTPRunnable runnable = new TOTPRunnable(mockedSpec, mockedCallback, mockedErrorCallback, mockedGenerator);
        Thread t = new Thread(() -> {
            try {
                runnable.run();
            } catch (RuntimeException ex) {
                fail();
            }
        });

        t.start();
        t.join();
    }

    private void executeAndWait(TOTPRunnable runnable) throws InterruptedException {
        Thread t = new Thread(runnable);
        t.start();
        t.join();
    }

}
