# EasyOTP
A Generator for HOTPs conform to [RFC4226](https://www.rfc-editor.org/info/rfc4226) and TOTPs conform to [RFC6238](https://www.rfc-editor.org/info/rfc6238) including a TOTP Runnable for continuous time based generation.

## Generator
```OTPGenerator``` generates OTPs based on an OTP specification (see Specs below) and a progression value. For furhter Details on OTP calculation, see RFC4226 section #5 RFC4226 and RFC6238 section #4 TOTP Algorithm
~~~
long progressionValue = 0; // counter for HOTP or timestamp for TOTP
OTPGenerator generator = new OTPGenerator();
String otp = generator.generate(spec, progressionValue);
~~~

## Specs
```HOTPSpec``` specifies the necessary information an OTPGenerator requires for generating HTOPs for any given OTP counter.
~~~
byte[] secret = ...; // secret used as key for hmac calculation
int length = 6; // character count of the generated otp
HOTPSpec spec = new HOTPSpec(secret, length);
~~~

```TOTPSpec``` extends ```HOTPSpec``` and additionally specifies the nesessary information for generating TOTPs for any given UTC timestamp.
~~~
int period = 30; // otp validity period, use long to define in millis
TOTPSpec.Algorithm algorithm = TOTPSpec.Algorithm.SHA512; // Support for SHA1, SHA256 and SHA512
TOTPSpec totpSpec = new TOTPSpec(secret, length, algorithm, period);
~~~

## TOTPRunnable
```TOTPRunnable``` continuously generates TOTPs based on its spec and the systems time. Notifies its ```Callback``` for each generated OTP. Optionally an ```ErrorCallback``` can be provided to handle errors during generation.
~~~
TOTPRunnable.Callback callback = (totp, spec, utcTimestamp) -> {
  // process new otp
};
TOTPRunnable.ErrorCallback errorCallback = (error, spec, utcTimestamp) -> {
  // handle error
  return false; // decide whether to cancel runnable or try again
};
TOTPRunnable runnable = new TOTPRunnable(spec, callback, errorCallback);
new Thread(runnable).start();
...
runnable.cancel(); // call to shutdown generation
~~~
