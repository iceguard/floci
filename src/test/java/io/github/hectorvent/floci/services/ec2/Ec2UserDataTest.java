package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.core.common.AwsException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Ec2UserDataTest {

    @Test
    void distinguishesAbsentFromPresentEmpty() {
        assertNull(Ec2UserData.fromEncoded(null));

        Ec2UserData empty = Ec2UserData.fromEncoded("");
        assertEquals("", empty.encoded());
        assertArrayEquals(new byte[0], empty.bytes());
    }

    @Test
    void preservesOriginalEncodingAndArbitraryDecodedBytes() {
        byte[] bytes = new byte[]{0x1f, (byte) 0x8b, 0x00, (byte) 0xff};
        String encoded = Base64.getEncoder().encodeToString(bytes);

        Ec2UserData userData = Ec2UserData.fromEncoded(encoded);

        assertEquals(encoded, userData.encoded());
        assertArrayEquals(bytes, userData.bytes());
        byte[] returned = userData.bytes();
        returned[0] = 0;
        assertArrayEquals(bytes, userData.bytes());
    }

    @Test
    void doesNotDecompressGzipAtAdmission() {
        byte[] invalidGzip = new byte[]{0x1f, (byte) 0x8b, 0x00, (byte) 0xff};

        Ec2UserData userData = Ec2UserData.fromEncoded(
                Base64.getEncoder().encodeToString(invalidGzip));

        assertArrayEquals(invalidGzip, userData.bytes());
    }

    @Test
    void acceptsExactlySixteenKibibytes() {
        byte[] bytes = new byte[Ec2UserData.MAX_DECODED_BYTES];
        Arrays.fill(bytes, (byte) 'a');

        Ec2UserData userData = Ec2UserData.fromEncoded(Base64.getEncoder().encodeToString(bytes));

        assertEquals(Ec2UserData.MAX_DECODED_BYTES, userData.bytes().length);
    }

    @Test
    void rejectsDecodedValueLargerThanSixteenKibibytes() {
        AwsException error = assertThrows(AwsException.class, () -> Ec2UserData.fromEncoded(
                Base64.getEncoder().encodeToString(new byte[Ec2UserData.MAX_DECODED_BYTES + 1])));

        assertEquals("InvalidParameterValue", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
        assertEquals("User data is limited to 16384 bytes", error.getMessage());
    }

    @Test
    void rejectsMalformedBase64WithEc2ErrorShape() {
        AwsException error = assertThrows(AwsException.class,
                () -> Ec2UserData.fromEncoded("not-valid-base64"));

        assertEquals("InvalidParameterValue", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
        assertEquals("UserData is not valid base64 content.", error.getMessage());
    }

    @Test
    void textFactoryUsesUtf8BytesForInternalCallers() {
        String text = "#!/bin/sh\necho exact\n";

        assertArrayEquals(text.getBytes(StandardCharsets.UTF_8), Ec2UserData.fromText(text).bytes());
    }
}
