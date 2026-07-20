package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.core.common.AwsException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Exact EC2 user-data bytes after the AWS Query protocol base64 decoding step. */
public final class Ec2UserData {

    public static final int MAX_DECODED_BYTES = 16 * 1024;

    private final String encoded;
    private final byte[] bytes;

    private Ec2UserData(String encoded, byte[] bytes) {
        this.encoded = encoded;
        this.bytes = bytes.clone();
    }

    public static Ec2UserData fromEncoded(String encoded) {
        if (encoded == null) {
            return null;
        }

        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new AwsException("InvalidParameterValue", "UserData is not valid base64 content.", 400);
        }
        validateSize(decoded);
        return new Ec2UserData(encoded, decoded);
    }

    public static Ec2UserData fromBytes(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        validateSize(bytes);
        return new Ec2UserData(Base64.getEncoder().encodeToString(bytes), bytes);
    }

    public static Ec2UserData fromText(String text) {
        return text == null ? null : fromBytes(text.getBytes(StandardCharsets.UTF_8));
    }

    public String encoded() {
        return encoded;
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    public String utf8Text() {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static void validateSize(byte[] bytes) {
        if (bytes.length > MAX_DECODED_BYTES) {
            throw new AwsException("InvalidParameterValue", "User data is limited to 16384 bytes", 400);
        }
    }
}
