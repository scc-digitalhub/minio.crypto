package it.smartcommunitylab.minio.crypto;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MinioSha256 {

    private static final char[] hexDigits = "0123456789abcdef".toCharArray();

    private static final String ALGO = "SHA-256";

    public static String hash(byte[] bytes) throws MinioCryptoException {

        try {
            MessageDigest md = MessageDigest.getInstance(ALGO);

            md.update(bytes);
            md.getDigestLength();

            return bytesToHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new MinioCryptoException(e.getMessage());
        }
    }

    public static String hash(String value, Charset charset) throws MinioCryptoException {
        try {
            MessageDigest md = MessageDigest.getInstance(ALGO);
            byte[] bytes = value.getBytes(charset);
            md.update(bytes);
            md.getDigestLength();
            return bytesToHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new MinioCryptoException(e.getMessage());
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            sb.append(hexDigits[(b >> 4) & 0xf]).append(hexDigits[b & 0xf]);
        }
        return sb.toString();
    }
}
