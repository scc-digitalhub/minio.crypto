package it.smartcommunitylab.minio.crypto.v3;

import it.smartcommunitylab.minio.crypto.MinioCryptoException;

public class MinioCrypto {
    /*
     * Factories
     */

    public static MinioDecrypter getDecrypter(String secretKey) throws MinioCryptoException {
        return new MinioDecrypter(secretKey);
    }

    public static MinioEncrypter getEncrypter(String secretKey) throws MinioCryptoException {
        return new MinioEncrypter(secretKey);
    }
}
