package it.smartcommunitylab.minio.crypto.v3;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import it.smartcommunitylab.minio.crypto.MinioCryptoException;

public class MinioEncrypter extends MinioCryptoBase {

    public MinioEncrypter(String password) {
        super(password);
    }

    /*
     * Crypto
     */

    public byte[] encrypt(final byte[] data) throws MinioCryptoException {
        try {
            /*
             * Init crypto data
             */

            byte[] salt = secureRandom(SALT_SIZE);
            byte[] nonce = secureRandom(NONCE_SIZE);

            // we always use AES
            byte[] cipher = new byte[1];
            cipher[0] = AES_256_GCM;

            // build byte buffer to store result
            // ciphertext = salt || AEAD ID | nonce | encrypted data
            // encrypted data length is plain data length + (tag size for 1 block aes aead)
            int clen = salt.length + 1 + nonce.length + data.length + overhead(AES_256_GCM, data.length);

            ByteBuffer ciphertext = ByteBuffer.allocate(clen);
            // Prefix the ciphertext with salt, AEAD ID and nonce
            ciphertext.put(salt);
            ciphertext.put(cipher);
            ciphertext.put(nonce);

            /*
             * Init AES
             */
            byte[] idkey = deriveKey(salt);
            SecretKey aesKey = new SecretKeySpec(idkey, 0, idkey.length, "AES");

            // derive AAD via custom secure-io scheme
            byte[] aad = deriveAAD(idkey, nonce);

            // all packets in stream have header = 0x00
            // last packet in a stream has 0x80 to avoid truncation attacks
            // we do not support multiple fragments
            if (data.length < BUF_SIZE) {
                // put here 0x80 since packet size is by default 16k our message is less
                aad[0] = (byte) 0x80;

                Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");

                // sequence number starts from 1
                // we will send only a single fragment here
                byte[] iv = deriveIV(nonce, 1);

                // init GCM with tag
                GCMParameterSpec spec = new GCMParameterSpec(Byte.SIZE * TAG_SIZE, iv);
                gcm.init(Cipher.ENCRYPT_MODE, aesKey, spec);

                // add derived complete AAD (with header!)
                gcm.updateAAD(aad);
                // add data which contains plaintext and
                // derive ciphertext (contains auth tag)
                // NOTE: we need to add plaintext to doFinal, do not use update()
                byte[] ctext = gcm.doFinal(data);

                // if we got the math right, buffer will contain exactly the cipher output
                ciphertext.put(ctext);

            } else {
                throw new MinioCryptoException("data too large");
            }

            ciphertext.position(0);
            return ciphertext.array();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            throw new MinioCryptoException(e.getMessage(), e.getCause());
        }

    }

}
