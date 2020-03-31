package it.smartcommunitylab.minio.crypto.v3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

public class MinioDecrypter extends MinioCryptoBase {

    protected MinioDecrypter(String password) {
        super(password);
    }

    /*
     * Crypto
     */

    public byte[] decrypt(final byte[] raw) throws MinioCryptoException {
        try {
            /*
             * Extract crypto data
             */
            byte[] salt = new byte[SALT_SIZE];
            byte[] cipher = new byte[1];
            byte[] nonce = new byte[NONCE_SIZE];

            // read packet
            ByteArrayInputStream is = new ByteArrayInputStream(raw);

            // ciphertext = salt || AEAD ID | nonce | encrypted data
            // encrypted data length is plain data length + (tag size for 1 block aes aead)
            is.read(salt);
            is.read(cipher);
            is.read(nonce);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int next = is.read();
            while (next > -1) {
                bos.write(next);
                next = is.read();
            }
            bos.flush();
            byte[] data = bos.toByteArray();

            // cleanup
            bos.close();
            is.close();

            // decrypt
            if (cipher[0] == AES_256_GCM) {

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
                // put here 0x80 since packet size is by default 16k our message is less
                aad[0] = (byte) 0x80;

                Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");

                // sequence number starts from 1
                // we support only a single fragment here
                byte[] iv = deriveIV(nonce, 1);

                // init GCM with tag
                GCMParameterSpec spec = new GCMParameterSpec(Byte.SIZE * TAG_SIZE, iv);
                gcm.init(Cipher.DECRYPT_MODE, aesKey, spec);

                // add derived complete AAD (with header!)
                gcm.updateAAD(aad);
                // add data which contains ciphertext (with auth tag!)
                gcm.update(data);
                // derive plaintext
                byte[] plaintext = gcm.doFinal();

                return plaintext;

            } else {
                // we do not support chachapoly now
                throw new MinioCryptoException("unsupported cipher " + String.valueOf(cipher[0]));
            }

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | IOException e) {
            e.printStackTrace();
            throw new MinioCryptoException(e.getMessage(), e.getCause());
        }

    }
}
