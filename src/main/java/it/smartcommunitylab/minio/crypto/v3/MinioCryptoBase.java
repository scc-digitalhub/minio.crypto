package it.smartcommunitylab.minio.crypto.v3;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static com.kosprov.jargon2.api.Jargon2.jargon2Hasher;
import com.kosprov.jargon2.api.Jargon2.Hasher;
import com.kosprov.jargon2.api.Jargon2.Type;

import it.smartcommunitylab.minio.crypto.MinioCryptoException;

public abstract class MinioCryptoBase {

    // salt for password
    public static final int SALT_SIZE = 32;
    // nonce for IV: base part, additional 4 bytes are derived from block sequence
    public static final int NONCE_SIZE = 8;
    // tag size for both ciphers
    public static final int TAG_SIZE = 16;
    // buffer size for stream based
    public static final int BUF_SIZE = 16 * 1024;

    // cipher
    public final static byte AES_256_GCM = (byte) 0x00;
    public final static byte ChaCha20Poly1305 = (byte) 0x01;

    protected final String password;

    protected MinioCryptoBase(String p) {
        password = p;
    }

    /*
     * Crypto
     */

    public byte[] deriveKey(byte[] salt) {
        // derive key from password with salt
        Hasher hasher = jargon2Hasher()
                .type(Type.ARGON2id) // Data-dependent hashing
                .memoryCost(65536) // 64MB memory cost
                .timeCost(1) // 3 passes through memory
                .parallelism(4) // use 4 lanes and 4 threads
                .hashLength(32); //

        return hasher.salt(salt).password(password.getBytes()).rawHash();
    }

    public byte[] deriveIV(byte[] nonce, int seqNum) {
        // we need 12 bytes of IV
        byte[] iv = makeByteArray(NONCE_SIZE + 4);

        // copy first 8 bytes
        System.arraycopy(nonce, 0, iv, 0, NONCE_SIZE);

        // build next 4 bytes
        // seqNum is 0 (zero) for AAD
        // 1...N for data fragments
        // NOTE byte order is little endian!!
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(seqNum);
        bb.position(0);

        // complete 12 byte IV for AAD derivation
        System.arraycopy(bb.array(), 0, iv, NONCE_SIZE, 4);

        return iv;
    }

    public byte[] deriveAAD(byte[] idkey, byte[] nonce) throws MinioCryptoException {
        try {
            /*
             * Derive additional data for AES
             */
            SecretKey aesKey = new SecretKeySpec(idkey, 0, idkey.length, "AES");

            Cipher ctr = Cipher.getInstance("AES/GCM/NoPadding");

            // derive AAD From nonce (8 bytes):
            // append seq = 0 as littlendian => obtain iv
            byte[] iv = deriveIV(nonce, 0);

            // for AAD derivation => encrypt null aad + null content + iv
            // => obtain AAD for encrypt/decrypt

            // init GCM with iv for this block
            GCMParameterSpec cspec = new GCMParameterSpec(Byte.SIZE * TAG_SIZE, iv);
            ctr.init(Cipher.ENCRYPT_MODE, aesKey, cspec);
            // derive AAD as output
            byte[] re = ctr.doFinal();

            // build complete AAD for enc/dec as header byte + derived AAD
            ByteBuffer bba = ByteBuffer.allocate(1 + TAG_SIZE);
            // all packets in stream have header = 0x00
            // last packet in a stream has 0x80 to avoid truncation attacks
            // we need to overwrite this byte later
            bba.put((byte) 0x00);
            bba.put(re);
            bba.position(0);
            // derive complete AAD
            byte[] aad = bba.array();

            return aad;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            throw new MinioCryptoException(e.getMessage(), e.getCause());
        }

    }

    /*
     * Helpers
     */
    protected byte[] secureRandom(int size) {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[size];
        random.nextBytes(bytes);

        return bytes;
    }

    protected byte[] makeByteArray(int size) {
        byte[] arr = new byte[size];
        for (int i = 0; i < arr.length; i++) {
            // initialize to zero
            arr[i] = (byte) 0x00;
        }

        return arr;
    }

    protected int overhead(byte cipher, int size) {
        if (size < 0) {
            return -1;
        }

        int overhead = 0;

        // we support only AES
        if (cipher == AES_256_GCM) {
            overhead = TAG_SIZE;
        }

        if (size > BUF_SIZE) {
            // TODO
            // stream will be segmented
            // we need to calculate number of packets and add overhead to each, plus one
            // overhead for final
            // go code
            // t := size / bufSize
            // if r := size % bufSize; r > 0 {
            // return (t * overhead) + overhead
            // }
        }

        return overhead;

    }

}
