package it.smartcommunitylab.minio.crypto;

public class MinioCryptoException extends Exception {

    private static final long serialVersionUID = -7450996938221130042L;

    public MinioCryptoException() {
        super();
    }

    public MinioCryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public MinioCryptoException(String message) {
        super(message);
    }

    public MinioCryptoException(Throwable cause) {
        super(cause);
    }
}
