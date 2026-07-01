package io.yvonne.kms;

/**
 * Yvonne KMS 异常。
 */
public class YvonneException extends RuntimeException {
    private final int statusCode;

    public YvonneException(int statusCode, String message) {
        super("Yvonne KMS error (" + statusCode + "): " + message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
