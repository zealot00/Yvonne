package io.yvonne.kms;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Yvonne KMS Java SDK 客户端。
 *
 * 支持：重试、熔断、trace_id 透传、超时。
 *
 * 用法：
 * <pre>
 * YvonneClient client = YvonneClient.builder()
 *     .baseUrl("https://kms.internal:8200")
 *     .token("admin-token")
 *     .timeout(Duration.ofSeconds(30))
 *     .retry(RetryConfig.defaultConfig())
 *     .circuitBreaker(CircuitBreaker.defaultBreaker())
 *     .traceIdHeader("X-Request-ID")
 *     .build();
 *
 * JsonObject enc = client.encrypt("order-key", "hello".getBytes());
 * String ciphertext = enc.getAsJsonObject("data").get("ciphertext").getAsString();
 * </pre>
 */
public class YvonneClient {

    private final String baseUrl;
    private final String token;
    private final HttpClient httpClient;
    private final Duration timeout;
    private final RetryConfig retryConfig;
    private final CircuitBreaker circuitBreaker;
    private final String traceIdHeader;
    private final Gson gson = new Gson();

    private YvonneClient(Builder builder) {
        this.baseUrl = builder.baseUrl.replaceAll("/$", "");
        this.token = builder.token;
        this.timeout = builder.timeout;
        this.retryConfig = builder.retryConfig;
        this.circuitBreaker = builder.circuitBreaker;
        this.traceIdHeader = builder.traceIdHeader;

        HttpClient.Builder hb = HttpClient.newBuilder()
            .connectTimeout(timeout);
        this.httpClient = hb.build();
    }

    // === 系统 ===

    public JsonObject health() throws YvonneException {
        return request("GET", "/api/v1/sys/health", null);
    }

    // === 密钥管理 ===

    public JsonObject createKey(String keyId) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("key_id", keyId);
        return request("POST", "/api/v1/keys", body);
    }

    public JsonObject createAsymmetricKey(String keyId, String keyType) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("key_id", keyId);
        body.put("key_type", keyType);
        return request("POST", "/api/v1/keys/asymmetric", body);
    }

    public JsonObject rotateKey(String keyId) throws YvonneException {
        return request("POST", "/api/v1/keys/" + keyId + "/rotate", null);
    }

    public JsonObject shredKey(String keyId, int version) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("version", version);
        return request("DELETE", "/api/v1/keys/" + keyId + "/shred", body);
    }

    public JsonObject getPublicKey(String keyId) throws YvonneException {
        return request("GET", "/api/v1/keys/public-key?key_id=" + keyId, null);
    }

    public JsonObject generateDataKey(String keyId) throws YvonneException {
        return request("POST", "/api/v1/keys/" + keyId + "/generate-data-key", null);
    }

    public JsonObject generateDataKeyWithoutPlaintext(String keyId) throws YvonneException {
        return request("POST", "/api/v1/keys/gdk-no-plaintext?key_id=" + keyId, null);
    }

    // === 密码运算 ===

    public JsonObject encrypt(String keyId, byte[] plaintext) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("key_id", keyId);
        body.put("plaintext", Base64.getEncoder().encodeToString(plaintext));
        return request("POST", "/api/v1/encrypt", body);
    }

    public JsonObject decrypt(String keyId, String ciphertextBase64) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("key_id", keyId);
        body.put("ciphertext", ciphertextBase64);
        return request("POST", "/api/v1/decrypt", body);
    }

    public JsonObject sign(String keyId, byte[] data) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("key_id", keyId);
        body.put("data", Base64.getEncoder().encodeToString(data));
        return request("POST", "/api/v1/sign", body);
    }

    public JsonObject verify(String keyId, byte[] data, String signatureBase64) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("key_id", keyId);
        body.put("data", Base64.getEncoder().encodeToString(data));
        body.put("signature", signatureBase64);
        return request("POST", "/api/v1/verify", body);
    }

    public JsonObject generateMac(String keyId, byte[] data) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("key_id", keyId);
        body.put("data", Base64.getEncoder().encodeToString(data));
        return request("POST", "/api/v1/mac/generate", body);
    }

    public JsonObject verifyMac(String keyId, byte[] data, String macBase64) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("key_id", keyId);
        body.put("data", Base64.getEncoder().encodeToString(data));
        body.put("mac", macBase64);
        return request("POST", "/api/v1/mac/verify", body);
    }

    public JsonObject reEncrypt(String sourceKeyId, String destKeyId, String ciphertextBase64) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("source_key_id", sourceKeyId);
        body.put("dest_key_id", destKeyId);
        body.put("ciphertext", ciphertextBase64);
        return request("POST", "/api/v1/re-encrypt", body);
    }

    // === BYOK ===

    public JsonObject transitPub() throws YvonneException {
        return request("GET", "/api/v1/keys/transit-pub", null);
    }

    // === MFA ===

    public JsonObject mfaSetup(String roleId) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("role_id", roleId);
        return request("POST", "/api/v1/auth/mfa/setup", body);
    }

    public JsonObject mfaVerify(String roleId, String code) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("role_id", roleId);
        body.put("code", code);
        return request("POST", "/api/v1/auth/mfa/verify", body);
    }

    // === Quorum ===

    public JsonObject createApproval(String operation, String keyId, int required, int ttlHours) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("operation", operation);
        body.put("key_id", keyId);
        body.put("required", required);
        body.put("ttl_hours", ttlHours);
        return request("POST", "/api/v1/approvals", body);
    }

    public JsonObject approveTicket(String ticketId) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("ticket_id", ticketId);
        return request("POST", "/api/v1/approvals/approve", body);
    }

    public JsonObject rejectTicket(String ticketId) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("ticket_id", ticketId);
        return request("POST", "/api/v1/approvals/reject", body);
    }

    public JsonObject listApprovals() throws YvonneException {
        return request("GET", "/api/v1/approvals", null);
    }

    // === 审计 ===

    public JsonObject auditQuery(int limit) throws YvonneException {
        Map<String, Object> body = new HashMap<>();
        body.put("limit", limit);
        return request("POST", "/api/v1/audit/query", body);
    }

    // === 内部 HTTP 请求 ===

    private JsonObject request(String method, String path, Object body) throws YvonneException {
        // 熔断检查。
        if (circuitBreaker != null && !circuitBreaker.allow()) {
            throw new YvonneException(503, "circuit breaker is open");
        }

        int maxRetries = (retryConfig != null) ? retryConfig.getMaxRetries() : 0;
        YvonneException lastErr = null;

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            if (attempt > 0) {
                try {
                    Thread.sleep(retryConfig.calculateBackoff(attempt).toMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new YvonneException(500, "interrupted during retry backoff");
                }
            }

            try {
                JsonObject resp = doRequest(method, path, body);

                // 成功：重置熔断器。
                if (circuitBreaker != null) {
                    circuitBreaker.recordSuccess();
                }
                return resp;

            } catch (YvonneException e) {
                lastErr = e;

                // 检查是否可重试。
                boolean retryable = false;
                if (retryConfig != null && retryConfig.isRetryable(e.getStatusCode())) {
                    retryable = true;
                } else if (e.getStatusCode() == 0) {
                    // 网络错误。
                    retryable = true;
                }

                if (!retryable || attempt >= maxRetries) {
                    if (circuitBreaker != null) {
                        circuitBreaker.recordFailure();
                    }
                    throw e;
                }

                // 记录失败。
                if (circuitBreaker != null) {
                    circuitBreaker.recordFailure();
                }
            }
        }

        throw lastErr != null ? lastErr : new YvonneException(500, "max retries exceeded");
    }

    private JsonObject doRequest(String method, String path, Object body) throws YvonneException {
        try {
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(timeout);

            // 认证。
            if (token != null && !token.isEmpty()) {
                reqBuilder.header("Authorization", "Bearer " + token);
            }

            // trace_id 透传。
            if (traceIdHeader != null && !traceIdHeader.isEmpty()) {
                reqBuilder.header(traceIdHeader, TraceIdUtil.generate());
            }

            // 请求体。
            if (body != null) {
                String jsonBody = gson.toJson(body);
                reqBuilder.header("Content-Type", "application/json");
                reqBuilder.method(method, HttpRequest.BodyPublishers.ofString(jsonBody));
            } else {
                reqBuilder.method(method, HttpRequest.BodyPublishers.noBody());
            }

            HttpResponse<String> response = httpClient.send(
                reqBuilder.build(),
                HttpResponse.BodyHandlers.ofString()
            );

            if (response.statusCode() >= 400) {
                String errMsg;
                try {
                    JsonObject errJson = JsonParser.parseString(response.body()).getAsJsonObject();
                    errMsg = errJson.has("error") ? errJson.get("error").getAsString() : response.body();
                } catch (Exception e) {
                    errMsg = response.body();
                }
                throw new YvonneException(response.statusCode(), errMsg);
            }

            return JsonParser.parseString(response.body()).getAsJsonObject();

        } catch (IOException e) {
            throw new YvonneException(0, "network error: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new YvonneException(0, "interrupted");
        }
    }

    // === Builder ===

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String baseUrl;
        private String token = "";
        private Duration timeout = Duration.ofSeconds(30);
        private RetryConfig retryConfig;
        private CircuitBreaker circuitBreaker;
        private String traceIdHeader;

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder token(String token) {
            this.token = token;
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder retry(RetryConfig retryConfig) {
            this.retryConfig = retryConfig;
            return this;
        }

        public Builder circuitBreaker(CircuitBreaker circuitBreaker) {
            this.circuitBreaker = circuitBreaker;
            return this;
        }

        public Builder traceIdHeader(String header) {
            this.traceIdHeader = header;
            return this;
        }

        public YvonneClient build() {
            if (baseUrl == null || baseUrl.isEmpty()) {
                throw new IllegalArgumentException("baseUrl is required");
            }
            return new YvonneClient(this);
        }
    }
}
