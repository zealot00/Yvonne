package io.yvonne.kms;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Java SDK 全功能集成测试（模拟 HTTP 服务端）。
 */
class YvonneClientIntegrationTest {

    private HttpServer server;
    private final AtomicInteger callCount = new AtomicInteger(0);
    private final AtomicReference<String> lastPath = new AtomicReference<>("");
    private final AtomicReference<String> lastMethod = new AtomicReference<>("");

    @org.junit.jupiter.api.BeforeEach
    void setUp() throws IOException {
        callCount.set(0);
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", this::handleRequest);
        server.start();
    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() {
        server.stop(0);
    }

    private void handleRequest(HttpExchange exchange) throws IOException {
        callCount.incrementAndGet();
        lastPath.set(exchange.getRequestURI().getPath());
        lastMethod.set(exchange.getRequestMethod());

        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        String body = "{}";
        int status = 200;

        // 路由模拟。
        if (path.equals("/api/v1/sys/health") && method.equals("GET")) {
            body = "{\"ok\":true,\"data\":{\"sealed\":false,\"state\":\"unsealed\",\"status\":\"alive\"}}";
        } else if (path.equals("/api/v1/keys") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"key_id\":\"test-key\",\"version\":1}}";
        } else if (path.equals("/api/v1/keys/asymmetric") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"key_id\":\"test-rsa\",\"version\":1,\"key_type\":\"rsa\",\"public_key\":\"PEM...\"}}";
        } else if (path.contains("/rotate") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"version\":2}}";
        } else if (path.equals("/api/v1/encrypt") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"ciphertext\":\"AAAA12345\",\"version\":1}}";
        } else if (path.equals("/api/v1/decrypt") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"plaintext\":\"" + Base64.getEncoder().encodeToString("test".getBytes()) + "\",\"version\":1}}";
        } else if (path.equals("/api/v1/sign") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"signature\":\"sig123\",\"version\":1}}";
        } else if (path.equals("/api/v1/verify") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"valid\":true,\"version\":1}}";
        } else if (path.equals("/api/v1/mac/generate") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"mac\":\"mac123\",\"version\":1}}";
        } else if (path.equals("/api/v1/mac/verify") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"valid\":true,\"version\":1}}";
        } else if (path.equals("/api/v1/re-encrypt") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"ciphertext\":\"AAAA67890\",\"version\":1}}";
        } else if (path.equals("/api/v1/keys/transit-pub") && method.equals("GET")) {
            body = "{\"ok\":true,\"data\":{\"transit_key_id\":\"t-1\",\"public_key\":\"PEM...\"}}";
        } else if (path.equals("/api/v1/keys/public-key") && method.equals("GET")) {
            body = "{\"ok\":true,\"data\":{\"public_key\":\"PEM...\",\"version\":1}}";
        } else if (path.equals("/api/v1/keys/gdk-no-plaintext") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"ciphertext\":\"AAAA11111\"}}";
        } else if (path.contains("/generate-data-key") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"plaintext_dek\":\"dek123\",\"ciphertext_dek\":\"AAAA22222\"}}";
        } else if (path.equals("/api/v1/auth/mfa/setup") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"secret\":\"JBSWY3DPEHPK3PXP\",\"uri\":\"otpauth://...\"}}";
        } else if (path.equals("/api/v1/auth/mfa/verify") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"enabled\":true}}";
        } else if (path.equals("/api/v1/approvals") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"id\":\"ticket-1\",\"status\":\"pending\"}}";
        } else if (path.equals("/api/v1/approvals/approve") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"status\":\"approved\"}}";
        } else if (path.equals("/api/v1/approvals/reject") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"status\":\"rejected\"}}";
        } else if (path.equals("/api/v1/approvals") && method.equals("GET")) {
            body = "{\"ok\":true,\"data\":{\"count\":1,\"tickets\":[]}}";
        } else if (path.equals("/api/v1/audit/query") && method.equals("POST")) {
            body = "{\"ok\":true,\"data\":{\"count\":0,\"entries\":[]}}";
        } else if (method.equals("DELETE")) {
            body = "{\"ok\":true,\"data\":{\"shred\":true}}";
        } else {
            status = 404;
            body = "{\"ok\":false,\"error\":\"not found\"}";
        }

        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body.getBytes());
        }
    }

    private YvonneClient client() {
        return YvonneClient.builder()
            .baseUrl("http://localhost:" + server.getAddress().getPort())
            .token("test-token")
            .build();
    }

    @org.junit.jupiter.api.Test
    void testHealth() throws YvonneException {
        var resp = client().health();
        assertTrue(resp.get("ok").getAsBoolean());
        assertEquals("unsealed", resp.getAsJsonObject("data").get("state").getAsString());
    }

    @org.junit.jupiter.api.Test
    void testCreateKey() throws YvonneException {
        var resp = client().createKey("test-key");
        assertEquals("test-key", resp.getAsJsonObject("data").get("key_id").getAsString());
    }

    @org.junit.jupiter.api.Test
    void testCreateAsymmetricKey() throws YvonneException {
        var resp = client().createAsymmetricKey("test-rsa", "rsa");
        assertEquals("rsa", resp.getAsJsonObject("data").get("key_type").getAsString());
    }

    @org.junit.jupiter.api.Test
    void testRotateKey() throws YvonneException {
        var resp = client().rotateKey("test-key");
        assertEquals(2, resp.getAsJsonObject("data").get("version").getAsInt());
    }

    @org.junit.jupiter.api.Test
    void testShredKey() throws YvonneException {
        var resp = client().shredKey("test-key", 1);
        assertTrue(resp.getAsJsonObject("data").get("shred").getAsBoolean());
    }

    @org.junit.jupiter.api.Test
    void testGetPublicKey() throws YvonneException {
        var resp = client().getPublicKey("test-rsa");
        assertNotNull(resp.getAsJsonObject("data").get("public_key"));
    }

    @org.junit.jupiter.api.Test
    void testGenerateDataKey() throws YvonneException {
        var resp = client().generateDataKey("test-key");
        assertNotNull(resp.getAsJsonObject("data").get("plaintext_dek"));
        assertNotNull(resp.getAsJsonObject("data").get("ciphertext_dek"));
    }

    @org.junit.jupiter.api.Test
    void testGenerateDataKeyWithoutPlaintext() throws YvonneException {
        var resp = client().generateDataKeyWithoutPlaintext("test-key");
        assertNotNull(resp.getAsJsonObject("data").get("ciphertext"));
    }

    @org.junit.jupiter.api.Test
    void testEncryptDecrypt() throws YvonneException {
        var enc = client().encrypt("test-key", "hello".getBytes());
        String ct = enc.getAsJsonObject("data").get("ciphertext").getAsString();
        assertNotNull(ct);

        var dec = client().decrypt("test-key", ct);
        byte[] pt = Base64.getDecoder().decode(dec.getAsJsonObject("data").get("plaintext").getAsString());
        assertEquals("test", new String(pt));
    }

    @org.junit.jupiter.api.Test
    void testSignVerify() throws YvonneException {
        var sig = client().sign("test-rsa", "data".getBytes());
        String signature = sig.getAsJsonObject("data").get("signature").getAsString();
        assertNotNull(signature);

        var verify = client().verify("test-rsa", "data".getBytes(), signature);
        assertTrue(verify.getAsJsonObject("data").get("valid").getAsBoolean());
    }

    @org.junit.jupiter.api.Test
    void testGenerateMacVerifyMac() throws YvonneException {
        var mac = client().generateMac("test-key", "data".getBytes());
        String macValue = mac.getAsJsonObject("data").get("mac").getAsString();
        assertNotNull(macValue);

        var verify = client().verifyMac("test-key", "data".getBytes(), macValue);
        assertTrue(verify.getAsJsonObject("data").get("valid").getAsBoolean());
    }

    @org.junit.jupiter.api.Test
    void testReEncrypt() throws YvonneException {
        var resp = client().reEncrypt("src-key", "dst-key", "AAAA12345");
        assertNotNull(resp.getAsJsonObject("data").get("ciphertext"));
    }

    @org.junit.jupiter.api.Test
    void testTransitPub() throws YvonneException {
        var resp = client().transitPub();
        assertNotNull(resp.getAsJsonObject("data").get("public_key"));
    }

    @org.junit.jupiter.api.Test
    void testMfaSetup() throws YvonneException {
        var resp = client().mfaSetup("admin");
        assertNotNull(resp.getAsJsonObject("data").get("secret"));
        assertNotNull(resp.getAsJsonObject("data").get("uri"));
    }

    @org.junit.jupiter.api.Test
    void testMfaVerify() throws YvonneException {
        var resp = client().mfaVerify("admin", "123456");
        assertTrue(resp.getAsJsonObject("data").get("enabled").getAsBoolean());
    }

    @org.junit.jupiter.api.Test
    void testCreateApproval() throws YvonneException {
        var resp = client().createApproval("ShredKey", "key-1", 2, 24);
        assertEquals("pending", resp.getAsJsonObject("data").get("status").getAsString());
    }

    @org.junit.jupiter.api.Test
    void testApproveTicket() throws YvonneException {
        var resp = client().approveTicket("ticket-1");
        assertEquals("approved", resp.getAsJsonObject("data").get("status").getAsString());
    }

    @org.junit.jupiter.api.Test
    void testRejectTicket() throws YvonneException {
        var resp = client().rejectTicket("ticket-1");
        assertEquals("rejected", resp.getAsJsonObject("data").get("status").getAsString());
    }

    @org.junit.jupiter.api.Test
    void testListApprovals() throws YvonneException {
        var resp = client().listApprovals();
        assertEquals(1, resp.getAsJsonObject("data").get("count").getAsInt());
    }

    @org.junit.jupiter.api.Test
    void testAuditQuery() throws YvonneException {
        var resp = client().auditQuery(100);
        assertEquals(0, resp.getAsJsonObject("data").get("count").getAsInt());
    }

    @org.junit.jupiter.api.Test
    void testAllEndpointsCalled() throws YvonneException {
        YvonneClient c = client();
        c.health();
        c.createKey("k");
        c.createAsymmetricKey("rsa", "rsa");
        c.rotateKey("k");
        c.shredKey("k", 1);
        c.getPublicKey("rsa");
        c.generateDataKey("k");
        c.generateDataKeyWithoutPlaintext("k");
        c.encrypt("k", "data".getBytes());
        c.decrypt("k", "AAAA12345");
        c.sign("rsa", "data".getBytes());
        c.verify("rsa", "data".getBytes(), "sig");
        c.generateMac("k", "data".getBytes());
        c.verifyMac("k", "data".getBytes(), "mac");
        c.reEncrypt("k", "k", "AAAA12345");
        c.transitPub();
        c.mfaSetup("admin");
        c.mfaVerify("admin", "123456");
        c.createApproval("ShredKey", "k", 2, 24);
        c.approveTicket("t1");
        c.rejectTicket("t1");
        c.listApprovals();
        c.auditQuery(10);

        assertTrue(callCount.get() >= 23, "all endpoints should be called");
    }
}
