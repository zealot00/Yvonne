package io.yvonne.kms;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * YvonneClient 测试（重试 + 熔断 + trace_id）。
 */
class YvonneClientTest {

    private HttpServer server;
    private AtomicInteger callCount;
    private int responseStatus;
    private String responseBody;

    @BeforeEach
    void setUp() throws IOException {
        callCount = new AtomicInteger(0);
        responseStatus = 200;
        responseBody = "{\"ok\":true,\"data\":{}}";
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", new TestHandler());
        server.start();
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    class TestHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            callCount.incrementAndGet();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(responseStatus, responseBody.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBody.getBytes());
            }
        }
    }

    private String baseUrl() {
        return "http://localhost:" + server.getAddress().getPort();
    }

    @Test
    void testHealthCheck() throws YvonneException {
        YvonneClient client = YvonneClient.builder()
            .baseUrl(baseUrl())
            .build();

        var resp = client.health();
        assertTrue(resp.get("ok").getAsBoolean());
        assertEquals(1, callCount.get());
    }

    @Test
    void testRetrySuccessAfterFailures() throws YvonneException {
        // 前 2 次返回 503，第 3 次返回 200。
        AtomicInteger localCalls = new AtomicInteger(0);
        server.removeContext("/");
        server.createContext("/", exchange -> {
            int count = localCalls.incrementAndGet();
            if (count < 3) {
                exchange.sendResponseHeaders(503, 0);
                exchange.getResponseBody().close();
                return;
            }
            String body = "{\"ok\":true,\"data\":{}}";
            exchange.sendResponseHeaders(200, body.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes());
            }
        });

        YvonneClient client = YvonneClient.builder()
            .baseUrl(baseUrl())
            .retry(RetryConfig.defaultConfig())
            .build();

        var resp = client.health();
        assertTrue(resp.get("ok").getAsBoolean());
        assertEquals(3, localCalls.get());
    }

    @Test
    void testRetryMaxExceeded() {
        responseStatus = 503;
        responseBody = "{\"ok\":false,\"error\":\"unavailable\"}";

        YvonneClient client = YvonneClient.builder()
            .baseUrl(baseUrl())
            .retry(new RetryConfig(2, Duration.ofMillis(10), Duration.ofMillis(100),
                java.util.Set.of(503)))
            .build();

        assertThrows(YvonneException.class, () -> client.health());
        assertEquals(3, callCount.get()); // 1 + 2 retries
    }

    @Test
    void testNonRetryableError() {
        responseStatus = 400;
        responseBody = "{\"ok\":false,\"error\":\"bad request\"}";

        YvonneClient client = YvonneClient.builder()
            .baseUrl(baseUrl())
            .retry(RetryConfig.defaultConfig())
            .build();

        assertThrows(YvonneException.class, () -> client.health());
        assertEquals(1, callCount.get()); // no retry for 400
    }

    @Test
    void testCircuitBreakerOpens() {
        responseStatus = 503;
        responseBody = "{\"ok\":false,\"error\":\"unavailable\"}";

        CircuitBreaker cb = new CircuitBreaker(3, Duration.ofSeconds(60));
        YvonneClient client = YvonneClient.builder()
            .baseUrl(baseUrl())
            .circuitBreaker(cb)
            .build();

        // 3 次请求触发熔断。
        for (int i = 0; i < 3; i++) {
            assertThrows(YvonneException.class, () -> client.health());
        }

        assertEquals(CircuitBreaker.State.OPEN, cb.getState());

        // 第 4 次应被熔断（不调用 server）。
        int callsBefore = callCount.get();
        assertThrows(YvonneException.class, () -> client.health());
        assertEquals(callsBefore, callCount.get()); // no new call
    }

    @Test
    void testCircuitBreakerResets() throws InterruptedException {
        responseStatus = 503;
        responseBody = "{\"ok\":false,\"error\":\"unavailable\"}";

        CircuitBreaker cb = new CircuitBreaker(2, Duration.ofMillis(100));
        YvonneClient client = YvonneClient.builder()
            .baseUrl(baseUrl())
            .circuitBreaker(cb)
            .build();

        // 触发熔断。
        for (int i = 0; i < 2; i++) {
            assertThrows(YvonneException.class, () -> client.health());
        }
        assertEquals(CircuitBreaker.State.OPEN, cb.getState());

        // 等待恢复。
        Thread.sleep(150);

        // 恢复为 200。
        responseStatus = 200;
        responseBody = "{\"ok\":true,\"data\":{}}";

        var resp = client.health();
        assertTrue(resp.get("ok").getAsBoolean());
        assertEquals(CircuitBreaker.State.CLOSED, cb.getState());
    }

    @Test
    void testTraceIdPropagation() throws YvonneException {
        StringBuilder receivedTraceId = new StringBuilder();
        server.removeContext("/");
        server.createContext("/", exchange -> {
            receivedTraceId.append(exchange.getRequestHeaders().getFirst("X-Request-ID"));
            String body = "{\"ok\":true,\"data\":{}}";
            exchange.sendResponseHeaders(200, body.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes());
            }
        });

        YvonneClient client = YvonneClient.builder()
            .baseUrl(baseUrl())
            .traceIdHeader("X-Request-ID")
            .build();

        client.health();

        assertNotNull(receivedTraceId.toString());
        assertFalse(receivedTraceId.toString().isEmpty());
        assertEquals(32, receivedTraceId.length());
    }

    @Test
    void testCircuitBreakerStateTransitions() {
        CircuitBreaker cb = new CircuitBreaker(2, Duration.ofMillis(50));

        assertEquals(CircuitBreaker.State.CLOSED, cb.getState());
        assertTrue(cb.allow());

        cb.recordFailure();
        assertEquals(CircuitBreaker.State.CLOSED, cb.getState());

        cb.recordFailure();
        assertEquals(CircuitBreaker.State.OPEN, cb.getState());
        assertFalse(cb.allow());

        // 等待恢复。
        try { Thread.sleep(60); } catch (InterruptedException e) {}

        assertTrue(cb.allow());
        assertEquals(CircuitBreaker.State.HALF_OPEN, cb.getState());

        cb.recordSuccess();
        assertEquals(CircuitBreaker.State.CLOSED, cb.getState());
    }

    @Test
    void testBuilderAllOptions() {
        YvonneClient client = YvonneClient.builder()
            .baseUrl("http://localhost:9999")
            .token("test-token")
            .timeout(Duration.ofSeconds(10))
            .retry(RetryConfig.defaultConfig())
            .circuitBreaker(CircuitBreaker.defaultBreaker())
            .traceIdHeader("X-Trace-ID")
            .build();

        assertNotNull(client);
    }

    @Test
    void testRetryConfigBackoff() {
        RetryConfig config = new RetryConfig(3, Duration.ofMillis(100), Duration.ofSeconds(5),
            java.util.Set.of(503));

        Duration backoff1 = config.calculateBackoff(1);
        assertTrue(backoff1.toMillis() >= 80 && backoff1.toMillis() <= 120); // ~100ms ± 20%

        Duration backoff3 = config.calculateBackoff(3);
        assertTrue(backoff3.toMillis() >= 320 && backoff3.toMillis() <= 480); // ~400ms ± 20%

        // 不超过 maxBackoff。
        Duration backoff10 = config.calculateBackoff(10);
        assertTrue(backoff10.toMillis() <= 5000 + 1000); // 5s + jitter
    }
}
