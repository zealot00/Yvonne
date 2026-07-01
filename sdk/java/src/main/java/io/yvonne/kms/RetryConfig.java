package io.yvonne.kms;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * 重试配置。
 */
public class RetryConfig {
    private int maxRetries;
    private Duration initialBackoff;
    private Duration maxBackoff;
    private Set<Integer> retryableStatusCodes;

    public RetryConfig(int maxRetries, Duration initialBackoff, Duration maxBackoff, Set<Integer> retryableStatusCodes) {
        this.maxRetries = maxRetries;
        this.initialBackoff = initialBackoff;
        this.maxBackoff = maxBackoff;
        this.retryableStatusCodes = retryableStatusCodes;
    }

    /**
     * 默认重试配置：3 次重试，100ms 初始退避，5s 最大退避，502/503/504 可重试。
     */
    public static RetryConfig defaultConfig() {
        return new RetryConfig(
            3,
            Duration.ofMillis(100),
            Duration.ofSeconds(5),
            new HashSet<>(Arrays.asList(502, 503, 504))
        );
    }

    public int getMaxRetries() { return maxRetries; }
    public Duration getInitialBackoff() { return initialBackoff; }
    public Duration getMaxBackoff() { return maxBackoff; }
    public Set<Integer> getRetryableStatusCodes() { return retryableStatusCodes; }

    public boolean isRetryable(int statusCode) {
        return retryableStatusCodes != null && retryableStatusCodes.contains(statusCode);
    }

    /**
     * 计算指数退避时间（含 ±20% 抖动）。
     */
    public Duration calculateBackoff(int attempt) {
        double backoffMs = initialBackoff.toMillis() * Math.pow(2, attempt - 1);
        if (backoffMs > maxBackoff.toMillis()) {
            backoffMs = maxBackoff.toMillis();
        }
        // 添加抖动。
        double jitter = backoffMs * 0.2 * (2 * Math.random() - 1);
        return Duration.ofMillis((long) (backoffMs + jitter));
    }
}
