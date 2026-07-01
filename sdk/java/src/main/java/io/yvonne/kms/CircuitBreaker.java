package io.yvonne.kms;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 熔断器（Circuit Breaker）。
 *
 * 状态机：CLOSED → OPEN → HALF_OPEN → CLOSED
 *
 * - CLOSED: 正常请求，记录失败次数
 * - OPEN: 拒绝所有请求，等待恢复超时
 * - HALF_OPEN: 允许一次试探请求，成功则 CLOSED，失败则 OPEN
 */
public class CircuitBreaker {

    public enum State { CLOSED, OPEN, HALF_OPEN }

    private final int failureThreshold;
    private final Duration resetTimeout;
    private final AtomicInteger failureCount = new AtomicInteger(0);
    private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
    private volatile Instant openedAt = Instant.MIN;

    /**
     * @param failureThreshold 连续失败次数阈值
     * @param resetTimeout     熔断后恢复等待时间
     */
    public CircuitBreaker(int failureThreshold, Duration resetTimeout) {
        this.failureThreshold = failureThreshold;
        this.resetTimeout = resetTimeout;
    }

    /**
     * 默认配置：10 次连续失败后熔断，60 秒后恢复。
     */
    public static CircuitBreaker defaultBreaker() {
        return new CircuitBreaker(10, Duration.ofSeconds(60));
    }

    /**
     * 检查是否允许请求。
     * @return true 如果允许请求（CLOSED 或 HALF_OPEN 且已过恢复超时）
     */
    public boolean allow() {
        State current = state.get();
        switch (current) {
            case CLOSED:
                return true;
            case OPEN:
                // 检查是否过了恢复时间。
                if (Instant.now().isAfter(openedAt.plus(resetTimeout))) {
                    // 尝试切换到 HALF_OPEN。
                    if (state.compareAndSet(State.OPEN, State.HALF_OPEN)) {
                        return true;
                    }
                    return false;
                }
                return false;
            case HALF_OPEN:
                return true;
            default:
                return true;
        }
    }

    /**
     * 记录成功。
     */
    public void recordSuccess() {
        failureCount.set(0);
        state.set(State.CLOSED);
    }

    /**
     * 记录失败。
     */
    public void recordFailure() {
        int count = failureCount.incrementAndGet();
        if (count >= failureThreshold) {
            if (state.compareAndSet(State.CLOSED, State.OPEN) ||
                state.compareAndSet(State.HALF_OPEN, State.OPEN)) {
                openedAt = Instant.now();
            }
        }
    }

    /**
     * 获取当前状态。
     */
    public State getState() {
        return state.get();
    }

    /**
     * 获取当前失败计数。
     */
    public int getFailureCount() {
        return failureCount.get();
    }

    /**
     * 熔断器是否开启。
     */
    public boolean isOpen() {
        return state.get() == State.OPEN;
    }
}
