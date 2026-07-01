package io.yvonne.kms;

import java.util.UUID;

/**
 * TraceID 生成与透传工具。
 */
public class TraceIdUtil {

    private TraceIdUtil() {}

    /**
     * 生成 32 字符 hex TraceID。
     */
    public static String generate() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
