package com.carmediabridge.license;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/**
 * 激活码格式 v2（与 fff_active 的 fffactive/codec.py、SPEC.md、zFloatWindow 的 ActivationCodec.java 字节级一致）。
 * 纯 Java，不依赖 Android（JVM 单元测试和 fff_active 的跨语言对拍都直接编译这个文件）。
 *
 * <pre>
 *   激活码 = base64url(Ed25519 签名 64 字节)，无填充 = 86 字符，区分大小写，不含 VIN/时间 → 同一 VIN 的码确定不变。
 *   msg    = "fff-active/v2/ed|" + product(1 字节) + bid          （APP 内只有公钥）
 *   bid    = 17 位 VIN（A-HJ-NPR-Z0-9，且不是全部字符相同）或机器码 "MC"+16 位 base32
 * </pre>
 * 本 APP 的产品号是 {@link #PRODUCT_CARMEDIABRIDGE}（zFloatWindow=1）。产品号与公钥一起决定了：
 * 别的 APP 生成的码即使 VIN 相同也通不过本 APP 的校验。
 * 注意：本文件不含任何包名字面量（package_custom_id.sh 会改写包名，授权逻辑与包名无关）。
 */
public final class ActivationCodec {
    private ActivationCodec() { }

    /** CarMediaBridge 的产品号（与 fff_active 里该 APP 的“产品号”必须一致）。 */
    public static final int PRODUCT_CARMEDIABRIDGE = 2;
    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static final class CodecException extends Exception {
        public CodecException(String m) { super(m); }
    }

    // ---------------- 标识 ----------------

    public static String normalizeBid(String s) {
        if (s == null) return "";
        return s.replaceAll("[\\s\\-_]", "").toUpperCase(Locale.ROOT);
    }

    public static boolean isVin(String bid) {
        if (bid == null || !bid.matches("[A-HJ-NPR-Z0-9]{17}")) return false;
        for (int i = 1; i < bid.length(); i++) if (bid.charAt(i) != bid.charAt(0)) return true;
        return false;   // 全部字符相同视为占位值
    }

    public static boolean isMachineCode(String bid) {
        return bid != null && bid.matches("MC[A-Z2-7]{16}");
    }

    /** 由稳定设备标识派生机器码："MC"+16 位 base32。 */
    public static String machineCode(String material) {
        byte[] h = sha256(("fff-active/v1/mc|" + material).getBytes(StandardCharsets.UTF_8));
        return "MC" + b32enc(Arrays.copyOf(h, 10));
    }

    /** 显示用：MC-XXXX-XXXX-XXXX-XXXX。 */
    public static String prettyMachineCode(String mc) {
        return "MC-" + mc.substring(2, 6) + "-" + mc.substring(6, 10) + "-" + mc.substring(10, 14) + "-" + mc.substring(14, 18);
    }

    // ---------------- 码 ----------------

    /** 去掉空白后是不是 86 位 base64url 字符。 */
    public static boolean looksLikeCode(String code) {
        return code != null && code.replaceAll("\\s", "").matches("[A-Za-z0-9_\\-]{86}");
    }

    /** 规范化后存起来的形式（去空白，大小写不变）。 */
    public static String canonical(String code) {
        return code == null ? "" : code.replaceAll("\\s", "");
    }

    static byte[] edMsg(String bid, int product) {
        return concat("fff-active/v2/ed|".getBytes(StandardCharsets.US_ASCII), new byte[]{(byte) product},
                bid.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * 校验。edPublic 为 null 表示该构建没配置公钥。
     * 失败抛 CodecException（message 可直接给用户看）。
     */
    public static void verify(byte[] edPublic, String code, String bid, int product) throws CodecException {
        bid = normalizeBid(bid);
        if (!isVin(bid) && !isMachineCode(bid)) throw new CodecException("本机识别码无效");
        if (!looksLikeCode(code)) throw new CodecException("激活码格式不对（应为 86 位字母数字，区分大小写）");
        if (edPublic == null) throw new CodecException("这个版本没有内置验证公钥，无法激活");
        byte[] sig;
        try {
            sig = java.util.Base64.getUrlDecoder().decode(canonical(code));
        } catch (IllegalArgumentException e) {
            throw new CodecException("激活码格式不对");
        }
        if (!Ed25519.verify(edPublic, edMsg(bid, product), sig)) {
            throw new CodecException("激活码有误，或不是本车（本机识别码）的");
        }
    }

    // ---------------- 工具 ----------------

    public static String b32enc(byte[] b) {
        StringBuilder sb = new StringBuilder();
        int buf = 0, bits = 0;
        for (byte x : b) {
            buf = (buf << 8) | (x & 0xFF);
            bits += 8;
            while (bits >= 5) {
                sb.append(B32.charAt((buf >> (bits - 5)) & 31));
                bits -= 5;
            }
            buf &= (1 << bits) - 1;
        }
        if (bits > 0) sb.append(B32.charAt((buf << (5 - bits)) & 31));
        return sb.toString();
    }

    public static byte[] sha256(byte[] in) {
        try { return MessageDigest.getInstance("SHA-256").digest(in); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    public static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] r = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, r, o, p.length); o += p.length; }
        return r;
    }

    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    public static byte[] unhex(String h) {
        if (h == null || h.length() % 2 != 0) return null;
        byte[] r = new byte[h.length() / 2];
        for (int i = 0; i < r.length; i++) {
            int hi = Character.digit(h.charAt(2 * i), 16), lo = Character.digit(h.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) return null;
            r[i] = (byte) (hi * 16 + lo);
        }
        return r;
    }
}
