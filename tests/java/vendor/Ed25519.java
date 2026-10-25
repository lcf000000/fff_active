package com.carmediabridge.license;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Ed25519 验签（RFC 8032，纯 Java/BigInteger）。Android 9（API 28）的 JCE 没有 Ed25519，所以自带一个只验签的实现。
 * 只有验签，没有签名/私钥相关代码；在 JVM 上用 RFC 8032 测试向量 + cryptography 库生成的签名交叉验证过（见 fff_active/tests）。
 * 与 zFloatWindow 的 Ed25519.java 相同，仅多一道“拒绝小阶公钥”检查（防止全零占位公钥被伪造签名）。
 * 严格模式：s 必须 < L，R/A 必须是合法点，检查 [s]B == R + [h]A（不乘余因子）。
 */
public final class Ed25519 {
    private Ed25519() { }

    private static volatile String lastError;
    /** 最近一次验签过程中出现的异常（不是“签名不对”，而是实现/运行环境出错）；没有则 null。读后清空。 */
    public static String lastError() { String e = lastError; lastError = null; return e; }

    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L = BigInteger.ONE.shiftLeft(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D = BigInteger.valueOf(-121665).multiply(inv(BigInteger.valueOf(121666))).mod(P);
    private static final BigInteger SQRT_M1 = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);
    private static final BigInteger[] B;

    static {
        BigInteger gy = BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5))).mod(P);
        BigInteger gx = recoverX(gy, 0);
        B = new BigInteger[]{gx, gy, BigInteger.ONE, gx.multiply(gy).mod(P)};
    }

    private static BigInteger inv(BigInteger x) { return x.modPow(P.subtract(BigInteger.valueOf(2)), P); }

    private static BigInteger recoverX(BigInteger y, int sign) {
        if (y.compareTo(P) >= 0) return null;
        BigInteger x2 = y.multiply(y).subtract(BigInteger.ONE).multiply(inv(D.multiply(y).multiply(y).add(BigInteger.ONE))).mod(P);
        if (x2.signum() == 0) return sign != 0 ? null : BigInteger.ZERO;
        BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) x = x.multiply(SQRT_M1).mod(P);
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) return null;
        if (x.testBit(0) != (sign != 0)) x = P.subtract(x);
        return x;
    }

    private static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger a = p[1].subtract(p[0]).multiply(q[1].subtract(q[0])).mod(P);
        BigInteger b = p[1].add(p[0]).multiply(q[1].add(q[0])).mod(P);
        BigInteger c = p[3].multiply(BigInteger.valueOf(2)).multiply(D).multiply(q[3]).mod(P);
        BigInteger d = p[2].multiply(BigInteger.valueOf(2)).multiply(q[2]).mod(P);
        BigInteger e = b.subtract(a), f = d.subtract(c), g = d.add(c), h = b.add(a);
        return new BigInteger[]{e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P)};
    }

    private static BigInteger[] mul(BigInteger s, BigInteger[] p) {
        BigInteger[] q = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        for (int i = s.bitLength() - 1; i >= 0; i--) {
            q = add(q, q);
            if (s.testBit(i)) q = add(q, p);
        }
        return q;
    }

    private static boolean equal(BigInteger[] p, BigInteger[] q) {
        return p[0].multiply(q[2]).subtract(q[0].multiply(p[2])).mod(P).signum() == 0
                && p[1].multiply(q[2]).subtract(q[1].multiply(p[2])).mod(P).signum() == 0;
    }

    private static BigInteger le(byte[] b, int off, int len) {
        byte[] r = new byte[len];
        for (int i = 0; i < len; i++) r[len - 1 - i] = b[off + i];
        return new BigInteger(1, r);
    }

    private static BigInteger[] decompress(byte[] b, int off) {
        byte[] y = Arrays.copyOfRange(b, off, off + 32);
        int sign = (y[31] >> 7) & 1;
        y[31] &= 0x7F;
        BigInteger yy = le(y, 0, 32);
        BigInteger x = recoverX(yy, sign);
        if (x == null) return null;
        return new BigInteger[]{x, yy, BigInteger.ONE, x.multiply(yy).mod(P)};
    }

    /** @return true 当且仅当 sig(64B) 是 pub(32B) 对 msg 的合法签名。 */
    public static boolean verify(byte[] pub, byte[] msg, byte[] sig) {
        if (pub == null || pub.length != 32 || sig == null || sig.length != 64) return false;
        try {
            BigInteger[] a = decompress(pub, 0);
            BigInteger[] r = decompress(sig, 0);
            if (a == null || r == null) return false;
            // 拒绝小阶（阶整除 8）公钥：全零等“占位公钥”是合法曲线点，但对它可以伪造签名。
            if (equal(mul(BigInteger.valueOf(8), a), new BigInteger[]{BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO})) return false;
            BigInteger s = le(sig, 32, 32);
            if (s.compareTo(L) >= 0) return false;
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(sig, 0, 32);
            md.update(pub);
            md.update(msg);
            BigInteger h = le(md.digest(), 0, 64).mod(L);
            return equal(mul(s, B), add(r, mul(h, a)));
        } catch (Exception e) {
            lastError = e.getClass().getName() + ": " + e.getMessage();
            return false;
        }
    }
}
