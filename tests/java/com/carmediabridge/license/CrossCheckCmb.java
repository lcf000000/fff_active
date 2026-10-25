package com.carmediabridge.license;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * 跨语言校验 CarMediaBridge 的验签代码（直接编译 APK 里的 ActivationCodec.java / Ed25519.java，与本类同包）。
 *   vectors <tsv>                          tests/vectors_carmediabridge.tsv：Python 生成的码，APK 侧必须验过（换 VIN / 换产品号必须失败）
 *   verify <pubHex> <bid> <code> [product] 打印 OK / FAIL:原因（默认产品号 2）
 *   sign <seedHex> <bid> [product]         用 JDK 自带 Ed25519 + 种子签名（APK 侧 edMsg），打印激活码，供 Python 验证
 */
public final class CrossCheckCmb {
    static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static boolean ok(byte[] pub, String code, String bid, int product) {
        try { ActivationCodec.verify(pub, code, bid, product); return true; } catch (ActivationCodec.CodecException e) { return false; }
    }

    public static void main(String[] a) throws Exception {
        switch (a[0]) {
            case "vectors": {
                int n = 0;
                for (String l : Files.readAllLines(Paths.get(a[1]))) {
                    if (l.isEmpty() || l.startsWith("#")) continue;
                    String[] f = l.split("\t");
                    byte[] pub = unhex(f[0]);
                    String bid = f[1];
                    int product = Integer.parseInt(f[2]);
                    String code = f[3];
                    if (!ok(pub, code, bid, product)) throw new AssertionError("向量未通过 " + bid);
                    if (code.length() != 86) throw new AssertionError("长度不符");
                    if (ok(pub, code, "LSJA24U62JG000000", product)) throw new AssertionError("换 VIN 竟然通过");
                    if (ok(pub, code, bid, product == 1 ? 2 : 1)) throw new AssertionError("换产品号竟然通过");
                    n++;
                }
                System.out.println("vectors OK " + n);
                break;
            }
            case "verify": {
                int product = a.length > 4 ? Integer.parseInt(a[4]) : ActivationCodec.PRODUCT_CARMEDIABRIDGE;
                try {
                    ActivationCodec.verify(unhex(a[1]), a[3], a[2], product);
                    System.out.println("OK");
                } catch (ActivationCodec.CodecException e) {
                    System.out.println("FAIL:" + e.getMessage());
                }
                break;
            }
            case "sign": {
                int product = a.length > 3 ? Integer.parseInt(a[3]) : ActivationCodec.PRODUCT_CARMEDIABRIDGE;
                byte[] prefix = unhex("302e020100300506032b657004220420");
                byte[] seed = unhex(a[1]);
                byte[] pkcs8 = new byte[prefix.length + 32];
                System.arraycopy(prefix, 0, pkcs8, 0, prefix.length);
                System.arraycopy(seed, 0, pkcs8, prefix.length, 32);
                Signature s = Signature.getInstance("Ed25519");
                s.initSign(KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
                s.update(ActivationCodec.edMsg(ActivationCodec.normalizeBid(a[2]), product));
                System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign()));
                break;
            }
            default:
                throw new IllegalArgumentException(a[0]);
        }
    }
}
