package com.fff.zfloatwindow;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * 跨语言校验：直接编译 APK 里的 ActivationCodec.java / Ed25519.java（与本类同包）。
 *   vectors <vectors.tsv>               Python 生成的码，APK 侧必须验过；紧凑码还要逐字符一致地重新生成
 *   rfc8032                             Ed25519 官方测试向量（RFC 8032 §7.1）+ 篡改必须失败
 *   verify <ed|mac> <keyHex> <bid> <code>   打印 OK / FAIL:原因（ed 的 keyHex 是公钥，mac 是对称密钥）
 *   genmac <secretHex> <bid>            APK 侧生成紧凑码，供 Python 验证
 */
public final class CrossCheck {
    static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static void check(boolean c, String m) { if (!c) throw new AssertionError(m); }

    public static void main(String[] a) throws Exception {
        switch (a[0]) {
            case "vectors": {
                List<String> lines = Files.readAllLines(Paths.get(a[1]));
                int n = 0;
                for (String l : lines) {
                    if (l.isEmpty() || l.startsWith("#")) continue;
                    String[] f = l.split("\t");
                    byte[] key = unhex(f[1]);
                    String bid = f[2];
                    int product = Integer.parseInt(f[3]);
                    String code = f[4];
                    boolean ed = f[0].equals("ed");
                    String kind = ActivationCodec.verify(ed ? key : null, ed ? null : key, code, bid, product);
                    check(kind.equals(f[0]), "类型不符 " + bid);
                    if (!ed) check(ActivationCodec.generateMac(key, bid, product).equals(code), "紧凑码 Java 生成与 Python 不一致 " + bid);
                    check(ed ? code.length() == 86 : code.length() == 23, "长度不符");
                    // 换一个 VIN 必须失败
                    try {
                        ActivationCodec.verify(ed ? key : null, ed ? null : key, code, "LSJA24U62JG000000", product);
                        throw new AssertionError("换 VIN 竟然通过 " + bid);
                    } catch (ActivationCodec.CodecException expected) { }
                    // 换产品号必须失败
                    try {
                        ActivationCodec.verify(ed ? key : null, ed ? null : key, code, bid, product + 1);
                        throw new AssertionError("换产品号竟然通过 " + bid);
                    } catch (ActivationCodec.CodecException expected) { }
                    n++;
                }
                System.out.println("vectors OK " + n);
                break;
            }
            case "rfc8032": {
                String[][] v = {
                    {"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
                    {"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
                };
                int n = 0;
                for (String[] t : v) {
                    byte[] pub = unhex(t[0]), msg = unhex(t[1]), sig = unhex(t[2]);
                    check(Ed25519.verify(pub, msg, sig), "RFC 向量验签失败 " + t[0]);
                    byte[] bad = sig.clone(); bad[5] ^= 1;
                    check(!Ed25519.verify(pub, msg, bad), "篡改 R 竟然通过");
                    bad = sig.clone(); bad[40] ^= 1;
                    check(!Ed25519.verify(pub, msg, bad), "篡改 S 竟然通过");
                    byte[] m2 = ActivationCodec.concat(msg, new byte[]{1});
                    check(!Ed25519.verify(pub, m2, sig), "篡改消息竟然通过");
                    n++;
                }
                System.out.println("rfc8032 OK " + n);
                break;
            }
            case "verify":
                try {
                    boolean ed = a[1].equals("ed");
                    byte[] k = unhex(a[2]);
                    ActivationCodec.verify(ed ? k : null, ed ? null : k, a[4], a[3], ActivationCodec.PRODUCT_ZFLOAT);
                    System.out.println("OK");
                } catch (ActivationCodec.CodecException e) {
                    System.out.println("FAIL:" + e.getMessage());
                }
                break;
            case "genmac":
                System.out.println(ActivationCodec.generateMac(unhex(a[1]), a[2], ActivationCodec.PRODUCT_ZFLOAT));
                break;
            default:
                throw new IllegalArgumentException(a[0]);
        }
    }
}
