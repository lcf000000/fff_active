package com.fff.zfloatwindow;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * 跨语言校验：直接编译 APK 里的 ActivationCodec.java（与本类同包），验证
 *   1) vectors.tsv 里 Python 生成的码，APK 侧 verify 通过且用相同 nonce/issued 重新生成逐字符一致；
 *   2) 随机码：参数 gen <secretHex> <bid> → 打印 APK 侧生成的码，供 Python 验证。
 * 用法： java com.fff.zfloatwindow.CrossCheck vectors <vectors.tsv>
 *        java com.fff.zfloatwindow.CrossCheck gen <secretHex> <bid>
 *        java com.fff.zfloatwindow.CrossCheck verify <secretHex> <bid> <code>   （打印 OK / FAIL:原因）
 */
public final class CrossCheck {
    static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    public static void main(String[] a) throws Exception {
        switch (a[0]) {
            case "vectors": {
                List<String> lines = Files.readAllLines(Paths.get(a[1]));
                int n = 0;
                for (String l : lines) {
                    if (l.isEmpty() || l.startsWith("#")) continue;
                    String[] f = l.split("\t");
                    byte[] secret = unhex(f[0]);
                    String bid = f[1];
                    int product = Integer.parseInt(f[2]);
                    long issued = Long.parseLong(f[3]);
                    byte[] nonce = unhex(f[4]);
                    String code = f[5];
                    ActivationCodec.Result r = ActivationCodec.verify(secret, code, bid);
                    if (r.product != product || r.issued != issued) throw new AssertionError("字段不符 " + bid);
                    String again = ActivationCodec.generate(secret, bid, product, issued, nonce);
                    if (!again.equals(code)) throw new AssertionError("Java 生成与 Python 不一致\n" + again + "\n" + code);
                    n++;
                }
                System.out.println("vectors OK " + n);
                break;
            }
            case "gen":
                System.out.println(ActivationCodec.generate(unhex(a[1]), a[2], ActivationCodec.PRODUCT_ZFLOAT,
                        System.currentTimeMillis() / 1000, null));
                break;
            case "verify":
                try {
                    ActivationCodec.verify(unhex(a[1]), a[3], a[2]);
                    System.out.println("OK");
                } catch (ActivationCodec.CodecException e) {
                    System.out.println("FAIL:" + e.getMessage());
                }
                break;
            default:
                throw new IllegalArgumentException(a[0]);
        }
    }
}
