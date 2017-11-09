package com.jnidemo.demo.rsademotest.utils;


import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * RSA算法 是非对称加密算法
 * RSA算法是最流行的公钥密码算法，使用长度可以变化的密钥。RSA是第一个既能用于数据加密也能用于数字签名的算法。
 * <p>
 * RSA 工具类。提供加密，解密，生成密钥对等方法。
 * RSA加密原理概述
 * RSA的安全性依赖于大数的分解，公钥和私钥都是两个大素数（大于100的十进制位）的函数。
 * 据猜测，从一个密钥和密文推断出明文的难度等同于分解两个大素数的积
 * ===================================================================
 * （该算法的安全性未得到理论的证明）
 * ===================================================================
 * 密钥的产生：
 * 1.选择两个大素数 p,q ,计算 n=p*q;
 * 2.随机选择加密密钥 e ,要求 e 和 (p-1)*(q-1)互质
 * 3.利用 Euclid 算法计算解密密钥 d , 使其满足 e*d = 1(mod(p-1)*(q-1)) (其中 n,d 也要互质)
 * 4:至此得出公钥为 (n,e) 私钥为 (n,d)
 * ===================================================================
 * 加解密方法：
 * 1.首先将要加密的信息 m(二进制表示) 分成等长的数据块 m1,m2,...,mi 块长 s(尽可能大) ,其中 2^s<n
 * 2:对应的密文是： ci = mi^e(mod n)
 * 3:解密时作如下计算： mi = ci^d(mod n)
 * ===================================================================
 * RSA速度
 * 由于进行的都是大数计算，使得RSA最快的情况也比DES慢上100倍，无论 是软件还是硬件实现。
 * 速度一直是RSA的缺陷。一般来说只用于少量数据 加密。
 *
 * BASE64转换说明:demo中是使用的android自带的,如果是java后台把对应的替换成org.apachesBASE64，这样就能兼容iOS和android等平台
 * 秘钥长度配置:修改DEFAULT_KEY_SIZE的长度即可
 *
 */
public class RSAUtil {

    public static final  String RSA                = "RSA";// 非对称加密密钥算法
    public static final  String ECB_PKCS1_PADDING  = "RSA/ECB/PKCS1Padding";//加密填充方式
    public static final  int    DEFAULT_KEY_SIZE   = 2048;//秘钥默认长度
    public static final  byte[] DEFAULT_SPLIT      = "#PART#".getBytes();    // 当要加密的内容超过bufferSize，则采用partSplit进行分块加密
    public static final  int    DEFAULT_BUFFERSIZE = (DEFAULT_KEY_SIZE / 8);// 当前秘钥支持加密的最大字节数
    static               String aPublicStr         = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApVxwgbEtur84XqUq7fdV2F1" +
            "+rqq5652c+Nym8Q4R6ejuKeRTWpJoVdjjZJJA1g87TWGUyjzNivlvJBMwH2173r5KwLI2nabgndIGzkxp/qYPRhBp3Kf/Kke3S7NpRrZtdXmK9jGzaeYBV1ZWRn0otDFNhwVavvuiLlhtp7ijSCQ3OOihrOA/zUtoeTT+vfpYouU9k8PH3VefL8TESB24ZM1AZjS65A9b/kTnfp8EajunP36LiIDf8QsIkOxWG8ZyAT3tII7HOWL6JDv74PVAGHIN/p5w0NNSmqhxgXQ/MhY/2WOh0AU9CVwykBdKa4PuUF5QlReYFE80+FnyNZ3gOwIDAQAB";
    static  String aprivateStr="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClXHCBsS26vzhepSrt91XYXX6uqrnrnZz43KbxDhHp6O4p5FNakmhV2ONkkkDWDztNYZTKPM2K+W8kEzAfbXvevkrAsjadpuCd0gbOTGn+pg9GEGncp/8qR7dLs2lGtm11eYr2MbNp5gFXVlZGfSi0MU2HBVq++6IuWG2nuKNIJDc46KGs4D/NS2h5NP69+lii5T2Tw8fdV58vxMRIHbhkzUBmNLrkD1v+ROd+nwRqO6c/fouIgN/xCwiQ7FYbxnIBPe0gjsc5YvokO/vg9UAYcg3+nnDQ01KaqHGBdD8yFj/ZY6HQBT0JXDKQF0prg+5QXlCVF5gUTzT4WfI1neA7AgMBAAECggEBAKAXFnT466TYa+J1VVJ9GgcWvQatEsIhHU9xj83gKUej0q+L9YbCJ3C1QbCkR1D1/hu0VTBWHUhmpErwqK5EeJ/06roTzvxiCyO/qgcfw55ddnwGd/bATjDIrZQEZe+nveD1gqtHAsOLgdDkLTKhCT8qXDxT2r77LtBfnAm8n5e+qNiPTlGku6+BmgIfx9+qk9LOV1msiosxlPZHIgY9uwMtdbkxbJR6S/GjOZlNGlaaYCoEdM6n/HHtiV7D6LfPUouGnb8DNZLRV/dOru1jxvozsECKORhd5vCtS2hIWoTRTWAzs6QJQoA678zaCJuHrU1wM1kXOtf6vu3/NMdw74ECgYEA27mArPbA8c9oyynZbxCRuwePfJhTBlaf4u5zhOxDQq7ZZ1EECfotKAXWAh+fMrNYvZHHa9XA7uQ3g125QqHDNoV8cMT/QJe8DVghUilmuNe5fjM5tgVofBaZBHCrliTjDjk9HTET60jz/kv4Y9kRumEGsycbiZlnjNWqL03KU2kCgYEAwKlNhkA6sAEPN5XxfIGY01QeviRBxhxgQqF1TR64FAhbfYOuv0k0zT6kXkSJRzmgjarbLvxTP2oSEAMVWYm7Z0YSd5cLvzk0GXfMZRvmPk/RBNGlP2JCIz9SjHMvfPA7F9yBuKebE82myrdxrDj4H2KeVXGOne2yVlbKmxRY9gMCgYAXkcCBzT5JMgx1rpmKVmarf1Ye8WAGkAg6mYV+vrFAV+0uLfyW7WUmo+me9LFpCN/+BcM0iAtYFNb3mngi86MzGAKPPjJ7RUuAyvFYFOTV8x4MsYYBRnc8yFfFqChfxLkub2lk1jziwkKaBqAwZbqHGZ1UXl+P1QrMiqbkyB1p8QKBgCuocePhPCtUIiGjfdSL/Zit8EWAK9N77KhMtCsksewANNNNetTn/uofrtmZyE32lhZkSETucuLk43DzcewXVPtDGr404TmU+eRnjE7BMryeE6x24W5qkrgwCkG/fFxgh9ORaWfxuyeSq6A2T7EKO9fI3j5YfEv3aDk+c60OwFYHAoGAYKBuQpJs9p/I9SOPqdEYXtmFqSgvU0sXFX4+fZim3nl0jmMGTeecZFyWZkED6+b96EOQw7OIpWf9QT2K1+ogUpkVx1YUipmJ60x/7aSH609vZcoTgfn3gf2w+Mcct2veb2IG39SDC5mkRQZtHwSQaFzw0gI+QPSprMg6WKvJF+w=";
    /** */
    /**
     * RSA最大加密明文大小
     */
    private static final int    MAX_ENCRYPT_BLOCK  = DEFAULT_BUFFERSIZE-11;

    /** */
    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = DEFAULT_BUFFERSIZE;

    /**
     * 随机生成RSA密钥对
     *
     * @param keyLength 密钥长度，范围：512～2048
     *                  一般1024
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用公钥对字符串进行加密
     *
     * @param data         原始数据
     * @param publicKeyStr 密钥
     */
    private static byte[] encryptByPublicKey(byte[] data, PublicKey publicKeyStr) throws Exception {
        // 得到公钥
        /*byte[] publicKey = Base64.decode(publicKeyStr, Base64.DEFAULT);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PublicKey keyPublic = kf.generatePublic(keySpec);*/
        // 加密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.ENCRYPT_MODE, publicKeyStr);
        return cp.doFinal(data);
    }

    /**
     * 私钥加密
     *
     * @param data          待加密数据
     * @param privateKeyStr 密钥
     * @return byte[] 加密数据
     */
    private static byte[] encryptByPrivateKey(byte[] data, PrivateKey privateKeyStr) throws Exception {
        // 得到私钥
        /*byte[] privateKey = Base64.decode(privateKeyStr, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PrivateKey keyPrivate = kf.generatePrivate(keySpec);*/
        // 数据加密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, privateKeyStr);
        return cipher.doFinal(data);
    }

    /**
     * 公钥解密
     *
     * @param data         待解密数据
     * @param publicKeyStr 密钥
     * @return byte[] 解密数据
     */
    private static byte[] decryptByPublicKey(byte[] data, PublicKey publicKeyStr) throws Exception {
        // 得到公钥
       /* byte[] publicKey = Base64.decode(publicKeyStr, Base64.DEFAULT);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PublicKey keyPublic = kf.generatePublic(keySpec);*/
        // 数据解密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, publicKeyStr);
        return cipher.doFinal(data);
    }

    /**
     * 使用私钥进行解密
     *
     * @param encrypted     待解密数据
     * @param privateKeyStr 密钥
     * @return byte[] 解密数据
     */
    private static byte[] decryptByPrivateKey(byte[] encrypted, PrivateKey privateKeyStr) throws Exception {
        // 得到私钥
        /*byte[] privateKey = Base64.decode(privateKeyStr, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PrivateKey keyPrivate = kf.generatePrivate(keySpec);*/

        // 解密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.DECRYPT_MODE, privateKeyStr);
        byte[] arr = cp.doFinal(encrypted);
        return arr;
    }

    /**
     * 用公钥对字符串进行分段加密
     */
    public static String encryptByPublicKeyForSpilt(String s) {
        try {
            PublicKey publicKey = getPublicKey(Base64.decode(aPublicStr, Base64.NO_WRAP));
            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] data = s.getBytes();
            int inputLen = data.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            out.close();
            return Base64.encodeToString(encryptedData, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
            return s;
        }

    }

    /**
     * 分段加密
     *
     * @param @s            要加密的原始数据
     *
     */
    public static String encryptByPrivateKeyForSpilt(String s) throws Exception {
        PrivateKey privateKey = getPrivateKey(Base64.decode(aprivateStr, Base64.NO_WRAP));
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] data = s.getBytes("utf-8");
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return Base64.encodeToString(encryptedData,Base64.NO_WRAP);
    }

    /**
     * 公钥分段解密
     *
     * @param @encrypted    待解密数据
     * @param @publicKeyStr 密钥
     */
    public static String decryptByPublicKeyForSpilt(String s) {
        try {
            PublicKey publicKey = getPublicKey(Base64.decode(aPublicStr, Base64.NO_WRAP));
            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] encrypted = Base64.decode(s, Base64.NO_WRAP);
            int inputLen = encrypted.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段解密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(encrypted, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(encrypted, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();
            return new String(decryptedData,"utf-8");
        } catch (Exception e) {
            e.printStackTrace();
            return s;
        }

    }

    /**
     * 使用私钥分段解密
     */
    public static String decryptByPrivateKeyForSpilt(String s) throws Exception {
        PrivateKey privateKey = getPrivateKey(Base64.decode(aprivateStr, Base64.NO_WRAP));
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encrypted = Base64.decode(s, Base64.NO_WRAP);
        int inputLen = encrypted.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encrypted, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encrypted, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return new String(decryptedData,"utf-8");
    }

    /**
     * 通过公钥byte[](publicKey.getEncoded())将公钥还原，适用于RSA算法
     *
     * @param keyBytes
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PublicKey getPublicKey(byte[] keyBytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 通过私钥byte[]将公钥还原，适用于RSA算法
     *
     * @param keyBytes
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PrivateKey getPrivateKey(byte[] keyBytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
}