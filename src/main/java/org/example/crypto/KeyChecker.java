package org.example.crypto;

import cn.hutool.core.codec.Base64;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

public class KeyChecker {

    public static boolean checkKeyPair(KeyPair keyPair) {
        String raw = "external key check";
        try {
            return encryptAndDecrypt(raw, keyPair) && signAndVerify(raw, keyPair);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean encryptAndDecrypt(String raw, KeyPair keyPair) throws Exception {
        String encode = encryptByPublicKey(raw, (ECPublicKey) keyPair.getPublic());
        String decode = decryptByPrivateKey(encode, (ECPrivateKey) keyPair.getPrivate());
        // 公私钥皆可加解密
//        String encode = encryptByPrivateKey(raw, (ECPrivateKey) keyPair.getPrivate());
//        String decode = decryptByPublicKey(encode, (ECPublicKey) keyPair.getPublic());
        return raw.equals(decode);
    }

    public static boolean signAndVerify(String raw, KeyPair keyPair) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String signature = sign(raw, keyPair.getPrivate());
        return verify(raw, signature, keyPair.getPublic());
    }

    public static String encryptByPublicKey(String str, ECPublicKey publicKey) throws Exception {
        // EC加密
        Cipher cipher = new NullCipher();
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(publicKey.getW(), publicKey.getParams());

        cipher.init(Cipher.ENCRYPT_MODE, publicKey, ecPublicKeySpec.getParams());
        return Base64.encode(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
    }
    public static String decryptByPublicKey(String str, ECPublicKey publicKey) throws GeneralSecurityException {
        // 64位解码加密后的字符串
        byte[] inputByte = Base64.decode(str.getBytes(StandardCharsets.UTF_8));

        // EC解密
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(publicKey.getW(), publicKey.getParams());
        Cipher cipher = new NullCipher();
        cipher.init(Cipher.DECRYPT_MODE, publicKey, ecPublicKeySpec.getParams());
        return new String(cipher.doFinal(inputByte));
    }

    public static String encryptByPrivateKey(String str, ECPrivateKey privateKey) throws GeneralSecurityException {

        // EC加密
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(privateKey.getS(), privateKey.getParams());
        Cipher cipher = new NullCipher();
        cipher.init(Cipher.DECRYPT_MODE, privateKey, ecPrivateKeySpec.getParams());
        return Base64.encode(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
    }
    public static String decryptByPrivateKey(String str, ECPrivateKey privateKey) throws GeneralSecurityException {
        // 64位解码加密后的字符串
        byte[] inputByte = Base64.decode(str.getBytes(StandardCharsets.UTF_8));

        // EC解密
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(privateKey.getS(), privateKey.getParams());

        Cipher cipher = new NullCipher();
        cipher.init(Cipher.DECRYPT_MODE, privateKey, ecPrivateKeySpec.getParams());

        return new String(cipher.doFinal(inputByte));
    }

    public static String sign(String src, PrivateKey priKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        byte[] srcData = src.getBytes();
        signature.initSign(priKey);
        signature.update(srcData);
        byte[] signBytes = signature.sign();
        return new BigInteger(1, signBytes).toString(16);
    }

    public static Boolean verify(String src, String signSrc, PublicKey pubKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] srcData = src.getBytes();
        Signature signatureV = Signature.getInstance("SHA256withECDSA");
        signatureV.initVerify(pubKey);
        signatureV.update(srcData);
        byte[] signBytes = new BigInteger(signSrc, 16).toByteArray();
        return signatureV.verify(signBytes);
    }
}
