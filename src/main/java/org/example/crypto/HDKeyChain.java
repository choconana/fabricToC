package org.example.crypto;

import cn.hutool.crypto.digest.HMac;
import cn.hutool.crypto.digest.HmacAlgorithm;
import lombok.Builder;
import lombok.Data;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import sun.security.jca.JCAUtil;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

public class HDKeyChain {

    private static final byte[] masterKey = "HyperledgerFabic Seed".getBytes();

    private static final long hardenedKeyStart = 0x80000000L;

    public static void main(String[] args) throws Exception {
        byte[] seed = new byte[32];
        SecureRandom random = JCAUtil.getSecureRandom();
        random.nextBytes(seed);
        ExtendedKey rootKey = genRootKey(seed);
        KeyPair keyPair = new KeyPair(rootKey.getExtendedPubKey(), (PrivateKey) rootKey.getKey());
        System.out.println(KeyChecker.checkKeyPair(keyPair));

        ExtendedKey childPrvKey = derive(1, rootKey);
        ExtendedKey childPubKey = derive(
                1,
                ExtendedKey.builder()
                        .key(rootKey.getExtendedPubKey())
                        .chaincode(rootKey.getChaincode())
                        .isPrivate(Boolean.FALSE)
                        .build().fillKeyBytes());
        KeyPair correctKeyPair = KeyConvertor.genByPrvKey(((ECPrivateKey) childPrvKey.getKey()).getS().toByteArray());
        System.out.println(KeyChecker.checkKeyPair(correctKeyPair));

        KeyPair childKeyPair = new KeyPair((PublicKey) childPubKey.getKey(), (PrivateKey) childPrvKey.getKey());
        System.out.println(KeyChecker.checkKeyPair(childKeyPair));

        for (int i = 0; i < 20; i++) {
            ExtendedKey grandChildPrvKey = derive(i, childPrvKey);
            ExtendedKey grandChildPubKey = derive(i, childPubKey);
            KeyPair grandChildKeyPair = new KeyPair((PublicKey) grandChildPubKey.getKey(), (PrivateKey) grandChildPrvKey.getKey());
            System.out.println(i + ": " + KeyChecker.checkKeyPair(grandChildKeyPair));
            childPrvKey = grandChildPrvKey;
            childPubKey = grandChildPubKey;
        }
    }

    public static ExtendedKey genRootKey(byte[] seed) throws Exception {
        if (seed.length < 16 || seed.length > 64) {
            throw new InvalidParameterException("seed bytes length should between 16 and 64");
        }

        HMac hMac = new HMac(HmacAlgorithm.HmacSHA512, masterKey);
        byte[] lr = hMac.digest(seed);
        byte[] secretKey = new byte[lr.length / 2];
        byte[] chainCode = new byte[lr.length / 2];
        System.arraycopy(lr, 0, secretKey, 0, lr.length / 2);
        System.arraycopy(lr, lr.length / 2, chainCode, 0, lr.length / 2);
        KeyPair keyPair = KeyConvertor.genByPrvKey(secretKey);
        return ExtendedKey.builder()
                .key(keyPair.getPrivate())
                .extendedPubKey(keyPair.getPublic())
                .chaincode(chainCode)
                .isPrivate(Boolean.TRUE)
                .build()
                .fillKeyBytes();
    }

    public static ExtendedKey derive(long index, ExtendedKey extendedKey) throws Exception {
        if (!extendedKey.isPrivate && index >= hardenedKeyStart) {
            throw new SecurityException("cannot derive key from hardened public key");
        }
        byte[] data;
        if (index >= hardenedKeyStart) {
            data = extendedKey.getKey().getEncoded();
        } else {
            if (extendedKey.isPrivate) {
                if (null == extendedKey.getExtendedPubKey()) {
                    PublicKey publicKey = KeyConvertor.genByPrvKey(((ECPrivateKey) extendedKey.getKey()).getS().toByteArray()).getPublic();
                    extendedKey.setExtendedPubKey(publicKey);
                }
                data = extendedKey.getExtendedPubKey().getEncoded();
            } else {
                data = extendedKey.getKey().getEncoded();
            }
        }

        byte[] chaincode = extendedKey.getChaincode();
        HMac hMac = new HMac(HmacAlgorithm.HmacSHA512, chaincode);
        byte[] lr = hMac.digest(data);
        byte[] secretKey = new byte[lr.length / 2];
        byte[] childChainCode = new byte[lr.length / 2];
        System.arraycopy(lr, 0, secretKey, 0, lr.length / 2);
        System.arraycopy(lr, lr.length / 2, childChainCode, 0, lr.length / 2);

        if (extendedKey.isPrivate()) {
            // 派生普通拓展私钥
            ECPrivateKey parentPrvKey = (ECPrivateKey) extendedKey.getKey();
            BigInteger childS = (parentPrvKey.getS().add(new BigInteger(1, secretKey))).mod(parentPrvKey.getParams().getOrder());
            Key childPrvKey = KeyConvertor.genByPrvKey(childS.toByteArray()).getPrivate();
            return ExtendedKey.builder()
                    .key(childPrvKey)
                    .chaincode(childChainCode)
                    .isPrivate(Boolean.TRUE)
                    .build()
                    .fillKeyBytes();
        } else {
            // 派生普通拓展公钥
            ECPublicKey parentPubKey = (ECPublicKey) extendedKey.getKey();
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            KeyFactory kf = KeyFactory.getInstance("EC");

            ECMultiplier multiplier = new ECMultiplier();
            org.bouncycastle.math.ec.ECPoint parentPoint = EC5Util.convertPoint(ecParameters, parentPubKey.getW(), false);
            org.bouncycastle.math.ec.ECPoint G = EC5Util.convertPoint(ecParameters, parentPubKey.getParams().getGenerator(), false);
            org.bouncycastle.math.ec.ECPoint childPoint = multiplier.multiply(G, new BigInteger(1, secretKey));
            ECPoint pubPoint = EC5Util.convertPoint(parentPoint.add(childPoint).normalize());
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
            ECPublicKey childPubKey = (ECPublicKey) kf.generatePublic(pubSpec);

            return ExtendedKey.builder()
                    .key(childPubKey)
                    .chaincode(childChainCode)
                    .isPrivate(Boolean.FALSE)
                    .build()
                    .fillKeyBytes();
        }
    }

    @Data
    @Builder
    public static class ExtendedKey {
        // This will be the pubkey for extended pub keys
        private Key key;

        // This will only be set for extended priv keys
        private PublicKey extendedPubKey;

        // 33字节
        private byte[] keyBytes;

        private byte[] chaincode;

        private int depth;

        private byte[] parentFP;

        private long childNum;

        private byte[] version;

        private boolean isPrivate;

        public ExtendedKey fillKeyBytes() throws Exception {
            if (isPrivate) {
                this.keyBytes = new byte[33];
                byte[] tmp = ((ECPrivateKey) this.key).getS().toByteArray();
                int offset = this.keyBytes.length - tmp.length;
                System.arraycopy(tmp, 0, this.keyBytes, offset, tmp.length);
            } else {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec("secp256r1"));
                ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
                org.bouncycastle.math.ec.ECPoint bcPoint = EC5Util.convertPoint(ecParameters, ((ECPublicKey) this.key).getW(), false);
                this.keyBytes = bcPoint.getEncoded(true);
            }
            return this;
        }
    }
}
