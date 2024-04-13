package org.example.crypto;

import cn.hutool.core.codec.Base58;
import cn.hutool.core.util.ByteUtil;
import cn.hutool.crypto.digest.HMac;
import cn.hutool.crypto.digest.HmacAlgorithm;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.digest.RIPEMD160;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.example.utils.ByteUtils;
import sun.security.jca.JCAUtil;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.zip.CRC32;

import static org.example.crypto.KeyConvertor.CURVE_SECP256R1;

public class HDKeyChain {

    private static final byte[] masterKey = "HyperledgerFabic Seed".getBytes();

    private static final long hardenedKeyStart = 0x80000000L;

    private static final int maxDepth = 255;

    private static final int versionLen = 4;

    public static final int depthLen = 1;

    public static final int parentFPLen = 4;

    public static final int indexLen = 4;

    public static final int chaincodeLen = 32;

    public static final int keyLen = 33;

    // 78字节
    public static final int serializedKeyLen = versionLen + depthLen + parentFPLen + indexLen + chaincodeLen + keyLen;

    // BIP32 hierarchical deterministic extended key magics
    public static final byte[] HDPrivateKeyID = new BigInteger("0488ade4", 16).toByteArray(); // starts with xprv
    public static final byte[] HDPublicKeyID = new BigInteger("0488b21e", 16).toByteArray(); // starts with xpub

    public static void main(String[] args) throws Exception {
//        testDerive();
        testSerialize();
    }

    public static void testDerive() throws Exception {
        byte[] seed = new byte[32];
        SecureRandom random = JCAUtil.getSecureRandom();
        random.nextBytes(seed);
        ExtendedKey rootPrvKey = genRootKey(HDPrivateKeyID, seed);
        ExtendedKey rootPubKey = neuter(rootPrvKey);
        KeyPair keyPair = new KeyPair((PublicKey) rootPubKey.getKey(), (PrivateKey) rootPrvKey.getKey());
        System.out.println(KeyChecker.checkKeyPair(keyPair));
        System.out.println(rootPrvKey.serialize());
        System.out.println(rootPubKey.serialize());

        ExtendedKey childPrvKey = derive(1, rootPrvKey);
        ExtendedKey childPubKey = derive(1, rootPubKey);
        System.out.println(childPrvKey.serialize());
        System.out.println(childPubKey.serialize());

        KeyPair correctKeyPair = KeyConvertor.genByPrvKey(((ECPrivateKey) childPrvKey.getKey()).getS().toByteArray());
        System.out.println(KeyChecker.checkKeyPair(correctKeyPair));

        KeyPair childKeyPair = new KeyPair((PublicKey) childPubKey.getKey(), (PrivateKey) childPrvKey.getKey());
        System.out.println(KeyChecker.checkKeyPair(childKeyPair));

        for (int i = 0; i < 20; i++) {
            System.out.println("=====================================");
            ExtendedKey grandChildPrvKey = derive(i, childPrvKey);
            ExtendedKey grandChildPubKey = derive(i, childPubKey);
            System.out.println(grandChildPrvKey.serialize());
            System.out.println(grandChildPubKey.serialize());
            KeyPair grandChildKeyPair = new KeyPair((PublicKey) grandChildPubKey.getKey(), (PrivateKey) grandChildPrvKey.getKey());
            System.out.println(i + ": " + KeyChecker.checkKeyPair(grandChildKeyPair));
            childPrvKey = grandChildPrvKey;
            childPubKey = grandChildPubKey;
        }
    }

    public static void testSerialize() throws Exception {
        byte[] seed = new byte[32];
        SecureRandom random = JCAUtil.getSecureRandom();
        random.nextBytes(seed);
        ExtendedKey rootPrvKey = genRootKey(HDPrivateKeyID, seed);
        ExtendedKey rootPubKey = neuter(rootPrvKey);
        KeyPair keyPair = new KeyPair((PublicKey) rootPubKey.getKey(), (PrivateKey) rootPrvKey.getKey());
        System.out.println(KeyChecker.checkKeyPair(keyPair));

        String prvKeySerialize = rootPrvKey.serialize();
        String pubKeySerialize = rootPubKey.serialize();
        System.out.println(prvKeySerialize);
        System.out.println(pubKeySerialize);

        ExtendedKey prvKeyDeserialize = ExtendedKey.deserialize(prvKeySerialize);
        ExtendedKey pubKeyDeserialize = ExtendedKey.deserialize(pubKeySerialize);
        KeyPair keyPair1 = new KeyPair((PublicKey) pubKeyDeserialize.getKey(), (PrivateKey) prvKeyDeserialize.getKey());
        System.out.println("deser:" + KeyChecker.checkKeyPair(keyPair1));

        ExtendedKey childPrvKey = derive(1, rootPrvKey);
        ExtendedKey childPubKey = derive(1, rootPubKey);
        System.out.println(childPrvKey.serialize());
        System.out.println(childPubKey.serialize());

        KeyPair childKeyPair = new KeyPair((PublicKey) childPubKey.getKey(), (PrivateKey) childPrvKey.getKey());
        System.out.println(KeyChecker.checkKeyPair(childKeyPair));

        for (int i = 0; i < 20; i++) {
            ExtendedKey grandChildPrvKey = derive(i, childPrvKey);
            ExtendedKey grandChildPubKey = derive(i, childPubKey);
            ExtendedKey grandSerPrvKey = ExtendedKey.deserialize(grandChildPrvKey.serialize());
            ExtendedKey grandSerPubKey = ExtendedKey.deserialize(grandChildPubKey.serialize());
            KeyPair grandChildKeyPair = new KeyPair((PublicKey) grandSerPubKey.getKey(), (PrivateKey) grandSerPrvKey.getKey());
            System.out.println("deser" + i + ": " + KeyChecker.checkKeyPair(grandChildKeyPair));
            childPrvKey = grandSerPrvKey;
            childPubKey = grandSerPubKey;
        }
    }

    public static ExtendedKey genRootKey(byte[] version, byte[] seed) throws Exception {
        if (seed.length < 16 || seed.length > 64) {
            throw new InvalidParameterException("seed bytes length should between 16 and 64");
        }

        HMac hMac = new HMac(HmacAlgorithm.HmacSHA512, masterKey);
        byte[] lr = hMac.digest(seed);
        byte[] secretKey = new byte[lr.length / 2];
        byte[] chainCode = new byte[lr.length / 2];
        System.arraycopy(lr, 0, secretKey, 0, lr.length / 2);
        System.arraycopy(lr, lr.length / 2, chainCode, 0, lr.length / 2);
        Key key = KeyConvertor.getPrvKey(secretKey);


        return ExtendedKey.builder()
                .version(version)
                .key(key)
                .chaincode(chainCode)
                .parentFP(new byte[]{0x00 ,0x00, 0x00 ,0x00})
                .depth(0)
                .childNum(0)
                .isPrivate(Boolean.TRUE)
                .build()
                .putKeyBytes();
    }

    // 生成扩展公钥
    public static ExtendedKey neuter(ExtendedKey extendedKey) throws Exception {
        if (!extendedKey.isPrivate()) {
            return extendedKey;
        }

        return ExtendedKey.builder()
                .version(HDPublicKeyID)
                .key(KeyConvertor.getPubKeyFromPrvKey((ECPrivateKey) extendedKey.getKey()))
                .chaincode(extendedKey.getChaincode())
                .parentFP(extendedKey.getParentFP())
                .depth(extendedKey.getDepth())
                .childNum(extendedKey.getChildNum())
                .isPrivate(Boolean.FALSE)
                .build()
                .putKeyBytes();
    }

    public static ExtendedKey derive(long index, ExtendedKey extendedKey) throws Exception {

        if (maxDepth == extendedKey.getDepth()) {
            throw new InvalidParameterException("cannot derive a key with more than 255 indices in its path");
        }

        boolean isChildHardened = index >= hardenedKeyStart;
        if (!extendedKey.isPrivate && isChildHardened) {
            throw new SecurityException("cannot derive a hardened key from a public key");
        }

        byte[] data = new byte[keyLen + 4];
        if (isChildHardened) {
            byte[] keyBytes = ((ECPrivateKey) extendedKey.getKey()).getS().toByteArray();
            int offset = keyLen - keyBytes.length;
            System.arraycopy(keyBytes, 0, data, offset, keyBytes.length);
        } else {
            byte[] pubKeyBytes = getPubKeyBytes(extendedKey);
            System.arraycopy(pubKeyBytes, 0, data, 0, pubKeyBytes.length);
        }

        ByteUtils.putUint32BigEndian(data, index, keyLen);

        byte[] chaincode = extendedKey.getChaincode();
        HMac hMac = new HMac(HmacAlgorithm.HmacSHA512, chaincode);
        byte[] lr = hMac.digest(data);
        byte[] secretKey = new byte[lr.length / 2];
        byte[] childChainCode = new byte[lr.length / 2];
        System.arraycopy(lr, 0, secretKey, 0, lr.length / 2);
        System.arraycopy(lr, lr.length / 2, childChainCode, 0, lr.length / 2);

        Key childKey;
        if (extendedKey.isPrivate()) {
            // 派生私钥
            ECPrivateKey parentPrvKey = (ECPrivateKey) extendedKey.getKey();
            BigInteger S = (parentPrvKey.getS().add(new BigInteger(1, secretKey))).mod(parentPrvKey.getParams().getOrder());
            childKey = KeyConvertor.getPrvKey(S);

        } else {
            // 派生公钥
            ECPublicKey parentPubKey = (ECPublicKey) extendedKey.getKey();
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            KeyFactory kf = KeyFactory.getInstance("EC");

            ECMultiplier multiplier = new ECMultiplier();
            org.bouncycastle.math.ec.ECPoint parentPoint = EC5Util.convertPoint(ecParameters, parentPubKey.getW(), false);
            org.bouncycastle.math.ec.ECPoint G = EC5Util.convertPoint(ecParameters, parentPubKey.getParams().getGenerator(), false);
            org.bouncycastle.math.ec.ECPoint childPoint = multiplier.multiply(G, new BigInteger(1, secretKey));
            ECPoint pubPoint = EC5Util.convertPoint(parentPoint.add(childPoint).normalize());
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
            childKey = kf.generatePublic(pubSpec);

        }

        byte[] parentFP = new byte[4];
        byte[] parentPubKeyHash = hash160(getPubKeyBytes(extendedKey));
        System.arraycopy(parentPubKeyHash, 0, parentFP, 0, parentFP.length);

        return ExtendedKey.builder()
                .version(extendedKey.getVersion())
                .key(childKey)
                .chaincode(childChainCode)
                .parentFP(parentFP)
                .depth(extendedKey.getDepth() + 1)
                .childNum(index)
                .isPrivate(extendedKey.isPrivate())
                .build()
                .putKeyBytes();
    }

    public static byte[] getPubKeyBytes(ExtendedKey extendedKey) throws Exception {
        byte[] data;
        if (extendedKey.isPrivate) {
            if (null == extendedKey.getExtendedPubKey()) {
                PublicKey publicKey = KeyConvertor.genByPrvKey(((ECPrivateKey) extendedKey.getKey()).getS().toByteArray()).getPublic();
                extendedKey.setExtendedPubKey(publicKey);
            }
            data = KeyConvertor.pubKey2Bytes((ECPublicKey) extendedKey.getExtendedPubKey());
        } else {
            data = KeyConvertor.pubKey2Bytes((ECPublicKey) extendedKey.getKey());
        }
        return data;
    }

    public static byte[] hash160(byte[] b) {
        RIPEMD160.Digest ripemd160 = new RIPEMD160.Digest();
        SHA256.Digest sha256 = new SHA256.Digest();
        return sha256.digest(ripemd160.digest(b));
    }

    @Data
    @Builder
    @ToString
    public static class ExtendedKey {
        // This will be the pubkey for extended pub keys
        @ToString.Exclude
        private Key key;

        // This will only be set for extended priv keys
        @ToString.Exclude
        private PublicKey extendedPubKey;

        // 33字节
        @ToString.Exclude
        private byte[] keyBytes;

        @ToString.Exclude
        private byte[] chaincode;

        private int depth;

        private byte[] parentFP;

        private long childNum;

        @ToString.Exclude 
        private byte[] version;

        private boolean isPrivate;

        public ExtendedKey putKeyBytes() throws Exception {
            if (isPrivate) {
                this.keyBytes = new byte[33];
                byte[] tmp = ((ECPrivateKey) this.key).getS().toByteArray();
                int offset = this.keyBytes.length - tmp.length;
                System.arraycopy(tmp, 0, this.keyBytes, offset, tmp.length);
            } else {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
                ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
                org.bouncycastle.math.ec.ECPoint bcPoint = EC5Util.convertPoint(ecParameters, ((ECPublicKey) this.key).getW(), false);
                this.keyBytes = bcPoint.getEncoded(true);
            }
            return this;
        }

        public String serialize() {
            System.out.println(this);
            StringBuilder binary = new StringBuilder()
                    .append(ByteUtils.toBinary(version, versionLen * 8))
                    .append(ByteUtils.formatBinary(Integer.toBinaryString(depth), depthLen * 8))
                    .append(ByteUtils.toBinary(parentFP, parentFPLen * 8))
                    .append(ByteUtils.formatBinary(Long.toBinaryString(childNum), indexLen * 8))
                    .append(ByteUtils.toBinary(chaincode, chaincodeLen * 8))
                    .append(ByteUtils.toBinary(keyBytes, keyLen * 8));
            CRC32 crc32 = new CRC32();
            crc32.reset();
            crc32.update(new BigInteger(binary.toString(), 2).toByteArray());
            binary.append(ByteUtils.formatBinary(Long.toBinaryString(crc32.getValue()), 32));
            return Base58.encode(new BigInteger(binary.toString(), 2).toByteArray());
        }

        public static ExtendedKey deserialize(String base58Key) throws Exception {

            byte[] decoded = Base58.decode(base58Key);
            if (decoded.length != serializedKeyLen + 4) {
                throw new InvalidKeyException("the provided serialized extended key length is invalid");
            }

            byte[] payload = Arrays.copyOfRange(decoded, 0, decoded.length - 4);
            byte[] checksum = Arrays.copyOfRange(decoded, decoded.length - 4, decoded.length);
            CRC32 crc32 = new CRC32();
            crc32.reset();
            crc32.update(payload);
            if (crc32.getValue() != new BigInteger(1, checksum).longValue()) {
                throw new InvalidKeyException("bad extended key checksum");
            }

            int cursor = 0;
            byte[] version = new byte[versionLen];
            System.arraycopy(decoded, cursor, version, 0, version.length);
            cursor += version.length;

            int depth = decoded[cursor] & 0xFF;
            cursor++;

            byte[] parentFP = new byte[parentFPLen];
            System.arraycopy(decoded, cursor, parentFP, 0, parentFP.length);
            cursor += parentFP.length;

            byte[] childNumBytes = new byte[indexLen];
            System.arraycopy(decoded, cursor, childNumBytes, 0, childNumBytes.length);
            long childNum = new BigInteger(1, childNumBytes).longValue();
            cursor += childNumBytes.length;

            byte[] chaincode = new byte[chaincodeLen];
            System.arraycopy(decoded, cursor, chaincode, 0, chaincode.length);
            cursor += chaincode.length;

            byte[] keyBytes = new byte[keyLen];
            System.arraycopy(decoded, cursor, keyBytes, 0, keyBytes.length);
            cursor += keyBytes.length;

            boolean isPrivate = keyBytes[0] == 0x00;

            Key key = isPrivate ? KeyConvertor.getPrvKey(keyBytes) : KeyConvertor.getPubKey(keyBytes);

            return ExtendedKey.builder()
                    .version(version)
                    .key(key)
                    .keyBytes(keyBytes)
                    .chaincode(chaincode)
                    .parentFP(parentFP)
                    .depth(depth)
                    .childNum(childNum)
                    .isPrivate(isPrivate)
                    .build();
        }
    }

    public String getDerivationPath() {
        return "";
    }
}
