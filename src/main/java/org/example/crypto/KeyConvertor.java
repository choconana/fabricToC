package org.example.crypto;

import cn.hutool.core.io.checksum.CRC8;
import cn.hutool.crypto.KeyUtil;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Point;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

public class KeyConvertor {
    
    public static final String CURVE_SECP256R1 = "secp256r1";
    
    public static void main(String[] args) throws Exception {
        CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
        KeyPair keyPair0 = cryptoSuite.keyGen();
        PrivateKey privateKey = keyPair0.getPrivate();
        System.out.println(privateKey);
        BigInteger d = ((BCECPrivateKey) privateKey).getD();
        PrivateKey privateKey1 = KeyUtil.generatePrivateKey("EC", privateKey.getEncoded());
        ECPrivateKeyParameters prvParam = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey1);
        ECMultiplier multiplier = new ECMultiplier();
        org.bouncycastle.math.ec.ECPoint Q = multiplier.multiply(prvParam.getParameters().getG(), d).normalize();



        KeyPair keyPair = createKey();
        KeyPair recreateKeyPair = recreateKey(keyPair);
        System.out.println(keyPair);
        String cert = cryptoSuite.generateCertificationRequest("admin", recreateKeyPair);
        System.out.println(cert);
        String binary = ((ECPrivateKey) keyPair0.getPrivate()).getS().toString(2);
        KeyPair recreateKeyPair1 = recreateByPrvKey(binary);
        System.out.println(recreateKeyPair1);

        CRC8 checksum = new CRC8(123, (short) 0);
        checksum.reset();
        byte[] bytes = new BigInteger(binary + "111", 2).toByteArray();
        checksum.update(bytes);
        long checksumValue = checksum.getValue();
        System.out.println(String.format("%8s", Long.toBinaryString(checksumValue)).replace(' ', '0'));
    }

    public static KeyPair createKey() throws Exception {
        return KeyPairGenerator.getInstance("EC").genKeyPair();
    }

    public static KeyPair recreateKey(KeyPair keyPair) throws Exception {
//        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
//        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        byte[] privateKeyS0 = privateKey.getS().toByteArray();
        byte[] publicKeyX0 = publicKey.getW().getAffineX().toByteArray();
        byte[] publicKeyY0 = publicKey.getW().getAffineY().toByteArray();
        String encodedPrivateKey = Base64.getEncoder().encodeToString(privateKeyS0);
        String encodedPublicKeyX = Base64.getEncoder().encodeToString(publicKeyX0);
        String encodedPublicKeyY = Base64.getEncoder().encodeToString(publicKeyY0);
        byte[] privateKeyS = Base64.getDecoder().decode(encodedPrivateKey);
        byte[] publicKeyX = Base64.getDecoder().decode(encodedPublicKeyX);
        byte[] publicKeyY = Base64.getDecoder().decode(encodedPublicKeyY);
        ECPoint pubPoint = new ECPoint(new BigInteger(1, publicKeyX), new BigInteger(1, publicKeyY));
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(new BigInteger(1, privateKeyS), ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPrivateKey newPrvKey = (ECPrivateKey) kf.generatePrivate(privateSpec);
        ECPublicKey newPubKey = (ECPublicKey) kf.generatePublic(pubSpec);
        return new KeyPair(newPubKey, newPrvKey);
    }

    public static KeyPair recreateByPrvKey(String binary) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

        BigInteger D = new BigInteger(binary, 2);
        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(D, ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(privateSpec);

//        PrivateKey privateKey1 = KeyUtil.generatePrivateKey("EC", privateKey.getEncoded());
        ECPrivateKeyParameters prvParam = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey);
        ECMultiplier multiplier = new ECMultiplier();
        org.bouncycastle.math.ec.ECPoint Q = multiplier.multiply(prvParam.getParameters().getG(), D).normalize();
        ECPoint pubPoint = EC5Util.convertPoint(Q);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);

        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair genByPrvKey(byte[] prvKey) throws Exception {
        return recreateByPrvKey(new BigInteger(1, prvKey).toString(2));
    }

    public static PrivateKey getPrvKey(BigInteger S) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(S, ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(privateSpec);
    }

    public static PrivateKey getPrvKey(byte[] prvKeyBytes) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(new BigInteger(1, prvKeyBytes), ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(privateSpec);
    }

    public static PublicKey getPubKey(byte[] pubKeyBytes) throws Exception {

        PublicKey publicKey = null;

        switch (pubKeyBytes.length) {
            case 65:
                // 未压缩
                return publicKey;
            case 33:
                // 压缩处理过
                byte format = pubKeyBytes[0];
                byte[] x = Arrays.copyOfRange(pubKeyBytes, 1, pubKeyBytes.length);
                boolean isOddY = format == 0x03;
                publicKey = decompressY(x, isOddY);
        }
        return publicKey;
    }

    private static PublicKey decompressY(byte[] x, boolean isOddY) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        KeyFactory kf = KeyFactory.getInstance("EC");

        // y^2 = x^3 + ax + b => y = +-sqrt(x^3 + ax + b)
        SecP256R1Curve curve = new SecP256R1Curve();
        ECFieldElement A = curve.getA();
        ECFieldElement B = curve.getB();
        ECFieldElement X = curve.fromBigInteger(new BigInteger(1, x));
        ECFieldElement Y = X.square().multiply(X).add(A.multiply(X)).add(B).sqrt();
        org.bouncycastle.math.ec.ECPoint P = new SecP256R1Point(curve, X, Y);
        P.normalize();
        if (P.getAffineYCoord().testBitZero() != isOddY) {
            P = P.negate();
        }
        ECPoint pubPoint = EC5Util.convertPoint(P);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        return kf.generatePublic(pubSpec);
    }

    public static byte[] getPubKeyBytesFromPrvKey(byte[] prvKey) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

        BigInteger S = new BigInteger(1, prvKey);
        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(S, ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(privateSpec);

        return getPubKeyBytesFromPrvKey(privateKey);
    }

    public static byte[] getPubKeyBytesFromPrvKey(ECPrivateKey privateKey) throws Exception {
        ECPrivateKeyParameters prvParam = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey);
        ECMultiplier multiplier = new ECMultiplier();
        org.bouncycastle.math.ec.ECPoint Q = multiplier.multiply(prvParam.getParameters().getG(), privateKey.getS()).normalize();
        return Q.getEncoded(true);
    }

    public static PublicKey getPubKeyFromPrvKey(ECPrivateKey privateKey) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        KeyFactory kf = KeyFactory.getInstance("EC");

        ECPrivateKeyParameters prvParam = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey);
        ECMultiplier multiplier = new ECMultiplier();
        org.bouncycastle.math.ec.ECPoint Q = multiplier.multiply(prvParam.getParameters().getG(), privateKey.getS()).normalize();
        ECPoint pubPoint = EC5Util.convertPoint(Q);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        return kf.generatePublic(pubSpec);
    }

    public static byte[] pubKey2Bytes(ECPublicKey publicKey) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        org.bouncycastle.math.ec.ECPoint bcPoint = EC5Util.convertPoint(ecParameters, publicKey.getW(), false);
        return bcPoint.getEncoded(true);
    }
}
