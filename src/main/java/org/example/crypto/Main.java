package org.example.crypto;

import cn.hutool.core.io.checksum.CRC8;
import cn.hutool.crypto.ECKeyUtil;
import cn.hutool.crypto.KeyUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;

public class Main {
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
        parameters.init(new ECGenParameterSpec("secp256r1"));
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
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

        BigInteger D = new BigInteger(binary, 2);
        byte[] privateKeyS = D.toByteArray();
        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(new BigInteger(1, privateKeyS), ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(privateSpec);

        PrivateKey privateKey1 = KeyUtil.generatePrivateKey("EC", privateKey.getEncoded());
        ECPrivateKeyParameters prvParam = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey1);
        ECMultiplier multiplier = new ECMultiplier();
        org.bouncycastle.math.ec.ECPoint Q = multiplier.multiply(prvParam.getParameters().getG(), D).normalize();
        ECPoint pubPoint = EC5Util.convertPoint(Q);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);

        return new KeyPair(publicKey, privateKey);
    }
}
