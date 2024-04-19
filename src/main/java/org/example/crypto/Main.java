package org.example.crypto;

import cn.hutool.core.io.checksum.CRC8;
import cn.hutool.crypto.ECKeyUtil;
import cn.hutool.crypto.KeyUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;

import static org.example.crypto.KeyConvertor.*;

public class Main {
    public static void main(String[] args) throws Exception {
        String pubKeyCompressedY = "03352db48f648270d0cef2d780512b39e37a5b6528e73dcac542aa5071a64e6385";
        String prvKeyHex = "f77ff8ab40835f5dd9845c5055bafc2baf4d80ceff2abb2b56597487c92028b0";
        PublicKey pubKey = getPubKey(new BigInteger(pubKeyCompressedY, 16).toByteArray(), CURVE_SECP256K1);
        PrivateKey prvKey = getPrvKey(new BigInteger(prvKeyHex, 16), CURVE_SECP256K1);
        System.out.println(KeyChecker.checkKeyPair(new KeyPair(pubKey, prvKey)));
        String signed = KeyChecker.sign("coco", prvKey);
        System.out.println(KeyChecker.verify("coco", signed, pubKey));
        String signText = "30440220256322dfbb8db6446e1dd50f850168b9e886e6fa53061d6a63330e4320a7c03102207d31dc65b057a394da12941805666bb8472785e744fef8e5974d18b273be00b7";
        System.out.println(KeyChecker.verify("coco", signText, pubKey));
    }
}
