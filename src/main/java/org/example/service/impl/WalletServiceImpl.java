package org.example.service.impl;

import cn.hutool.core.io.checksum.CRC16;
import cn.hutool.core.io.checksum.CRC8;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.block.Connection;
import org.example.crypto.HDKeyChain;
import org.example.crypto.KeyChecker;
import org.example.crypto.Main;
import org.example.service.TokenErc20Service;
import org.example.service.WalletService;
import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.gateway.impl.identity.GatewayUser;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

import static org.example.crypto.KeyConvertor.CURVE_SECP256K1;
import static org.example.crypto.KeyConvertor.getPubKey;

@Slf4j
@Service
@RequiredArgsConstructor
public class WalletServiceImpl implements WalletService {

    private final TokenErc20Service tokenErc20Service;

    @Override
    public Identity createAdmin() throws Exception {
        // Create a CA client for interacting with the CA.
        Properties props = new Properties();
        props.put("pemFile",
                "/Users/hezhidong/Documents/learningspace/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem");
        props.put("allowAllHostNames", "true");
        HFCAClient caClient = HFCAClient.createNewInstance("https://localhost:7054", props);
        CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
        caClient.setCryptoSuite(cryptoSuite);

        // Create a wallet for managing identities
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));

        final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
        enrollmentRequestTLS.addHost("localhost");
        enrollmentRequestTLS.setProfile("tls");
        Enrollment enrollment = caClient.enroll("admin", "adminpw", enrollmentRequestTLS);
        Identity identity = Identities.newX509Identity("Org1MSP", enrollment);
        wallet.put("admin", identity);
        return identity;
    }

    @Override
    public User getWalletAdmin() throws Exception {


        // Create a wallet for managing identities
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));

        X509Identity identity;
        // Check to see if we've already enrolled the admin user.
        if ((identity = (X509Identity) wallet.get("admin")) == null) {
            // Enroll the admin user, and import the new identity into the wallet.
            identity = (X509Identity) this.createAdmin();
        }
        return new GatewayUser("admin", "Org1MSP", new X509Enrollment(identity.getPrivateKey(), Identities.toPemString(identity.getCertificate())));
    }

    @Override
    public Identity register(String address, KeyPair proxyKey) throws Exception {
        // Create a CA client for interacting with the CA.
        Properties props = new Properties();
        props.put("pemFile",
                "/Users/hezhidong/Documents/learningspace/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem");
        props.put("allowAllHostNames", "true");
        HFCAClient caClient = HFCAClient.createNewInstance("https://localhost:7054", props);
        CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
        caClient.setCryptoSuite(cryptoSuite);

        // Create a wallet for managing identities
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));

        Identity user;
        // Check to see if we've already enrolled the user.
        if ((user = wallet.get(address)) == null) {
            User admin = this.getWalletAdmin();

            // Register the user, enroll the user, and import the new identity into the wallet.
            RegistrationRequest registrationRequest = new RegistrationRequest(address);
            registrationRequest.setAffiliation("org1.department1");
            registrationRequest.setEnrollmentID(address);
            String enrollmentSecret = caClient.register(registrationRequest, admin);
            final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
            enrollmentRequestTLS.addHost("localhost");
            enrollmentRequestTLS.setProfile("tls");
            enrollmentRequestTLS.setKeyPair(proxyKey);
            Enrollment enrollment = caClient.enroll(address, enrollmentSecret, enrollmentRequestTLS);
            user = Identities.newX509Identity("Org1MSP", enrollment);
            wallet.put(address, user);
        }

        return user;
    }

    /**
     * 采用的是集中管理策略：一个admin管理所有用户
     * @param pubkeyHex
     * @param signature
     * @return
     * @throws Exception
     */
    @Override
    public String connect(String pubkeyHex, String signature) throws Exception {
        PublicKey pubKey = getPubKey(new BigInteger(pubkeyHex, 16).toByteArray(), CURVE_SECP256K1);
        boolean isValid = KeyChecker.verify(this.getAuthCode(pubKey), signature, pubKey);
        if (!isValid) {
            return "failed";
        }
        HDKeyChain.ExtendedKey rootPrv = HDKeyChain.genRootKey(HDKeyChain.HDPublicKeyID_BIP44, new BigInteger(pubkeyHex, 16).toByteArray());
        HDKeyChain.ExtendedKey rootPub = HDKeyChain.neuter(rootPrv);
        long index = (long) (Math.random() * (Integer.MAX_VALUE - 1) + 1);
        HDKeyChain.ExtendedKey proxyPrv = HDKeyChain.derive(index, rootPrv);
        HDKeyChain.ExtendedKey proxyPub = HDKeyChain.derive(index, rootPub);
        KeyPair proxyKey = new KeyPair((PublicKey) proxyPub.getKey(), (PrivateKey) proxyPrv.getKey());
        String address = rootPub.addressP2PKH(HDKeyChain.pubKeyHashAddrID_Test);
        Identity user = this.register(address, proxyKey);
        Connection connection = new Connection();
        connection.connect(pubkeyHex, user);
        return address;
    }

    private String getAuthCode(PublicKey pubKey) {
        return "coco";
    }

}
