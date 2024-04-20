package org.example.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.example.config.CaConfig;
import org.example.service.LoginService;
import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.gateway.impl.identity.GatewayUser;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
public class LoginServiceImpl implements LoginService {

    public final Map<String, User> userMap = new HashMap<>();

    @Autowired
    private CaConfig caConfig;

    @Override
    public Identity register(String username, String mspId, String affiliation) {
        Wallet wallet;
        try {
            wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));
            User admin = userMap.get("admin");
            if (null == admin) {
                X509Identity adminIdentity = (X509Identity) this.createAdmin(mspId);
                wallet.put("admin", adminIdentity);
                admin = new GatewayUser("admin", mspId, new X509Enrollment(adminIdentity.getPrivateKey(), Identities.toPemString(adminIdentity.getCertificate())));
                userMap.put("admin", admin);
            }
            Identity userIdentity = this.createUser(mspId, affiliation, admin);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public String login(String cert) {
        return "";
    }

    private Identity createAdmin(String mspId) throws Exception{
        final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
        enrollmentRequestTLS.addHost("localhost");
        enrollmentRequestTLS.setProfile("tls");
        Enrollment enrollment = caConfig.hfcaClient().enroll("admin", "adminpw", enrollmentRequestTLS);
        return Identities.newX509Identity(mspId, enrollment);
    }

    private Identity createUser(String mspId, String affiliation, User registrar) throws Exception {
        String id = UUID.randomUUID().toString();
        RegistrationRequest registrationRequest = new RegistrationRequest(id);
        registrationRequest.setAffiliation(affiliation);
        registrationRequest.setEnrollmentID(id);
        String enrollmentSecret = caConfig.hfcaClient().register(registrationRequest, registrar);
        Enrollment enrollment = caConfig.hfcaClient().enroll(id, enrollmentSecret);
        return Identities.newX509Identity(mspId, enrollment);
    }
}
