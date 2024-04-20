package org.example.block;

import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentHashMap;

public class Connection {

    private static final ConcurrentHashMap<Identity, Gateway> connectMap = new ConcurrentHashMap<>();

    public void connect(Identity identity) throws Exception {
        // load a CCP
        Path networkConfigPath = Paths.get("/Users/hezhidong/Documents/learningspace/fabric-samples/", "test-network", "organizations", "peerOrganizations", "org1.example.com", "connection-org1.yaml");

        Gateway.Builder builder = Gateway.createBuilder();
        builder.identity(identity).networkConfig(networkConfigPath).discovery(true);
        connectMap.putIfAbsent(identity, builder.connect());
    }

    public static Gateway getConnection(Identity identity) {
        return connectMap.get(identity);
    }
}
