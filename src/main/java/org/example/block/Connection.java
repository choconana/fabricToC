package org.example.block;

import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class Connection {

    public static final String CHANNEL = "mychannel";

    private static final ConcurrentHashMap<String, Gateway> connectMap = new ConcurrentHashMap<>();

    public void connect(String pubkeyHex, Identity identity) throws Exception {
        // load a CCP
        Path networkConfigPath = Paths.get("/Users/hezhidong/Documents/learningspace/fabric-samples/", "test-network", "organizations", "peerOrganizations", "org1.example.com", "connection-org1.yaml");

        Gateway.Builder builder = Gateway.createBuilder();
        builder.identity(identity).networkConfig(networkConfigPath).discovery(true);
        connectMap.putIfAbsent(pubkeyHex, builder.connect());
        log.info("{},{} has connected", pubkeyHex, identity);
    }

    public static Gateway getConnection(String pubkeyHex) {
        return connectMap.get(pubkeyHex);
    }
}
