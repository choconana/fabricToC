package org.example.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.example.block.Connection;
import org.example.crypto.HDKeyChain;
import org.example.service.TokenErc20Service;
import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.BlockchainInfo;
import org.hyperledger.fabric.sdk.SDKUtils;
import org.hyperledger.fabric.sdk.transaction.ProtoUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.concurrent.TimeoutException;

import static org.example.crypto.KeyConvertor.CURVE_SECP256K1;
import static org.example.crypto.KeyConvertor.getPubKey;

@Slf4j
@Service
public class TokenErc20ServiceImpl implements TokenErc20Service {

    private static final String CONTRACT = "erc20";


    @Override
    public boolean initialize(Identity admin) {
        Path networkConfigPath = Paths.get("/Users/hezhidong/Documents/learningspace/fabric-samples/", "test-network", "organizations", "peerOrganizations", "org1.example.com", "connection-org1.yaml");

        Gateway.Builder builder = Gateway.createBuilder();
        try {
            builder.identity(admin).networkConfig(networkConfigPath).discovery(true);
            Gateway gateway = builder.connect();
            Network network = gateway.getNetwork(Connection.CHANNEL);
            Contract contract = network.getContract(CONTRACT);

            if (isInitialized(contract)) {
                return true;
            }
            byte[] submitted = contract.submitTransaction("Initialize", "YUANBAO", "YB", "18");
        } catch (IOException | ContractException | InterruptedException | TimeoutException e) {
            log.error("Error initializing contract", e);
            return false;
        }
        return true;
    }

    // todo pubkeyHex作为userid，在登录后应当存储在session或者缓存中，不应当从前端接收
    @Override
    public long mint(String pubkeyHex, int amount) throws Exception {

        Gateway gateway = Connection.getConnection(pubkeyHex);
        Network network = gateway.getNetwork(Connection.CHANNEL);
        Contract contract = network.getContract(CONTRACT);

        byte[] submitted = contract.submitTransaction("Mint", String.valueOf(amount));

        byte[] balance = contract.evaluateTransaction("ClientAccountBalance");

        return Long.parseLong(new String(balance));
    }

    @Override
    public long burn(String pubkeyHex, int amount) throws Exception {
        Gateway gateway = Connection.getConnection(pubkeyHex);
        Network network = gateway.getNetwork(Connection.CHANNEL);
        Contract contract = network.getContract(CONTRACT);

        byte[] submitted = contract.submitTransaction("Burn", String.valueOf(amount));

        byte[] balance = contract.evaluateTransaction("ClientAccountBalance");

        return Long.parseLong(new String(balance));
    }

    @Override
    public long totalSupply(String pubkeyHex) throws Exception {
        Gateway gateway = Connection.getConnection(pubkeyHex);
        Network network = gateway.getNetwork(Connection.CHANNEL);
        Contract contract = network.getContract(CONTRACT);

        BlockchainInfo blockchainInfo = network.getChannel().queryBlockchainInfo();
        BlockInfo blockInfo = network.getChannel().queryBlockByNumber(23);
        blockInfo.getBlock().getData();

        byte[] total = contract.evaluateTransaction("TotalSupply");

        return Long.parseLong(new String(total));
    }

    public boolean isInitialized(Contract contract) throws ContractException, InterruptedException, TimeoutException {
        byte[] submitted = contract.submitTransaction("IsInitialized");
        return "true".equals(new String(submitted));
    }
}
