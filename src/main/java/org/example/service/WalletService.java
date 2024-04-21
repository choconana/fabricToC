package org.example.service;

import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.sdk.User;

import java.security.KeyPair;

public interface WalletService {

    Identity createAdmin() throws Exception;

    User getWalletAdmin() throws Exception;

    Identity register(String address, KeyPair proxyKey) throws Exception;

    String connect(String pubkey, String signature) throws Exception;
}
