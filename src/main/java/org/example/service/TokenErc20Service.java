package org.example.service;

import org.hyperledger.fabric.gateway.Identity;

public interface TokenErc20Service {

    boolean initialize(Identity admin);

    long mint(String pubkey, int amount) throws Exception;

    long burn(String pubkey, int amount) throws Exception;

    long totalSupply(String pubkey) throws Exception;
}
