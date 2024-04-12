package org.example.service;

import org.hyperledger.fabric.gateway.Identity;

public interface LoginService {

    Identity register(String username, String mspId, String affiliation);

    String login(String cert);
}
