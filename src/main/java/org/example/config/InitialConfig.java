package org.example.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.service.TokenErc20Service;
import org.example.service.WalletService;
import org.hyperledger.fabric.gateway.Identity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class InitialConfig {

    private final WalletService walletService;

    private final TokenErc20Service tokenErc20Service;

    @Bean
    public void init() {
        try {
            Identity identity = walletService.createAdmin();
            tokenErc20Service.initialize(identity);
        } catch (Exception e) {
            log.error("initialize failed", e);
        }
    }
}
