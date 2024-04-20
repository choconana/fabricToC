package org.example.controller;

import lombok.RequiredArgsConstructor;
import org.example.service.WalletService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletService walletService;

    @PostMapping("/connect")
    public String connect(Map<String, String> params) {
        String pubkey = params.get("pub");
        String signature = params.get("sig");
        try {
            return walletService.connect(pubkey, signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
