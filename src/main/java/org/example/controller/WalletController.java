package org.example.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/wallet")
public class WalletController {

    @PostMapping("/createWallet")
    public String createWallet(String password, String phase) {
        return "mnemonic";
    }

    @PostMapping("/importWordlist")
    public String importWordlist(String wordlist) {
        return "";
    }

}
