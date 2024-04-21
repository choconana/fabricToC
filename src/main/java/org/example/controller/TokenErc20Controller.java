package org.example.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.example.service.TokenErc20Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/erc20")
@RequiredArgsConstructor
public class TokenErc20Controller {

    private final TokenErc20Service tokenErc20Service;

    @PostMapping("/mint")
    public Object mint(@RequestBody Map<String, String> params) {
        String pubkey = params.get("pub");
        String amount = params.get("amount");
        try {
            return tokenErc20Service.mint(pubkey, Integer.parseInt(amount));
        } catch (Exception e) {
            log.error(ExceptionUtils.getStackTrace(e));
            return "failed";
        }
    }

    @PostMapping("/burn")
    public Object burn(@RequestBody Map<String, String> params) {
        String pubkey = params.get("pub");
        String amount = params.get("amount");
        try {
            return tokenErc20Service.burn(pubkey, Integer.parseInt(amount));
        } catch (Exception e) {
            log.error(ExceptionUtils.getStackTrace(e));
            return "failed";
        }
    }

    @PostMapping("/totalSupply")
    public Object totalSupply(@RequestBody Map<String, String> params) {
        String pubkey = params.get("pub");
        try {
            return tokenErc20Service.totalSupply(pubkey);
        } catch (Exception e) {
            log.error(ExceptionUtils.getStackTrace(e));
            return "failed";
        }
    }
}
