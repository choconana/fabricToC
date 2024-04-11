package org.example.controller;

import org.example.service.TokenErc20Service;
import org.example.service.TransferService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/transfer")
public class TransferController {

    @Autowired
    private TransferService transferService;

    @GetMapping("/basic")
    public String test() {
        transferService.runDemo();
        return "ok";
    }
}
