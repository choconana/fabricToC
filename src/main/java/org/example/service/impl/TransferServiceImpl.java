package org.example.service.impl;

import org.example.block.App;
import org.example.service.TokenErc20Service;
import org.example.service.TransferService;
import org.springframework.stereotype.Service;

@Service
public class TransferServiceImpl implements TransferService {

    @Override
    public void runDemo() {
        App app = new App();
        app.run();
    }
}
