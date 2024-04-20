package org.example.service.impl;

import cn.hutool.core.io.checksum.CRC16;
import cn.hutool.core.io.checksum.CRC8;
import lombok.extern.slf4j.Slf4j;
import org.example.service.WalletService;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

@Slf4j
@Service
public class WalletServiceImpl implements WalletService {

    static {
    }

    @Override
    public String importWordlist(String wordlist) {
        return "";
    }

    public static void main(String[] args) {
        String binary = "1001001101111101101011001110111111111011010011011010011100110001010101011001100110011101010101011001101010000111011011101111011100110101100101011000101000010110011111110101101111011001100010100000001100000101100001110000011001111110011010000000110011100010";
        CRC8 checksum = new CRC8(123, (short) 0);
        checksum.reset();
        byte[] bytes = new BigInteger(binary + "111", 2).toByteArray();
        checksum.update(bytes);
        long checksumValue = checksum.getValue();
        System.out.println(String.format("%8s", Long.toBinaryString(checksumValue)).replace(' ', '0'));
    }
}
