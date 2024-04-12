package org.example.crypto;

import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.symmetric.PBKDF2;
import org.apache.commons.lang3.StringUtils;
import sun.security.util.BitArray;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;

public class MnemonicWordConvertor {

    private final static String[] words = new String[2048];

    static {
        String resourcePath = MnemonicWordConvertor.class.getClassLoader().getResource("").getPath();
        String filePath = resourcePath + "static/bip-0032/chinese_simplified.txt";
        try {
            FileInputStream fin = new FileInputStream(filePath);
            InputStreamReader reader = new InputStreamReader(fin);
            BufferedReader buffReader = new BufferedReader(reader);
            String strTmp;
            int i = 0;
            while((strTmp = buffReader.readLine())!=null){
                words[i++] = strTmp;
            }
            buffReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static byte[] toSeed(String[] mnemonic, String phase) throws NoSuchAlgorithmException {
        PBKDF2 sec = new PBKDF2();
        String entropy = StringUtils.join(mnemonic, ":");
        if (StringUtils.isEmpty(phase)) {
            return sec.encrypt(entropy.toCharArray(), random(16));
        } else {
            return sec.encrypt(entropy.toCharArray(), phase.getBytes(StandardCharsets.UTF_8));
        }
    }

    public static byte[] random(int size) throws NoSuchAlgorithmException {

        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

        byte[] salt = new byte[size];

        sr.nextBytes(salt);

        return salt;

    }

    public static String[] genMnemonic() throws NoSuchAlgorithmException {
        byte[] seed = random(16);
        SecureRandom sr = new SecureRandom();
        String seedStr = String.format("%128s", new BigInteger(1, seed).toString(2)).replace(' ', '0');
        String pad = String.format("%4s", new BigInteger(String.valueOf(sr.nextInt(16))).toString(2)).replace(' ', '0');
        char[] binary = (seedStr + pad).toCharArray();
        String[] mnemonic = new String[12];
        int index;
        int i = 0, m = 0;
        int len = binary.length;
        while (m < len) {
            char[] tmp = new char[11];
            System.arraycopy(binary, m, tmp, 0, 11);
            index = new BigInteger(new String(tmp), 2).intValueExact();
            mnemonic[i++] = words[index];
            m += 11;
        }
        return mnemonic;
    }

    public static void main(String[] args) throws Exception {
        String[] mnemonic = genMnemonic();
        String phase = "test";
        HDKeyChain.ExtendedKey rootPrvKey = HDKeyChain.genRootKey(HDKeyChain.HDPrivateKeyID, toSeed(mnemonic, phase));
        HDKeyChain.ExtendedKey rootPubKey = HDKeyChain.neuter(rootPrvKey);
        KeyPair keyPair = new KeyPair((PublicKey) rootPubKey.getKey(), (PrivateKey) rootPrvKey.getKey());
        System.out.println(KeyChecker.checkKeyPair(keyPair));

    }
}
