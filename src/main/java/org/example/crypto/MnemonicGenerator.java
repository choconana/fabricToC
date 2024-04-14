package org.example.crypto;

import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.PBKDF2;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jcajce.provider.digest.SHA256;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HashMap;

public class MnemonicGenerator {

    private final static String[] words = new String[2048];

    // Map<word, binary>
    private final static HashMap<String, String> wordsIndex = new HashMap<>();

    static {
        try {
            String resourcePath = MnemonicGenerator.class.getClassLoader().getResource("").getPath();
            String filePath = resourcePath + "static/bip-0032/chinese_simplified.txt";
            FileInputStream fin = new FileInputStream(filePath);
            InputStreamReader reader = new InputStreamReader(fin);
            BufferedReader buffReader = new BufferedReader(reader);
            String strTmp;
            int i = 0;
            while((strTmp = buffReader.readLine())!=null){
                wordsIndex.put(strTmp, String.format("%11s", Integer.toBinaryString(i)).replace(" ", "0"));
                words[i++] = strTmp;
            }
            buffReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static byte[] mnemonic2Entropy(byte[] mnemonic, String phase) throws NoSuchAlgorithmException {
        PBKDF2 pbkdf2 = new PBKDF2();
        String salt = "mnemonic" + (StringUtils.isEmpty(phase) ? "" : ":" + phase);
        return pbkdf2.encrypt(StringUtils.toEncodedString(mnemonic, StandardCharsets.UTF_8).toCharArray(), salt.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] random(int size) throws NoSuchAlgorithmException {

        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

        byte[] salt = new byte[size];

        sr.nextBytes(salt);

        return salt;

    }

    // 12助记词
    public static String[] genMnemonic12() throws NoSuchAlgorithmException {
        byte[] seed = random(16);
        MD5.create().digest(seed);
        String seedStr = StringUtils.leftPad(new BigInteger(1, MD5.create().digest(seed)).toString(2), 128, '0');
        String pad = StringUtils.leftPad(BigInteger.valueOf(crc4ITU(seed, 0, seed.length)).toString(2), 4, '0');
        return genMnemonic(seedStr + pad, 12);
    }

    // 24助记词
    public static String[] genMnemonic24() throws NoSuchAlgorithmException {
        byte[] seed = random(32);
        SHA256.Digest sha256 = new SHA256.Digest();
        String seedStr = StringUtils.leftPad(new BigInteger(1, sha256.digest(seed)).toString(2), 256, '0');
        String pad = StringUtils.leftPad(BigInteger.valueOf(crc4ITU(seed, 0, seed.length)).toString(2), 8, '0');
        return genMnemonic(seedStr + pad, 24);
    }

    public static String[] genMnemonic(String binaryStr, int size) {
        if (binaryStr.length() != size * 11) {
            throw new IllegalArgumentException("invalid mnemonic size");
        }
        char[] binary = binaryStr.toCharArray();
        String[] mnemonic = new String[size];
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

    public static byte[] mnemonic2Entropy(String[] mnemonic) {
        StringBuilder binary = new StringBuilder();
        for (String word : mnemonic) {
            binary.append(wordsIndex.get(word));
        }
        return new BigInteger(binary.toString(), 2).toByteArray();
    }

    public static byte crc4ITU(byte[] data, int offset,int length){
        byte crc = 0;
        length += offset;
        for(int j = offset; j < length; j++) {
            crc ^= data[j];
            for (int i = 0; i < 8; ++i){
                if ((crc & 1) != 0x00)
                    crc = (byte) (((crc & 0xff) >> 1 ) ^ 0x0C);
                else
                    crc = (byte) ((crc & 0xff) >> 1);
            }
        }
        return (byte) (crc & 0xf);
    }

    public static void testCrc4() throws NoSuchAlgorithmException {
        byte[] seed = random(1);
        String seedStr = new BigInteger(1, seed).toString(2);
        String pad = String.format("%4s", BigInteger.valueOf(crc4ITU(seed, 0, seed.length)).toString(2)).replace(' ', '0');
        System.out.println(seedStr+pad);
    }

    public static void main(String[] args) throws Exception {
        String[] mnemonic = genMnemonic24();
        String phase = "";
        HDKeyChain.ExtendedKey rootPrvKey = HDKeyChain.genRootKey(HDKeyChain.HDPrivateKeyID_BIP44, mnemonic2Entropy(mnemonic2Entropy(mnemonic), phase));
        HDKeyChain.ExtendedKey rootPubKey = HDKeyChain.neuter(rootPrvKey);
        KeyPair keyPair = new KeyPair((PublicKey) rootPubKey.getKey(), (PrivateKey) rootPrvKey.getKey());
        System.out.println(KeyChecker.checkKeyPair(keyPair));
//        testCrc4();
    }
}
