package com.vega.protocol.auth;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class Wallet {

    private byte[] seed = new byte[]{};
    private final Map<Integer, KeyPair> derivedKeys = new HashMap<>();

    public Wallet(final String mnemonic) {
        if(mnemonic == null) {
            throw new RuntimeException("invalid mnemonic");
        }
        try {
            seed = new DeterministicSeed(mnemonic, null, "", 0).getSeedBytes();
        } catch(Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public KeyPair get(int idx) {
        var keyPair = derivedKeys.get(idx);
        if(keyPair == null) {
            DeterministicKey root = HDKeyDerivation.createMasterPrivateKey(seed);
            DeterministicKey key = HDKeyDerivation.deriveChildKey(root, idx);
            keyPair = new KeyPair()
                    .setPrivateKey(key.getPrivateKeyAsHex())
                    .setPublicKey(getPublicKey(key.getPrivateKeyAsHex()));
            derivedKeys.put(idx, keyPair);
        }
        return keyPair;
    }

    public KeyPair getByPublicKey(final String publicKey) {
        return derivedKeys.values().stream()
                .filter(kp -> kp.getPublicKey().equalsIgnoreCase(publicKey))
                .findFirst()
                .orElse(null);
    }

    private static String getPublicKey(
            final String privateKey
    ) {
        try {
            Ed25519PrivateKeyParameters privateKeyRebuild = new Ed25519PrivateKeyParameters(
                    Hex.decodeHex(privateKey), 0);
            Ed25519PublicKeyParameters publicKeyRebuild = privateKeyRebuild.generatePublicKey();
            return Hex.encodeHexString(publicKeyRebuild.getEncoded());
        } catch(Exception e) {
            log.error(e.getMessage(), e);
            return "";
        }
    }
}