package com.vega.protocol.auth;

import io.grpc.ManagedChannelBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import vega.api.v1.Core;
import vega.api.v1.CoreServiceGrpc;
import vega.commands.v1.SignatureOuterClass;
import vega.commands.v1.TransactionOuterClass;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.UUID;

@Slf4j
public class Authenticator {

    private final Wallet wallet;
    private final String coreNode;
    private final int corePort;

    public Authenticator(final Wallet wallet, final String coreNode, final int corePort) {
        this.wallet = wallet;
        this.coreNode = coreNode;
        this.corePort = corePort;
    }

    public Core.LastBlockHeightResponse getLastBlock() {
        var request = Core.LastBlockHeightRequest.newBuilder().build();
        var channel = ManagedChannelBuilder.forAddress(this.coreNode, this.corePort).usePlaintext().build();
        var client = CoreServiceGrpc.newBlockingStub(channel);
        var lastBlock = client.lastBlockHeight(request);
        channel.shutdownNow();
        return lastBlock;
    }

    private static byte[] sha3(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        return digest.digest(data);
    }

    private String signInputData(String key, byte[] msg) throws
            DecoderException, NoSuchAlgorithmException, CryptoException {
        Signer signer = new Ed25519Signer();
        signer.init(true, new Ed25519PrivateKeyParameters(Hex.decodeHex(key), 0));
        msg = sha3(msg);
        signer.update(msg, 0, msg.length);
        byte[] signature = signer.generateSignature();
        return Hex.encodeHexString(signature);
    }

    private TransactionOuterClass.Transaction buildTx(
            final KeyPair keyPair,
            final ProofOfWork pow,
            final Core.LastBlockHeightResponse lastBlock,
            final TransactionOuterClass.InputData inputData
    ) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(lastBlock.getChainId().getBytes(StandardCharsets.UTF_8));
        outputStream.write("\u0000".getBytes(StandardCharsets.UTF_8));
        outputStream.write(inputData.toByteArray());
        byte[] inputDataPacked = outputStream.toByteArray();
        String hexSig = signInputData(keyPair.getPrivateKey(), inputDataPacked);
        SignatureOuterClass.Signature signature = SignatureOuterClass.Signature.newBuilder()
                .setVersion(1)
                .setAlgo("vega/ed25519")
                .setValue(hexSig)
                .build();
        TransactionOuterClass.ProofOfWork proofOfWork = TransactionOuterClass.ProofOfWork.newBuilder()
                .setTid(pow.getTxId())
                .setNonce(pow.getNonce()).build();
        return TransactionOuterClass.Transaction.newBuilder()
                .setVersion(TransactionOuterClass.TxVersion.TX_VERSION_V3)
                .setSignature(signature)
                .setPubKey(keyPair.getPublicKey())
                .setPow(proofOfWork)
                .setInputData(inputData.toByteString())
                .build();
    }

    public ProofOfWork getProofOfWork(final Core.LastBlockHeightResponse lastBlock) {
        var txId = UUID.randomUUID().toString();
        try {
            var nonce = pow(lastBlock.getSpamPowDifficulty(),
                    lastBlock.getHash(), txId, lastBlock.getSpamPowHashFunction());
            return new ProofOfWork()
                    .setBlockHeight(lastBlock.getHeight())
                    .setDifficulty(lastBlock.getSpamPowDifficulty())
                    .setTxId(txId)
                    .setBlockHash(lastBlock.getHash())
                    .setNonce(nonce);
        } catch(Exception e) {
            log.warn("cannot get pow {}", e.getMessage());
            return null;
        }
    }

    private long pow(
            final long difficulty,
            final String blockHash,
            final String txId,
            final String powHashFunction) throws Exception {
        long nonce = 0;
        byte[] hash;
        if(!powHashFunction.equals("sha3_24_rounds")) {
            throw new RuntimeException(String.format("unsupported hash function: %s", powHashFunction));
        }
        while (true) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write("Vega_SPAM_PoW".getBytes(StandardCharsets.UTF_8));
            outputStream.write(blockHash.getBytes(StandardCharsets.UTF_8));
            outputStream.write(txId.getBytes(StandardCharsets.UTF_8));
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.putLong(nonce);
            outputStream.write(buffer.array());
            byte[] dataPacked = outputStream.toByteArray();
            hash = sha3(dataPacked);
            int leadingZeroes = countZeroes(hash);
            if(leadingZeroes >= difficulty) {
                break;
            }
            nonce++;
        }
        return nonce;
    }

    private int lz(int num) {
        if(num == 0) return 8;
        int lz = 0;
        while ((num & (1 << 7)) == 0) {
            num = (num << 1);
            lz++;
        }
        return lz;
    }

    private int countZeroes(byte[] hash) {
        int zeroes = 0;
        for(byte b : hash) {
            int lz = lz(b);
            zeroes += lz;
            if(lz < 8) {
                break;
            }
        }
        return zeroes;
    }

    public TransactionOuterClass.InputData.Builder getInputDataBuilder(
            final ProofOfWork pow
    ) {
        return TransactionOuterClass.InputData.newBuilder()
                .setNonce(Math.abs(new Random().nextLong()))
                .setBlockHeight(pow.getBlockHeight());
    }

    public TransactionOuterClass.Transaction sign(
            final String partyId,
            final ProofOfWork pow,
            final Core.LastBlockHeightResponse lastBlock,
            final TransactionOuterClass.InputData inputData
    ) {
        KeyPair keyPair = wallet.getByPublicKey(partyId);
        if(keyPair == null) {
            log.warn("pub key not found {}", partyId);
            return null;
        }
        try {
            return buildTx(keyPair, pow, lastBlock, inputData);
        } catch(Exception e) {
            log.warn("cannot build tx {}", e.getMessage());
            return null;
        }
    }

    public Core.SubmitTransactionResponse submitTx(TransactionOuterClass.Transaction tx) {
        Core.SubmitTransactionRequest request = Core.SubmitTransactionRequest.newBuilder().setTx(tx).build();
        var channel = ManagedChannelBuilder.forAddress(this.coreNode, this.corePort).usePlaintext().build();
        var client = CoreServiceGrpc.newBlockingStub(channel);
        var resp = client.submitTransaction(request);
        channel.shutdownNow();
        return resp;
    }
}