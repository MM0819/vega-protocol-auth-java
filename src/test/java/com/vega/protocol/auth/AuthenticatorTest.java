package com.vega.protocol.auth;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import vega.Governance;
import vega.commands.v1.Commands;
import vega.commands.v1.TransactionOuterClass;

import java.util.Random;

@Slf4j
public class AuthenticatorTest {

    private static final String MNEMONIC = "voyage credit question ride kite race " +
            "ladder indoor net select margin canvas zone talk have";
    private static final String CORE_NODE = "n08.testnet.vega.xyz";
    private static final int CORE_PORT = 3002;
    private static final String PROPOSAL_ID = "0f4d06000087b989f613bf3a651842b88874d70c4b8b3161c7257837447c3400";

    @Test
    public void testSign() {
        // create wallet with bip32 mnemonic
        var wallet = new Wallet(MNEMONIC);
        // instantiate authenticator
        var authenticator = new Authenticator(wallet, CORE_NODE, CORE_PORT);
        // get the last block
        var lastBlock = authenticator.getLastBlock();
        // get new pow
        var pow = authenticator.getProofOfWork(lastBlock);
        // build the tx
        var inputData = TransactionOuterClass.InputData.newBuilder()
                .setNonce(Math.abs(new Random().nextLong()))
                .setBlockHeight(lastBlock.getHeight())
                .setVoteSubmission(Commands.VoteSubmission.newBuilder()
                        .setProposalId(PROPOSAL_ID)
                        .setValue(Governance.Vote.Value.VALUE_YES)
                        .build())
                .build();
        // sign the tx
        var tx = authenticator.sign(wallet.get(0).getPublicKey(), pow, lastBlock, inputData);
        log.info("{}", tx);
        // submit the tx to the network
        var resp = authenticator.submitTx(tx);
        log.info("{}", resp);
    }
}