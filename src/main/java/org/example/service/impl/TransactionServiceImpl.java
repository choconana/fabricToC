package org.example.service.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.protobuf.InvalidProtocolBufferException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import org.example.block.Connection;
import org.example.service.TransactionService;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.protos.ledger.rwset.kvrwset.KvRwset;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.BlockchainInfo;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.TxReadWriteSetInfo;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class TransactionServiceImpl implements TransactionService {


    @Override
    public Object query(String pubkeyHex) {
        Gateway gateway = Connection.getConnection(pubkeyHex);
        Network network = gateway.getNetwork(Connection.CHANNEL);
        Channel channel = network.getChannel();
        JSONObject json = new JSONObject();
        JSONArray rwJsonArray = new JSONArray();
        try {
            BlockchainInfo blockchainInfo = channel.queryBlockchainInfo();
            long height = blockchainInfo.getHeight();
            log.info("当前区块高度:{}", height);
            json.put("height", height);
            // todo 分页显示
            // todo 组装交易数据
            for (long i = height - 1; i >= 0 ; i--) {
                BlockInfo blockInfo = channel.queryBlockByNumber(i);
                final int envelopeCount = blockInfo.getEnvelopeCount();
                final int txCountTotal = blockInfo.getTransactionCount();
                for (BlockInfo.EnvelopeInfo envelopeInfo : blockInfo.getEnvelopeInfos()) {
                    if (envelopeInfo.getType() != BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE) {
                        continue;
                    }
                    BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;
                    final int txCount = transactionEnvelopeInfo.getTransactionActionInfoCount();
                    final boolean isValid = transactionEnvelopeInfo.isValid();
                    final int validationCode = transactionEnvelopeInfo.getValidationCode();

                    for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo : transactionEnvelopeInfo.getTransactionActionInfos()) {
                        final int endorsementsCount = transactionActionInfo.getEndorsementsCount();
                        for (int j = 0; j < endorsementsCount; j++) {
                            BlockInfo.EndorserInfo endorserInfo = transactionActionInfo.getEndorsementInfo(j);
                            final String endorserSignature = Hex.encodeHexString(endorserInfo.getSignature());
                            final String endorserMspid = endorserInfo.getMspid();
                            final String endorserId = endorserInfo.getId();
                        }

                        for (int j = 0; j < transactionActionInfo.getChaincodeInputArgsCount(); j++) {
                            final String args = printableString(new String(transactionActionInfo.getChaincodeInputArgs(j), StandardCharsets.UTF_8));
                        }

                        String payload = printableString(new String(transactionActionInfo.getProposalResponsePayload()));

                        String chaincodeIDName = transactionActionInfo.getChaincodeIDName();
                        String chaincodeIDVersion = transactionActionInfo.getChaincodeIDVersion();

                        TxReadWriteSetInfo rwsetInfo = transactionActionInfo.getTxReadWriteSet();
                        if (null != rwsetInfo) {
                            int rwsetCount = rwsetInfo.getNsRwsetCount();

                            JSONObject rwJson = new JSONObject();
                            rwJson.put("index", i);
                            JSONArray rwArray = new JSONArray();
                            for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                                final String namespace = nsRwsetInfo.getNamespace();
                                KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();

                                List<String> rks = new ArrayList<>(rws.getReadsCount());
                                for (KvRwset.KVRead readList : rws.getReadsList()) {
                                    String rk = readList.getKey();
                                    KvRwset.Version version = readList.getVersion();
                                    rks.add(rk);
                                }
                                JSONObject tmp = new JSONObject();
                                tmp.put("readSet", rks);

                                JSONObject wJson = new JSONObject();
                                for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                                    String key = writeList.getKey();
                                    String val = printableString(new String(writeList.getValue().toByteArray(), StandardCharsets.UTF_8));
                                    wJson.put(key, val);
                                }
                                tmp.put("writeSet", wJson);
                                rwArray.add(tmp);
                            }

                            rwJsonArray.add(rwArray);
                        }
                    }
                }
            }
            json.put("info", rwJsonArray);
            log.info("txinfo:{}", json.toJSONString());
            return json;
        } catch (ProposalException | InvalidArgumentException | InvalidProtocolBufferException e) {
            throw new RuntimeException(e);
        }
    }

    static String printableString(final String string) {
        int maxLogStringLength = 64;
        if (string == null || string.length() == 0) {
            return string;
        }

        String ret = string.replaceAll("[^\\p{Print}]", "?");

        ret = ret.substring(0, Math.min(ret.length(), maxLogStringLength)) + (ret.length() > maxLogStringLength ? "..." : "");

        return ret;

    }
}
