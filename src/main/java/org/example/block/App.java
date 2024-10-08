/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Running TestApp: 
// gradle runApp 

package org.example.block;

import java.nio.file.Path;
import java.nio.file.Paths;

import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

@Slf4j
public class App {

	static {
		System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
	}

	// helper function for getting connected to the gateway
	public static Gateway connect() throws Exception{
		// Load a file system based wallet for managing identities.
		Path walletPath = Paths.get("wallet");
		Wallet wallet = Wallets.newFileSystemWallet(walletPath);
		// load a CCP
		Path networkConfigPath = Paths.get("/Users/hezhidong/Documents/learningspace/fabric-samples/", "test-network", "organizations", "peerOrganizations", "org1.example.com", "connection-org1.yaml");

		Gateway.Builder builder = Gateway.createBuilder();
		builder.identity(wallet, "appUser").networkConfig(networkConfigPath).discovery(true);
		return builder.connect();
	}

	public void run() {
		// enrolls the admin and registers the user
		try {
			EnrollAdmin enrollAdmin = new EnrollAdmin();
			enrollAdmin.enroll();
			RegisterUser registerUser = new RegisterUser();
			registerUser.register();
		} catch (Exception e) {
			System.err.println(e);
		}

		// connect to the network and invoke the smart contract
		try (Gateway gateway = connect()) {

			// get the network and contract
			Network network = gateway.getNetwork("mychannel");
			Contract contract = network.getContract("basic");

			byte[] result;

			log.info("Submit Transaction: InitLedger creates the initial set of assets on the ledger.");
			contract.submitTransaction("InitLedger");

			log.info("\n");
			result = contract.evaluateTransaction("GetAllAssets");
			log.info("Evaluate Transaction: GetAllAssets, result: " + new String(result));

			log.info("\n");
			log.info("Submit Transaction: CreateAsset asset15");
			// CreateAsset creates an asset with ID asset13, color yellow, owner Tom, size 5 and appraisedValue of 1300
			contract.submitTransaction("CreateAsset", "asset15", "pink", "7", "Alice", "1600");

			log.info("\n");
			log.info("Evaluate Transaction: ReadAsset asset6");
			// ReadAsset returns an asset with given assetID
			result = contract.evaluateTransaction("ReadAsset", "asset16");
			log.info("result: {}", new String(result));

			log.info("\n");
			log.info("Evaluate Transaction: AssetExists asset1");
			// AssetExists returns "true" if an asset with given assetID exist
			result = contract.evaluateTransaction("AssetExists", "asset1");
			log.info("result: {}", new String(result));

			log.info("\n");
			log.info("Submit Transaction: UpdateAsset asset1, new AppraisedValue : 350");
			// UpdateAsset updates an existing asset with new properties. Same args as CreateAsset
			contract.submitTransaction("UpdateAsset", "asset1", "blue", "5", "Tomoko", "350");

			log.info("\n");
			log.info("Evaluate Transaction: ReadAsset asset1");
			result = contract.evaluateTransaction("ReadAsset", "asset1");
			log.info("result: " + new String(result));

			try {
				log.info("\n");
				log.info("Submit Transaction: UpdateAsset asset70");
				// Non existing asset asset70 should throw Error
				contract.submitTransaction("UpdateAsset", "asset70", "blue", "5", "Tomoko", "300");
			} catch (Exception e) {
				System.err.println("Expected an error on UpdateAsset of non-existing Asset: " + e);
			}

			log.info("\n");
			log.info("Submit Transaction: TransferAsset asset1 from owner Tomoko > owner Tom");
			// TransferAsset transfers an asset with given ID to new owner Tom
			contract.submitTransaction("TransferAsset", "asset1", "Tom");

			log.info("\n");
			log.info("Evaluate Transaction: ReadAsset asset1");
			result = contract.evaluateTransaction("ReadAsset", "asset1");
			log.info("result: " + new String(result));
		}
		catch(Exception e){
			System.err.println(e);
		}

	}
}
