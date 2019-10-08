// Copyright 2019 The Grin Developers
// Modifications Copyright 2019 The Gotts Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! JSON-RPC Stub generation for the Foreign API

use crate::keychain::Keychain;
use crate::libwallet::{
	self, BlockFees, CbData, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeVersionInfo, Slate, VersionInfo, VersionedSlate, WalletBackend,
};
use crate::{Foreign, ForeignCheckMiddlewareFn};
use easy_jsonrpc;

/// Public definition used to generate Foreign jsonrpc api.
/// * When running `gotts-wallet listen` with defaults, the V2 api is available at
/// `localhost:3515/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc::rpc]
pub trait ForeignRpc {
	/**
	Networked version of [Foreign::check_version](struct.Foreign.html#method.check_version).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "check_version",
		"id": 1,
		"params": []
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"foreign_api_version": 2,
				"supported_slate_versions": [
					"V2"
				]
			}
		}
	}
	# "#
	# , 0, false, false);
	```
	*/
	fn check_version(&self) -> Result<VersionInfo, ErrorKind>;

	/**
	Networked version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"id": 1,
		"params": [
			{
				"fees": 0,
				"height": 0,
				"key_id": null
			}
		]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"kernel": {
					"excess": "08453117c78d6d9f2885602a843856b4737b3e0838b28b3f861c5082fbfa428c36",
					"excess_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc0ee8ca4fb15df5dfed54a8350fa0b30014f1eb55dc076e156a79c4caa16b286",
					"features": "Coinbase"
				},
				"key_id": "0300000000000000000000000400000000",
				"output": {
					"commit": "08453117c78d6d9f2885602a843856b4737b3e0838b28b3f861c5082fbfa428c36",
					"features": {
					  "Coinbase": {
						"spath": "ff776b7e9f6edb03aea68dce23493f012e0c0e267e052ecf0b0fb714"
					  }
					},
					"value": 60000000000
				}
			}
		}
	}
	# "#
	# , 4, false, false);
	```
	*/
	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind>;

	/**
	Networked version of [Foreign::verify_slate_messages](struct.Foreign.html#method.verify_slate_messages).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"id": 1,
		"params": [ {
				"amount": "60000000000",
				"w": "-130160296693033216",
				"fee": "7000000",
				"height": "5",
				"lock_height": "0",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
					"recipient_pubkey": null,
					"message": "my message",
					"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b1d4c1358be398f801eb90d933774b5218fa7e769b11c4c640402253353656f75",
					"part_sig": null,
					"public_blind_excess": "034b4df2f0558b73ea72a1ca5c4ab20217c66bbe0829056fca7abe76888e9349ee",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
					"body": {
						"inputs": [
							{
							  "features": "Coinbase",
							  "commit": "09eae1a4ac785f845b33d2689d3a48df7c158e602564d23d81078ecd5b6385b491"
							},
							{
							  "features": "Coinbase",
							  "commit": "09a75b07e6b329e5a98be34e88d7bec3062fdddc2044a1b9efe9accec9858571c4"
							}
						],
						"kernels": [
							{
							  "features": "Plain",
							  "fee": "7000000",
							  "lock_height": "0",
							  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
							  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
							}
						],
						"outputs": [
							{
							  "features": {
								"Plain": {
								  "spath": "6279b7a4c3fd0119d07a11a7c83b4badc009513514f5f7dac63c19cf"
								}
							  },
							  "commit": "088c02d8ac5ce7b7a19fcb42973c55e1e84b7c86fa83c2a5ec6f4b23fd06c11a25",
							  "value": 59993000000
							}
						]
					}
				},
				"version_info": {
					"orig_version": 2,
					"version": 2,
					"block_header_version": 1
				}
			}
		]
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# ,1 ,false, false);
	```
	*/
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind>;

	/**
		Networked version of [Foreign::receive_tx](struct.Foreign.html#method.receive_tx).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "receive_tx",
		"id": 1,
		"params": [
			{
			"version_info": {
				"version": 2,
				"orig_version": 2,
				"block_header_version": 1
			},
			"num_participants": 2,
			"id": "0436430c-2b02-624c-2032-570501212b00",
			"tx": {
				"body": {
					"inputs": [
						{
						  "features": "Coinbase",
						  "commit": "09eae1a4ac785f845b33d2689d3a48df7c158e602564d23d81078ecd5b6385b491"
						},
						{
						  "features": "Coinbase",
						  "commit": "09a75b07e6b329e5a98be34e88d7bec3062fdddc2044a1b9efe9accec9858571c4"
						}
					],
					"outputs": [
						{
						  "features": {
							"Plain": {
							  "spath": "9e0f681afae46a92556f7086b1e6c2146effd2c8f2c25727946b249e"
							}
						  },
						  "commit": "099af2fbafc88308fc210cf6341a443b90312f2dfb90b50cda0c7d1dc5d5a59c6e",
						  "value": 59993000000
						}
					],
					"kernels": [
						{
						  "features": "Plain",
						  "fee": "7000000",
						  "lock_height": "0",
						  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
						  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
						}
					]
				}
			},
			"amount": "60000000000",
			"w": "-64",
			"fee": "7000000",
			"height": "5",
			"lock_height": "0",
			"participant_data": [
				{
				  "id": "0",
				  "recipient_pubkey": null,
				  "public_blind_excess": "02c1ec76d058ab1fe9120d2c907e42e930df2217d20b8159de9b6c985eec49dc12",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": null,
				  "message": null,
				  "message_sig": null
				}
			]
		},
		null,
		"Thanks, Gotts"
		]
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
	"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amount": "60000000000",
				"fee": "7000000",
				"height": "5",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"num_participants": 2,
				"participant_data": [
					{
					  "id": "0",
						"recipient_pubkey": null,
					  "message": null,
					  "message_sig": null,
					  "part_sig": null,
					  "public_blind_excess": "02c1ec76d058ab1fe9120d2c907e42e930df2217d20b8159de9b6c985eec49dc12",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
					  "id": "1",
						"recipient_pubkey": null,
					  "message": "Thanks, Gotts",
					  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bfd0a9a7f8a0c487a008a0d20f26abad55bbae626e7ddaf985cf57452f27c44a1",
					  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bb05fc02172486516c4f13e5d3fb07a10128a99d93cc293373337c770be7fbf24",
					  "public_blind_excess": "026fd9331688e26ba0703f700d6d1c0c1626ca02389d5a1aa981cf0e77bb83d370",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				],
				"tx": {
				"body": {
					"inputs": [
						{
						  "commit": "09eae1a4ac785f845b33d2689d3a48df7c158e602564d23d81078ecd5b6385b491",
						  "features": "Coinbase"
						},
						{
						  "commit": "09a75b07e6b329e5a98be34e88d7bec3062fdddc2044a1b9efe9accec9858571c4",
						  "features": "Coinbase"
						}
					],
					"kernels": [
					{
						"excess": "000000000000000000000000000000000000000000000000000000000000000000",
						"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
						"features": "Plain",
						"fee": "7000000",
						"lock_height": "0"
					}
					],
					"outputs": [
						{
						  "commit": "099af2fbafc88308fc210cf6341a443b90312f2dfb90b50cda0c7d1dc5d5a59c6e",
						  "features": {
							"Plain": {
							  "spath": "9e0f681afae46a92556f7086b1e6c2146effd2c8f2c25727946b249e"
							}
						  },
						  "value": 59993000000
						},
						{
						  "commit": "08f1d803372a08c4f2b456efc207dc6d761ffdc3933cf6f8894a18f923614cf33d",
						  "features": {
							"Plain": {
							  "spath": "e84cac3c1f54d6b4da205012eaa1a0a20af497faee5e7ea28dd159f2"
							}
						  },
						  "value": 60000000000
						}
					]
				}
				},
				"version_info": {
					"block_header_version": 1,
					"orig_version": 2,
					"version": 2
				},
				"w": "-64"
			}
		}
	}
	# "#
	# , 5, true, false);
	```
	*/
	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind>;

	/**

	Networked version of [Foreign::finalize_invoice_tx](struct.Foreign.html#method.finalize_invoice_tx).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_invoice_tx",
		"id": 1,
		"params": [{
			"version_info": {
				"version": 2,
				"orig_version": 2,
				"block_header_version": 1
			},
			"num_participants": 2,
			"id": "0436430c-2b02-624c-2032-570501212b00",
			"tx": {
				"body": {
					"inputs": [
						{
						  "features": "Coinbase",
						  "commit": "09eae1a4ac785f845b33d2689d3a48df7c158e602564d23d81078ecd5b6385b491"
						},
						{
						  "features": "Coinbase",
						  "commit": "09a75b07e6b329e5a98be34e88d7bec3062fdddc2044a1b9efe9accec9858571c4"
						}
					],
					"outputs": [
						{
						  "features": {
							"Plain": {
							  "spath": "ff025131ff654169e576baeba558a3a43043699745a188a3ef7622ed"
							}
						  },
						  "commit": "08a731abf4be6e11b29beb185ef0f0bab42e5030c7cbcf3f1479abafa0faee3d8f",
						  "value": 60000000000
						},
						{
						  "features": {
							"Plain": {
							  "spath": "a204b97f97f1e4a244ad04a9ba3a9add96f96d98dc7bb67bf47471a6"
							}
						  },
						  "commit": "089666c8f88c6aab115a041551f37cc5f9d03e6180f8f9d2613a7f8485dcc81df5",
						  "value": 59993000000
						}
					],
					"kernels": [
						{
						  "features": "Plain",
						  "fee": "7000000",
						  "lock_height": "0",
						  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
						  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
						}
					]
				}
			},
			"amount": "60000000000",
			"w": "64",
			"fee": "7000000",
			"height": "5",
			"lock_height": "0",
			"participant_data": [
				{
				  "id": "1",
				  "recipient_pubkey": null,
				  "public_blind_excess": "03900add00e609f21c5565fa95b09824973d2f8985119e59fcf26acb27b6133fd3",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": null,
				  "message": null,
				  "message_sig": null
				},
				{
				  "id": "0",
				  "recipient_pubkey": null,
				  "public_blind_excess": "020e44132261fcdc9112d1bae25ab54d9c00609353cb23143771f2dc3c3f94484e",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b267c4d03effc5d6961657de79245ffe3d90637df26cbaa5a06f2be09f8550402",
				  "message": null,
				  "message_sig": null
				}
			]
		}]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amount": "60000000000",
				"fee": "7000000",
				"height": "5",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"num_participants": 2,
				"participant_data": [
					{
					  "id": "1",
						"recipient_pubkey": null,
					  "message": null,
					  "message_sig": null,
					  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b02f44f6e1a2b319a8cfb59afbf87e3cded9036e8eabd3cd3a66ff8145b685a0b",
					  "public_blind_excess": "03900add00e609f21c5565fa95b09824973d2f8985119e59fcf26acb27b6133fd3",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
					  "id": "0",
						"recipient_pubkey": null,
					  "message": null,
					  "message_sig": null,
					  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b267c4d03effc5d6961657de79245ffe3d90637df26cbaa5a06f2be09f8550402",
					  "public_blind_excess": "020e44132261fcdc9112d1bae25ab54d9c00609353cb23143771f2dc3c3f94484e",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				],
				"tx": {
					"body": {
						"inputs": [
							{
							  "commit": "09eae1a4ac785f845b33d2689d3a48df7c158e602564d23d81078ecd5b6385b491",
							  "features": "Coinbase"
							},
							{
							  "commit": "09a75b07e6b329e5a98be34e88d7bec3062fdddc2044a1b9efe9accec9858571c4",
							  "features": "Coinbase"
							}
						],
						"kernels": [
							{
							  "excess": "087e67f6adc6e5d29345d2155e190cf90822dfdd3a4fab1f3f033b44f8c1827b62",
							  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4d28709d7109288f03ee60d79652cde2b1c7976dc71189e72dad61b71e53be5e0d",
							  "features": "Plain",
							  "fee": "7000000",
							  "lock_height": "0"
							}
						],
						"outputs": [
							{
							  "commit": "08a731abf4be6e11b29beb185ef0f0bab42e5030c7cbcf3f1479abafa0faee3d8f",
							  "features": {
								"Plain": {
								  "spath": "ff025131ff654169e576baeba558a3a43043699745a188a3ef7622ed"
								}
							  },
							  "value": 60000000000
							},
							{
							  "commit": "089666c8f88c6aab115a041551f37cc5f9d03e6180f8f9d2613a7f8485dcc81df5",
							  "features": {
								"Plain": {
								  "spath": "a204b97f97f1e4a244ad04a9ba3a9add96f96d98dc7bb67bf47471a6"
								}
							  },
							  "value": 59993000000
							}
						]
					}
				},
				"version_info": {
					"block_header_version": 1,
					"orig_version": 2,
					"version": 2
				},
				"w": "64"
			}
		}
	}
	# "#
	# , 5, false, true);
	```
	*/
	fn finalize_invoice_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind>;
}

impl<W: ?Sized, C, K> ForeignRpc for Foreign<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn check_version(&self) -> Result<VersionInfo, ErrorKind> {
		Foreign::check_version(self).map_err(|e| e.kind())
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind> {
		Foreign::build_coinbase(self, block_fees).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind> {
		Foreign::verify_slate_messages(self, &Slate::from(slate)).map_err(|e| e.kind())
	}

	fn receive_tx(
		&self,
		in_slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind> {
		let version = in_slate.version();
		let out_slate = Foreign::receive_tx(
			self,
			&Slate::from(in_slate),
			dest_acct_name.as_ref().map(String::as_str),
			message,
		)
		.map_err(|e| e.kind())?;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn finalize_invoice_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind> {
		let version = in_slate.version();
		let out_slate =
			Foreign::finalize_invoice_tx(self, &Slate::from(in_slate)).map_err(|e| e.kind())?;
		Ok(VersionedSlate::into_version(out_slate, version))
	}
}

fn test_check_middleware(
	_name: ForeignCheckMiddlewareFn,
	_node_version_info: Option<NodeVersionInfo>,
	_slate: Option<&Slate>,
) -> Result<(), libwallet::Error> {
	// TODO: Implement checks
	// return Err(ErrorKind::GenericError("Test Rejection".into()))?
	Ok(())
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	init_tx: bool,
	init_invoice_tx: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc::Handler;
	use gotts_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use gotts_wallet_libwallet::api_impl;
	use gotts_wallet_util::gotts_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use gotts_wallet_util::gotts_util as util;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<LocalWalletClient, ExtKeychain> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 =
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch";
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let wallet1 = test_framework::create_wallet(
		&format!("{}/wallet1", test_dir),
		client1.clone(),
		Some(rec_phrase_1),
	);
	wallet_proxy.add_wallet("wallet1", client1.get_send_instance(), wallet1.clone());

	let rec_phrase_2 =
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile";
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let wallet2 = test_framework::create_wallet(
		&format!("{}/wallet2", test_dir),
		client2.clone(),
		Some(rec_phrase_2),
	);
	wallet_proxy.add_wallet("wallet2", client2.get_send_instance(), wallet2.clone());

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 1 as usize, false);
		//update local outputs after each block, so transaction IDs stay consistent
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let (wallet_refreshed, _) =
			api_impl::owner::retrieve_summary_info(&mut *w, true, 1).unwrap();
		assert!(wallet_refreshed);
		w.close().unwrap();
	}

	if init_invoice_tx {
		let amount = 60_000_000_000;
		let mut slate = {
			let mut w = wallet2.lock();
			w.open_with_credentials().unwrap();
			let args = IssueInvoiceTxArgs {
				amount,
				..Default::default()
			};
			api_impl::owner::issue_invoice_tx(&mut *w, args, true).unwrap()
		};
		slate = {
			let mut w = wallet1.lock();
			w.open_with_credentials().unwrap();
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy: "all".to_owned(),
				..Default::default()
			};
			api_impl::owner::process_invoice_tx(&mut *w, &slate, args, true).unwrap()
		};
		println!("INIT INVOICE SLATE");
		// Spit out slate for input to finalize_invoice_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	if init_tx {
		let amount = 60_000_000_000;
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy: "all".to_owned(),
			..Default::default()
		};
		let slate = api_impl::owner::init_send_tx(&mut *w, args, true).unwrap();
		println!("INIT SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	let mut api_foreign = match init_invoice_tx {
		false => Foreign::new(wallet1.clone(), Some(test_check_middleware)),
		true => Foreign::new(wallet2.clone(), Some(test_check_middleware)),
	};
	api_foreign.doctest_mode = true;
	let foreign_api = &api_foreign as &dyn ForeignRpc;
	Ok(foreign_api.handle_request(request).as_option())
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $init_tx:expr, $init_invoice_tx:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use gotts_wallet_api::run_doctest_foreign;
		use serde_json;
		use serde_json::Value;
		use tempfile::tempdir;

		let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
		let dir = dir
			.path()
			.to_str()
			.ok_or("Failed to convert tmpdir path to string.".to_owned())
			.unwrap();

		let request_val: Value = serde_json::from_str($request).unwrap();
		let expected_response: Value = serde_json::from_str($expected_response).unwrap();

		let response = run_doctest_foreign(
			request_val,
			dir,
			$blocks_to_mine,
			$init_tx,
			$init_invoice_tx,
			)
		.unwrap()
		.unwrap();

		if response != expected_response {
			panic!(
				"(left != right) \nleft: {}\nright: {}",
				serde_json::to_string_pretty(&response).unwrap(),
				serde_json::to_string_pretty(&expected_response).unwrap()
				);
			}
	};
}
