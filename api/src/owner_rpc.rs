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

//! JSON-RPC Stub generation for the Owner API
use uuid::Uuid;

use crate::core::core::Transaction;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::slate_versions::v2::TransactionV2;
use crate::libwallet::{
	AcctPathMapping, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	OutputCommitMapping, Slate, SlateVersion, TxLogEntry, VersionedSlate, WalletBackend,
	WalletInfo,
};
use crate::Owner;
use easy_jsonrpc;

/// Public definition used to generate Owner jsonrpc api.
/// * When running `gotts-wallet owner_api` with defaults, the V2 api is available at
/// `localhost:3520/v2/owner`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc::rpc]
pub trait OwnerRpc {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false);
	```
	*/
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": ["account1"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# "#
	# ,4, false, false, false);
	```
	 */
	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": ["default"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false);
	```
	 */
	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": [false, true, null],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				[
					{
					  "commit": "09a75b07e6b329e5a98be34e88d7bec3062fdddc2044a1b9efe9accec9858571c4",
					  "output": {
						"commit": "09a75b07e6b329e5a98be34e88d7bec3062fdddc2044a1b9efe9accec9858571c4",
						"height": "1",
						"is_change": false,
						"is_coinbase": true,
						"key_id": "0300000000000000000000000000000000",
						"lock_height": "4",
						"mmr_index": null,
						"n_child": 0,
						"root_key_id": "0200000000000000000000000000000000",
						"slate_id": null,
						"status": "Unspent",
						"tx_log_entry": 0,
						"value": "60000000000",
						"w": "0"
					  }
					},
					{
					  "commit": "09eae1a4ac785f845b33d2689d3a48df7c158e602564d23d81078ecd5b6385b491",
					  "output": {
						"commit": "09eae1a4ac785f845b33d2689d3a48df7c158e602564d23d81078ecd5b6385b491",
						"height": "2",
						"is_change": false,
						"is_coinbase": true,
						"key_id": "0300000000000000000000000100000000",
						"lock_height": "5",
						"mmr_index": null,
						"n_child": 1,
						"root_key_id": "0200000000000000000000000000000000",
						"slate_id": null,
						"status": "Unspent",
						"tx_log_entry": 1,
						"value": "60000000000",
						"w": "0"
					  }
					}
				]
			]
		}
	}
	# "#
	# , 2, false, false, false);
	```
	*/
	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).

	# Json rpc example

	```
		# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": [true, null, null],
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  [
			{
			  "amount_credited": "60000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "height": null,
			  "id": 0,
			  "kernel_excess": null,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "posted": false,
			  "stored_tx": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			},
			{
			  "amount_credited": "60000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "height": null,
			  "id": 1,
			  "kernel_excess": null,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "posted": false,
			  "stored_tx": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			}
		  ]
		]
	  }
	}
	# "#
	# , 2, false, false, false);
	```
	*/

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": [true, 1],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				{
					"amount_awaiting_confirmation": "0",
					"amount_awaiting_finalization": "0",
					"amount_currently_spendable": "60000000000",
					"amount_immature": "180000000000",
					"amount_locked": "0",
					"last_confirmed_height": "4",
					"minimum_confirmations": "1",
					"total": "240000000000"
				}
			]
		}
	}
	# "#
	# ,4, false, false, false);
	```
	 */

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;

	/**
		Networked version of [Owner::init_send_tx](struct.Owner.html#method.init_send_tx).

	```
		# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "init_send_tx",
			"params": {
				"args": {
					"src_acct_name": null,
					"amount": "6000000000",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy": "all",
					"message": "my message",
					"target_slate_version": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": {
		  "amount": "6000000000",
		  "fee": "8000000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
		  "num_participants": 2,
		  "participant_data": [
				{
				  "id": "0",
				  "message": "my message",
				  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bafc95c004d52a03b867c2200c36c3cab585b2926e2e747e4410dc996b9a0ff64",
				  "part_sig": null,
				  "public_blind_excess": "0306ba3e5c535f6fc26fea5b7a37ab21c99b7b31c86ab922e0e175b6998dcd36c0",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
		  ],
		  "tx": {
			"body": {
			  "inputs": [
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
				  "fee": "8000000",
				  "lock_height": "0"
				}
			  ],
			  "outputs": [
				{
				  "commit": "08e7af2033557d22be69fbffca0cd2181ab775b1a7ae594ba01248e410c6587a78",
				  "features": {
					"Plain": {
					  "spath": "0b3fbe3083c497835386fabb3b26bce280d49567e29d36fd877af1d4"
					}
				  },
				  "value": 53992000000
				}
			  ]
			}
		  },
		  "version_info": {
				"orig_version": 2,
				"version": 2,
				"block_header_version": 1
		  },
		  "w": "-64"
		}
	  }
	}
		# "#
		# ,4, false, false, false);
	```
	*/

	fn init_send_tx(&self, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		Networked version of [Owner::non_interactive_send](struct.Owner.html#method.non_interactive_send).

	```
		# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "non_interactive_send",
			"params": {
				"args": {
					"src_acct_name": null,
					"amount": "6000000000",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy": "all",
					"message": null,
					"target_slate_version": null,
					"send_args": {
						"method": "addr",
						"dest": "gs1qqvau3jpu2t04wy3znghhygrdjqvjxekrvs5vkrqjk6hesvjdj7lmcnvhhlvqdfrsjt",
						"finalize": true,
						"post_tx": true,
						"fluff": true
					}
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		  "id": 1,
		  "jsonrpc": "2.0",
		  "result": {
			"Ok": {
			  "amount": "6000000000",
			  "fee": "8000000",
			  "height": "4",
			  "id": "0436430c-2b02-624c-2032-570501212b00",
			  "lock_height": "0",
			  "num_participants": 2,
			  "participant_data": [
				{
				  "id": "0",
				  "message": null,
				  "message_sig": null,
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b6af49d8670a46a2a7cb74e5cd02ece5e3bda2bff223fbaacdfdf97ee36af331b",
				  "public_blind_excess": "0306ba3e5c535f6fc26fea5b7a37ab21c99b7b31c86ab922e0e175b6998dcd36c0",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				},
				{
				  "id": "1",
				  "message": null,
				  "message_sig": null,
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b2a8a824481c6f97e7b6239d142d8962ffb1b4bf51a873c40a100a09513017e15",
				  "public_blind_excess": "02c2f5703e71c33ab624f05c7e78db0dc97dfca228f93f69382cb297db1d30cdb1",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
			  ],
			  "tx": {
				"body": {
				  "inputs": [
					{
					  "commit": "09a75b07e6b329e5a98be34e88d7bec3062fdddc2044a1b9efe9accec9858571c4",
					  "features": "Coinbase"
					}
				  ],
				  "kernels": [
					{
					  "excess": "0945178d4fd63b5924302247f23a02ac0e2c6e366b2eb330c5a4ab03babb7d777e",
					  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4d947e20cbf16a64a9f719882d1307658e36f676f43dc6f6ec80e037844ab0b130",
					  "features": "Plain",
					  "fee": "8000000",
					  "lock_height": "0"
					}
				  ],
				  "outputs": [
					{
					  "commit": "089666c8f88c6aab115a041551f37cc5f9d03e6180f8f9d2613a7f8485dcc81df5",
					  "features": {
						"SigLocked": {
						  "locker": {
							"p2pkh": "cef5ad3c9482d1e831ceacadbd53469198f33f10b3822cfef77f33a3dc9b9dd8",
							"pub_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
							"relative_lock_height": 1,
							"secured_w": -8917468827927417694
						  }
						}
					  },
					  "value": 6000000000
					},
					{
					  "commit": "08e7af2033557d22be69fbffca0cd2181ab775b1a7ae594ba01248e410c6587a78",
					  "features": {
						"Plain": {
						  "spath": "0b3fbe3083c497835386fabb3b26bce280d49567e29d36fd877af1d4"
						}
					  },
					  "value": 53992000000
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
		# ,4, false, false, false);
	```
	*/

	fn non_interactive_send(&self, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	```
		# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"args": {
					"amount": "6000000000",
					"message": "Please give me your gotts",
					"dest_acct_name": null,
					"target_slate_version": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
			"id": 1,
			"jsonrpc": "2.0",
			"result": {
				"Ok": {
					"amount": "6000000000",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"num_participants": 2,
					"participant_data": [
						{
						  "id": "1",
						  "message": "Please give me your gotts",
						  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b9e196e487ee7865a2901d1ad0012a7bd25ddc0759fd1cca3e02e8f402dd01dd2",
						  "part_sig": null,
						  "public_blind_excess": "03453117c78d6d9f2885602a843856b4737b3e0838b28b3f861c5082fbfa428c36",
						  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
						}
					],
					"tx": {
						"body": {
							"inputs": [],
							"kernels": [
								{
									"excess": "000000000000000000000000000000000000000000000000000000000000000000",
									"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"features": "Plain",
									"fee": "0",
									"lock_height": "0"
								}
							],
							"outputs": [
								{
								  "commit": "08e7af2033557d22be69fbffca0cd2181ab775b1a7ae594ba01248e410c6587a78",
								  "features": {
									"Plain": {
									  "spath": "0b3fbe3083c497835386fabb3b26bce280d49567e29d36fd877af1d4"
									}
								  },
								  "value": 6000000000
								}
							]
						}
					},
					"version_info": {
						"orig_version": 2,
						"version": 2,
						"block_header_version": 1
					},
					"w": "64"
				}
			}
		}
		# "#
		# ,4, false, false, false);
	```
	*/

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		 Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	```
		# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": [
				{
					"amount": "6000000000",
					"w": "64",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"num_participants": 2,
					"participant_data": [
						{
						  "id": "1",
						  "message": "Please give me your gotts",
						  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b5e2dca8b19c930f5f2db2b83163172610cf2b4038e8add5b1f471680e7db55d0",
						  "part_sig": null,
						  "public_blind_excess": "03af68dd2d26dfc9ade85441e8b41c49b6160423f3b0ca820a4703fa9b6a7b64cd",
						  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
						}
					],
					"tx": {
						"body": {
							"inputs": [],
							"kernels": [
								{
									"excess": "000000000000000000000000000000000000000000000000000000000000000000",
									"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"features": "Plain",
									"fee": "0",
									"lock_height": "0"
								}
							],
							"outputs": [
								{
								  "commit": "08e7af2033557d22be69fbffca0cd2181ab775b1a7ae594ba01248e410c6587a78",
								  "features": {
									"Plain": {
									  "spath": "0b3fbe3083c497835386fabb3b26bce280d49567e29d36fd877af1d4"
									}
								  },
								  "value": 6000000000
								}
							]
						}
					},
					"version_info": {
						"orig_version": 2,
						"version": 2,
						"block_header_version": 1
					}
				},
				{
					"src_acct_name": null,
					"amount": "0",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy": "all",
					"message": "Ok, here are your gotts",
					"target_slate_version": null,
					"send_args": null
				}
			],
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amount": "6000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"num_participants": 2,
				"participant_data": [
					{
					  "id": "1",
					  "message": "Please give me your gotts",
					  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b5e2dca8b19c930f5f2db2b83163172610cf2b4038e8add5b1f471680e7db55d0",
					  "part_sig": null,
					  "public_blind_excess": "03af68dd2d26dfc9ade85441e8b41c49b6160423f3b0ca820a4703fa9b6a7b64cd",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
					  "id": "0",
					  "message": "Ok, here are your gotts",
					  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bfc5a7e9c2fb684ffb21618abccff2f78f9355ab93213defa3a9566a561797dd6",
					  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc0f1a8b847af95c4aae9a50ec9ef396a79bae307a17dd1c29a85fd1a0454763e",
					  "public_blind_excess": "0306ba3e5c535f6fc26fea5b7a37ab21c99b7b31c86ab922e0e175b6998dcd36c0",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				],
				"tx": {
					"body": {
						"inputs": [
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
								"fee": "8000000",
								"lock_height": "0"
							}
						],
						"outputs": [
							{
							  "commit": "08e1e17735ff0e4217bdd253bc0e9933a0c01bdf1dd08dccf6cf2e36b776ebae9d",
							  "features": {
								"Plain": {
								  "spath": "a49a6ddeb5054ff64a3837ff8a68e8a4f475c71c51b7acc6d44a5014"
								}
							  },
							  "value": 53992000000
							},
							{
							  "commit": "08e7af2033557d22be69fbffca0cd2181ab775b1a7ae594ba01248e410c6587a78",
							  "features": {
								"Plain": {
								  "spath": "0b3fbe3083c497835386fabb3b26bce280d49567e29d36fd877af1d4"
								}
							  },
							  "value": 6000000000
							}
						]
					}
				},
				"version_info": {
					"orig_version": 2,
					"version": 2,
					"block_header_version": 1
				},
				"w": "64"
			}
		}
	}
	# "#
	# ,4, false, false, false);
	```
	*/

	fn process_invoice_tx(
		&self,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": [ {
				"amount": "60000000000",
				"w": "-64",
				"fee": "7000000",
				"height": "5",
				"lock_height": "0",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
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
								  "spath": "9e0f681afae46a92556f7086b1e6c2146effd2c8f2c25727946b249e"
								}
							  },
							  "commit": "099af2fbafc88308fc210cf6341a443b90312f2dfb90b50cda0c7d1dc5d5a59c6e",
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
			},
			0
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
	# ,5 ,true, false, false);

	```
	 */
	fn tx_lock_outputs(
		&self,
		slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
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
							  "spath": "c7392a2915c120a3072571a19a7e73ae71ceee117c5c8615b1aeb44a"
							}
						  },
						  "commit": "09e66a240425be5d6e8873c78f87c1489cb77736216a8fb0639962d7e3b4111b9e",
						  "value": 60000000000
						},
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
				  "public_blind_excess": "020e44132261fcdc9112d1bae25ab54d9c00609353cb23143771f2dc3c3f94484e",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": null,
				  "message": null,
				  "message_sig": null
				},
				{
				  "id": "1",
				  "public_blind_excess": "03900add00e609f21c5565fa95b09824973d2f8985119e59fcf26acb27b6133fd3",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b02f44f6e1a2b319a8cfb59afbf87e3cded9036e8eabd3cd3a66ff8145b685a0b",
				  "message": null,
				  "message_sig": null
				}
			]
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
					  "message": null,
					  "message_sig": null,
					  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b267c4d03effc5d6961657de79245ffe3d90637df26cbaa5a06f2be09f8550402",
					  "public_blind_excess": "020e44132261fcdc9112d1bae25ab54d9c00609353cb23143771f2dc3c3f94484e",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
					  "id": "1",
					  "message": null,
					  "message_sig": null,
					  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b02f44f6e1a2b319a8cfb59afbf87e3cded9036e8eabd3cd3a66ff8145b685a0b",
					  "public_blind_excess": "03900add00e609f21c5565fa95b09824973d2f8985119e59fcf26acb27b6133fd3",
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
							  "excess": "087e67f6adc6e5d29345d2155e190cf90822dfdd3a4fab1f3f033b44f8c1827b62",
							  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4d28709d7109288f03ee60d79652cde2b1c7976dc71189e72dad61b71e53be5e0d",
							  "features": "Plain",
							  "fee": "7000000",
							  "lock_height": "0"
							}
						],
						"outputs": [
							{
							  "features": {
								"Plain": {
								  "spath": "c7392a2915c120a3072571a19a7e73ae71ceee117c5c8615b1aeb44a"
								}
							  },
							  "commit": "09e66a240425be5d6e8873c78f87c1489cb77736216a8fb0639962d7e3b4111b9e",
							  "value": 60000000000
							},
							{
							  "features": {
								"Plain": {
								  "spath": "9e0f681afae46a92556f7086b1e6c2146effd2c8f2c25727946b249e"
								}
							  },
							  "commit": "099af2fbafc88308fc210cf6341a443b90312f2dfb90b50cda0c7d1dc5d5a59c6e",
							  "value": 59993000000
							}
						]
					}
				},
				"version_info": {
					"orig_version": 2,
					"version": 2,
					"block_header_version": 1
				},
				"w": "-64"
			}
		}
	}
	# "#
	# , 5, true, true, false);
	```
	 */
	fn finalize_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": [
		null,
		{
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
					  "excess": "087e67f6adc6e5d29345d2155e190cf90822dfdd3a4fab1f3f033b44f8c1827b62",
					  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4d28709d7109288f03ee60d79652cde2b1c7976dc71189e72dad61b71e53be5e0d",
					  "features": "Plain",
					  "fee": "7000000",
					  "lock_height": "0"
					}
				],
				"outputs": [
					{
					  "features": {
						"Plain": {
						  "spath": "c7392a2915c120a3072571a19a7e73ae71ceee117c5c8615b1aeb44a"
						}
					  },
					  "commit": "09e66a240425be5d6e8873c78f87c1489cb77736216a8fb0639962d7e3b4111b9e",
					  "value": 60000000000
					},
					{
					  "features": {
						"Plain": {
						  "spath": "9e0f681afae46a92556f7086b1e6c2146effd2c8f2c25727946b249e"
						}
					  },
					  "commit": "099af2fbafc88308fc210cf6341a443b90312f2dfb90b50cda0c7d1dc5d5a59c6e",
					  "value": 59993000000
					}
				]
			}
		},
		false
		]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, true, true, true);
	```
	 */

	fn post_tx(
		&self,
		tx_slate_id: Option<Uuid>,
		tx: &TransactionV2,
		fluff: bool,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": [null, "0436430c-2b02-624c-2032-570501212b00"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, true, true, false);
	```
	 */
	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": [
			{
				"amount_credited": "59993000000",
				"amount_debited": "120000000000",
				"confirmation_ts": "2019-01-15T16:01:26Z",
				"confirmed": false,
				"creation_ts": "2019-01-15T16:01:26Z",
				"fee": "7000000",
				"id": 5,
				"messages": {
					"messages": [
						{
							"id": "0",
							"message": null,
							"message_sig": null,
							"public_key": "033ac2158fa0077f087de60c19d8e431753baa5b63b6e1477f05a2a6e7190d4592"
						},
						{
							"id": "1",
							"message": null,
							"message_sig": null,
							"public_key": "024f9bc78c984c78d6e916d3a00746aa30fa1172124c8dbc0cbddcb7b486719bc7"
						}
					]
				},
				"num_inputs": 2,
				"num_outputs": 1,
				"parent_key_id": "0200000000000000000000000000000000",
				"stored_tx": "0436430c-2b02-624c-2032-570501212b00.gottstx",
				"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00",
				"tx_type": "TxSent"
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
			"Ok": {
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
							"commit": "09e66a240425be5d6e8873c78f87c1489cb77736216a8fb0639962d7e3b4111b9e",
							"features": {
							  "Plain": {
								"spath": "c7392a2915c120a3072571a19a7e73ae71ceee117c5c8615b1aeb44a"
							  }
							},
							"value": 60000000000
						  },
						  {
							"commit": "099af2fbafc88308fc210cf6341a443b90312f2dfb90b50cda0c7d1dc5d5a59c6e",
							"features": {
							  "Plain": {
								"spath": "9e0f681afae46a92556f7086b1e6c2146effd2c8f2c25727946b249e"
							  }
							},
							"value": 59993000000
						  }
					]
				}
			}
		}
	}
	# "#
	# , 5, true, true, false);
	```
	 */
	fn get_stored_tx(&self, tx: &TxLogEntry) -> Result<Option<TransactionV2>, ErrorKind>;

	/**
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).

	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	# ,5 ,true, false, false);
	```
	*/
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::restore](struct.Owner.html#method.restore).


	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "restore",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 1, false, false, false);
	```
	 */
	fn restore(&self) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::check_repair](struct.Owner.html#method.check_repair).


	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "check_repair",
		"params": [false],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 1, false, false, false);
	```
	 */
	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).


	```
	# gotts_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , 5, false, false, false);
	```
	 */
	fn node_height(&self) -> Result<NodeHeightResult, ErrorKind>;
}

impl<W: ?Sized, C, K> OwnerRpc for Owner<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		Owner::accounts(self).map_err(|e| e.kind())
	}

	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind> {
		Owner::create_account_path(self, label).map_err(|e| e.kind())
	}

	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind> {
		Owner::set_active_account(self, label).map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind> {
		Owner::retrieve_outputs(self, include_spent, refresh_from_node, tx_id).map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind> {
		Owner::retrieve_txs(self, refresh_from_node, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		Owner::retrieve_summary_info(self, refresh_from_node, minimum_confirmations)
			.map_err(|e| e.kind())
	}

	fn init_send_tx(&self, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::init_send_tx(self, args).map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn non_interactive_send(&self, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::non_interactive_send(self, args).map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::issue_invoice_tx(self, args).map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn process_invoice_tx(
		&self,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate =
			Owner::process_invoice_tx(self, &Slate::from(in_slate), args).map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn finalize_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::finalize_tx(self, &Slate::from(in_slate)).map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn tx_lock_outputs(
		&self,
		slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind> {
		Owner::tx_lock_outputs(self, &Slate::from(slate), participant_id).map_err(|e| e.kind())
	}

	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind> {
		Owner::cancel_tx(self, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn get_stored_tx(&self, tx: &TxLogEntry) -> Result<Option<TransactionV2>, ErrorKind> {
		Owner::get_stored_tx(self, tx)
			.map(|x| x.map(|y| TransactionV2::from(y)))
			.map_err(|e| e.kind())
	}

	fn post_tx(
		&self,
		tx_slate_id: Option<Uuid>,
		tx: &TransactionV2,
		fluff: bool,
	) -> Result<(), ErrorKind> {
		Owner::post_tx(self, tx_slate_id, &Transaction::from(tx), fluff).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind> {
		Owner::verify_slate_messages(self, &Slate::from(slate)).map_err(|e| e.kind())
	}

	fn restore(&self) -> Result<(), ErrorKind> {
		Owner::restore(self).map_err(|e| e.kind())
	}

	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind> {
		Owner::check_repair(self, delete_unconfirmed).map_err(|e| e.kind())
	}

	fn node_height(&self) -> Result<NodeHeightResult, ErrorKind> {
		Owner::node_height(self).map_err(|e| e.kind())
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_owner(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	perform_tx: bool,
	lock_tx: bool,
	finalize_tx: bool,
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

	if perform_tx {
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
		let mut slate = api_impl::owner::init_send_tx(&mut *w, args, true).unwrap();
		println!("INITIAL SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		{
			let mut w2 = wallet2.lock();
			w2.open_with_credentials().unwrap();
			slate = api_impl::foreign::receive_tx(&mut *w2, &slate, None, None, true).unwrap();
			w2.close().unwrap();
		}
		// Spit out slate for input to finalize_tx
		if lock_tx {
			api_impl::owner::tx_lock_outputs(&mut *w, &slate, 0).unwrap();
		}
		println!("RECEIPIENT SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		if finalize_tx {
			slate = api_impl::owner::finalize_tx(&mut *w, &slate).unwrap();
			error!("FINALIZED TX SLATE");
			println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		}
		w.close().unwrap();
	}

	if perform_tx && lock_tx && finalize_tx {
		// mine to move the chain on
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3 as usize, false);
	}

	let mut api_owner = Owner::new(wallet1.clone());
	api_owner.doctest_mode = true;
	let owner_api = &api_owner as &dyn OwnerRpc;
	Ok(owner_api.handle_request(request).as_option())
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use gotts_wallet_api::run_doctest_owner;
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

		let response = run_doctest_owner(
			request_val,
			dir,
			$blocks_to_mine,
			$perform_tx,
			$lock_tx,
			$finalize_tx,
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
