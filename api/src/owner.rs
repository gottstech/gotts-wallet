// Copyright 2018 The Grin Developers
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

//! Owner API External Definition

use crate::util::{Mutex, ZeroingString};
use chrono::prelude::*;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use crate::core::address::Address;
use crate::core::core::Transaction;
use crate::impls::{HTTPWalletCommAdapter, KeybaseWalletCommAdapter, WalletSeed};
use crate::keychain::{Identifier, Keychain, RecipientKey};
use crate::libwallet::api_impl::owner;
use crate::libwallet::{
	AcctPathMapping, Error, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeHeightResult, OutputCommitMapping, PaymentData, Slate, TxLogEntry, WalletBackend,
	WalletInfo,
};

/// Main interface into all wallet API functions.
/// Wallet APIs are split into two seperate blocks of functionality
/// called the ['Owner'](struct.Owner.html) and ['Foreign'](struct.Foreign.html) APIs
///
/// * The 'Owner' API is intended to expose methods that are to be
/// used by the wallet owner only. It is vital that this API is not
/// exposed to anyone other than the owner of the wallet (i.e. the
/// person with access to the seed and password.
///
/// Methods in both APIs are intended to be 'single use', that is to say each
/// method will 'open' the wallet (load the keychain with its master seed), perform
/// its operation, then 'close' the wallet (unloading references to the keychain and master
/// seed).

pub struct Owner<W: ?Sized, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// A reference-counted mutex to an implementation of the
	/// [`WalletBackend`](../gotts_wallet_libwallet/types/trait.WalletBackend.html) trait.
	pub wallet: Arc<Mutex<W>>,
	/// Flag to normalize some output during testing. Can mostly be ignored.
	pub doctest_mode: bool,
	phantom: PhantomData<K>,
	phantom_c: PhantomData<C>,
}

impl<W: ?Sized, C, K> Owner<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// Create a new API instance with the given wallet instance. All subsequent
	/// API calls will operate on this instance of the wallet.
	///
	/// Each method will call the [`WalletBackend`](../gotts_wallet_libwallet/types/trait.WalletBackend.html)'s
	/// [`open_with_credentials`](../gotts_wallet_libwallet/types/trait.WalletBackend.html#tymethod.open_with_credentials)
	/// (initialising a keychain with the master seed,) perform its operation, then close the keychain
	/// with a call to [`close`](../gotts_wallet_libwallet/types/trait.WalletBackend.html#tymethod.close)
	///
	/// # Arguments
	/// * `wallet_in` - A reference-counted mutex containing an implementation of the
	/// [`WalletBackend`](../gotts_wallet_libwallet/types/trait.WalletBackend.html) trait.
	///
	/// # Returns
	/// * An instance of the OwnerApi holding a reference to the provided wallet
	///
	/// # Example
	/// ```
	/// use gotts_wallet_util::gotts_keychain as keychain;
	/// use gotts_wallet_util::gotts_util as util;
	/// use gotts_wallet_api as api;
	/// use gotts_wallet_config as config;
	/// use gotts_wallet_impls as impls;
	/// use gotts_wallet_libwallet as libwallet;
	///
	/// use keychain::ExtKeychain;
	/// use tempfile::tempdir;
	///
	/// use std::sync::Arc;
	/// use util::Mutex;
	///
	/// use api::Owner;
	/// use config::WalletConfig;
	/// use impls::{HTTPNodeClient, LMDBBackend};
	/// use libwallet::WalletBackend;
	///
	/// let mut wallet_config = WalletConfig::default();
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// # 	.path()
	/// # 	.to_str()
	/// # 	.ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// # 	.unwrap();
	/// # wallet_config.data_file_dir = dir.to_owned();
	///
	/// // A NodeClient must first be created to handle communication between
	/// // the wallet and the node.
	///
	/// let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// let mut wallet:Arc<Mutex<dyn WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	///		Arc::new(Mutex::new(
	///			LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	///		));
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(wallet_in: Arc<Mutex<W>>) -> Self {
		Owner {
			wallet: wallet_in,
			doctest_mode: false,
			phantom: PhantomData,
			phantom_c: PhantomData,
		}
	}

	/// Returns a list of accounts stored in the wallet (i.e. mappings between
	/// user-specified labels and BIP32 derivation paths.
	///
	/// # Returns
	/// * Result Containing:
	/// * A Vector of [`AcctPathMapping`](../gotts_wallet_libwallet/types/struct.AcctPathMapping.html) data
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * A wallet should always have the path with the label 'default' path defined,
	/// with path m/0/0
	/// * This method does not need to use the wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	///
	/// let result = api_owner.accounts();
	///
	/// if let Ok(accts) = result {
	///		//...
	/// }
	/// ```

	pub fn accounts(&self) -> Result<Vec<AcctPathMapping>, Error> {
		let mut w = self.wallet.lock();
		owner::accounts(&mut *w)
	}

	/// Creates a new 'account', which is a mapping of a user-specified
	/// label to a BIP32 path
	///
	/// # Arguments
	/// * `label` - A human readable label to which to map the new BIP32 Path
	///
	/// # Returns
	/// * Result Containing:
	/// * A [Keychain Identifier](../gotts_keychain/struct.Identifier.html) for the new path
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * Wallets should be initialised with the 'default' path mapped to `m/0/0`
	/// * Each call to this function will increment the first element of the path
	/// so the first call will create an account at `m/1/0` and the second at
	/// `m/2/0` etc. . .
	/// * The account path is used throughout as the parent key for most key-derivation
	/// operations. See [`set_active_account`](struct.Owner.html#method.set_active_account) for
	/// further details.
	///
	/// * This function does not need to use the root wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	///
	/// let result = api_owner.create_account_path("account1");
	///
	/// if let Ok(identifier) = result {
	///		//...
	/// }
	/// ```

	pub fn create_account_path(&self, label: &str) -> Result<Identifier, Error> {
		let mut w = self.wallet.lock();
		owner::create_account_path(&mut *w, label)
	}

	/// Sets the wallet's currently active account. This sets the
	/// BIP32 parent path used for most key-derivation operations.
	///
	/// # Arguments
	/// * `label` - The human readable label for the account. Accounts can be retrieved via
	/// the [`account`](struct.Owner.html#method.accounts) method
	///
	/// # Returns
	/// * Result Containing:
	/// * `Ok(())` if the path was correctly set
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * Wallet parent paths are 2 path elements long, e.g. `m/0/0` is the path
	/// labelled 'default'. Keys derived from this parent path are 3 elements long,
	/// e.g. the secret keys derived from the `m/0/0` path will be  at paths `m/0/0/0`,
	/// `m/0/0/1` etc...
	///
	/// * This function does not need to use the root wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	///
	/// let result = api_owner.create_account_path("account1");
	///
	/// if let Ok(identifier) = result {
	///		// set the account active
	///		let result2 = api_owner.set_active_account("account1");
	/// }
	/// ```

	pub fn set_active_account(&self, label: &str) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		owner::set_active_account(&mut *w, label)
	}

	/// Returns a list of outputs from the active account in the wallet.
	///
	/// # Arguments
	/// * `include_spent` - If `true`, outputs that have been marked as 'spent'
	/// in the wallet will be returned. If `false`, spent outputs will omitted
	/// from the results.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../gotts_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain output information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `tx_id` - If `Some(i)`, only return the outputs associated with
	/// the transaction log entry of id `i`.
	///
	/// # Returns
	/// * `(bool, Vec<OutputCommitMapping>)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains a vector of
	/// [OutputCommitMapping](../gotts_wallet_libwallet/types/struct.OutputCommitMapping.html)
	/// of which each element is a mapping between the wallet's internal
	/// [OutputData](../gotts_wallet_libwallet/types/struct.Output.html)
	/// and the Output commitment as identified in the chain's UTXO set
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// let show_spent = false;
	/// let update_from_node = true;
	/// let tx_id = None;
	///
	/// let result = api_owner.retrieve_outputs(show_spent, update_from_node, tx_id);
	///
	/// if let Ok((was_updated, output_mappings)) = result {
	///		//...
	/// }
	/// ```

	pub fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::retrieve_outputs(&mut *w, include_spent, refresh_from_node, tx_id);
		w.close()?;
		res
	}

	/// Returns a list of payment outputs from the active account in the wallet.
	///
	/// # Arguments
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../gotts_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain output information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `tx_id` - If `Some(i)`, only return the outputs associated with
	/// the transaction log entry of id `i`.
	///
	/// # Returns
	/// * `(bool, Vec<PaymentData>)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains a vector of
	/// [PaymentData](../gotts_wallet_libwallet/types/struct.Output.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// let update_from_node = true;
	/// let tx_id = None;
	///
	/// let result = api_owner.retrieve_payments(update_from_node, tx_id);
	///
	/// if let Ok((was_updated, payments)) = result {
	///		//...
	/// }
	/// ```

	pub fn retrieve_payments(
		&self,
		refresh_from_node: bool,
		tx_id: Option<Uuid>,
	) -> Result<(bool, Vec<PaymentData>), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::retrieve_payments(&mut *w, refresh_from_node, tx_id);
		w.close()?;
		res
	}

	/// Returns a list of [Transaction Log Entries](../gotts_wallet_libwallet/types/struct.TxLogEntry.html)
	/// from the active account in the wallet.
	///
	/// # Arguments
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../gotts_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `tx_id` - If `Some(i)`, only return the transactions associated with
	/// the transaction log entry of id `i`.
	/// * `tx_slate_id` - If `Some(uuid)`, only return transactions associated with
	/// the given [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html) uuid.
	///
	/// # Returns
	/// * `(bool, Vec<TxLogEntry)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the set of retrieved
	/// [TxLogEntries](../gotts_wallet_libwallet/types/struct.TxLogEntry.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(update_from_node, tx_id, tx_slate_id);
	///
	/// if let Ok((was_updated, tx_log_entries)) = result {
	///		//...
	/// }
	/// ```

	pub fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let mut res = owner::retrieve_txs(&mut *w, refresh_from_node, tx_id, tx_slate_id)?;
		if self.doctest_mode {
			res.1 = res
				.1
				.into_iter()
				.map(|mut t| {
					t.confirmation_ts = Some(Utc.ymd(2019, 1, 15).and_hms(16, 1, 26));
					t.creation_ts = Utc.ymd(2019, 1, 15).and_hms(16, 1, 26);
					t
				})
				.collect();
		}
		w.close()?;
		Ok(res)
	}

	/// Returns summary information from the active account in the wallet.
	///
	/// # Arguments
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../gotts_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `minimum_confirmations` - The minimum number of confirmations an output
	/// should have before it's included in the 'amount_currently_spendable' total
	///
	/// # Returns
	/// * (`bool`, [`WalletInfo`](../gotts_wallet_libwallet/types/struct.WalletInfo.html)) - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the Summary [`WalletInfo`](../gotts_wallet_libwallet/types/struct.WalletInfo.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let update_from_node = true;
	/// let minimum_confirmations=10;
	///
	/// // Return summary info for active account
	/// let result = api_owner.retrieve_summary_info(update_from_node, minimum_confirmations);
	///
	/// if let Ok((was_updated, summary_info)) = result {
	///		//...
	/// }
	/// ```

	pub fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::retrieve_summary_info(&mut *w, refresh_from_node, minimum_confirmations);
		w.close()?;
		res
	}

	/// Initiates a new transaction as the sender, creating a new
	/// [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html) object containing
	/// the sender's inputs, change outputs, and public signature data. This slate can
	/// then be sent to the recipient to continue the transaction via the
	/// [Foreign API's `receive_tx`](struct.Foreign.html#method.receive_tx) method.
	///
	/// When a transaction is created, the wallet must also lock inputs (and create unconfirmed
	/// outputs) corresponding to the transaction created in the slate, so that the wallet doesn't
	/// attempt to re-spend outputs that are already included in a transaction before the transaction
	/// is confirmed. This method also returns a function that will perform that locking, and it is
	/// up to the caller to decide the best time to call the lock function
	/// (via the [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs) method).
	/// If the exchange method is intended to be synchronous (such as via a direct http call,)
	/// then the lock call can wait until the response is confirmed. If it is asynchronous, (such
	/// as via file transfer,) the lock call should happen immediately (before the file is sent
	/// to the recipient).
	///
	/// If the `send_args` [`InitTxSendArgs`](../gotts_wallet_libwallet/types/struct.InitTxSendArgs.html),
	/// of the [`args`](../gotts_wallet_libwallet/types/struct.InitTxArgs.html), field is Some, this
	/// function will attempt to perform a synchronous send to the recipient specified in the `dest`
	/// field according to the `method` field, and will also finalize and post the transaction if
	/// the `finalize` field is set.
	///
	/// # Arguments
	/// * `args` - [`InitTxArgs`](../gotts_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * a result containing:
	/// * The transaction [Slate](../gotts_wallet_libwallet/slate/struct.Slate.html),
	/// which can be forwarded to the recieving party by any means. Once the caller is relatively
	/// certain that the transaction has been sent to the recipient, the associated wallet
	/// transaction outputs should be locked via a call to
	/// [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs). This must be called before calling
	/// [`finalize_tx`](struct.Owner.html#method.finalize_tx).
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * This method requires an active connection to a node, and will fail with error if a node
	/// cannot be contacted to refresh output statuses.
	/// * This method will store a partially completed transaction in the wallet's transaction log,
	/// which will be updated on the corresponding call to [`finalize_tx`](struct.Owner.html#method.finalize_tx).
	///
	/// # Example
	/// Set up as in [new](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// // Attempt to create a transaction using the 'default' account
	/// let args = InitTxArgs {
	/// 	src_acct_name: None,
	/// 	amount: 2_000_000_000,
	/// 	minimum_confirmations: 2,
	/// 	max_outputs: 500,
	/// 	num_change_outputs: 1,
	/// 	selection_strategy: "all".to_owned(),
	/// 	message: Some("Have some Gotts. Love, Gotts".to_owned()),
	/// 	..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	args,
	/// );
	///
	/// if let Ok(slate) = result {
	/// 	// Send slate somehow
	/// 	// ...
	/// 	// Lock our outputs if we're happy the slate was (or is being) sent
	/// 	api_owner.tx_lock_outputs(&slate, 0);
	/// }
	/// ```

	pub fn init_send_tx(&self, args: InitTxArgs) -> Result<Slate, Error> {
		let send_args = args.send_args.clone();
		let mut slate = {
			let mut w = self.wallet.lock();
			w.open_with_credentials()?;
			let slate = owner::init_send_tx(&mut *w, args, self.doctest_mode)?;
			w.close()?;
			slate
		};
		// Helper functionality. If send arguments exist, attempt to send
		match send_args {
			Some(sa) => {
				match sa.method.as_ref() {
					"http" => {
						slate = HTTPWalletCommAdapter::new().send_tx_sync(&sa.dest, &slate)?
					}
					"keybase" => {
						//TODO: in case of keybase, the response might take 60s and leave the service hanging
						slate = KeybaseWalletCommAdapter::new().send_tx_sync(&sa.dest, &slate)?;
					}
					_ => {
						error!("unsupported payment method: {}", sa.method);
						return Err(ErrorKind::ClientCallback(
							"unsupported payment method".to_owned(),
						))?;
					}
				}
				self.tx_lock_outputs(&slate, 0)?;
				let slate = match sa.finalize {
					true => self.finalize_tx(&slate)?,
					false => slate,
				};

				if sa.post_tx {
					self.post_tx(Some(slate.id), &slate.tx, sa.fluff)?;
				}
				Ok(slate)
			}
			None => Ok(slate),
		}
	}

	/// Non-interactive transaction send, creating a new
	/// [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html) object containing
	/// the sender's inputs, change outputs, and public signature data. This slate can
	/// then be posted to the chain via the
	/// [Owner API's `post_tx`](struct.Owner.html#method.post_tx) method.
	///
	/// The `send_args` [`InitTxSendArgs`](../gotts_wallet_libwallet/types/struct.InitTxSendArgs.html),
	/// of the [`args`](../gotts_wallet_libwallet/types/struct.InitTxArgs.html) field is mandatory
	/// (i.e. must be Some), because the non-interactive transaction don't need payee's cooperation. The
	/// `method` field must be 'addr', this function will finalize and post the transaction
	/// if the `post_tx` field is set. The `finalize` field will be ignored because the transaction
	/// is always finalized here.
	///
	/// # Arguments
	/// * `args` - [`InitTxArgs`](../gotts_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * a result containing:
	/// * The transaction [Slate](../gotts_wallet_libwallet/slate/struct.Slate.html),
	/// which can be forwarded to the recieving party by any means.
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * This method requires an active connection to a node, and will fail with error if a node
	/// cannot be contacted to refresh output status.
	/// * This method will store a completed transaction in the wallet's transaction log.
	///
	/// # Example
	/// Set up as in [new](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use gotts_wallet_libwallet::api_impl::types::InitTxSendArgs;
	/// let mut api_owner = Owner::new(wallet.clone());
	/// // Attempt to create a non-interactive transaction using the 'default' account
	/// let args = InitTxArgs {
	/// 	src_acct_name: None,
	/// 	amount: 2_000_000_000,
	/// 	minimum_confirmations: 2,
	/// 	max_outputs: 500,
	/// 	num_change_outputs: 1,
	/// 	selection_strategy: "all".to_owned(),
	/// 	message: None,
	///     send_args: Some(InitTxSendArgs {
	///                   method: "addr".to_string(),
	///                   dest: "gs1qqvau3jpu2t04wy3znghhygrdjqvjxekrvs5vkrqjk6hesvjdj7lmcwlwvtd".to_string(),
	///                   finalize: true,
	///                   post_tx: true,
	///                   fluff: true,
	///                }),
	/// 	..Default::default()
	/// };
	/// let result = api_owner.non_interactive_send(
	/// 	args,
	/// );
	///
	/// if let Ok(slate) = result {
	/// 	// A non-interactive transaction is created and sent successfully and has been posted.
	/// }
	/// ```
	pub fn non_interactive_send(&self, args: InitTxArgs) -> Result<Slate, Error> {
		let send_args = args.send_args.clone();
		let mut slate;
		{
			let mut w = self.wallet.lock();
			w.open_with_credentials()?;
			slate = owner::init_send_tx(&mut *w, args, self.doctest_mode)?;
			w.close()?;
		}
		// Helper functionality. If send arguments exist, attempt to process them.
		match send_args {
			Some(sa) => {
				if sa.method != "addr" {
					return Err(ErrorKind::ClientCallback(
						"unsupported payment method".to_owned(),
					))?;
				}
				let recipient_address = Address::from_str(&sa.dest)?;

				// Construction of a non-interactive transaction output
				{
					let mut w = self.wallet.lock();
					w.open_with_credentials()?;
					slate = owner::create_non_interactive_output(
						&mut *w,
						&slate,
						recipient_address,
						self.doctest_mode,
					)?;
					w.close()?;
				}

				// Finalize transaction
				self.tx_lock_outputs(&slate, 0)?;
				slate = self.finalize_tx(&slate)?;

				if sa.post_tx {
					self.post_tx(Some(slate.id), &slate.tx, sa.fluff)?;
				}
				Ok(slate)
			}
			None => Ok(slate),
		}
	}

	/// Get the wallet receiving key for the non-interactive transaction.
	///
	/// # Returns
	/// * ``Ok([`RecipientKey`](../gotts_keychain/RecipientKey/struct.RecipientKey.html))` if successful,
	/// containing the updated slate.
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	///
	/// let result = api_owner.get_recipient_key();
	///
	/// if let Ok(recipient_key) = result {
	///		// if okay, convert it to Address and get the string address to tell the payer.
	///		// . . .
	/// }
	/// ```
	pub fn get_recipient_key(&self) -> Result<RecipientKey, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let recipient_key = owner::get_recipient_key(&mut *w)?;
		w.close()?;
		Ok(recipient_key)
	}

	/// Get the wallet receiving key for the non-interactive transaction, by a specified key id.
	///
	/// # Returns
	/// * ``Ok([`RecipientKey`](../gotts_keychain/RecipientKey/struct.RecipientKey.html))` if successful,
	/// containing the updated slate.
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	///
	/// let key_id =
	///		ExtKeychainPath::new(4, <u32>::max_value(), <u32>::max_value(), 0, 100).to_identifier();
	///
	/// let result = api_owner.get_recipient_key_by_id(&key_id);
	///
	/// if let Ok(recipient_key) = result {
	///		// if okay, convert it to Address and get the string address to tell the payer.
	///		// . . .
	/// }
	/// ```
	pub fn get_recipient_key_by_id(&self, key_id: &Identifier) -> Result<RecipientKey, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let recipient_key = owner::get_recipient_key_by_id(&mut *w, key_id)?;
		w.close()?;
		Ok(recipient_key)
	}

	/// Issues a new invoice transaction slate, essentially a `request for payment`.
	/// The slate created by this function will contain the amount, an output for the amount,
	/// as well as round 1 of singature creation complete. The slate should then be send
	/// to the payer, who should add their inputs and signature data and return the slate
	/// via the [Foreign API's `finalize_invoice_tx`](struct.Foreign.html#method.finalize_invoice_tx) method.
	///
	/// # Arguments
	/// * `args` - [`IssueInvoiceTxArgs`](../gotts_wallet_libwallet/types/struct.IssueInvoiceTxArgs.html),
	/// invoice transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * ``Ok([`slate`](../gotts_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the updated slate.
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	///
	/// let args = IssueInvoiceTxArgs {
	/// 	amount: 60_000_000_000,
	/// 	..Default::default()
	/// };
	/// let result = api_owner.issue_invoice_tx(args);
	///
	/// if let Ok(slate) = result {
	///		// if okay, send to the payer to add their inputs
	///		// . . .
	/// }
	/// ```
	pub fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<Slate, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let slate = owner::issue_invoice_tx(&mut *w, args, self.doctest_mode)?;
		w.close()?;
		Ok(slate)
	}

	/// Processes an invoice tranaction created by another party, essentially
	/// a `request for payment`. The incoming slate should contain a requested
	/// amount, an output created by the invoicer convering the amount, and
	/// part 1 of signature creation completed. This function will add inputs
	/// equalling the amount + fees, as well as perform round 1 and 2 of signature
	/// creation.
	///
	/// Callers should note that no prompting of the user will be done by this function
	/// it is up to the caller to present the request for payment to the user
	/// and verify that payment should go ahead.
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	///
	/// # Arguments
	/// * `slate` - The transaction [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html). The
	/// payer should have filled in round 1 and 2.
	/// * `args` - [`InitTxArgs`](../gotts_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * ``Ok([`slate`](../gotts_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the updated slate.
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	///
	/// // . . .
	/// // The slate has been recieved from the invoicer, somehow
	/// # let slate = Slate::blank(2);
	/// let args = InitTxArgs {
	///		src_acct_name: None,
	///		amount: slate.amount,
	///		minimum_confirmations: 2,
	///		max_outputs: 500,
	///		num_change_outputs: 1,
	///		selection_strategy: "all".to_owned(),
	///		..Default::default()
	///	};
	///
	/// let result = api_owner.process_invoice_tx(&slate, args);
	///
	/// if let Ok(slate) = result {
	///	// If result okay, send back to the invoicer
	///	// . . .
	///	}
	/// ```

	pub fn process_invoice_tx(&self, slate: &Slate, args: InitTxArgs) -> Result<Slate, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let slate = owner::process_invoice_tx(&mut *w, slate, args, self.doctest_mode)?;
		w.close()?;
		Ok(slate)
	}

	/// Locks the outputs associated with the inputs to the transaction in the given
	/// [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html),
	/// making them unavailable for use in further transactions. This function is called
	/// by the sender, (or more generally, all parties who have put inputs into the transaction,)
	/// and must be called before the corresponding call to [`finalize_tx`](struct.Owner.html#method.finalize_tx)
	/// that completes the transaction.
	///
	/// Outputs will generally remain locked until they are removed from the chain,
	/// at which point they will become `Spent`. It is commonplace for transactions not to complete
	/// for various reasons over which a particular wallet has no control. For this reason,
	/// [`cancel_tx`](struct.Owner.html#method.cancel_tx) can be used to manually unlock outputs
	/// and return them to the `Unspent` state.
	///
	/// # Arguments
	/// * `slate` - The transaction [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html). All
	/// * `participant_id` - The participant id, generally 0 for the party putting in funds, 1 for the
	/// party receiving.
	/// elements in the `input` vector of the `tx` field that are found in the wallet's currently
	/// active account will be set to status `Locked`
	///
	/// # Returns
	/// * Ok(()) if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let args = InitTxArgs {
	/// 	src_acct_name: None,
	/// 	amount: 2_000_000_000,
	/// 	minimum_confirmations: 10,
	/// 	max_outputs: 500,
	/// 	num_change_outputs: 1,
	/// 	selection_strategy: "all".to_owned(),
	/// 	message: Some("Remember to lock this when we're happy this is sent".to_owned()),
	/// 	..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	args,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		api_owner.tx_lock_outputs(&slate, 0);
	/// }
	/// ```

	pub fn tx_lock_outputs(&self, slate: &Slate, participant_id: usize) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::tx_lock_outputs(&mut *w, slate, participant_id);
		w.close()?;
		res
	}

	/// Finalizes a transaction, after all parties
	/// have filled in both rounds of Slate generation. This step adds
	/// all participants partial signatures to create the final signature,
	/// resulting in a final transaction that is ready to post to a node.
	///
	/// Note that this function DOES NOT POST the transaction to a node
	/// for validation. This is done in separately via the
	/// [`post_tx`](struct.Owner.html#method.post_tx) function.
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	///
	/// # Arguments
	/// * `slate` - The transaction [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html). All
	/// participants must have filled in both rounds, and the sender should have locked their
	/// outputs (via the [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs) function).
	///
	/// # Returns
	/// * ``Ok([`slate`](../gotts_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the new finalized slate.
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let args = InitTxArgs {
	/// 	src_acct_name: None,
	/// 	amount: 2_000_000_000,
	/// 	minimum_confirmations: 10,
	/// 	max_outputs: 500,
	/// 	num_change_outputs: 1,
	/// 	selection_strategy: "all".to_owned(),
	/// 	message: Some("Finalize this tx now".to_owned()),
	/// 	..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	args,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(&slate);
	/// }
	/// ```

	pub fn finalize_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		let mut w = self.wallet.lock();
		let mut slate = slate.clone();
		w.open_with_credentials()?;
		slate = owner::finalize_tx(&mut *w, &slate)?;
		w.close()?;
		Ok(slate)
	}

	/// Posts a completed transaction to the listening node for validation and inclusion in a block
	/// for mining.
	///
	/// # Arguments
	/// * `tx_slate_id` - If `Some(uuid)`, only return transactions associated with
	/// the given [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html) uuid.
	///
	/// * `tx` - A completed [`Transaction`](../gotts_core/core/transaction/struct.Transaction.html),
	/// typically the `tx` field in the transaction [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html).
	///
	/// * `fluff` - Instruct the node whether to use the Dandelion protocol when posting the
	/// transaction. If `true`, the node should skip the Dandelion phase and broadcast the
	/// transaction to all peers immediately. If `false`, the node will follow dandelion logic and
	/// initiate the stem phase.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let args = InitTxArgs {
	/// 	src_acct_name: None,
	/// 	amount: 2_000_000_000,
	/// 	minimum_confirmations: 10,
	/// 	max_outputs: 500,
	/// 	num_change_outputs: 1,
	/// 	selection_strategy: "all".to_owned(),
	/// 	message: Some("Post this tx".to_owned()),
	/// 	..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	args,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(&slate);
	///		let res = api_owner.post_tx(Some(slate.id), &slate.tx, true);
	/// }
	/// ```
	pub fn post_tx(
		&self,
		tx_slate_id: Option<Uuid>,
		tx: &Transaction,
		fluff: bool,
	) -> Result<(), Error> {
		let client = {
			// todo: try to avoid locking wallet twice in this function.
			// Note: 'owner::post_tx()' can't allow wallet locked, because 'testclient' need to lock
			// wallet for 'award_block_to_wallet'.
			let mut w = self.wallet.lock();
			w.w2n_client().clone()
		};
		let post_res = owner::post_tx(&client, tx, fluff);

		if post_res.is_ok() {
			if tx_slate_id.is_some() {
				let mut w = self.wallet.lock();
				w.open_with_credentials()?;
				owner::set_tx_posted(&mut *w, None, tx_slate_id)?;
				w.close()?;
			}
		}
		post_res
	}

	/// Re-Posts the last unconfirmed transaction/s to the listening node for validation and inclusion in a block
	/// for mining.
	///
	/// # Arguments
	/// * `fluff` - Instruct the node whether to use the Dandelion protocol when posting the
	/// transaction. If `true`, the node should skip the Dandelion phase and broadcast the
	/// transaction to all peers immediately. If `false`, the node will follow dandelion logic and
	/// initiate the stem phase.
	///
	/// * `include_last` - Whether including the last one transaction, which could be the current
	/// operating transaction.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let args = InitTxArgs {
	/// 	src_acct_name: None,
	/// 	amount: 2_000_000_000,
	/// 	minimum_confirmations: 10,
	/// 	max_outputs: 500,
	/// 	num_change_outputs: 1,
	/// 	selection_strategy: "all".to_owned(),
	/// 	message: Some("Post this tx".to_owned()),
	/// 	..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	args,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(&slate);
	///		let res = api_owner.repost_last_txs(true, true);
	/// }
	/// ```
	pub fn repost_last_txs(&self, fluff: bool, include_last: bool) -> Result<bool, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::repost_last_txs(&mut *w, fluff, include_last);
		w.close()?;
		res
	}

	/// Cancels a transaction. This entails:
	/// * Setting the transaction status to either `TxSentCancelled` or `TxReceivedCancelled`
	/// * Deleting all change outputs or recipient outputs associated with the transaction
	/// * Setting the status of all assocatied inputs from `Locked` to `Spent` so they can be
	/// used in new transactions.
	///
	/// Transactions can be cancelled by transaction log id or slate id (call with either set to
	/// Some, not both)
	///
	/// # Arguments
	///
	/// * `tx_id` - If present, cancel by the [`TxLogEntry`](../gotts_wallet_libwallet/types/struct.TxLogEntry.html) id
	/// for the transaction.
	///
	/// * `tx_slate_id` - If present, cancel by the Slate id.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let args = InitTxArgs {
	/// 	src_acct_name: None,
	/// 	amount: 2_000_000_000,
	/// 	minimum_confirmations: 10,
	/// 	max_outputs: 500,
	/// 	num_change_outputs: 1,
	/// 	selection_strategy: "all".to_owned(),
	/// 	message: Some("Cancel this tx".to_owned()),
	/// 	..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	args,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate, 0);
	///		//
	///		// We didn't get the slate back, or something else went wrong
	///		//
	///		let res = api_owner.cancel_tx(None, Some(slate.id.clone()));
	/// }
	/// ```

	pub fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::cancel_tx(&mut *w, tx_id, tx_slate_id);
		w.close()?;
		res
	}

	/// Retrieves the stored transaction associated with a TxLogEntry. Can be used even after the
	/// transaction has completed.
	///
	/// # Arguments
	///
	/// * `tx_log_entry` - A [`TxLogEntry`](../gotts_wallet_libwallet/types/struct.TxLogEntry.html)
	///
	/// # Returns
	/// * Ok with the stored  [`Transaction`](../gotts_core/core/transaction/struct.Transaction.html)
	/// if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(update_from_node, tx_id, tx_slate_id);
	///
	/// if let Ok((was_updated, tx_log_entries)) = result {
	///		let stored_tx = api_owner.get_stored_tx(&tx_log_entries[0]).unwrap();
	///		//...
	/// }
	/// ```

	// TODO: Should be accepting an id, not an entire entry struct
	pub fn get_stored_tx(&self, tx_log_entry: &TxLogEntry) -> Result<Option<Transaction>, Error> {
		let w = self.wallet.lock();
		owner::get_stored_tx(&*w, tx_log_entry)
	}

	/// Verifies all messages in the slate match their public keys.
	///
	/// The optional messages themselves are part of the `participant_data` field within the slate.
	/// Messages are signed with the same key used to sign for the paricipant's inputs, and can thus be
	/// verified with the public key found in the `public_blind_excess` field. This function is a
	/// simple helper to returns whether all signatures in the participant data match their public
	/// keys.
	///
	/// # Arguments
	///
	/// * `slate` - The transaction [`Slate`](../gotts_wallet_libwallet/slate/struct.Slate.html).
	///
	/// # Returns
	/// * `Ok(())` if successful and the signatures validate
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let args = InitTxArgs {
	/// 	src_acct_name: None,
	/// 	amount: 2_000_000_000,
	/// 	minimum_confirmations: 10,
	/// 	max_outputs: 500,
	/// 	num_change_outputs: 1,
	/// 	selection_strategy: "all".to_owned(),
	/// 	message: Some("Just verify messages".to_owned()),
	/// 	..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	args,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.verify_slate_messages(&slate);
	/// }
	/// ```
	pub fn verify_slate_messages(&self, slate: &Slate) -> Result<(), Error> {
		owner::verify_slate_messages(slate)
	}

	/// Scans the entire UTXO set from the node, creating outputs for each scanned
	/// output that matches the wallet's master seed. This function is intended to be called as part
	/// of a recovery process (either from BIP32 phrase or backup seed files,) and will error if the
	/// wallet is non-empty, i.e. contains any outputs at all.
	///
	/// This operation scans the entire chain, and is expected to be time intensive. It is imperative
	/// that no other processes should be trying to use the wallet at the same time this function is
	/// running.
	///
	/// A single [TxLogEntry](../gotts_wallet_libwallet/types/struct.TxLogEntry.html) is created for
	/// all non-coinbase outputs discovered and restored during this process. A separate entry
	/// is created for each coinbase output.
	///
	/// # Arguments
	///
	/// * None
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let result = api_owner.restore();
	///
	/// if let Ok(_) = result {
	///		// Wallet outputs should be consistent with what's on chain
	///		// ...
	/// }
	/// ```
	pub fn restore(&self) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::restore(&mut *w);
		w.close()?;
		res
	}

	/// Scans the UTXO set on batch (from a start_index for a batch size) from the node, creating
	/// outputs for each scanned output that matches the wallet's master seed. This function is
	/// intended to be called as part of a recovery process (either from BIP32 phrase or backup
	/// seed files,).
	///
	/// This operation scans the chain UTXO sets starting from a PMMR index, and is expected to be
	/// NOT too time intensive because of a small `batch_size` such as 1,000. It is imperative
	/// that no other processes should be trying to use the wallet at the same time this function is
	/// running.
	///
	/// A single [TxLogEntry](../gotts_wallet_libwallet/types/struct.TxLogEntry.html) is created for
	/// all non-coinbase outputs discovered and restored during this process. A separate entry
	/// is created for each coinbase output.
	///
	/// # Arguments
	///
	/// * `start_index` - the UTXO sets PMMR start index
	///
	/// * `batch_size` - batch size of UTXO sets retrieving
	///
	/// # Returns
	/// * `Ok((highest_index, last_retrieved_index))` if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let result = api_owner.restore_batch(1, 1000);
	///
	/// if let Ok((highest_index, last_retrieved_index, num_of_found)) = result {
	///		// ...
	/// }
	/// ```
	pub fn restore_batch(
		&self,
		start_index: u64,
		batch_size: u64,
	) -> Result<(u64, u64, u64), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::restore_batch(&mut *w, start_index, batch_size);
		w.close()?;
		res
	}

	/// Scans the entire UTXO set from the node, identify which outputs belong to the given wallet
	/// update the wallet state to be consistent with what's currently in the UTXO set.
	///
	/// This function can be used to repair wallet state, particularly by restoring outputs that may
	/// be missing if the wallet owner has cancelled transactions locally that were then successfully
	/// posted to the chain.
	///
	/// This operation scans the entire chain, and is expected to be time intensive. It is imperative
	/// that no other processes should be trying to use the wallet at the same time this function is
	/// running.
	///
	/// When an output is found that doesn't exist in the wallet, a corresponding
	/// [TxLogEntry](../gotts_wallet_libwallet/types/struct.TxLogEntry.html) is created.
	///
	/// # Arguments
	///
	/// * `delete_unconfirmed` - if `false`, the check_repair process will be non-destructive, and
	/// mostly limited to restoring missing outputs. It will leave unconfirmed transaction logs entries
	/// and unconfirmed outputs intact. If `true`, the process will unlock all locked outputs,
	/// restore all missing outputs, and mark any outputs that have been marked 'Spent' but are still
	/// in the UTXO set as 'Unspent' (as can happen during a fork). It will also attempt to cancel any
	/// transaction log entries associated with any locked outputs or outputs incorrectly marked 'Spent'.
	/// Note this completely removes all outstanding transactions, so users should be very aware what
	/// will happen if this flag is set. Note that if transactions/outputs are removed that later
	/// confirm on the chain, another call to this function will restore them.
	///
	/// * `ignore_within` - ignore checking the txs which just happened within this specified minutes,
	/// if 0, check all txs including recent Spent and Locked output; proposed value is 30 minutes.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let result = api_owner.check_repair(
	/// 	false,
	///     30,
	/// );
	///
	/// if let Ok(_) = result {
	///		// Wallet outputs should be consistent with what's on chain
	///		// ...
	/// }
	/// ```

	pub fn check_repair(&self, delete_unconfirmed: bool, ignore_within: u64) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::check_repair(&mut *w, delete_unconfirmed, ignore_within);
		w.close()?;
		res
	}

	/// Same as `check_repair` except by index on batch
	///
	/// # Arguments
	///
	/// * `delete_unconfirmed` - same as in `check_repair`
	///
	/// * `ignore_within` - same as in `check_repair`
	///
	/// * `start_index` - the UTXO sets PMMR start index
	///
	/// * `batch_size` - batch size of UTXO sets retrieving
	///
	/// * `is_update_outputs` - if `false`, the check_repair_batch process will skip the update_outputs.
	/// This is useful to speed up this check_repair_batch function, because it only make sense to call
	/// one time of update_outputs() in a whole check_repair_batch procedure. Only set this parameter
	/// as `true` in the 1st call of this function in a check_repair_batch procedure.
	///
	/// # Returns
	/// * `Ok((highest_index, last_retrieved_index))` if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let result = api_owner.check_repair_batch(
	/// 	false, 30, 1, 1000, true
	/// );
	///
	/// if let Ok((highest_index, last_retrieved_index)) = result {
	///		// ...
	/// }
	/// ```

	pub fn check_repair_batch(
		&self,
		delete_unconfirmed: bool,
		ignore_within: u64,
		start_index: u64,
		batch_size: u64,
		is_update_outputs: bool,
	) -> Result<(u64, u64), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::check_repair_batch(
			&mut *w,
			delete_unconfirmed,
			ignore_within,
			start_index,
			batch_size,
			is_update_outputs,
		);
		w.close()?;
		res
	}

	/// Retrieves the last known height known by the wallet. This is determined as follows:
	/// * If the wallet can successfully contact its configured node, the reported node
	/// height is returned, and the `updated_from_node` field in the response is `true`
	/// * If the wallet cannot contact the node, this function returns the maximum height
	/// of all outputs contained within the wallet, and the `updated_from_node` fields
	/// in the response is set to false.
	///
	/// Clients should generally ensure the `updated_from_node` field is returned as
	/// `true` before assuming the height for any operation.
	///
	/// # Arguments
	///
	/// * None
	///
	/// # Returns
	/// * Ok with a  [`NodeHeightResult`](../gotts_wallet_libwallet/types/struct.NodeHeightResult.html)
	/// if successful. If the height result was obtained from the configured node,
	/// `updated_from_node` will be set to `true`
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// let result = api_owner.node_height();
	///
	/// if let Ok(node_height_result) = result {
	///		if node_height_result.updated_from_node {
	///			//we can assume node_height_result.height is relatively safe to use
	///
	///		}
	///		//...
	/// }
	/// ```

	pub fn node_height(&self) -> Result<NodeHeightResult, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::node_height(&mut *w);
		w.close()?;
		res
	}

	/// Change password. This is determined as follows:
	///
	/// # Arguments
	///
	/// * `old_password` - the old password
	///
	/// * `new_password` - the new password
	///
	/// # Returns
	///
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../gotts_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # gotts_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// let oldpass = Some(ZeroingString::from("password"));
	/// let result = api_owner.change_password(&oldpass, "password");
	/// if let Ok(_) = result {
	///		//password has been changed successfully
	/// }
	/// ```
	pub fn change_password(
		&self,
		old_password: &Option<ZeroingString>,
		new_password: &str,
	) -> Result<(), Error> {
		if old_password.is_none() {
			return Err(ErrorKind::GenericError(
				"change_password failed for empty old password".to_owned(),
			)
			.into());
		}

		let mut w = self.wallet.lock();
		w.open_with_credentials()?;

		//TODO: move these out of 'gotts_wallet_api' crate, since it's not an owner_api.
		// Move to 'gotts_wallet_libwallet' crate for example.
		{
			let data_file_dir = w.wallet_data_dir();
			let wallet_seed =
				WalletSeed::update(data_file_dir, &old_password.clone().unwrap(), new_password);
			if let Err(e) = wallet_seed {
				return Err(
					ErrorKind::GenericError(format!("wallet seed update fail for {}", e)).into(),
				);
			}

			w.update_passphrase(new_password);
		}

		w.close()?;
		Ok(())
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_setup_doc_env {
	($wallet:ident, $wallet_config:ident) => {
		use gotts_wallet_api as api;
		use gotts_wallet_config as config;
		use gotts_wallet_impls as impls;
		use gotts_wallet_libwallet as libwallet;
		use gotts_wallet_util::gotts_keychain as keychain;
		use gotts_wallet_util::gotts_util as util;

		use keychain::{ExtKeychain, ExtKeychainPath};
		use tempfile::tempdir;

		use std::sync::Arc;
		use util::Mutex;

		use api::Owner;
		use config::WalletConfig;
		use impls::{HTTPNodeClient, LMDBBackend, WalletSeed};
		use libwallet::{InitTxArgs, IssueInvoiceTxArgs, Slate, WalletBackend};
		use util::ZeroingString;

		let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
		let dir = dir
			.path()
			.to_str()
			.ok_or("Failed to convert tmpdir path to string.".to_owned())
			.unwrap();
		let mut wallet_config = WalletConfig::default();
		wallet_config.data_file_dir = dir.to_owned();
		let pw = "";

		let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
		let mut $wallet: Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> = Arc::new(
			Mutex::new(LMDBBackend::new(wallet_config.clone(), pw, node_client).unwrap()),
			);
	};
}
