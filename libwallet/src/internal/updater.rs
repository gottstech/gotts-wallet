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

//! Utilities to check the status of all the outputs we have stored in
//! the wallet storage and update them.

use std::collections::HashMap;
use uuid::Uuid;

use super::keys::recipient_parent_key_id;
use crate::error::Error;
use crate::gotts_core::consensus::reward;
use crate::gotts_core::core::{Output, TxKernel, TxKernelApiEntry};
use crate::gotts_core::global;
use crate::gotts_core::libtx::proof::ProofBuilder;
use crate::gotts_core::libtx::reward;
use crate::gotts_keychain::{Identifier, Keychain};
use crate::gotts_util as util;
use crate::gotts_util::secp::pedersen;
use crate::internal::keys;
use crate::types::{
	NodeClient, OutputData, OutputStatus, TxLogEntry, TxLogEntryType, WalletBackend, WalletInfo,
};
use crate::{BlockFees, CbData, OutputCommitMapping, PaymentData};

/// Retrieve all of the outputs (doesn't attempt to update from node)
pub fn retrieve_outputs<T: ?Sized, C, K>(
	wallet: &mut T,
	show_spent: bool,
	tx_id: Option<u32>,
	slate_id: Option<Uuid>,
	parent_key_id: Option<&Identifier>,
) -> Result<Vec<OutputCommitMapping>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// just read the wallet here, no need for a write lock
	let mut outputs = wallet
		.iter()
		.filter(|out| show_spent || out.status != OutputStatus::Spent)
		.collect::<Vec<_>>();

	// only include outputs with a given tx_id if provided
	if let Some(id) = tx_id {
		outputs = outputs
			.into_iter()
			.filter(|out| out.tx_log_entry == Some(id))
			.collect::<Vec<_>>();
	}

	// only include outputs with a given slate_id if provided
	if let Some(id) = slate_id {
		outputs = outputs
			.into_iter()
			.filter(|out| out.slate_id == Some(id))
			.collect::<Vec<_>>();
	}

	if let Some(k) = parent_key_id {
		outputs = outputs
			.iter()
			.filter(|o| o.root_key_id == *k || o.root_key_id == recipient_parent_key_id())
			.map(|o| o.clone())
			.collect();
	}

	outputs.sort_by_key(|out| out.n_child);
	let keychain = wallet.keychain().clone();

	let res = outputs
		.into_iter()
		.map(|output| {
			let commit = match output.commit.clone() {
				Some(c) => pedersen::Commitment::from_vec(util::from_hex(c).unwrap()),
				None => keychain.commit(output.w, &output.key_id).unwrap(),
			};
			OutputCommitMapping { output, commit }
		})
		.collect();
	Ok(res)
}

/// Retrieve all of the payment outputs (doesn't attempt to update from node)
pub fn retrieve_payments<T: ?Sized, C, K>(
	wallet: &mut T,
	tx_id: Option<Uuid>,
) -> Result<Vec<PaymentData>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// just read the wallet here, no need for a write lock

	let mut payments = if let Some(slate_id) = tx_id {
		wallet
			.payment_entries_iter_tx(&slate_id)
			.collect::<Vec<_>>()
	} else {
		wallet.payment_entries_iter_all().collect::<Vec<_>>()
	};

	payments.sort_by(|a, b| a.height.cmp(&b.height).then(a.id.cmp(&b.id)));
	Ok(payments)
}

/// Retrieve all of the transaction entries, or a particular entry
/// if `parent_key_id` is set, only return entries from that key
pub fn retrieve_txs<T: ?Sized, C, K>(
	wallet: &mut T,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
	parent_key_id: Option<&Identifier>,
	outstanding_only: bool,
	tx_type: Option<TxLogEntryType>,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut txs: Vec<TxLogEntry> = wallet
		.tx_log_iter()
		.filter(|tx_entry| {
			let f_pk = match parent_key_id {
				Some(k) => tx_entry.parent_key_id == *k,
				None => true,
			};
			let f_tx_id = match tx_id {
				Some(i) => tx_entry.id == i,
				None => true,
			};
			let f_txs = match tx_slate_id {
				Some(t) => tx_entry.tx_slate_id == Some(t),
				None => true,
			};
			let f_outstanding = match outstanding_only {
				true => {
					!tx_entry.confirmed
						&& (tx_entry.tx_type == TxLogEntryType::TxReceived
							|| tx_entry.tx_type == TxLogEntryType::TxSent
							|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled)
				}
				false => true,
			};
			let f_tx_type = match &tx_type {
				Some(t) => tx_entry.tx_type == *t,
				None => true,
			};
			f_pk && f_tx_id && f_txs && f_outstanding && f_tx_type
		})
		.collect();
	txs.sort_by_key(|tx| tx.creation_ts);
	Ok(txs)
}

/// Refreshes the outputs in a wallet with the latest information
/// from a node
pub fn refresh_outputs<T: ?Sized, C, K>(
	wallet: &mut T,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let height = wallet.w2n_client().get_chain_height()?;
	refresh_output_state(wallet, height, parent_key_id, update_all)?;
	Ok(())
}

/// build a local map of wallet outputs keyed by commit
/// and a list of outputs we want to query the node for
pub fn map_wallet_outputs<T: ?Sized, C, K>(
	wallet: &mut T,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<HashMap<pedersen::Commitment, (Identifier, Option<u64>)>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut wallet_outputs: HashMap<pedersen::Commitment, (Identifier, Option<u64>)> =
		HashMap::new();
	let keychain = wallet.keychain().clone();
	let unspents: Vec<OutputData> = wallet
		.iter()
		.filter(|x| {
			(x.root_key_id == *parent_key_id || x.root_key_id == recipient_parent_key_id())
				&& x.status != OutputStatus::Spent
		})
		.collect();

	let tx_entries = retrieve_txs(wallet, None, None, Some(&parent_key_id), true, None)?;

	// Only select outputs that are actually involved in an outstanding transaction
	let unspents: Vec<OutputData> = match update_all {
		false => unspents
			.into_iter()
			.filter(|x| match x.tx_log_entry.as_ref() {
				Some(t) => {
					if let Some(_) = tx_entries.iter().find(|&te| te.id == *t) {
						true
					} else {
						false
					}
				}
				None => true,
			})
			.collect(),
		true => unspents,
	};

	for out in unspents {
		let commit = match out.commit.clone() {
			Some(c) => pedersen::Commitment::from_vec(util::from_hex(c).unwrap()),
			None => keychain.commit(out.w, &out.key_id).unwrap(),
		};
		wallet_outputs.insert(commit, (out.key_id.clone(), out.mmr_index));
	}
	Ok(wallet_outputs)
}

/// Cancel transaction and associated outputs
pub fn cancel_tx_and_outputs<T: ?Sized, C, K>(
	wallet: &mut T,
	tx: TxLogEntry,
	outputs: Vec<OutputData>,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut batch = wallet.batch()?;

	for mut o in outputs {
		match o.status {
			OutputStatus::Unconfirmed => batch.delete(&o.key_id, &o.mmr_index)?,
			OutputStatus::Locked => {
				// unlock locked outputs
				o.status = OutputStatus::Unspent;
				batch.save(o)?;
			}
			OutputStatus::Spent => {
				//assert_eq!(o.is_change, Some(true));
				o.status = OutputStatus::Unconfirmed;
				batch.save(o)?;
			}
			_ => {}
		}
	}
	let mut tx = tx.clone();
	if tx.tx_type == TxLogEntryType::TxSent {
		tx.tx_type = TxLogEntryType::TxSentCancelled;
	}
	if tx.tx_type == TxLogEntryType::TxReceived {
		tx.tx_type = TxLogEntryType::TxReceivedCancelled;
	}
	batch.save_tx_log_entry(tx, parent_key_id)?;
	batch.commit()?;
	Ok(())
}

/// Cancel transaction payments
pub fn cancel_payments<T: ?Sized, C, K>(wallet: &mut T, tx_slate_id: Uuid) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut batch = wallet.batch()?;
	batch.delete_payment(&tx_slate_id)?;
	batch.commit()?;
	Ok(())
}

/// Apply refreshed API output data to the wallet
pub fn apply_api_outputs<T: ?Sized, C, K>(
	wallet: &mut T,
	wallet_outputs: &HashMap<pedersen::Commitment, (Identifier, Option<u64>)>,
	api_outputs: &HashMap<pedersen::Commitment, (String, u64, u64)>,
	height: u64,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// now for each commit, find the output in the wallet and the corresponding
	// api output (if it exists) and refresh it in-place in the wallet.
	// Note: minimizing the time we spend holding the wallet lock.
	{
		let last_confirmed_height = wallet.last_confirmed_height()?;
		// If the server height is less than our confirmed height, don't apply
		// these changes as the chain is syncing, incorrect or forking
		if height < last_confirmed_height {
			warn!(
				"Not updating outputs as the height of the node's chain \
				 is less than the last reported wallet update height."
			);
			warn!("Please wait for sync on node to complete or fork to resolve and try again.");
			return Ok(());
		}
		let mut batch = wallet.batch()?;
		for (commit, (id, mmr_index)) in wallet_outputs.iter() {
			if let Ok(mut output) = batch.get(id, mmr_index) {
				match api_outputs.get(&commit) {
					Some(o) => {
						// if this is a coinbase tx being confirmed, it's recordable in tx log
						if output.is_coinbase && output.status == OutputStatus::Unconfirmed {
							let log_id = batch.next_tx_log_id(parent_key_id)?;
							let mut t = TxLogEntry::new(
								parent_key_id.clone(),
								TxLogEntryType::ConfirmedCoinbase,
								log_id,
							);
							t.confirmed = true;
							t.amount_credited = output.value;
							t.amount_debited = 0;
							t.num_outputs = 1;
							t.update_confirmation_ts();
							output.tx_log_entry = Some(log_id);
							batch.save_tx_log_entry(t, &parent_key_id)?;
						}
						// also mark the transaction in which this output is involved as confirmed
						// note that one involved input/output confirmation SHOULD be enough
						// to reliably confirm the tx
						if !output.is_coinbase && output.status == OutputStatus::Unconfirmed {
							let tx = batch.tx_log_iter().find(|t| {
								Some(t.id) == output.tx_log_entry
									&& t.parent_key_id == *parent_key_id
							});

							let mut is_canceled_tx = false;
							if let Some(mut t) = tx {
								if t.tx_type == TxLogEntryType::TxSentCancelled {
									// For a send cancelled tx, the 'output' presented in 'api_outputs' is actually the unlocked 'input'.
									// in this case, we shouldn't mark the cancelled transaction as 'confirmed'.
									is_canceled_tx = true;
								} else {
									// todo: use block time instead of local time.
									t.update_confirmation_ts();
									t.height = Some(o.1);
									t.confirmed = true;
									batch.save_tx_log_entry(t, &parent_key_id)?;
								}
							}

							if !is_canceled_tx {
								// if there's a related payment output being confirmed, refresh that payment log
								if let Some(slate_id) = output.slate_id {
									let payment_entries = batch
										.payment_entries_iter_tx(&slate_id)
										.collect::<Vec<_>>();

									for mut payment in payment_entries {
										payment.height = o.1;
										payment.mark_confirmed();
										batch.save_payment(payment)?;
									}
								}
							}
						}
						output.height = o.1;
						output.mark_unspent();
					}
					None => output.mark_spent(),
				};
				batch.save(output)?;
			}
		}
		{
			batch.save_last_confirmed_height(parent_key_id, height)?;
		}
		batch.commit()?;
	}
	Ok(())
}

/// Apply refreshed API tx kernels data to the wallet
pub fn apply_api_tx_kernels<T: ?Sized, C, K>(
	wallet: &mut T,
	tx_entries: Vec<TxLogEntry>,
	api_tx_kernels: &HashMap<pedersen::Commitment, TxKernelApiEntry>,
	height: u64,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// now find the transaction in the wallet and the corresponding
	// api tx kernels (if it exists) and refresh it in-place in the wallet.
	// Note: minimizing the time we spend holding the wallet lock.
	{
		let last_confirmed_height = wallet.last_confirmed_height()?;
		// If the server height is less than our confirmed height, don't apply
		// these changes as the chain is syncing, incorrect or forking
		if height < last_confirmed_height {
			warn!("apply_api_tx_kernels ignored. node is syncing?");
			return Ok(());
		}
		let mut batch = wallet.batch()?;
		for mut tx_entry in tx_entries {
			if let Some(excess) = tx_entry.kernel_excess.clone() {
				if let Ok(excess) = util::from_hex(excess) {
					let excess = pedersen::Commitment::from_vec(excess);
					match api_tx_kernels.get(&excess) {
						Some(tx_kernel_api_entry) => {
							// mark the output/s involved as confirmed
							let outputs = batch
								.iter()
								.filter(|out| out.tx_log_entry == Some(tx_entry.id))
								.collect::<Vec<_>>();
							for mut output in outputs {
								match output.status {
									// for transaction output/s
									OutputStatus::Unconfirmed => {
										output.mark_unspent();
										output.height = tx_kernel_api_entry.height;
										batch.save(output)?;
									}
									// for transaction input/s
									OutputStatus::Locked => {
										output.mark_spent();
										output.height = tx_kernel_api_entry.height;
										batch.save(output)?;
									}
									_ => {}
								}

								// refresh the payment log
								if let Some(slate_id) = tx_entry.tx_slate_id {
									let payment_entries = batch
										.payment_entries_iter_tx(&slate_id)
										.collect::<Vec<_>>();

									for mut payment in payment_entries {
										payment.height = tx_kernel_api_entry.height;
										payment.mark_confirmed();
										batch.save_payment(payment)?;
									}
								}
							}

							// also mark the transaction as confirmed
							// todo: use block time instead of local time.
							tx_entry.update_confirmation_ts();
							tx_entry.height = Some(tx_kernel_api_entry.height);
							tx_entry.confirmed = true;
							batch.save_tx_log_entry(tx_entry, &parent_key_id)?;
						}
						None => {}
					};
				}
			}
		}
		{
			// Note: don't do this, instead, leave the 'apply_api_outputs' to update this.
			// batch.save_last_confirmed_height(parent_key_id, height)?;
		}
		batch.commit()?;
	}
	Ok(())
}

/// Builds a single api query to retrieve the latest output data from the node.
/// So we can refresh the local wallet outputs.
fn refresh_output_state<T: ?Sized, C, K>(
	wallet: &mut T,
	height: u64,
	parent_key_id: &Identifier,
	update_all: bool,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	debug!("Refreshing wallet outputs");

	// Firstly, query the sending tx kernel/s to refresh the txs state
	// Notes:
	//	1. This ONLY works for sending transactions (because we don't know the tx kernel for receiving tx)
	//  2. There's time limitation for this refreshing
	//		- ONLY works for the transactions happened in 2 days.
	//		- Normally also works for transactions happened in 2 weeks (non-archive mode node).
	//		- Depending on the node status of tx kernel mmr position index, which is configurable.
	{
		let tx_entries: Vec<TxLogEntry> =
			retrieve_txs(wallet, None, None, Some(&parent_key_id), true, None)?
				.into_iter()
				.filter(|t| {
					(t.tx_type == TxLogEntryType::TxSent
						|| t.tx_type == TxLogEntryType::TxSentCancelled)
						&& t.kernel_excess.is_some()
				})
				.collect();
		let wallet_kernels_keys = tx_entries
			.iter()
			.map(|tx| tx.kernel_excess.clone().unwrap())
			.collect();

		let api_tx_kernels = wallet
			.w2n_client()
			.get_tx_kernels_from_node(wallet_kernels_keys)?;
		if api_tx_kernels.len() > 0 {
			apply_api_tx_kernels(wallet, tx_entries, &api_tx_kernels, height, parent_key_id)?;
		}
	}

	// Secondly, query the output/s existence in the chain UTXO sets to refresh the txs state.
	// Note:
	//	1. Normally, after above tx kernel querying, this should only update the receiving transaction state.
	//	2. But for some cases, when a transaction is old (2 weeks ago for example), the node could not
	//		have the tx kernel mmr position index, if one of the transaction outputs is still unspent,
	//		this query will work.
	{
		// build a local map of wallet outputs keyed by commit
		// and a list of outputs we want to query the node for
		let wallet_outputs = map_wallet_outputs(wallet, parent_key_id, update_all)?;

		let wallet_output_keys = wallet_outputs.keys().map(|commit| commit.clone()).collect();

		let api_outputs = wallet
			.w2n_client()
			.get_outputs_from_node(wallet_output_keys)?;
		apply_api_outputs(wallet, &wallet_outputs, &api_outputs, height, parent_key_id)?;
	}
	clean_old_unconfirmed(wallet, height)?;
	Ok(())
}

/// Only for miner wallet.
/// Clean the unconfirmed coinbase output which was created at 50 minutes ago.
fn clean_old_unconfirmed<T: ?Sized, C, K>(wallet: &mut T, height: u64) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	if height < 50 {
		return Ok(());
	}
	let mut ids_to_del = vec![];
	for out in wallet.iter() {
		if out.status == OutputStatus::Unconfirmed
			&& out.height > 0
			&& out.height < height - 50
			&& out.is_coinbase
		{
			ids_to_del.push(out.key_id.clone())
		}
	}

	if ids_to_del.len() > 0 {
		let mut batch = wallet.batch()?;
		for id in ids_to_del {
			batch.delete(&id, &None)?;
		}
		batch.commit()?;
	}
	Ok(())
}

/// Retrieve summary info about the wallet
/// caller should refresh first if desired
pub fn retrieve_info<T: ?Sized, C, K>(
	wallet: &mut T,
	parent_key_id: &Identifier,
	minimum_confirmations: u64,
) -> Result<WalletInfo, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let current_height = wallet.last_confirmed_height()?;
	let outputs = wallet.iter().filter(|out| {
		out.root_key_id == *parent_key_id || out.root_key_id == recipient_parent_key_id()
	});

	let mut unspent_total = 0;
	let mut immature_total = 0;
	let mut awaiting_finalization_total = 0;
	let mut unconfirmed_total = 0;
	let mut locked_total = 0;

	for out in outputs {
		match out.status {
			OutputStatus::Unspent => {
				if out.is_coinbase && out.lock_height > current_height {
					immature_total += out.value;
				} else if out.num_confirmations(current_height) < minimum_confirmations {
					// Treat anything less than minimum confirmations as "unconfirmed".
					unconfirmed_total += out.value;
				} else {
					unspent_total += out.value;
				}
			}
			OutputStatus::Unconfirmed => {
				// We ignore unconfirmed coinbase outputs completely.
				if !out.is_coinbase {
					if minimum_confirmations == 0 {
						unconfirmed_total += out.value;
					} else {
						awaiting_finalization_total += out.value;
					}
				}
			}
			OutputStatus::Locked => {
				locked_total += out.value;
			}
			OutputStatus::Spent => {}
			OutputStatus::Confirmed => {}
		}
	}

	Ok(WalletInfo {
		last_confirmed_height: current_height,
		minimum_confirmations,
		total: unspent_total + unconfirmed_total + immature_total,
		amount_awaiting_finalization: awaiting_finalization_total,
		amount_awaiting_confirmation: unconfirmed_total,
		amount_immature: immature_total,
		amount_locked: locked_total,
		amount_currently_spendable: unspent_total,
	})
}

/// Build a coinbase output and insert into wallet
pub fn build_coinbase<T: ?Sized, C, K>(
	wallet: &mut T,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<CbData, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let (out, kern, block_fees) = receive_coinbase(wallet, block_fees, test_mode)?;

	Ok(CbData {
		output: out,
		kernel: kern,
		key_id: block_fees.key_id,
	})
}

//TODO: Split up the output creation and the wallet insertion
/// Build a coinbase output and the corresponding kernel
pub fn receive_coinbase<T: ?Sized, C, K>(
	wallet: &mut T,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<(Output, TxKernel, BlockFees), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let height = block_fees.height;
	let lock_height = height + global::coinbase_maturity();
	let key_id = block_fees.key_id();
	let parent_key_id = wallet.parent_key_id();

	let key_id = match key_id {
		Some(key_id) => match keys::retrieve_existing_key(wallet, key_id, None) {
			Ok((kid, _derivation)) => {
				let existing_coinbase_output = wallet
					.iter()
					.find(|out| out.key_id == kid && out.is_coinbase);
				if let Some(o) = existing_coinbase_output {
					// force to use a new key_id if height different
					if o.height != height {
						keys::next_available_key(wallet)?
					} else {
						kid
					}
				} else {
					kid
				}
			}
			Err(_) => keys::next_available_key(wallet)?,
		},
		None => keys::next_available_key(wallet)?,
	};

	{
		// Now acquire the wallet lock and write the new output.
		let amount = reward(block_fees.fees);
		let commit = wallet.calc_commit_for_cache(0i64, &key_id)?;
		let mut batch = wallet.batch()?;
		batch.save(OutputData {
			root_key_id: parent_key_id,
			key_id: key_id.clone(),
			ephemeral_key: None,
			p2pkh: None,
			n_child: key_id.to_path().last_path_index(),
			mmr_index: None,
			commit,
			value: amount,
			w: 0i64,
			status: OutputStatus::Unconfirmed,
			height,
			lock_height,
			is_coinbase: true,
			tx_log_entry: None,
			slate_id: None,
			is_change: Some(false),
		})?;
		batch.commit()?;
	}

	debug!(
		"receive_coinbase: built candidate output - {:?}",
		key_id.clone(),
	);

	let mut block_fees = block_fees.clone();
	block_fees.key_id = Some(key_id.clone());

	debug!("receive_coinbase: {:?}", block_fees);

	let keychain = wallet.keychain();
	let (out, kern) = reward::output(
		keychain,
		&ProofBuilder::new(keychain, &parent_key_id),
		&key_id,
		block_fees.fees,
		test_mode,
	)?;
	Ok((out, kern, block_fees))
}
