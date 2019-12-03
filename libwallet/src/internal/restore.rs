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
//! Functions to restore a wallet's outputs from just the master seed

use crate::gotts_core::address::Address;
use crate::gotts_core::core::hash::Hash;
use crate::gotts_core::core::{Output, OutputFeatures};
use crate::gotts_core::global;
use crate::gotts_core::libtx::proof;
use crate::gotts_keychain::{ExtKeychain, Identifier, Keychain, RecipientKey};
use crate::gotts_util::secp::{pedersen, SecretKey};
use crate::gotts_util::to_hex;
use crate::internal::{keys, updater};
use crate::types::*;
use crate::{Error, ErrorKind, OutputCommitMapping};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Instant;

/// Utility struct for return values from below
#[derive(Clone)]
struct OutputResult {
	pub commit: pedersen::Commitment,
	pub key_id: Identifier,
	pub ephemeral_key: Option<SecretKey>,
	pub p2pkh: Option<Hash>,
	pub n_child: u32,
	pub mmr_index: u64,
	pub value: u64,
	pub w: i64,
	pub height: u64,
	pub lock_height: u64,
	pub is_coinbase: bool,
}

#[derive(Debug, Clone)]
/// Collect stats in case we want to just output a single tx log entry
/// for restored non-coinbase outputs
struct RestoredTxStats {
	pub log_id: u32,
	pub amount_credited: u64,
	pub num_outputs: usize,
}

fn identify_utxo_outputs<T, C, K>(
	wallet: &mut T,
	outputs: Vec<(pedersen::Commitment, Output, bool, u64, u64)>,
	recipient_key_to_check: &Option<RecipientKey>,
) -> Result<Vec<OutputResult>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut wallet_outputs: Vec<OutputResult> = Vec::new();

	debug!(
		"Scanning {} outputs in the current Gotts utxo set",
		outputs.len(),
	);

	let recipient_key = if let Some(r) = recipient_key_to_check {
		r.clone()
	} else {
		wallet.recipient_key()?
	};
	let keychain = wallet.keychain();
	let builder = proof::ProofBuilder::new(keychain);

	for output in outputs.iter() {
		let (commit, ot, is_coinbase, height, mmr_index) = output;
		// attempt to unwind message from the SecuredPath and get a 'w'
		// will fail if it's not ours
		let w;
		let key_id;
		let mut ephemeral_key = None;
		let mut p2pkh = None;
		match ot.features.as_flag() {
			OutputFeatures::Plain | OutputFeatures::Coinbase => {
				let spath = match ot.features.get_spath() {
					Ok(s) => s,
					Err(_) => continue,
				};
				match proof::rewind(keychain.secp(), &builder, commit, spath) {
					Ok(i) => {
						w = i.w;
						key_id = i.key_id;
					}
					Err(_) => continue,
				}
			}
			OutputFeatures::SigLocked => {
				let locker = match ot.features.get_locker() {
					Ok(l) => l,
					Err(_) => continue,
				};
				match proof::rewind_outputlocker(
					keychain,
					ot.value,
					&recipient_key.recipient_pri_key,
					commit,
					locker,
				) {
					Ok((i, e)) => {
						w = i;
						ephemeral_key = Some(e);
						p2pkh = Some(locker.p2pkh);
						key_id = recipient_key.recipient_key_id.clone();
					}
					Err(_) => continue,
				}
			}
		};

		let lock_height = if *is_coinbase {
			*height + global::coinbase_maturity()
		} else {
			*height
		};

		info!(
			"{:?} Output found: {:?}, amount: {:?}, key_id: {:?}, mmr_index: {},",
			ot.features.as_flag(),
			commit,
			ot.value,
			key_id,
			mmr_index,
		);
		wallet_outputs.push(OutputResult {
			commit: *commit,
			key_id: key_id.clone(),
			ephemeral_key,
			p2pkh,
			n_child: key_id.to_path().last_path_index(),
			value: ot.value,
			w,
			height: *height,
			lock_height,
			is_coinbase: *is_coinbase,
			mmr_index: *mmr_index,
		});
	}
	Ok(wallet_outputs)
}

fn collect_chain_outputs<T, C, K>(
	wallet: &mut T,
	recipient_key_to_check: &Option<RecipientKey>,
) -> Result<Vec<OutputResult>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let batch_size = 1000;
	let mut start_index = 1;
	let mut result_vec: Vec<OutputResult> = vec![];
	let nit_only = if recipient_key_to_check.is_some() {
		true
	} else {
		false
	};
	loop {
		let (highest_index, last_retrieved_index, outputs) = wallet
			.w2n_client()
			.get_outputs_by_pmmr_index(start_index, batch_size, nit_only)?;
		info!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);

		result_vec.append(&mut identify_utxo_outputs(
			wallet,
			outputs,
			recipient_key_to_check,
		)?);

		if highest_index == last_retrieved_index {
			break;
		}
		start_index = last_retrieved_index + 1;
	}
	info!(
		"collect_chain_outputs: {} utxo outputs identified",
		result_vec.len()
	);
	Ok(result_vec)
}

///
fn restore_missing_output<T, C, K>(
	wallet: &mut T,
	output: OutputResult,
	found_parents: &mut HashMap<Identifier, u32>,
	tx_stats: &mut Option<&mut HashMap<Identifier, RestoredTxStats>>,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let commit = Some(to_hex(output.commit.0.to_vec()));
	let mut batch = wallet.batch()?;

	let parent_key_id = output.key_id.parent_path();
	if !found_parents.contains_key(&parent_key_id) {
		found_parents.insert(parent_key_id.clone(), 0);
		if let Some(ref mut s) = tx_stats {
			s.insert(
				parent_key_id.clone(),
				RestoredTxStats {
					log_id: batch.next_tx_log_id(&parent_key_id)?,
					amount_credited: 0,
					num_outputs: 0,
				},
			);
		}
	}

	let log_id = if tx_stats.is_none() || output.is_coinbase {
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let entry_type = match output.is_coinbase {
			true => TxLogEntryType::ConfirmedCoinbase,
			false => TxLogEntryType::TxReceived,
		};
		let mut t = TxLogEntry::new(parent_key_id.clone(), entry_type, log_id);
		t.confirmed = true;
		t.amount_credited = output.value;
		t.num_outputs = 1;
		t.update_confirmation_ts();
		batch.save_tx_log_entry(t, &parent_key_id)?;
		log_id
	} else {
		if let Some(ref mut s) = tx_stats {
			let ts = s.get(&parent_key_id).unwrap().clone();
			s.insert(
				parent_key_id.clone(),
				RestoredTxStats {
					log_id: ts.log_id,
					amount_credited: ts.amount_credited + output.value,
					num_outputs: ts.num_outputs + 1,
				},
			);
			ts.log_id
		} else {
			0
		}
	};

	let _ = batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output.key_id,
		ephemeral_key: output.ephemeral_key,
		p2pkh: output.p2pkh,
		n_child: output.n_child,
		mmr_index: Some(output.mmr_index),
		commit,
		value: output.value,
		w: output.w,
		status: OutputStatus::Unspent,
		height: output.height,
		lock_height: output.lock_height,
		is_coinbase: output.is_coinbase,
		tx_log_entry: Some(log_id),
		slate_id: None,
		is_change: None,
	});

	let max_child_index = found_parents.get(&parent_key_id).unwrap().clone();
	if output.n_child >= max_child_index {
		found_parents.insert(parent_key_id.clone(), output.n_child);
	}

	batch.commit()?;
	Ok(())
}

///
fn cancel_tx_log_entry<T, C, K>(wallet: &mut T, output: &OutputData) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let parent_key_id = output.key_id.parent_path();
	let updated_tx_entry = if output.tx_log_entry.is_some() {
		let entries = updater::retrieve_txs(
			wallet,
			output.tx_log_entry.clone(),
			None,
			Some(&parent_key_id),
			false,
			None,
		)?;
		if entries.len() > 0 {
			let mut entry = entries[0].clone();
			match entry.tx_type {
				TxLogEntryType::TxSent => entry.tx_type = TxLogEntryType::TxSentCancelled,
				TxLogEntryType::TxReceived => entry.tx_type = TxLogEntryType::TxReceivedCancelled,
				_ => {}
			}
			Some(entry)
		} else {
			None
		}
	} else {
		None
	};
	let mut batch = wallet.batch()?;
	if let Some(t) = updated_tx_entry {
		batch.save_tx_log_entry(t, &parent_key_id)?;
	}
	batch.commit()?;
	Ok(())
}

fn check_repair_from_outputs<T, C, K>(
	wallet: &mut T,
	delete_unconfirmed: bool,
	ignore_within: u64,
	chain_outs: Vec<OutputResult>,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// Now, get all outputs owned by this wallet (regardless of account)
	let wallet_outputs = updater::retrieve_outputs(&mut *wallet, true, None, None, None)?;

	// Also get all outstanding txs in local wallet database
	let tx_vec = updater::retrieve_txs(&mut *wallet, None, None, None, true, None)?;
	let outstanding_txs_id: Vec<u32> = tx_vec.iter().map(|e| e.id).collect();

	let mut missing_outs = vec![];
	let mut accidental_spend_outs = vec![];
	let mut locked_outs = vec![];

	// check all definitive outputs exist in the wallet outputs
	for deffo in chain_outs.into_iter() {
		let matched_out = wallet_outputs.iter().find(|wo| wo.commit == deffo.commit);
		match matched_out {
			Some(s) => {
				let mut is_waiting_confirm = false;
				if ignore_within != 0 {
					// 0 means 'checking all txs'.
					if let Some(tx_log_entry) = s.output.tx_log_entry {
						if outstanding_txs_id.contains(&tx_log_entry) {
							let tx_log = tx_vec.iter().find(|e| e.id == tx_log_entry).unwrap();
							// let's ignore the checking on the txs which just happened within 30 minutes, which could still stay in tx pool and wait
							// for packaging into a block.
							if tx_log.creation_ts + Duration::minutes(ignore_within as i64)
								> Utc::now()
							{
								is_waiting_confirm = true;
							}
						}
					}
				}
				if !is_waiting_confirm {
					if s.output.status == OutputStatus::Spent {
						accidental_spend_outs.push((s.output.clone(), deffo.clone()));
					}
					if s.output.status == OutputStatus::Locked {
						locked_outs.push((s.output.clone(), deffo.clone()));
					}
				}
			}
			None => missing_outs.push(deffo),
		}
	}

	// mark problem spent outputs as unspent (confirmed against a short-lived fork, for example)
	for m in accidental_spend_outs.into_iter() {
		let mut o = m.0;
		warn!(
			"Output for {} with ID {} ({:?}) marked as spent but exists in UTXO set. \
			 Marking unspent and cancelling any associated transaction log entries.",
			o.value, o.key_id, m.1.commit,
		);
		o.status = OutputStatus::Unspent;
		// any transactions associated with this should be cancelled
		cancel_tx_log_entry(wallet, &o)?;
		let mut batch = wallet.batch()?;
		batch.save(o)?;
		batch.commit()?;
	}

	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();

	// Restore missing outputs, adding transaction for it back to the log
	for m in missing_outs.into_iter() {
		warn!(
			"Confirmed output for {} with Identifier({}) {:?} exists in UTXO set but not in wallet. \
			 Restoring.",
			m.value, m.key_id, m.commit,
		);
		restore_missing_output(wallet, m, &mut found_parents, &mut None)?;
	}

	if delete_unconfirmed {
		// Unlock locked outputs
		for m in locked_outs.into_iter() {
			let mut o = m.0;
			warn!(
				"Confirmed output for {} with ID {} ({:?}) exists in UTXO set and is locked. \
				 Unlocking and cancelling associated transaction log entries.",
				o.value, o.key_id, m.1.commit,
			);
			o.status = OutputStatus::Unspent;
			cancel_tx_log_entry(wallet, &o)?;
			let mut batch = wallet.batch()?;
			batch.save(o)?;
			batch.commit()?;
		}

		let unconfirmed_outs: Vec<&OutputCommitMapping> = wallet_outputs
			.iter()
			.filter(|o| o.output.status == OutputStatus::Unconfirmed)
			.collect();
		// Delete unconfirmed outputs
		for m in unconfirmed_outs.into_iter() {
			let o = m.output.clone();
			warn!(
				"Unconfirmed output for {} with ID {} ({:?}) not in UTXO set. \
				 Deleting and cancelling associated transaction log entries.",
				o.value, o.key_id, m.commit,
			);
			cancel_tx_log_entry(wallet, &o)?;
			let mut batch = wallet.batch()?;
			batch.delete(&o.key_id, &o.mmr_index)?;
			batch.commit()?;
		}
	}

	// restore labels, account paths and child derivation indices
	let label_base = "account";
	let mut acct_index = 1;
	for (path, max_child_index) in found_parents.iter() {
		// skip the recipient key path
		if *path == ExtKeychain::derive_key_id(3, <u32>::max_value(), <u32>::max_value(), 0, 0) {
			continue;
		}

		// default path already exists
		if *path != ExtKeychain::derive_key_id(2, 0, 0, 0, 0) {
			let label = format!("{}_{}", label_base, acct_index);
			keys::set_acct_path(wallet, &label, path)?;
			acct_index += 1;
		}
		let mut batch = wallet.batch()?;
		debug!("Next child for account {} is {}", path, max_child_index + 1);
		batch.save_child_index(path, max_child_index + 1)?;
		batch.commit()?;
	}
	Ok(())
}

fn check_nit_outputs<T, C, K>(wallet: &mut T, chain_outs: Vec<OutputResult>) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// Now, get all outputs owned by this wallet (regardless of account)
	let wallet_outputs = updater::retrieve_outputs(&mut *wallet, true, None, None, None)?;

	let mut missing_outs = vec![];
	// check all definitive outputs exist in the wallet outputs
	for deffo in chain_outs.into_iter() {
		let matched_out = wallet_outputs.iter().find(|wo| wo.commit == deffo.commit);
		if matched_out.is_none() {
			missing_outs.push(deffo);
		}
	}

	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();
	// Restore missing outputs, adding transaction for it back to the log
	for m in missing_outs.into_iter() {
		warn!(
			"Confirmed output for {} with Identifier({}) {:?} exists in UTXO set but not in wallet. \
			 Restoring.",
			m.value, m.key_id, m.commit,
		);
		restore_missing_output(wallet, m, &mut found_parents, &mut None)?;
	}

	Ok(())
}

/// Check / repair wallet contents
/// assume wallet contents have been freshly updated with contents
/// of latest block
pub fn check_repair<T, C, K>(
	wallet: &mut T,
	delete_unconfirmed: bool,
	ignore_within: u64,
	address_to_check: Option<String>,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut recipient_key_to_check = None;
	if let Some(addr) = address_to_check {
		// Check whether this address belongs to this wallet
		let address = Address::from_str(&addr)?;
		let mut is_mine = false;
		if let Ok(recipient_key) = wallet.recipient_key_by_id(&address.get_key_id()) {
			if recipient_key.recipient_pub_key == address.get_inner_pubkey() {
				is_mine = true;
				recipient_key_to_check = Some(recipient_key);
			}
		}
		if !is_mine {
			return Err(ErrorKind::GenericError(
				"address not owned by this wallet".to_string(),
			))?;
		}
	}

	// First, get a definitive list of outputs we own from the chain
	let now = Instant::now();
	info!("Starting wallet check.");
	let chain_outs = collect_chain_outputs(wallet, &recipient_key_to_check)?;
	info!(
		"Identified {} wallet_outputs as belonging to this wallet",
		chain_outs.len(),
	);

	if recipient_key_to_check.is_none() {
		check_repair_from_outputs(wallet, delete_unconfirmed, ignore_within, chain_outs)?;
	} else {
		check_nit_outputs(wallet, chain_outs)?;
	}

	let mut sec = now.elapsed().as_secs();
	let min = sec / 60;
	sec %= 60;
	info!("Repaired wallet in {}m{}s", min, sec);

	Ok(())
}

/// Check / repair wallet contents, by index on batch
/// assume wallet contents have been freshly updated with contents
/// of latest block
pub fn check_repair_batch<T, C, K>(
	wallet: &mut T,
	delete_unconfirmed: bool,
	ignore_within: u64,
	start_index: u64,
	batch_size: u64,
	address_to_check: Option<String>,
) -> Result<(u64, u64), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut recipient_key_to_check = None;
	if let Some(addr) = address_to_check {
		// Check whether this address belongs to this wallet
		let address = Address::from_str(&addr)?;
		let mut is_mine = false;
		if let Ok(recipient_key) = wallet.recipient_key_by_id(&address.get_key_id()) {
			if recipient_key.recipient_pub_key == address.get_inner_pubkey() {
				is_mine = true;
				recipient_key_to_check = Some(recipient_key);
			}
		}
		if !is_mine {
			return Err(ErrorKind::GenericError(
				"address not owned by this wallet".to_string(),
			))?;
		}
	}

	let nit_only = if recipient_key_to_check.is_some() {
		true
	} else {
		false
	};
	let mut chain_outs: Vec<OutputResult> = vec![];
	let (highest_index, last_retrieved_index, outputs) = wallet
		.w2n_client()
		.get_outputs_by_pmmr_index(start_index, batch_size, nit_only)?;

	chain_outs.append(&mut identify_utxo_outputs(
		wallet,
		outputs,
		&recipient_key_to_check,
	)?);

	// 'delete_unconfirmed' only make sense at the last call of this batch repair
	let mut delete_unconfirmed = delete_unconfirmed;
	if delete_unconfirmed && last_retrieved_index < highest_index {
		delete_unconfirmed = false;
	}

	if recipient_key_to_check.is_none() {
		check_repair_from_outputs(wallet, delete_unconfirmed, ignore_within, chain_outs)?;
	} else {
		check_nit_outputs(wallet, chain_outs)?;
	}
	Ok((highest_index, last_retrieved_index))
}

fn restore_from_outputs<T, C, K>(wallet: &mut T, outputs: Vec<OutputResult>) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	info!(
		"Identified {} wallet_outputs as belonging to this wallet",
		outputs.len(),
	);

	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();
	let mut restore_stats = HashMap::new();

	// Now save what we have
	for output in outputs {
		restore_missing_output(
			wallet,
			output,
			&mut found_parents,
			&mut Some(&mut restore_stats),
		)?;
	}

	// restore labels, account paths and child derivation indices
	let label_base = "account";
	let mut acct_index = 1;
	for (path, max_child_index) in found_parents.iter() {
		// default path already exists
		if *path != ExtKeychain::derive_key_id(2, 0, 0, 0, 0) {
			let label = format!("{}_{}", label_base, acct_index);
			keys::set_acct_path(wallet, &label, path)?;
			acct_index += 1;
		}
		// restore tx log entry for non-coinbase outputs
		if let Some(s) = restore_stats.get(path) {
			let mut batch = wallet.batch()?;
			let mut t = TxLogEntry::new(path.clone(), TxLogEntryType::TxReceived, s.log_id);
			t.confirmed = true;
			t.amount_credited = s.amount_credited;
			t.num_outputs = s.num_outputs;
			t.update_confirmation_ts();
			batch.save_tx_log_entry(t, &path)?;
			batch.commit()?;
		}
		let mut batch = wallet.batch()?;
		batch.save_child_index(path, max_child_index + 1)?;
		debug!("Next child for account {} is {}", path, max_child_index + 1);
		batch.commit()?;
	}

	Ok(())
}

/// Restore a wallet
pub fn restore<T, C, K>(wallet: &mut T) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// Don't proceed if wallet_data has anything in it
	let is_empty = wallet.iter().next().is_none();
	if !is_empty {
		error!("Not restoring. Please back up and remove existing db directory first.");
		return Ok(());
	}

	let now = Instant::now();
	info!("Starting restore.");

	let result_vec = collect_chain_outputs(wallet, &None)?;

	restore_from_outputs(wallet, result_vec)?;

	let mut sec = now.elapsed().as_secs();
	let min = sec / 60;
	sec %= 60;
	info!("Restored wallet in {}m{}s", min, sec);

	Ok(())
}

/// Restore outputs by index on batch
pub fn restore_batch<T, C, K>(
	wallet: &mut T,
	start_index: u64,
	batch_size: u64,
) -> Result<(u64, u64, u64), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut result_vec: Vec<OutputResult> = vec![];
	let (highest_index, last_retrieved_index, outputs) = wallet
		.w2n_client()
		.get_outputs_by_pmmr_index(start_index, batch_size, false)?;

	result_vec.append(&mut identify_utxo_outputs(wallet, outputs.clone(), &None)?);

	let num_of_found = result_vec.len();
	restore_from_outputs(wallet, result_vec)?;
	Ok((highest_index, last_retrieved_index, num_of_found as u64))
}
