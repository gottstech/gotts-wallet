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

//! Selection of inputs for building transactions

use crate::error::{Error, ErrorKind};
use crate::gotts_core::core::{amount_to_hr_string, TransactionBody};
use crate::gotts_core::libtx::{
	build,
	proof::{ProofBuild, ProofBuilder},
	tx_fee,
};
use crate::gotts_core::{consensus, global};
use crate::gotts_keychain::{Identifier, Keychain};
use crate::internal::keys;
use crate::slate::Slate;
use crate::types::*;
use rand::{thread_rng, Rng};
use std::cmp::Reverse;
use std::i64;
use std::collections::HashMap;

/// Initialize a transaction on the sender side, returns a corresponding
/// libwallet transaction slate with the appropriate inputs selected,
/// and saves the private wallet identifiers of our selected outputs
/// into our transaction context

pub fn build_send_tx<T: ?Sized, C, K>(
	wallet: &mut T,
	slate: &mut Slate,
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy: String,
	parent_key_id: Identifier,
	is_initator: bool,
	use_test_rng: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let (elems, inputs, change_amounts_derivations, fee) = select_send_tx(
		wallet,
		slate.amount,
		slate.height,
		minimum_confirmations,
		slate.lock_height,
		max_outputs,
		change_outputs,
		selection_strategy,
		&parent_key_id,
		if !is_initator { Some(slate.w) } else { None },
		use_test_rng,
	)?;
	let keychain = wallet.keychain();
	let blinding = slate.add_transaction_elements(keychain, &ProofBuilder::new(keychain), elems)?;

	slate.fee = fee;
	let mut sum_of_w: i64 = inputs.iter().fold(0i64, |acc, x| acc.saturating_add(x.w));
	sum_of_w = change_amounts_derivations.iter().fold(sum_of_w, |acc, x| acc.saturating_sub(x.3));
	if sum_of_w == i64::MAX || sum_of_w == i64::MIN {
		error!("build_send_tx: w overflow, please try again");
		return Err(ErrorKind::GenericError("w overflow".to_string()))?;
	}
	if is_initator {
		slate.w = sum_of_w;
	} else if sum_of_w != slate.w {
		error!("build_send_tx: w not balanced, a wrong buiding");
		return Err(ErrorKind::GenericError("w not balanced".to_string()))?;
	}

	// Create our own private context
	let mut context = Context::new(
		keychain.secp(),
		blinding.secret_key(&keychain.secp()).unwrap(),
		&parent_key_id,
		use_test_rng,
		0,
	);

	context.fee = fee;

	// Store our private identifiers for each input
	for input in inputs {
		context.add_input(&input.key_id, &input.mmr_index, input.value, input.w);
	}

	// Store change output(s) and cached commits
	for (change_amount, id, mmr_index, w) in &change_amounts_derivations {
		context.add_output(&id, &mmr_index, *change_amount, *w);
	}

	Ok(context)
}

/// Locks all corresponding outputs in the context, creates
/// change outputs and tx log entry
pub fn lock_tx_context<T: ?Sized, C, K>(
	wallet: &mut T,
	slate: &Slate,
	context: &Context,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut output_commits: HashMap<Identifier, (Option<String>, u64, i64)> = HashMap::new();
	// Store cached commits before locking wallet
	for (id, _, change_amount, w) in &context.get_outputs() {
		output_commits.insert(
			id.clone(),
			(wallet.calc_commit_for_cache(*w, &id)?, *change_amount, *w),
		);
	}

	let tx_entry = {
		let lock_inputs = context.get_inputs().clone();
		let messages = Some(slate.participant_messages());
		let slate_id = slate.id;
		let height = slate.height;
		let parent_key_id = context.parent_key_id.clone();
		let mut batch = wallet.batch()?;
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, log_id);
		t.tx_slate_id = Some(slate_id.clone());
		let filename = format!("{}.gottstx", slate_id);
		t.stored_tx = Some(filename);
		t.fee = Some(slate.fee);
		let mut amount_debited = 0;
		t.num_inputs = lock_inputs.len();
		for id in lock_inputs {
			let mut coin = batch.get(&id.0, &id.1).unwrap();
			coin.tx_log_entry = Some(log_id);
			amount_debited = amount_debited + coin.value;
			batch.lock_output(&mut coin)?;
		}

		t.amount_debited = amount_debited;
		t.messages = messages;

		// write the output representing our change
		for (id, _, _, _) in &context.get_outputs() {
			t.num_outputs += 1;
			let (commit, change_amount, w) = output_commits.get_mut(&id).unwrap();
			t.amount_credited += change_amount.clone();
			batch.save(OutputData {
				root_key_id: parent_key_id.clone(),
				key_id: id.clone(),
				n_child: id.to_path().last_path_index(),
				commit: commit.clone(),
				mmr_index: None,
				value: change_amount.clone(),
				w: *w,
				status: OutputStatus::Unconfirmed,
				height,
				lock_height: 0,
				is_coinbase: false,
				tx_log_entry: Some(log_id),
				slate_id: Some(slate_id.clone()),
				is_change: Some(true),
			})?;
		}
		batch.save_tx_log_entry(t.clone(), &parent_key_id)?;
		batch.commit()?;
		t
	};
	wallet.store_tx(&format!("{}", tx_entry.tx_slate_id.unwrap()), &slate.tx)?;
	Ok(())
}

/// Creates a new output in the wallet for the recipient,
/// returning the key of the fresh output
/// Also creates a new transaction containing the output
pub fn build_recipient_output<T: ?Sized, C, K>(
	wallet: &mut T,
	slate: &mut Slate,
	parent_key_id: Identifier,
	use_test_rng: bool,
) -> Result<(Identifier, Context), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// Create a potential output for this transaction
	let key_id = keys::next_available_key(wallet).unwrap();
	let keychain = wallet.keychain().clone();
	let key_id_inner = key_id.clone();
	let amount = slate.amount;
	let w = slate.w;
	let height = slate.height;

	let slate_id = slate.id.clone();
	let blinding = slate.add_transaction_elements(
		&keychain,
		&ProofBuilder::new(&keychain),
		vec![build::output(amount, Some(w), key_id.clone())],
	)?;

	// Add blinding sum to our context
	let mut context = Context::new(
		keychain.secp(),
		blinding
			.secret_key(wallet.keychain().clone().secp())
			.unwrap(),
		&parent_key_id,
		use_test_rng,
		1,
	);

	context.add_output(&key_id, &None, amount, w);
	let messages = Some(slate.participant_messages());
	let commit = wallet.calc_commit_for_cache(slate.w, &key_id_inner)?;
	let mut batch = wallet.batch()?;
	let log_id = batch.next_tx_log_id(&parent_key_id)?;
	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);
	t.tx_slate_id = Some(slate_id);
	t.amount_credited = amount;
	t.num_outputs = 1;
	t.messages = messages;
	batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: key_id_inner.clone(),
		mmr_index: None,
		n_child: key_id_inner.to_path().last_path_index(),
		commit,
		value: amount,
		w: slate.w,
		status: OutputStatus::Unconfirmed,
		height,
		lock_height: 0,
		is_coinbase: false,
		tx_log_entry: Some(log_id),
		slate_id: Some(slate_id),
		is_change: Some(false),
	})?;
	batch.save_tx_log_entry(t, &parent_key_id)?;
	batch.commit()?;

	Ok((key_id, context))
}

/// Builds a transaction to send to someone from the HD seed associated with the
/// wallet and the amount to send. Handles reading through the wallet data file,
/// selecting outputs to spend and building the change.
pub fn select_send_tx<T: ?Sized, C, K, B>(
	wallet: &mut T,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	lock_height: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy: String,
	parent_key_id: &Identifier,
	slate_w: Option<i64>,
	use_test_rng: bool,
) -> Result<
	(
		Vec<Box<build::Append<K, B>>>,
		Vec<OutputData>,
		Vec<(u64, Identifier, Option<u64>, i64)>, // change amounts, derivations, mmr_index and w
		u64,                                      // fee
	),
	Error,
>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
	B: ProofBuild,
{
	let (coins, _total, amount, fee) = select_coins_and_fee(
		wallet,
		amount,
		current_height,
		minimum_confirmations,
		max_outputs,
		change_outputs,
		selection_strategy,
		&parent_key_id,
	)?;

	{
		// Quick block weight check before proceeding.
		// Note: We use weight_as_block here (inputs have weight).
		let tx_block_weight = TransactionBody::weight_as_block(coins.len(), change_outputs + 2, 2);

		if tx_block_weight > global::max_block_weight() {
			info!(
				"transaction size overloaded. please limit the change outputs in [1..{}]",
				(global::max_block_weight()
					- coins.len().saturating_mul(consensus::BLOCK_INPUT_WEIGHT)
					- 2usize.saturating_mul(consensus::BLOCK_KERNEL_WEIGHT))
					/ consensus::BLOCK_OUTPUT_WEIGHT
					- 3,
			);
			return Err(ErrorKind::GenericError("transaction size overloading".to_string()).into());
		}
	}

	// build transaction skeleton with inputs and change
	let (mut parts, change_amounts_derivations) =
		inputs_and_change(&coins, wallet, amount, fee, change_outputs, slate_w, use_test_rng)?;

	// Build a "Plain" kernel unless lock_height>0 explicitly specified.
	if lock_height > 0 {
		parts.push(build::with_lock_height(lock_height));
	}

	Ok((parts, coins, change_amounts_derivations, fee))
}

/// Select outputs and calculating fee.
pub fn select_coins_and_fee<T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy: String,
	parent_key_id: &Identifier,
) -> Result<
	(
		Vec<OutputData>,
		u64, // total
		u64, // amount
		u64, // fee
	),
	Error,
>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// select some spendable coins from the wallet
	let (max_outputs, mut coins) = select_coins(
		wallet,
		amount,
		current_height,
		minimum_confirmations,
		max_outputs,
		selection_strategy.clone(),
		parent_key_id,
	);

	// sender is responsible for setting the fee on the partial tx
	// recipient should double check the fee calculation and not blindly trust the
	// sender

	// TODO - Is it safe to spend without a change output? (1 input -> 1 output)
	// TODO - Does this not potentially reveal the senders private key?
	//
	// First attempt to spend without change
	let mut fee = tx_fee(coins.len(), 1, 1, None);
	let mut total: u64 = coins.iter().map(|c| c.value).sum();
	let mut amount_with_fee = amount + fee;

	if total == 0 {
		return Err(ErrorKind::NotEnoughFunds {
			available: 0,
			available_disp: amount_to_hr_string(0, false),
			needed: amount_with_fee as u64,
			needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
		})?;
	}

	// The amount with fee is more than the total values of our max outputs
	if total < amount_with_fee && coins.len() == max_outputs {
		return Err(ErrorKind::NotEnoughFunds {
			available: total,
			available_disp: amount_to_hr_string(total, false),
			needed: amount_with_fee as u64,
			needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
		})?;
	}

	let num_outputs = change_outputs + 1;

	// We need to add a change address or amount with fee is more than total
	if total != amount_with_fee {
		fee = tx_fee(coins.len(), num_outputs, 1, None);
		amount_with_fee = amount + fee;

		// Here check if we have enough outputs for the amount including fee otherwise
		// look for other outputs and check again
		while total < amount_with_fee {
			// End the loop if we have selected all the outputs and still not enough funds
			if coins.len() == max_outputs {
				return Err(ErrorKind::NotEnoughFunds {
					available: total as u64,
					available_disp: amount_to_hr_string(total, false),
					needed: amount_with_fee as u64,
					needed_disp: amount_to_hr_string(amount_with_fee as u64, false),
				})?;
			}

			// select some spendable coins from the wallet
			coins = select_coins(
				wallet,
				amount_with_fee,
				current_height,
				minimum_confirmations,
				max_outputs,
				selection_strategy.clone(),
				parent_key_id,
			)
			.1;
			fee = tx_fee(coins.len(), num_outputs, 1, None);
			total = coins.iter().map(|c| c.value).sum();
			amount_with_fee = amount + fee;
		}
	}
	Ok((coins, total, amount, fee))
}

/// Selects inputs and change for a transaction
pub fn inputs_and_change<T: ?Sized, C, K, B>(
	coins: &Vec<OutputData>,
	wallet: &mut T,
	amount: u64,
	fee: u64,
	num_change_outputs: usize,
	slate_w: Option<i64>,
	use_test_rng: bool,
) -> Result<
	(
		Vec<Box<build::Append<K, B>>>,
		Vec<(u64, Identifier, Option<u64>, i64)>, // change amounts, derivations, mmr_index and w
	),
	Error,
>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
	B: ProofBuild,
{
	let mut parts = vec![];

	// calculate the total across all inputs, and how much is left
	let total: u64 = coins.iter().map(|c| c.value).sum();

	parts.push(build::with_fee(fee));

	// if we are spending 10,000 coins to send 1,000 then our change will be 9,000
	// if the fee is 80 then the recipient will receive 1000 and our change will be
	// 8,920
	let change = total - amount - fee;

	// build inputs using the appropriate derived key_ids
	for coin in coins {
		if coin.is_coinbase {
			parts.push(build::coinbase_input(coin.value, coin.key_id.clone()));
		} else {
			parts.push(build::input(coin.value, coin.w, coin.key_id.clone()));
		}
	}

	let mut change_amounts_derivations = vec![];

	if change == 0 {
		debug!("No change (sending exactly amount + fee), no change outputs to build");
	} else {
		debug!(
			"Building change outputs: total change: {} ({} outputs)",
			change, num_change_outputs
		);

		let part_change = change / num_change_outputs as u64;
		let remainder_change = change % part_change;
		let mut sum_of_w: i64 = coins.iter().fold(0i64, |acc, x| acc.saturating_add(x.w));

		for x in 0..num_change_outputs {
			let mut w: i64 = if use_test_rng { 4096 } else { thread_rng().gen() };
			//todo: how to avoid overflow here? a temporary solution is to limit the w range.
			w = w / 64;
			{
				// for invoice feature, the final change accounting for the 'w' balance
				if slate_w.is_some() && x == (num_change_outputs - 1) {
					w = sum_of_w.saturating_sub(slate_w.unwrap());
					sum_of_w = sum_of_w.saturating_sub(w);
					if sum_of_w != 0 {
						error!("inputs_and_change: w not balanced");
					}
				} else {
					let test = sum_of_w.saturating_sub(w);
					if test == i64::max_value() || test == i64::min_value() {
						//revert the 'w' to try avoiding overflow
						w = -w;
					}
					sum_of_w = sum_of_w.saturating_sub(w);
				}
			}
			// n-1 equal change_outputs and a final one accounting for any remainder
			let change_amount = if x == (num_change_outputs - 1) {
				part_change + remainder_change
			} else {
				part_change
			};

			let change_key = wallet.next_child().unwrap();

			change_amounts_derivations.push((change_amount, change_key.clone(), None, w));
			parts.push(build::output(change_amount, Some(w), change_key));
		}
	}

	Ok((parts, change_amounts_derivations))
}

/// Select spendable coins from a wallet.
/// Default strategy is to spend the maximum number of outputs (up to
/// max_outputs). Alternative strategy is to spend smallest outputs first
/// but only as many as necessary. When we introduce additional strategies
/// we should pass something other than a bool in.
/// TODO: Possibly move this into another trait to be owned by a wallet?

pub fn select_coins<T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	selection_strategy: String,
	parent_key_id: &Identifier,
) -> (usize, Vec<OutputData>)
//    max_outputs_available, Outputs
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	// first find all eligible outputs based on number of confirmations
	let mut eligible = wallet
		.iter()
		.filter(|out| {
			out.root_key_id == *parent_key_id
				&& out.eligible_to_spend(current_height, minimum_confirmations)
		})
		.collect::<Vec<OutputData>>();

	let max_available = eligible.len();

	// sort eligible outputs by increasing value ("smallest" strategy) or
	// decreasing value ("biggest" selection strategy)
	if selection_strategy == "biggest" {
		eligible.sort_by_key(|out| Reverse(out.value));
	} else {
		eligible.sort_by_key(|out| out.value);
	}

	// use a sliding window to identify potential sets of possible outputs to spend
	// Case of amount > total amount of max_outputs(500):
	// The limit exists because by default, we always select as many inputs as
	// possible in a transaction, to reduce both the Output set and the fees.
	// But that only makes sense up to a point, hence the limit to avoid being too
	// greedy. But if max_outputs(500) is actually not enough to cover the whole
	// amount, the wallet should allow going over it to satisfy what the user
	// wants to send. So the wallet considers max_outputs more of a soft limit.
	if eligible.len() > max_outputs {
		for window in eligible.windows(max_outputs) {
			let windowed_eligible = window.iter().cloned().collect::<Vec<_>>();
			if let Some(outputs) =
				select_from(amount, selection_strategy.clone(), windowed_eligible)
			{
				return (max_available, outputs);
			}
		}
		// Not exist in any window of which total amount >= amount.
		// Then take coins from the smallest one up to the total amount of selected
		// coins = the amount.
		if let Some(outputs) = select_from(
			amount,
			if selection_strategy == "all" {
				"smallest".to_owned()
			} else {
				selection_strategy.clone()
			},
			eligible.clone(),
		) {
			debug!(
				"Extending maximum number of outputs. {} outputs selected.",
				outputs.len()
			);
			return (max_available, outputs);
		}
	} else {
		if let Some(outputs) = select_from(amount, selection_strategy, eligible.clone()) {
			return (max_available, outputs);
		}
	}

	// we failed to find a suitable set of outputs to spend,
	// so return the largest amount we can so we can provide guidance on what is
	// possible
	eligible.reverse();
	(
		max_available,
		eligible.iter().take(max_outputs).cloned().collect(),
	)
}

fn select_from(
	amount: u64,
	selection_strategy: String,
	outputs: Vec<OutputData>,
) -> Option<Vec<OutputData>> {
	let total = outputs.iter().fold(0, |acc, x| acc + x.value);
	if total >= amount {
		if selection_strategy == "all" {
			return Some(outputs.iter().cloned().collect());
		} else {
			let mut selected_amount = 0;
			return Some(
				outputs
					.iter()
					.take_while(|out| {
						let res = selected_amount < amount;
						selected_amount += out.value;
						res
					})
					.cloned()
					.collect(),
			);
		}
	} else {
		None
	}
}
