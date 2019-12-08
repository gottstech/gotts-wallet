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

use crate::core::core::{self, amount_to_hr_string};
use crate::core::global;
use crate::libwallet::{
	AcctPathMapping, Error, OutputCommitMapping, OutputStatus, PaymentData, TxLogEntry, WalletInfo,
};
use crate::util;
use prettytable;
use std::io::prelude::Write;
use term;

/// Display outputs in a pretty way
pub fn outputs(
	account: &str,
	cur_height: u64,
	validated: bool,
	outputs: Vec<OutputCommitMapping>,
	dark_background_color_scheme: bool,
) -> Result<(), Error> {
	let title = format!(
		"Wallet Outputs - Account '{}' - Block Height: {}",
		account, cur_height
	);
	println!();
	if term::stdout().is_none() {
		println!("Could not open terminal");
		return Ok(());
	}
	let mut t = term::stdout().unwrap();
	t.fg(term::color::MAGENTA).unwrap();
	writeln!(t, "{}", title).unwrap();
	t.reset().unwrap();

	let mut table = table!();

	table.set_titles(row![
		bMG->"Output Commitment",
		bMG->"MMR Index",
		bMG->"Block Height",
		bMG->"Locked Until",
		bMG->"Status",
		bMG->"Coinbase?",
		bMG->"Change?",
		bMG->"# Confirms",
		bMG->"Value",
		bMG->"Tx"
	]);

	let len = outputs.len();
	for m in outputs {
		let commit = format!("{}", util::to_hex(m.commit.as_ref().to_vec()));
		let index = match m.output.mmr_index {
			None => "None".to_owned(),
			Some(t) => t.to_string(),
		};
		let height = format!("{}", m.output.height);
		let lock_height = format!("{}", m.output.lock_height);
		let is_coinbase = format!("{}", m.output.is_coinbase);
		let is_change = match m.output.is_change {
			None => String::new(),
			Some(t) => t.to_string(),
		};

		// Mark unconfirmed coinbase outputs as "Mining" instead of "Unconfirmed"
		let status = match m.output.status {
			OutputStatus::Unconfirmed if m.output.is_coinbase => "Mining".to_string(),
			_ => format!("{}", m.output.status),
		};

		let num_confirmations = format!("{}", m.output.num_confirmations(cur_height));
		let value = format!("{}", core::amount_to_hr_string(m.output.value, true));
		let tx = match m.output.tx_log_entry {
			None => "".to_owned(),
			Some(t) => t.to_string(),
		};

		match m.output.status {
			OutputStatus::Unspent => {
				if dark_background_color_scheme {
					table.add_row(row![
						bFC->commit,
						bFB->index,
						bFB->height,
						bFB->lock_height,
						bFG->status,
						bFY->is_coinbase,
						bFY->is_change,
						bFB->num_confirmations,
						bFG->value,
						bFC->tx,
					]);
				} else {
					table.add_row(row![
						bFD->commit,
						bFB->index,
						bFB->height,
						bFB->lock_height,
						bFG->status,
						bFD->is_coinbase,
						bFD->is_change,
						bFB->num_confirmations,
						bFG->value,
						bFD->tx,
					]);
				}
			}
			_ => {
				if dark_background_color_scheme {
					table.add_row(row![
						bFC->commit,
						bFB->index,
						bFB->height,
						bFB->lock_height,
						bFR->status,
						bFY->is_coinbase,
						bFY->is_change,
						bFB->num_confirmations,
						bFG->value,
						bFC->tx,
					]);
				} else {
					table.add_row(row![
						bFD->commit,
						bFB->index,
						bFB->height,
						bFB->lock_height,
						bFR->status,
						bFD->is_coinbase,
						bFD->is_change,
						bFB->num_confirmations,
						bFG->value,
						bFD->tx,
					]);
				}
			}
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();
	println!("total displayed outputs: {}", len);

	if !validated {
		println!(
			"\nWARNING: Wallet failed to verify data. \
			 The above is from local cache and possibly invalid! \
			 (is your `gotts server` offline or broken?)"
		);
	}
	Ok(())
}

/// Display payments in a pretty way
pub fn payments(
	account: &str,
	cur_height: u64,
	validated: bool,
	outputs: Vec<PaymentData>,
	dark_background_color_scheme: bool,
) -> Result<(), Error> {
	let title = format!(
		"Wallet Payments - Account '{}' - Block Height: {}",
		account, cur_height
	);
	println!();
	let mut t = term::stdout().unwrap();
	t.fg(term::color::MAGENTA).unwrap();
	writeln!(t, "{}", title).unwrap();
	t.reset().unwrap();

	let mut table = table!();

	table.set_titles(row![
		bMG->"Output Commitment",
		bMG->"Block Height",
		bMG->"Locked Until",
		bMG->"Confirmed?",
		bMG->"# Confirms",
		bMG->"Value",
		bMG->"Shared Transaction Id",
		bMG->"TxId",
	]);

	let len = outputs.len();
	let mut sum = 0;
	for payment in outputs {
		sum += payment.value;
		let commit = format!("{}", util::to_hex(payment.commit.as_ref().to_vec()));

		let height = format!("{}", payment.height);
		let lock_height = format!("{}", payment.lock_height);
		let status = format!(
			"{}",
			if payment.status == OutputStatus::Confirmed {
				"Yes"
			} else {
				"No"
			}
		);

		let num_confirmations = format!("{}", payment.num_confirmations(cur_height));
		let value = if payment.value == 0 {
			"unknown".to_owned()
		} else {
			format!("{}", core::amount_to_hr_string(payment.value, true))
		};
		let slate_id = format!("{}", payment.slate_id);
		let tx_id = format!(
			"{}",
			if let Some(id) = payment.id {
				id.to_string()
			} else {
				"".to_string()
			}
		);

		match payment.status {
			OutputStatus::Confirmed => {
				if dark_background_color_scheme {
					table.add_row(row![
						bFC->commit,
						bFB->height,
						bFB->lock_height,
						bFG->status,
						bFB->num_confirmations,
						bFG->value,
						bFC->slate_id,
						bFC->tx_id,
					]);
				} else {
					table.add_row(row![
						bFD->commit,
						bFB->height,
						bFB->lock_height,
						bFG->status,
						bFB->num_confirmations,
						bFG->value,
						bFD->slate_id,
						bFD->tx_id,
					]);
				}
			}
			_ => {
				if dark_background_color_scheme {
					table.add_row(row![
						bFC->commit,
						bFB->height,
						bFB->lock_height,
						bFR->status,
						bFB->num_confirmations,
						bFG->value,
						bFC->slate_id,
						bFC->tx_id,
					]);
				} else {
					table.add_row(row![
						bFD->commit,
						bFB->height,
						bFB->lock_height,
						bFR->status,
						bFB->num_confirmations,
						bFG->value,
						bFD->slate_id,
						bFD->tx_id,
					]);
				}
			}
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	if len > 1 {
		println!();
		println!("total displayed payments:\t{}", len);
		println!(
			"total displayed values: \t{}",
			core::amount_to_hr_string(sum, true)
		);
	}

	if !validated {
		println!(
			"\nWARNING: Wallet failed to verify data. \
			 The above is from local cache and possibly invalid! \
			 (is your `gotts server` offline or broken?)"
		);
	}
	Ok(())
}

/// Display transaction log in a pretty way
pub fn txs(
	account: &str,
	cur_height: u64,
	validated: bool,
	txs: &Vec<TxLogEntry>,
	include_status: bool,
	dark_background_color_scheme: bool,
) -> Result<(), Error> {
	let title = format!(
		"Transaction Log - Account '{}' - Block Height: {}",
		account, cur_height
	);
	println!();
	if term::stdout().is_none() {
		println!("Could not open terminal");
		return Ok(());
	}
	let mut t = term::stdout().unwrap();
	t.fg(term::color::MAGENTA).unwrap();
	writeln!(t, "{}", title).unwrap();
	t.reset().unwrap();

	let mut table = table!();

	table.set_titles(row![
		bMG->"Id",
		bMG->"Type",
		bMG->"Shared Transaction Id",
		bMG->"Creation Time",
		bMG->"Confirmed?",
		bMG->"# Confirms",
		bMG->"Num. \nInputs",
		bMG->"Num. \nOutputs",
		bMG->"Amount \nCredited",
		bMG->"Amount \nDebited",
		bMG->"Fee",
		bMG->"Net \nDifference",
		bMG->"Tx \nData",
	]);

	let mut total_fee: u64 = 0;
	let mut total_amount_credited = 0;
	let mut total_amount_debited = 0;
	for t in txs {
		total_fee += if let Some(fee) = t.fee { fee as u64 } else { 0 };
		total_amount_credited += t.amount_credited;
		total_amount_debited += t.amount_debited;

		let id = format!("{}", t.id);
		let slate_id = match t.tx_slate_id {
			Some(m) => format!("{}", m),
			None => "None".to_owned(),
		};
		let entry_type = format!("{}", t.tx_type);
		let creation_ts = format!("{}", t.creation_ts.format("%Y-%m-%d %H:%M:%S"));
		let confirmed = format!("{}", if t.confirmed { "Yes" } else { "No" });
		let num_confirmations = format!("{}", t.num_confirmations(cur_height));
		let num_inputs = format!("{}", t.num_inputs);
		let num_outputs = format!("{}", t.num_outputs);
		let amount_debited_str = core::amount_to_hr_string(t.amount_debited, true);
		let amount_credited_str = core::amount_to_hr_string(t.amount_credited, true);
		let fee = match t.fee {
			Some(f) => format!("{}", core::amount_to_hr_string(f as u64, true)),
			None => "None".to_owned(),
		};
		let net_diff = if t.amount_credited >= t.amount_debited {
			core::amount_to_hr_string(t.amount_credited - t.amount_debited, true)
		} else {
			format!(
				"-{}",
				core::amount_to_hr_string(t.amount_debited - t.amount_credited, true)
			)
		};
		let tx_data = match t.stored_tx {
			Some(_) => "Yes".to_owned(),
			None => "".to_owned(),
		};
		match t.confirmed {
			true => {
				if dark_background_color_scheme {
					table.add_row(row![
						bFC->id,
						bFC->entry_type,
						bFC->slate_id,
						bFB->creation_ts,
						bFg->confirmed,
						bFB->num_confirmations,
						bFC->num_inputs,
						bFC->num_outputs,
						bFG->amount_credited_str,
						bFR->amount_debited_str,
						bFR->fee,
						bFY->net_diff,
						bFb->tx_data,
					]);
				} else {
					table.add_row(row![
						bFD->id,
						bFb->entry_type,
						bFD->slate_id,
						bFB->creation_ts,
						bFg->confirmed,
						bFB->num_confirmations,
						bFD->num_inputs,
						bFD->num_outputs,
						bFG->amount_credited_str,
						bFD->amount_debited_str,
						bFD->fee,
						bFG->net_diff,
						bFB->tx_data,
					]);
				}
			}
			false => {
				if dark_background_color_scheme {
					table.add_row(row![
						bFC->id,
						bFC->entry_type,
						bFC->slate_id,
						bFB->creation_ts,
						bFC->confirmed,
						bFB->num_confirmations,
						bFC->num_inputs,
						bFC->num_outputs,
						bFG->amount_credited_str,
						bFR->amount_debited_str,
						bFR->fee,
						bFY->net_diff,
						bFb->tx_data,
					]);
				} else {
					table.add_row(row![
						bFD->id,
						bFb->entry_type,
						bFD->slate_id,
						bFB->creation_ts,
						bFR->confirmed,
						bFB->num_confirmations,
						bFD->num_inputs,
						bFD->num_outputs,
						bFG->amount_credited_str,
						bFD->amount_debited_str,
						bFD->fee,
						bFG->net_diff,
						bFB->tx_data,
					]);
				}
			}
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	if txs.len() > 1 {
		println!();
		println!("total displayed txs:\t{}", txs.len());
		println!(
			"total displayed fee:\t{}",
			core::amount_to_hr_string(total_fee, true)
		);
		let total_net_diff = if total_amount_credited >= total_amount_debited {
			core::amount_to_hr_string(total_amount_credited - total_amount_debited, true)
		} else {
			format!(
				"-{}",
				core::amount_to_hr_string(total_amount_debited - total_amount_credited, true)
			)
		};
		println!("total net difference:\t{}", total_net_diff);
	}

	if !validated && include_status {
		println!(
			"\nWARNING: Wallet failed to verify data. \
			 The above is from local cache and possibly invalid! \
			 (is your `gotts server` offline or broken?)"
		);
	}
	Ok(())
}
/// Display summary info in a pretty way
pub fn info(
	account: &str,
	wallet_info: &WalletInfo,
	validated: bool,
	dark_background_color_scheme: bool,
) {
	println!(
		"\n____ Wallet Summary Info - Account '{}' as of height {} ____\n",
		account, wallet_info.last_confirmed_height,
	);

	let mut table = table!();

	if dark_background_color_scheme {
		table.add_row(row![
			bFG->"Confirmed Total",
			FG->amount_to_hr_string(wallet_info.total, false)
		]);
		// Only dispay "Immature Coinbase" if we have related outputs in the wallet.
		// This row just introduces confusion if the wallet does not receive coinbase rewards.
		if wallet_info.amount_immature > 0 {
			table.add_row(row![
				bFY->format!("Immature Coinbase (< {})", global::coinbase_maturity()),
				FY->amount_to_hr_string(wallet_info.amount_immature, false)
			]);
		}
		table.add_row(row![
			bFY->format!("Awaiting Confirmation (< {})", wallet_info.minimum_confirmations),
			FY->amount_to_hr_string(wallet_info.amount_awaiting_confirmation, false)
		]);
		table.add_row(row![
			bFB->format!("Awaiting Finalization"),
			FB->amount_to_hr_string(wallet_info.amount_awaiting_finalization, false)
		]);
		table.add_row(row![
			Fr->"Locked by previous transaction",
			Fr->amount_to_hr_string(wallet_info.amount_locked, false)
		]);
		table.add_row(row![
			Fw->"--------------------------------",
			Fw->"-------------"
		]);
		table.add_row(row![
			bFG->"Currently Spendable",
			FG->amount_to_hr_string(wallet_info.amount_currently_spendable, false)
		]);
	} else {
		table.add_row(row![
			bFG->"Total",
			FG->amount_to_hr_string(wallet_info.total, false)
		]);
		// Only dispay "Immature Coinbase" if we have related outputs in the wallet.
		// This row just introduces confusion if the wallet does not receive coinbase rewards.
		if wallet_info.amount_immature > 0 {
			table.add_row(row![
				bFB->format!("Immature Coinbase (< {})", global::coinbase_maturity()),
				FB->amount_to_hr_string(wallet_info.amount_immature, false)
			]);
		}
		table.add_row(row![
			bFB->format!("Awaiting Confirmation (< {})", wallet_info.minimum_confirmations),
			FB->amount_to_hr_string(wallet_info.amount_awaiting_confirmation, false)
		]);
		table.add_row(row![
			Fr->"Locked by previous transaction",
			Fr->amount_to_hr_string(wallet_info.amount_locked, false)
		]);
		table.add_row(row![
			Fw->"--------------------------------",
			Fw->"-------------"
		]);
		table.add_row(row![
			bFG->"Currently Spendable",
			FG->amount_to_hr_string(wallet_info.amount_currently_spendable, false)
		]);
	};
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
	if !validated {
		println!(
			"\nWARNING: Wallet failed to verify data against a live chain. \
			 The above is from local cache and only valid up to the given height! \
			 (is your `gotts server` offline or broken?)"
		);
	}
}

/// Display summary info in a pretty way
pub fn estimate(
	amount: u64,
	strategies: Vec<(
		&str, // strategy
		u64,  // total amount to be locked
		u32,  // fee
	)>,
	dark_background_color_scheme: bool,
) {
	println!(
		"\nEstimation for sending {}:\n",
		amount_to_hr_string(amount, false)
	);

	let mut table = table!();

	table.set_titles(row![
		bMG->"Selection strategy",
		bMG->"Fee",
		bMG->"Will be locked",
	]);

	for (strategy, total, fee) in strategies {
		if dark_background_color_scheme {
			table.add_row(row![
				bFC->strategy,
				FR->amount_to_hr_string(fee as u64, false),
				FY->amount_to_hr_string(total, false),
			]);
		} else {
			table.add_row(row![
				bFD->strategy,
				FR->amount_to_hr_string(fee as u64, false),
				FY->amount_to_hr_string(total, false),
			]);
		}
	}
	table.printstd();
	println!();
}

/// Display list of wallet accounts in a pretty way
pub fn accounts(acct_mappings: Vec<AcctPathMapping>) {
	println!("\n____ Wallet Accounts ____\n",);
	let mut table = table!();

	table.set_titles(row![
		mMG->"Name",
		bMG->"Parent BIP-32 Derivation Path",
	]);
	for m in acct_mappings {
		table.add_row(row![
			bFC->m.label,
			bGC->m.path.to_bip_32_string(),
		]);
	}
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
}

/// Display transaction log messages
pub fn tx_messages(tx: &TxLogEntry, dark_background_color_scheme: bool) -> Result<(), Error> {
	let title = format!("Transaction Messages - Transaction '{}'", tx.id,);
	println!();
	if term::stdout().is_none() {
		println!("Could not open terminal");
		return Ok(());
	}
	let mut t = term::stdout().unwrap();
	t.fg(term::color::MAGENTA).unwrap();
	writeln!(t, "{}", title).unwrap();
	t.reset().unwrap();

	let msgs = match tx.messages.clone() {
		None => {
			writeln!(t, "{}", "None").unwrap();
			t.reset().unwrap();
			return Ok(());
		}
		Some(m) => m.clone(),
	};

	if msgs.messages.is_empty() {
		writeln!(t, "{}", "None").unwrap();
		t.reset().unwrap();
		return Ok(());
	}

	let mut table = table!();

	table.set_titles(row![
		bMG->"Participant Id",
		bMG->"Message",
		bMG->"Public Key",
		bMG->"Signature",
	]);

	for m in msgs.messages {
		let id = format!("{}", m.id);
		let public_key = format!(
			"{}",
			util::to_hex(m.public_key.serialize_vec(true).to_vec())
		);
		let message = match m.message {
			Some(m) => format!("{}", m),
			None => "None".to_owned(),
		};
		let message_sig = match m.message_sig {
			Some(s) => format!("{}", util::to_hex(s.serialize_der())),
			None => "None".to_owned(),
		};
		if dark_background_color_scheme {
			table.add_row(row![
				bFC->id,
				bFC->message,
				bFC->public_key,
				bFB->message_sig,
			]);
		} else {
			table.add_row(row![
				bFD->id,
				bFb->message,
				bFD->public_key,
				bFB->message_sig,
			]);
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();

	Ok(())
}
