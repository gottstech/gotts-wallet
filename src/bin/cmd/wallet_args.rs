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

use crate::api::TLSConfig;
use crate::util::file::get_first_line;
use crate::util::{Mutex, ZeroingString};
/// Argument parsing and error handling for wallet commands
use clap::ArgMatches;
use failure::Fail;
use gotts_wallet_config::WalletConfig;
use gotts_wallet_controller::command;
use gotts_wallet_controller::{DateTime, Error, ErrorKind};
use gotts_wallet_impls::{instantiate_wallet, WalletSeed};
use gotts_wallet_libwallet::{
	IssueInvoiceTxArgs, NodeClient, OutputStatus, TxLogEntryType, WalletInst,
};
use gotts_wallet_util::gotts_core as core;
use gotts_wallet_util::gotts_keychain as keychain;
use linefeed::terminal::Signal;
use linefeed::{Interface, ReadResult};
use rpassword;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

// shut up test compilation warnings
#[cfg(not(test))]
use gotts_wallet_impls::FileWalletCommAdapter;
#[cfg(not(test))]
use gotts_wallet_libwallet::Slate;
#[cfg(not(test))]
use gotts_wallet_util::gotts_core::core::amount_to_hr_string;

// define what to do on argument error
macro_rules! arg_parse {
	( $r:expr ) => {
		match $r {
			Ok(res) => res,
			Err(e) => {
				return Err(ErrorKind::ArgumentError(format!("{}", e)).into());
				}
			}
	};
}
/// Simple error definition, just so we can return errors from all commands
/// and let the caller figure out what to do
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ParseError {
	#[fail(display = "Invalid Arguments: {}", _0)]
	ArgumentError(String),
	#[fail(display = "Parsing IO error: {}", _0)]
	IOError(String),
	#[fail(display = "User Cancelled")]
	CancelledError,
}

impl From<std::io::Error> for ParseError {
	fn from(e: std::io::Error) -> ParseError {
		ParseError::IOError(format!("{}", e))
	}
}

fn prompt_password_stdout(prompt: &str) -> ZeroingString {
	ZeroingString::from(rpassword::prompt_password_stdout(prompt).unwrap())
}

pub fn prompt_password(password: &Option<ZeroingString>) -> ZeroingString {
	match password {
		None => prompt_password_stdout("Password: "),
		Some(p) => p.clone(),
	}
}

fn prompt_password_confirm() -> ZeroingString {
	let mut first = ZeroingString::from("first");
	let mut second = ZeroingString::from("second");
	while first != second {
		first = prompt_password_stdout("Password: ");
		second = prompt_password_stdout("Confirm Password: ");

		if first != second {
			let mut stdout = std::io::stdout();

			write!(
				stdout,
				"{}",
				"Password and confirm password doesn't match. Please try again.\n"
			)
			.unwrap();
			stdout.flush().unwrap();
		}
	}
	first
}

fn prompt_replace_seed() -> Result<bool, ParseError> {
	let interface = Arc::new(Interface::new("replace_seed")?);
	interface.set_report_signal(Signal::Interrupt, true);
	interface.set_prompt("Replace seed? (y/n)> ")?;
	println!();
	println!("Existing wallet.seed file already exists. Continue?");
	println!("Continuing will back up your existing 'wallet.seed' file as 'wallet.seed.bak'");
	println!();
	loop {
		let res = interface.read_line()?;
		match res {
			ReadResult::Eof => return Ok(false),
			ReadResult::Signal(sig) => {
				if sig == Signal::Interrupt {
					interface.cancel_read_line()?;
					return Err(ParseError::CancelledError);
				}
			}
			ReadResult::Input(line) => match line.trim() {
				"Y" | "y" => return Ok(true),
				"N" | "n" => return Ok(false),
				_ => println!("Please respond y or n"),
			},
		}
	}
}

fn prompt_recovery_phrase() -> Result<ZeroingString, ParseError> {
	let interface = Arc::new(Interface::new("recover")?);
	let mut phrase = ZeroingString::from("");
	interface.set_report_signal(Signal::Interrupt, true);
	interface.set_prompt("phrase> ")?;
	loop {
		println!("Please enter your recovery phrase:");
		let res = interface.read_line()?;
		match res {
			ReadResult::Eof => break,
			ReadResult::Signal(sig) => {
				if sig == Signal::Interrupt {
					interface.cancel_read_line()?;
					return Err(ParseError::CancelledError);
				}
			}
			ReadResult::Input(line) => {
				if WalletSeed::from_mnemonic(&line).is_ok() {
					phrase = ZeroingString::from(line);
					break;
				} else {
					println!();
					println!("Recovery word phrase is invalid.");
					println!();
					interface.set_buffer(&line)?;
				}
			}
		}
	}
	Ok(phrase)
}

#[cfg(not(test))]
fn prompt_pay_invoice(slate: &Slate, method: &str, dest: &str) -> Result<bool, ParseError> {
	let interface = Arc::new(Interface::new("pay")?);
	let amount = amount_to_hr_string(slate.amount, false);
	interface.set_report_signal(Signal::Interrupt, true);
	interface.set_prompt(
		"To proceed, type the exact amount of the invoice as displayed above (or Q/q to quit) > ",
	)?;
	println!();
	println!(
		"This command will pay the amount specified in the invoice using your wallet's funds."
	);
	println!("After you confirm, the following will occur: ");
	println!();
	println!(
		"* {} of your wallet funds will be added to the transaction to pay this invoice.",
		amount
	);
	if method == "http" {
		println!("* The resulting transaction will IMMEDIATELY be sent to the wallet listening at: '{}'.", dest);
	} else {
		println!("* The resulting transaction will be saved to the file '{}', which you can manually send back to the invoice creator.", dest);
	}
	println!();
	println!("The invoice slate's participant info is:");
	for m in slate.participant_messages().messages {
		println!("{}", m);
	}
	println!("Please review the above information carefully before proceeding");
	println!();
	loop {
		let res = interface.read_line()?;
		match res {
			ReadResult::Eof => return Ok(false),
			ReadResult::Signal(sig) => {
				if sig == Signal::Interrupt {
					interface.cancel_read_line()?;
					return Err(ParseError::CancelledError);
				}
			}
			ReadResult::Input(line) => {
				match line.trim() {
					"Q" | "q" => return Err(ParseError::CancelledError),
					result => {
						if result == amount {
							return Ok(true);
						} else {
							println!("Please enter exact amount of the invoice as shown above or Q to quit");
							println!();
						}
					}
				}
			}
		}
	}
}

// instantiate wallet (needed by most functions)

pub fn inst_wallet(
	config: WalletConfig,
	g_args: &command::GlobalArgs,
	node_client: impl NodeClient + 'static,
) -> Result<Arc<Mutex<dyn WalletInst<impl NodeClient + 'static, keychain::ExtKeychain>>>, ParseError>
{
	let res = instantiate_wallet(
		config.clone(),
		node_client,
		&g_args.password.clone().unwrap(),
		&g_args.account,
	);
	match res {
		Ok(p) => Ok(p),
		Err(e) => {
			let msg = {
				match e.kind() {
					gotts_wallet_impls::ErrorKind::Encryption => {
						format!("Error decrypting wallet seed (check provided password)")
					}
					_ => format!("Error instantiating wallet: {}", e),
				}
			};
			Err(ParseError::ArgumentError(msg))
		}
	}
}

// parses a required value, or throws error with message otherwise
fn parse_required<'a>(args: &'a ArgMatches, name: &str) -> Result<&'a str, ParseError> {
	let arg = args.value_of(name);
	match arg {
		Some(ar) => Ok(ar),
		None => {
			let msg = format!("Value for argument '{}' is required in this context", name,);
			Err(ParseError::ArgumentError(msg))
		}
	}
}

// parses a number, or throws error with message otherwise
fn parse_u64(arg: &str, name: &str) -> Result<u64, ParseError> {
	let val = arg.parse::<u64>();
	match val {
		Ok(v) => Ok(v),
		Err(e) => {
			let msg = format!("Could not parse {} as a whole number. e={}", name, e);
			Err(ParseError::ArgumentError(msg))
		}
	}
}

// parses a float Gotts value, or throws error with message otherwise
fn parse_value(arg: &str, name: &str) -> Result<u64, ParseError> {
	let amount = core::core::amount_from_hr_string(arg);
	match amount {
		Ok(a) => Ok(a),
		Err(e) => {
			let msg = format!(
				"Could not parse {} as a number with optional decimal point. e={}",
				name, e
			);
			Err(ParseError::ArgumentError(msg))
		}
	}
}

// parses an output status, or throws error with message otherwise
fn parse_status(arg: &str, name: &str) -> Result<OutputStatus, ParseError> {
	let status = match arg.to_lowercase().as_str() {
		"unconfirmed" => Ok(OutputStatus::Unconfirmed),
		"unspent" => Ok(OutputStatus::Unspent),
		"locked" => Ok(OutputStatus::Locked),
		"spent" => Ok(OutputStatus::Spent),
		"confirmed" => Ok(OutputStatus::Confirmed),
		_ => Err(()),
	};
	match status {
		Ok(a) => Ok(a),
		Err(_) => {
			let msg = format!("Could not parse {} as an output status", name);
			Err(ParseError::ArgumentError(msg))
		}
	}
}

// parses a tx type, or throws error with message otherwise
fn parse_tx_type(arg: &str, name: &str) -> Result<TxLogEntryType, ParseError> {
	let status = match arg.to_lowercase().as_str() {
		"coinbase" => Ok(TxLogEntryType::ConfirmedCoinbase),
		"rx" => Ok(TxLogEntryType::TxReceived),
		"tx" => Ok(TxLogEntryType::TxSent),
		"rxc" => Ok(TxLogEntryType::TxReceivedCancelled),
		"txc" => Ok(TxLogEntryType::TxSentCancelled),
		_ => Err(()),
	};
	match status {
		Ok(a) => Ok(a),
		Err(_) => {
			let msg = format!("Could not parse {} as a tx type", name);
			Err(ParseError::ArgumentError(msg))
		}
	}
}

// parses a date, or throws error with message otherwise
fn parse_date(arg: &str, name: &str) -> Result<DateTime, ParseError> {
	let status = DateTime::parse_from_str(arg, "%Y-%m-%d %H:%M:%S");
	match status {
		Ok(a) => Ok(a),
		Err(_) => {
			let msg = format!("Could not parse {} as a tx type", name);
			Err(ParseError::ArgumentError(msg))
		}
	}
}

pub fn parse_global_args(
	config: &WalletConfig,
	args: &ArgMatches,
) -> Result<command::GlobalArgs, ParseError> {
	let account = parse_required(args, "account")?;
	let mut show_spent = false;
	if args.is_present("show_spent") {
		show_spent = true;
	}
	let node_api_secret = get_first_line(config.node_api_secret_path.clone());
	let password = match args.value_of("pass") {
		None => None,
		Some(p) => Some(ZeroingString::from(p)),
	};

	let tls_conf = match config.tls_certificate_file.clone() {
		None => None,
		Some(file) => {
			let key = match config.tls_certificate_key.clone() {
				Some(k) => k,
				None => {
					let msg = format!("Private key for certificate is not set");
					return Err(ParseError::ArgumentError(msg));
				}
			};
			Some(TLSConfig::new(file, key))
		}
	};

	Ok(command::GlobalArgs {
		account: account.to_owned(),
		show_spent: show_spent,
		node_api_secret: node_api_secret,
		password: password,
		tls_conf: tls_conf,
	})
}

pub fn parse_init_args(
	config: &WalletConfig,
	g_args: &command::GlobalArgs,
	args: &ArgMatches,
) -> Result<command::InitArgs, ParseError> {
	if let Err(e) = WalletSeed::seed_file_exists(config.data_file_dir.as_str()) {
		let msg = format!("Not creating wallet - {}", e.inner);
		return Err(ParseError::ArgumentError(msg));
	}
	let list_length = match args.is_present("short_wordlist") {
		false => 32,
		true => 16,
	};
	let recovery_phrase = match args.is_present("recover") {
		true => Some(prompt_recovery_phrase()?),
		false => None,
	};

	if recovery_phrase.is_some() {
		println!("Please provide a new password for the recovered wallet");
	} else {
		println!("Please enter a password for your new wallet");
	}

	let password = match g_args.password.clone() {
		Some(p) => p,
		None => prompt_password_confirm(),
	};

	Ok(command::InitArgs {
		list_length: list_length,
		password: password,
		config: config.clone(),
		recovery_phrase: recovery_phrase,
		restore: false,
	})
}

pub fn parse_recover_args(
	config: &WalletConfig,
	g_args: &command::GlobalArgs,
	args: &ArgMatches,
) -> Result<command::RecoverArgs, ParseError> {
	let (passphrase, recovery_phrase) = {
		match args.is_present("display") {
			true => (prompt_password(&g_args.password), None),
			false => {
				let cont = {
					match WalletSeed::seed_file_exists(config.data_file_dir.as_str()) {
						Err(_) => prompt_replace_seed()?,
						Ok(_) => true,
					}
				};
				if !cont {
					return Err(ParseError::CancelledError);
				}
				let phrase = prompt_recovery_phrase()?;
				println!("Please provide a new password for the recovered wallet");
				(prompt_password_confirm(), Some(phrase.to_owned()))
			}
		}
	};
	Ok(command::RecoverArgs {
		passphrase,
		recovery_phrase,
	})
}

pub fn parse_address_args(args: &ArgMatches) -> Result<command::AddressArgs, ParseError> {
	let address_to_check = if let Ok(addr) = parse_required(args, "check") {
		Some(addr.to_string())
	} else {
		None
	};
	let d0 = parse_required(args, "d0")?;
	let d0 = parse_u64(d0, "d0")?;
	// Valid range: [0..2^31-1].
	if d0 > (std::u32::MAX >> 1) as u64 {
		return Err(ParseError::ArgumentError(
			"valid range: [0..2^31-1]".to_string(),
		));
	}
	let d1 = parse_required(args, "d1")?;
	let d1 = parse_u64(d1, "d1")?;
	// Valid range: [0..2^31-1].
	if d1 > (std::u32::MAX >> 1) as u64 {
		return Err(ParseError::ArgumentError(
			"valid range: [0..2^31-1]".to_string(),
		));
	}
	Ok(command::AddressArgs {
		address_to_check,
		d0_until: d0 as u32,
		d1_until: d1 as u32,
	})
}

pub fn parse_listen_args(
	config: &mut WalletConfig,
	g_args: &mut command::GlobalArgs,
	args: &ArgMatches,
) -> Result<command::ListenArgs, ParseError> {
	// listen args
	let pass = match g_args.password.clone() {
		Some(p) => Some(p.to_owned()),
		None => Some(prompt_password(&None)),
	};
	g_args.password = pass;
	if let Some(port) = args.value_of("port") {
		config.api_listen_port = port.parse().unwrap();
	}
	let method = parse_required(args, "method")?;
	Ok(command::ListenArgs {
		method: method.to_owned(),
	})
}

pub fn parse_account_args(account_args: &ArgMatches) -> Result<command::AccountArgs, ParseError> {
	let create = match account_args.value_of("create") {
		None => None,
		Some(s) => Some(s.to_owned()),
	};
	Ok(command::AccountArgs { create: create })
}

pub fn parse_send_args(args: &ArgMatches) -> Result<command::SendArgs, ParseError> {
	// amount
	let amount = parse_required(args, "amount")?;
	let amount = core::core::amount_from_hr_string(amount);
	let amount = match amount {
		Ok(a) => a,
		Err(e) => {
			let msg = format!(
				"Could not parse amount as a number with optional decimal point. e={}",
				e
			);
			return Err(ParseError::ArgumentError(msg));
		}
	};

	// message
	let message = match args.is_present("message") {
		true => Some(args.value_of("message").unwrap().to_owned()),
		false => None,
	};

	// minimum_confirmations
	let min_c = parse_required(args, "minimum_confirmations")?;
	let min_c = parse_u64(min_c, "minimum_confirmations")?;

	// selection_strategy
	let selection_strategy = parse_required(args, "selection_strategy")?;

	// estimate_selection_strategies
	let estimate_selection_strategies = args.is_present("estimate_selection_strategies");

	// method
	let mut method = parse_required(args, "method")?;

	// dest
	let dest = {
		if method == "self" {
			match args.value_of("dest") {
				Some(d) => d,
				None => "default",
			}
		} else {
			if !estimate_selection_strategies {
				parse_required(args, "dest")?
			} else {
				""
			}
		}
	};

	if (dest.starts_with("ts1") || dest.starts_with("gs1")) && dest.len() >= 63 {
		method = "addr";
	}

	if !estimate_selection_strategies
		&& method == "http"
		&& !dest.starts_with("http://")
		&& !dest.starts_with("https://")
	{
		let msg = format!(
			"HTTP Destination should start with http://: or https://: {}",
			dest,
		);
		return Err(ParseError::ArgumentError(msg));
	}

	// change_outputs
	let change_outputs = parse_required(args, "change_outputs")?;
	let change_outputs = parse_u64(change_outputs, "change_outputs")? as usize;

	// fluff
	let fluff = args.is_present("fluff");

	// max_outputs
	let max_outputs = 10_000;

	// target slate version to create/send
	let target_slate_version = {
		match args.is_present("slate_version") {
			true => {
				let v = parse_required(args, "slate_version")?;
				Some(parse_u64(v, "slate_version")? as u16)
			}
			false => None,
		}
	};

	Ok(command::SendArgs {
		amount,
		message,
		minimum_confirmations: min_c,
		selection_strategy: selection_strategy.to_owned(),
		estimate_selection_strategies,
		method: method.to_owned(),
		dest: dest.to_owned(),
		change_outputs,
		fluff,
		max_outputs,
		target_slate_version,
	})
}

pub fn parse_receive_args(receive_args: &ArgMatches) -> Result<command::ReceiveArgs, ParseError> {
	// message
	let message = match receive_args.is_present("message") {
		true => Some(receive_args.value_of("message").unwrap().to_owned()),
		false => None,
	};

	// input
	let tx_file = parse_required(receive_args, "input")?;

	// validate input
	if !Path::new(&tx_file).is_file() {
		let msg = format!("File {} not found.", &tx_file);
		return Err(ParseError::ArgumentError(msg));
	}

	Ok(command::ReceiveArgs {
		input: tx_file.to_owned(),
		message: message,
	})
}

pub fn parse_finalize_args(args: &ArgMatches) -> Result<command::FinalizeArgs, ParseError> {
	let fluff = args.is_present("fluff");
	let tx_file = parse_required(args, "input")?;

	if !Path::new(&tx_file).is_file() {
		let msg = format!("File {} not found.", tx_file);
		return Err(ParseError::ArgumentError(msg));
	}
	Ok(command::FinalizeArgs {
		input: tx_file.to_owned(),
		fluff: fluff,
	})
}

pub fn parse_issue_invoice_args(
	args: &ArgMatches,
) -> Result<command::IssueInvoiceArgs, ParseError> {
	let amount = parse_required(args, "amount")?;
	let amount = core::core::amount_from_hr_string(amount);
	let amount = match amount {
		Ok(a) => a,
		Err(e) => {
			let msg = format!(
				"Could not parse amount as a number with optional decimal point. e={}",
				e
			);
			return Err(ParseError::ArgumentError(msg));
		}
	};
	// message
	let message = match args.is_present("message") {
		true => Some(args.value_of("message").unwrap().to_owned()),
		false => None,
	};
	// target slate version to create
	let target_slate_version = {
		match args.is_present("slate_version") {
			true => {
				let v = parse_required(args, "slate_version")?;
				Some(parse_u64(v, "slate_version")? as u16)
			}
			false => None,
		}
	};
	// dest (output file)
	let dest = parse_required(args, "dest")?;
	Ok(command::IssueInvoiceArgs {
		dest: dest.into(),
		issue_args: IssueInvoiceTxArgs {
			dest_acct_name: None,
			amount,
			message,
			target_slate_version,
		},
	})
}

pub fn parse_process_invoice_args(
	args: &ArgMatches,
) -> Result<command::ProcessInvoiceArgs, ParseError> {
	// TODO: display and prompt for confirmation of what we're doing
	// message
	let message = match args.is_present("message") {
		true => Some(args.value_of("message").unwrap().to_owned()),
		false => None,
	};

	// minimum_confirmations
	let min_c = parse_required(args, "minimum_confirmations")?;
	let min_c = parse_u64(min_c, "minimum_confirmations")?;

	// selection_strategy
	let selection_strategy = parse_required(args, "selection_strategy")?;

	// estimate_selection_strategies
	let estimate_selection_strategies = args.is_present("estimate_selection_strategies");

	// method
	let method = parse_required(args, "method")?;

	// dest
	let dest = {
		if method == "self" {
			match args.value_of("dest") {
				Some(d) => d,
				None => "default",
			}
		} else {
			if !estimate_selection_strategies {
				parse_required(args, "dest")?
			} else {
				""
			}
		}
	};
	if !estimate_selection_strategies
		&& method == "http"
		&& !dest.starts_with("http://")
		&& !dest.starts_with("https://")
	{
		let msg = format!(
			"HTTP Destination should start with http://: or https://: {}",
			dest,
		);
		return Err(ParseError::ArgumentError(msg));
	}

	// max_outputs
	let max_outputs = 500;

	// file input only
	let tx_file = parse_required(args, "input")?;

	// Now we need to prompt the user whether they want to do this,
	// which requires reading the slate
	#[cfg(not(test))]
	let adapter = FileWalletCommAdapter::new();
	#[cfg(not(test))]
	let slate = match adapter.receive_tx_async(&tx_file) {
		Ok(s) => s,
		Err(e) => return Err(ParseError::ArgumentError(format!("{}", e))),
	};

	#[cfg(not(test))] // don't prompt during automated testing
	prompt_pay_invoice(&slate, method, dest)?;

	Ok(command::ProcessInvoiceArgs {
		message: message,
		minimum_confirmations: min_c,
		selection_strategy: selection_strategy.to_owned(),
		estimate_selection_strategies,
		method: method.to_owned(),
		dest: dest.to_owned(),
		max_outputs: max_outputs,
		input: tx_file.to_owned(),
	})
}

pub fn parse_info_args(args: &ArgMatches) -> Result<command::InfoArgs, ParseError> {
	// minimum_confirmations
	let mc = parse_required(args, "minimum_confirmations")?;
	let mc = parse_u64(mc, "minimum_confirmations")?;
	Ok(command::InfoArgs {
		minimum_confirmations: mc,
	})
}

pub fn parse_check_args(args: &ArgMatches) -> Result<command::CheckArgs, ParseError> {
	let delete_unconfirmed = args.is_present("delete_unconfirmed");
	let ignore_within = parse_required(args, "ignore_within")?;
	let mut ignore_within = parse_u64(ignore_within, "ignore_within")?;
	// Valid range: [0..1440]. Unit: Minute.
	if ignore_within > 1440 {
		ignore_within = 1440;
	}
	let address_to_check = if let Ok(addr) = parse_required(args, "address") {
		Some(addr.to_string())
	} else {
		None
	};
	Ok(command::CheckArgs {
		delete_unconfirmed,
		ignore_within,
		address_to_check,
	})
}

pub fn parse_pwdupdate_args(_args: &ArgMatches) -> Result<command::PwdUpdateArgs, ParseError> {
	let mut stdout = std::io::stdout();
	write!(
		stdout,
		"{}",
		"Changing password for wallet. Please Input your new password.\n"
	)?;

	let passphrase = prompt_password_confirm();

	Ok(command::PwdUpdateArgs {
		new_password: passphrase,
	})
}

pub fn parse_outputs_args(args: &ArgMatches) -> Result<command::OutputsArgs, ParseError> {
	let minvalue = match args.value_of("minvalue") {
		None => None,
		Some(value) => Some(parse_value(value, "minvalue")? as u64),
	};
	let status = match args.value_of("status") {
		None => None,
		Some(status) => Some(parse_status(status, "status")? as OutputStatus),
	};
	let limit = match args.value_of("limit") {
		None => None,
		Some(limit) => Some(parse_u64(limit, "limit")? as u64),
	};
	Ok(command::OutputsArgs {
		minvalue,
		status,
		limit,
	})
}

pub fn parse_payments_args(args: &ArgMatches) -> Result<command::PaymentsArgs, ParseError> {
	let status = match args.value_of("status") {
		None => None,
		Some(status) => Some(parse_status(status, "status")? as OutputStatus),
	};
	let limit = match args.value_of("limit") {
		None => None,
		Some(limit) => Some(parse_u64(limit, "limit")? as u64),
	};
	Ok(command::PaymentsArgs { status, limit })
}

pub fn parse_txs_args(args: &ArgMatches) -> Result<command::TxsArgs, ParseError> {
	let tx_id = match args.value_of("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};
	let raw = args.is_present("raw");
	let tx_type = match args.value_of("type") {
		None => None,
		Some(tx_type) => Some(parse_tx_type(tx_type, "type")? as TxLogEntryType),
	};
	let start_date = match args.value_of("startdate") {
		None => None,
		Some(date) => Some(parse_date(date, "startdate")? as DateTime),
	};
	let end_date = match args.value_of("enddate") {
		None => None,
		Some(date) => Some(parse_date(date, "enddate")? as DateTime),
	};
	let limit = match args.value_of("limit") {
		None => None,
		Some(limit) => Some(parse_u64(limit, "limit")? as u64),
	};
	Ok(command::TxsArgs {
		id: tx_id,
		show_raw_tx_data: raw,
		tx_type,
		start_date,
		end_date,
		limit,
	})
}

pub fn parse_repost_args(args: &ArgMatches) -> Result<command::RepostArgs, ParseError> {
	let tx_id = match args.value_of("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};

	let fluff = args.is_present("fluff");
	let dump_file = match args.value_of("dumpfile") {
		None => None,
		Some(d) => Some(d.to_owned()),
	};

	Ok(command::RepostArgs {
		id: tx_id.unwrap(),
		dump_file: dump_file,
		fluff: fluff,
	})
}

pub fn parse_cancel_args(args: &ArgMatches) -> Result<command::CancelArgs, ParseError> {
	let mut tx_id_string = "";
	let tx_id = match args.value_of("id") {
		None => None,
		Some(tx) => Some(parse_u64(tx, "id")? as u32),
	};
	let tx_slate_id = match args.value_of("txid") {
		None => None,
		Some(tx) => match tx.parse() {
			Ok(t) => {
				tx_id_string = tx;
				Some(t)
			}
			Err(e) => {
				let msg = format!("Could not parse txid parameter. e={}", e);
				return Err(ParseError::ArgumentError(msg));
			}
		},
	};
	if (tx_id.is_none() && tx_slate_id.is_none()) || (tx_id.is_some() && tx_slate_id.is_some()) {
		let msg = format!("'id' (-i) or 'txid' (-t) argument is required.");
		return Err(ParseError::ArgumentError(msg));
	}
	Ok(command::CancelArgs {
		tx_id: tx_id,
		tx_slate_id: tx_slate_id,
		tx_id_string: tx_id_string.to_owned(),
	})
}

pub fn wallet_command(
	wallet_args: &ArgMatches,
	mut wallet_config: WalletConfig,
	mut node_client: impl NodeClient + 'static,
) -> Result<String, Error> {
	if let Some(t) = wallet_config.chain_type.clone() {
		core::global::set_mining_mode(t);
	}

	if wallet_args.is_present("external") {
		wallet_config.api_listen_interface = "0.0.0.0".to_string();
	}

	if let Some(dir) = wallet_args.value_of("data_dir") {
		wallet_config.data_file_dir = dir.to_string().clone();
	}

	if let Some(sa) = wallet_args.value_of("api_server_address") {
		wallet_config.check_node_api_http_addr = sa.to_string().clone();
	}

	let mut global_wallet_args = arg_parse!(parse_global_args(&wallet_config, &wallet_args));

	node_client.set_node_url(&wallet_config.check_node_api_http_addr);
	node_client.set_node_api_secret(global_wallet_args.node_api_secret.clone());

	// prompt to input password
	if global_wallet_args.password.is_none() {
		global_wallet_args.password = Some(prompt_password(&global_wallet_args.password));
	}

	// closure to instantiate wallet as needed by each subcommand
	let inst_wallet = || {
		let res = inst_wallet(wallet_config.clone(), &global_wallet_args, node_client);
		res.unwrap_or_else(|e| {
			println!("{}", e);
			std::process::exit(1);
		})
	};

	let res = match wallet_args.subcommand() {
		("init", Some(args)) => {
			let a = arg_parse!(parse_init_args(&wallet_config, &global_wallet_args, &args));
			command::init(&global_wallet_args, a)
		}
		("recover", Some(args)) => {
			let a = arg_parse!(parse_recover_args(
				&wallet_config,
				&global_wallet_args,
				&args
			));
			command::recover(&wallet_config, a)
		}
		("listen", Some(args)) => {
			let mut c = wallet_config.clone();
			let mut g = global_wallet_args.clone();
			let a = arg_parse!(parse_listen_args(&mut c, &mut g, &args));
			command::listen(&c, &a, &g)
		}
		("owner_api", Some(_)) => {
			let mut g = global_wallet_args.clone();
			g.tls_conf = None;
			command::owner_api(inst_wallet(), &wallet_config, &g)
		}
		("web", Some(_)) => command::owner_api(inst_wallet(), &wallet_config, &global_wallet_args),
		("account", Some(args)) => {
			let a = arg_parse!(parse_account_args(&args));
			command::account(inst_wallet(), a)
		}
		("send", Some(args)) => {
			let a = arg_parse!(parse_send_args(&args));
			command::send(
				inst_wallet(),
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("receive", Some(args)) => {
			let a = arg_parse!(parse_receive_args(&args));
			command::receive(inst_wallet(), &global_wallet_args, a)
		}
		("finalize", Some(args)) => {
			let a = arg_parse!(parse_finalize_args(&args));
			command::finalize(inst_wallet(), a)
		}
		("invoice", Some(args)) => {
			let a = arg_parse!(parse_issue_invoice_args(&args));
			command::issue_invoice_tx(inst_wallet(), a)
		}
		("pay", Some(args)) => {
			let a = arg_parse!(parse_process_invoice_args(&args));
			command::process_invoice(
				inst_wallet(),
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("info", Some(args)) => {
			let a = arg_parse!(parse_info_args(&args));
			command::info(
				inst_wallet(),
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("outputs", Some(args)) => {
			let a = arg_parse!(parse_outputs_args(&args));
			command::outputs(
				inst_wallet(),
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("payments", Some(args)) => {
			let a = arg_parse!(parse_payments_args(&args));
			command::payments(
				inst_wallet(),
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("txs", Some(args)) => {
			let a = arg_parse!(parse_txs_args(&args));
			command::txs(
				inst_wallet(),
				&global_wallet_args,
				a,
				wallet_config.dark_background_color_scheme.unwrap_or(true),
			)
		}
		("address", Some(args)) => {
			let a = arg_parse!(parse_address_args(&args));
			command::address(inst_wallet(), a)
		}
		("repost", Some(args)) => {
			let a = arg_parse!(parse_repost_args(&args));
			command::repost(inst_wallet(), a)
		}
		("cancel", Some(args)) => {
			let a = arg_parse!(parse_cancel_args(&args));
			command::cancel(inst_wallet(), a)
		}
		("restore", Some(_)) => command::restore(inst_wallet()),
		("check", Some(args)) => {
			let a = arg_parse!(parse_check_args(&args));
			command::check_repair(inst_wallet(), a)
		}
		("passwd", Some(args)) => {
			let wallet = inst_wallet();

			let a = arg_parse!(parse_pwdupdate_args(&args));
			command::change_password(wallet, &global_wallet_args, a)
		}
		_ => {
			let msg = format!("Unknown wallet command, use 'gotts help wallet' for details");
			return Err(ErrorKind::ArgumentError(msg).into());
		}
	};
	if let Err(e) = res {
		Err(e)
	} else {
		Ok(wallet_args.subcommand().0.to_owned())
	}
}
