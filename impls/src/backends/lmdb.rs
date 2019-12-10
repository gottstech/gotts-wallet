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

use std::cell::RefCell;
use std::{fs, path};

// for writing stored transaction files
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use failure::ResultExt;
use uuid::Uuid;

use crate::blake2::blake2b::Blake2b;

use super::wallet_store::{self, option_to_not_found};
use crate::keychain::{
	ChildNumber, ExtKeychain, ExtKeychainPath, Identifier, Keychain, RecipientKey,
};
use crate::store::{to_key, to_key_u64};

use crate::core::address::Address;
use crate::core::core::Transaction;
use crate::core::{self, global};
use crate::libwallet::{check_repair, check_repair_batch, restore, restore_batch};
use crate::libwallet::{
	AcctPathMapping, Context, Error, ErrorKind, NodeClient, OutputData, PaymentData, TxLogEntry,
	WalletBackend, WalletOutputBatch,
};
use crate::util;
use crate::util::secp::constants::SECRET_KEY_SIZE;
use crate::util::secp::PublicKey;
use crate::util::ZeroingString;
use crate::WalletSeed;
use config::WalletConfig;

pub const DB_DIR: &'static str = "db";
pub const TX_SAVE_DIR: &'static str = "saved_txs";

const OUTPUT_PREFIX: u8 = 'o' as u8;
const PAYMENT_PREFIX: u8 = 'P' as u8;
const DERIV_PREFIX: u8 = 'd' as u8;
const RECIPIENT_DERIV_PREFIX: u8 = 'r' as u8;
const CONFIRMED_HEIGHT_PREFIX: u8 = 'c' as u8;
const PRIVATE_TX_CONTEXT_PREFIX: u8 = 'p' as u8;
const TX_LOG_ENTRY_PREFIX: u8 = 't' as u8;
const TX_LOG_ID_PREFIX: u8 = 'i' as u8;
const ACCOUNT_PATH_MAPPING_PREFIX: u8 = 'a' as u8;

/// test to see if database files exist in the current directory. If so,
/// use a DB backend for all operations
pub fn wallet_db_exists(config: WalletConfig) -> bool {
	let db_path = path::Path::new(&config.data_file_dir).join(DB_DIR);
	db_path.exists()
}

/// Helper to derive XOR keys for storing private transaction keys in the DB
/// (blind_xor_key, nonce_xor_key)
fn private_ctx_xor_keys<K>(
	keychain: &K,
	slate_id: &[u8],
) -> Result<([u8; SECRET_KEY_SIZE], [u8; SECRET_KEY_SIZE]), Error>
where
	K: Keychain,
{
	let root_key = keychain.derive_key(&K::root_key_id())?;

	// derive XOR values for storing secret values in DB
	// h(root_key|slate_id|"blind")
	let mut hasher = Blake2b::new(SECRET_KEY_SIZE);
	hasher.update(&root_key.0[..]);
	hasher.update(&slate_id[..]);
	hasher.update(&"blind".as_bytes()[..]);
	let blind_xor_key = hasher.finalize();
	let mut ret_blind = [0; SECRET_KEY_SIZE];
	ret_blind.copy_from_slice(&blind_xor_key.as_bytes()[0..SECRET_KEY_SIZE]);

	// h(root_key|slate_id|"nonce")
	let mut hasher = Blake2b::new(SECRET_KEY_SIZE);
	hasher.update(&root_key.0[..]);
	hasher.update(&slate_id[..]);
	hasher.update(&"nonce".as_bytes()[..]);
	let nonce_xor_key = hasher.finalize();
	let mut ret_nonce = [0; SECRET_KEY_SIZE];
	ret_nonce.copy_from_slice(&nonce_xor_key.as_bytes()[0..SECRET_KEY_SIZE]);

	Ok((ret_blind, ret_nonce))
}

pub struct LMDBBackend<C, K> {
	db: wallet_store::Store,
	config: WalletConfig,
	/// passphrase: TODO better ways of dealing with this other than storing
	passphrase: ZeroingString,
	/// Keychain
	pub keychain: Option<K>,
	/// Recipient Key Id
	recipient_key_id: Option<Identifier>,
	/// Parent path to use by default for output operations
	parent_key_id: Identifier,
	/// wallet to node client
	w2n_client: C,
}

impl<C, K> LMDBBackend<C, K> {
	pub fn new(config: WalletConfig, passphrase: &str, n_client: C) -> Result<Self, Error> {
		let db_path = path::Path::new(&config.data_file_dir).join(DB_DIR);
		fs::create_dir_all(&db_path).expect("Couldn't create wallet backend directory!");

		let stored_tx_path = path::Path::new(&config.data_file_dir).join(TX_SAVE_DIR);
		fs::create_dir_all(&stored_tx_path)
			.expect("Couldn't create wallet backend tx storage directory!");

		let store = wallet_store::Store::new(db_path.to_str().unwrap(), None, Some(DB_DIR), None)?;

		// Make sure default wallet derivation path always exists
		// as well as path (so it can be retrieved by batches to know where to store
		// completed transactions, for reference
		let default_account = AcctPathMapping {
			label: "default".to_owned(),
			path: LMDBBackend::<C, K>::default_path(),
		};
		let acct_key = to_key(
			ACCOUNT_PATH_MAPPING_PREFIX,
			&mut default_account.label.as_bytes().to_vec(),
		);

		{
			let batch = store.batch()?;
			batch.put_ser(&acct_key, &default_account)?;
			batch.commit()?;
		}

		let res = LMDBBackend {
			db: store,
			config: config.clone(),
			passphrase: ZeroingString::from(passphrase),
			keychain: None,
			recipient_key_id: None,
			parent_key_id: LMDBBackend::<C, K>::default_path(),
			w2n_client: n_client,
		};
		Ok(res)
	}

	fn default_path() -> Identifier {
		// return the default parent wallet path, corresponding to the default account
		// in the BIP32 spec. Parent is account 0 at level 2, child output identifiers
		// are all at level 3
		ExtKeychain::derive_key_id(2, 0, 0, 0, 0)
	}

	/// Just test to see if database files exist in the current directory. If
	/// so, use a DB backend for all operations
	pub fn exists(config: WalletConfig) -> bool {
		let db_path = path::Path::new(&config.data_file_dir).join(DB_DIR);
		db_path.exists()
	}
}

impl<C, K> WalletBackend<C, K> for LMDBBackend<C, K>
where
	C: NodeClient,
	K: Keychain,
{
	/// Initialise with whatever stored credentials we have
	fn open_with_credentials(&mut self) -> Result<(), Error> {
		let wallet_seed =
			WalletSeed::from_file(&self.config.data_file_dir.as_str(), &self.passphrase)
				.context(ErrorKind::CallbackImpl("Error opening wallet"))?;
		self.keychain = Some(
			wallet_seed
				.derive_keychain(global::is_floonet())
				.context(ErrorKind::CallbackImpl("Error deriving keychain"))?,
		);
		// Initial the recipient key if configured, otherwise use random last key path for it.
		if let Some(recipient_keypath) = self.config.recipient_keypath {
			self.set_recipient_key(recipient_keypath).unwrap();
		}
		Ok(())
	}

	/// Set recipient key.
	/// Considering the address length, we only open the 'd3' of the path to be configurable by user,
	/// - d0,d1 are fixed as u32::max, no matter what is the parent_key_id.
	/// - d2 are fixed as 0 and should not be changed for recipient key.
	/// i.e. The path = ExtKeychainPath::new(4, u32::max, u32::max, 0, d3).
	///
	/// Note: when the 'parent_key_id' changed, for example switching to a different account,
	/// this recipient key will be same.
	fn set_recipient_key(&mut self, keypath: u32) -> Result<(), Error> {
		if self.keychain.is_none() {
			return Err(ErrorKind::Backend("keychain is none".to_string()).into());
		}
		// Initialize the recipient key for non-interactive transaction.
		self.recipient_key_id = Some(self.parent_key_id.extend(keypath));
		Ok(())
	}

	fn recipient_key(&self) -> Result<RecipientKey, Error> {
		if self.keychain.is_none() {
			return Err(ErrorKind::Backend("keychain is none".to_string()).into());
		}

		let keychain = self.keychain_immutable();
		let recipient_key_id = match &self.recipient_key_id {
			Some(key_id) => key_id.clone(),
			None => {
				let mut last_path_index: u32 = thread_rng().gen();
				last_path_index >>= 1;
				self.parent_key_id.extend(last_path_index)
			}
		};
		let recipient_pri_key = keychain.derive_key(&recipient_key_id).unwrap();
		let recipient_pub_key =
			PublicKey::from_secret_key(keychain.secp(), &recipient_pri_key).unwrap();
		Ok(RecipientKey {
			recipient_key_id,
			recipient_pub_key,
			recipient_pri_key,
		})
	}

	fn recipient_key_by_id(&self, key_id: &Identifier) -> Result<RecipientKey, Error> {
		if self.keychain.is_none() {
			return Err(ErrorKind::Backend("keychain is none".to_string()).into());
		}

		let keychain = self.keychain_immutable();
		let recipient_pri_key = keychain.derive_key(key_id).unwrap();
		let recipient_pub_key =
			PublicKey::from_secret_key(keychain.secp(), &recipient_pri_key).unwrap();
		Ok(RecipientKey {
			recipient_key_id: key_id.clone(),
			recipient_pub_key,
			recipient_pri_key,
		})
	}

	fn check_address(
		&self,
		addr: &Address,
		d0_until: u32,
		d1_until: u32,
	) -> Result<AcctPathMapping, Error> {
		if self.keychain.is_none() {
			return Err(ErrorKind::Backend("keychain is none".to_string()).into());
		}

		let keychain = self.keychain_immutable();
		let target_pub_key = addr.get_inner_pubkey();
		let last_path = addr.get_key_id_last_path();

		// searching the existing accounts firstly.
		for acct_path in self.acct_path_iter() {
			let key_id = addr.get_key_id(&acct_path.path);
			let recipient_pub_key = keychain.derive_pub_key(&key_id)?;
			if recipient_pub_key == target_pub_key {
				return Ok(acct_path.clone());
			}
		}

		// if not found, searching the first 10,000 possible accounts
		info!(
			"check_address: start searching the first {} possible accounts (until m/{}/{}) ...",
			d0_until as u64 * d1_until as u64,
			d0_until,
			d1_until,
		);
		if let Ok(key_id) = keychain.search_pub_key(d0_until, d1_until, last_path, &target_pub_key)
		{
			info!("check_address: matching address found. key_id: {}", key_id);
			Ok(AcctPathMapping {
				label: "none".to_string(),
				path: key_id,
			})
		} else {
			info!("check_address: stop searching, no matching address found.");
			Err(ErrorKind::Backend(format!(
				"address checking stop at path m/{}/{}",
				d0_until, d1_until
			))
			.into())
		}
	}

	/// Close wallet and remove any stored credentials (TBD)
	fn close(&mut self) -> Result<(), Error> {
		self.keychain = None;
		self.recipient_key_id = None;
		Ok(())
	}

	/// Return the keychain being used
	fn keychain(&mut self) -> &mut K {
		self.keychain.as_mut().unwrap()
	}

	/// Return the keychain being used as immutable
	fn keychain_immutable(&self) -> &K {
		self.keychain.as_ref().unwrap()
	}

	/// Return the node client being used
	fn w2n_client(&mut self) -> &mut C {
		&mut self.w2n_client
	}

	/// Return the wallet data file dir
	fn wallet_data_dir(&self) -> &str {
		self.config.data_file_dir.as_str()
	}

	/// Update passphrase
	fn update_passphrase(&mut self, new_password: &str) {
		self.passphrase = ZeroingString::from(new_password);
	}

	/// return the version of the commit for caching
	fn calc_commit_for_cache(&mut self, w: i64, id: &Identifier) -> Result<Option<String>, Error> {
		if self.config.no_commit_cache == Some(true) {
			Ok(None)
		} else {
			Ok(Some(util::to_hex(
				self.keychain().commit(w, &id)?.0.to_vec(),
			)))
		}
	}

	/// Set parent path by account name
	fn set_parent_key_id_by_name(&mut self, label: &str) -> Result<(), Error> {
		let label = label.to_owned();
		let res = self.acct_path_iter().find(|l| l.label == label);
		if let Some(a) = res {
			self.set_parent_key_id(a.path);
			Ok(())
		} else {
			return Err(ErrorKind::UnknownAccountLabel(label.clone()).into());
		}
	}

	/// set parent path
	fn set_parent_key_id(&mut self, id: Identifier) {
		self.parent_key_id = id;
	}

	fn parent_key_id(&mut self) -> Identifier {
		self.parent_key_id.clone()
	}

	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error> {
		let key = match mmr_index {
			Some(i) => to_key_u64(OUTPUT_PREFIX, &mut id.to_bytes().to_vec(), *i),
			None => to_key(OUTPUT_PREFIX, &mut id.to_bytes().to_vec()),
		};
		option_to_not_found(self.db.get_ser(&key), &format!("Key Id: {}", id)).map_err(|e| e.into())
	}

	fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = OutputData> + 'a> {
		Box::new(self.db.iter(&[OUTPUT_PREFIX]).unwrap().map(|o| o.1))
	}

	fn payment_entries_iter_tx<'a>(
		&'a self,
		u: &Uuid,
	) -> Box<dyn Iterator<Item = PaymentData> + 'a> {
		let key = to_key(PAYMENT_PREFIX, &mut u.as_bytes().to_vec());
		Box::new(self.db.iter(&key).unwrap().map(|o| o.1))
	}

	fn payment_entries_iter_all<'a>(&'a self) -> Box<dyn Iterator<Item = PaymentData> + 'a> {
		Box::new(self.db.iter(&[PAYMENT_PREFIX]).unwrap().map(|o| o.1))
	}

	fn get_tx_log_entry(&self, u: &Uuid) -> Result<Option<TxLogEntry>, Error> {
		let key = to_key(TX_LOG_ENTRY_PREFIX, &mut u.as_bytes().to_vec());
		self.db.get_ser(&key).map_err(|e| e.into())
	}

	fn tx_log_iter<'a>(&'a self) -> Box<dyn Iterator<Item = TxLogEntry> + 'a> {
		Box::new(self.db.iter(&[TX_LOG_ENTRY_PREFIX]).unwrap().map(|o| o.1))
	}

	fn get_private_context(
		&mut self,
		slate_id: &[u8],
		participant_id: usize,
	) -> Result<Context, Error> {
		let ctx_key = to_key_u64(
			PRIVATE_TX_CONTEXT_PREFIX,
			&mut slate_id.to_vec(),
			participant_id as u64,
		);
		let (blind_xor_key, nonce_xor_key) = private_ctx_xor_keys(self.keychain(), slate_id)?;

		let mut ctx: Context = option_to_not_found(
			self.db.get_ser(&ctx_key),
			&format!("Slate id: {:x?}", slate_id.to_vec()),
		)?;

		for i in 0..SECRET_KEY_SIZE {
			ctx.sec_key.0[i] = ctx.sec_key.0[i] ^ blind_xor_key[i];
			ctx.sec_nonce.0[i] = ctx.sec_nonce.0[i] ^ nonce_xor_key[i];
		}

		Ok(ctx)
	}

	fn acct_path_iter<'a>(&'a self) -> Box<dyn Iterator<Item = AcctPathMapping> + 'a> {
		Box::new(
			self.db
				.iter(&[ACCOUNT_PATH_MAPPING_PREFIX])
				.unwrap()
				.map(|o| o.1),
		)
	}

	fn get_acct_path(&self, label: String) -> Result<Option<AcctPathMapping>, Error> {
		let acct_key = to_key(ACCOUNT_PATH_MAPPING_PREFIX, &mut label.as_bytes().to_vec());
		self.db.get_ser(&acct_key).map_err(|e| e.into())
	}

	fn store_tx(&self, uuid: &str, tx: &Transaction) -> Result<(), Error> {
		let filename = format!("{}.gottstx", uuid);
		let path = path::Path::new(&self.config.data_file_dir)
			.join(TX_SAVE_DIR)
			.join(filename);
		let path_buf = Path::new(&path).to_path_buf();
		let mut stored_tx = File::create(path_buf)?;
		let tx_hex =
			util::to_hex(core::ser::ser_vec(tx, core::ser::ProtocolVersion::local()).unwrap());
		stored_tx.write_all(&tx_hex.as_bytes())?;
		stored_tx.sync_all()?;
		Ok(())
	}

	fn get_stored_tx(&self, entry: &TxLogEntry) -> Result<Option<Transaction>, Error> {
		let filename = match entry.stored_tx.clone() {
			Some(f) => f,
			None => return Ok(None),
		};
		let path = path::Path::new(&self.config.data_file_dir)
			.join(TX_SAVE_DIR)
			.join(filename);
		let tx_file = Path::new(&path).to_path_buf();
		let mut tx_f = File::open(tx_file)?;
		let mut content = String::new();
		tx_f.read_to_string(&mut content)?;
		let tx_bin = util::from_hex(content).unwrap();
		Ok(Some(
			core::ser::deserialize::<Transaction>(
				&mut &tx_bin[..],
				core::ser::ProtocolVersion::local(),
			)
			.unwrap(),
		))
	}

	fn batch<'a>(&'a mut self) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error> {
		Ok(Box::new(Batch {
			_store: self,
			db: RefCell::new(Some(self.db.batch()?)),
			keychain: self.keychain.clone(),
		}))
	}

	fn next_child<'a>(&mut self) -> Result<Identifier, Error> {
		let parent_key_id = self.parent_key_id.clone();
		let mut deriv_idx = {
			let batch = self.db.batch()?;
			let deriv_key = to_key(DERIV_PREFIX, &mut self.parent_key_id.to_bytes().to_vec());
			match batch.get_ser(&deriv_key)? {
				Some(idx) => idx,
				None => 0,
			}
		};
		let mut return_path = self.parent_key_id.to_path();
		return_path.depth = return_path.depth + 1;
		return_path.path[return_path.depth as usize - 1] = ChildNumber::from(deriv_idx);
		deriv_idx = deriv_idx + 1;
		let mut batch = self.batch()?;
		batch.save_child_index(&parent_key_id, deriv_idx)?;
		batch.commit()?;
		Ok(Identifier::from_path(&return_path))
	}

	fn get_recipient_child<'a>(&mut self) -> Result<Identifier, Error> {
		let parent_key_id =
			ExtKeychainPath::new(2, <u32>::max_value(), <u32>::max_value(), 0, 0).to_identifier();
		let deriv_idx = {
			let deriv_key = to_key(
				RECIPIENT_DERIV_PREFIX,
				&mut parent_key_id.to_bytes().to_vec(),
			);
			match self.db.get_ser(&deriv_key)? {
				Some(idx) => idx,
				None => 0,
			}
		};
		let mut return_path = parent_key_id.to_path();
		return_path.depth = 4;
		return_path.path[2] = ChildNumber::from(<u32>::max_value());
		return_path.path[3] = ChildNumber::from(deriv_idx);
		Ok(Identifier::from_path(&return_path))
	}

	fn next_recipient_child<'a>(&mut self) -> Result<Identifier, Error> {
		let parent_key_id =
			ExtKeychainPath::new(2, <u32>::max_value(), <u32>::max_value(), 0, 0).to_identifier();
		let mut deriv_idx = {
			let batch = self.db.batch()?;
			let deriv_key = to_key(
				RECIPIENT_DERIV_PREFIX,
				&mut parent_key_id.to_bytes().to_vec(),
			);
			match batch.get_ser(&deriv_key)? {
				Some(idx) => idx,
				None => 0,
			}
		};
		deriv_idx = deriv_idx + 1;

		let mut return_path = self.parent_key_id.to_path();
		assert_eq!(return_path.depth, 2);
		return_path.depth = 4;
		return_path.path[2] = ChildNumber::from(<u32>::max_value());
		return_path.path[3] = ChildNumber::from(deriv_idx);
		let mut batch = self.batch()?;
		batch.save_recipient_child_index(deriv_idx)?;
		batch.commit()?;
		Ok(Identifier::from_path(&return_path))
	}

	fn last_confirmed_height<'a>(&mut self) -> Result<u64, Error> {
		let batch = self.db.batch()?;
		let height_key = to_key(
			CONFIRMED_HEIGHT_PREFIX,
			&mut self.parent_key_id.to_bytes().to_vec(),
		);
		let last_confirmed_height = match batch.get_ser(&height_key)? {
			Some(h) => h,
			None => 0,
		};
		Ok(last_confirmed_height)
	}

	fn restore(&mut self) -> Result<(), Error> {
		restore(self)?;
		Ok(())
	}

	fn restore_batch(
		&mut self,
		start_index: u64,
		batch_size: u64,
	) -> Result<(u64, u64, u64), Error> {
		let res = restore_batch(self, start_index, batch_size)?;
		Ok(res)
	}

	fn check_repair(
		&mut self,
		delete_unconfirmed: bool,
		ignore_within: u64,
		address_to_check: Option<String>,
	) -> Result<(), Error> {
		check_repair(self, delete_unconfirmed, ignore_within, address_to_check)?;
		Ok(())
	}

	fn check_repair_batch(
		&mut self,
		delete_unconfirmed: bool,
		ignore_within: u64,
		start_index: u64,
		batch_size: u64,
		address_to_check: Option<String>,
	) -> Result<(u64, u64), Error> {
		let res = check_repair_batch(
			self,
			delete_unconfirmed,
			ignore_within,
			start_index,
			batch_size,
			address_to_check,
		)?;
		Ok(res)
	}
}

/// An atomic batch in which all changes can be committed all at once or
/// discarded on error.
pub struct Batch<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	_store: &'a LMDBBackend<C, K>,
	db: RefCell<Option<wallet_store::Batch<'a>>>,
	/// Keychain
	keychain: Option<K>,
}

#[allow(missing_docs)]
impl<'a, C, K> WalletOutputBatch<K> for Batch<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	fn keychain(&mut self) -> &mut K {
		self.keychain.as_mut().unwrap()
	}

	fn save(&mut self, out: OutputData) -> Result<(), Error> {
		// Save the self output data to the db.
		{
			let key = match out.mmr_index {
				Some(i) => to_key_u64(OUTPUT_PREFIX, &mut out.key_id.to_bytes().to_vec(), i),
				None => to_key(OUTPUT_PREFIX, &mut out.key_id.to_bytes().to_vec()),
			};
			self.db.borrow().as_ref().unwrap().put_ser(&key, &out)?;
		}

		Ok(())
	}

	fn save_payment(&mut self, out: PaymentData) -> Result<(), Error> {
		// Save the payment output data to the db.
		{
			let mut slate_id_commit = out.slate_id.clone().as_bytes().to_vec();
			slate_id_commit.extend_from_slice(&out.commit.clone().as_ref().to_vec());

			let key = to_key(PAYMENT_PREFIX, &mut slate_id_commit);
			self.db.borrow().as_ref().unwrap().put_ser(&key, &out)?;
		}

		Ok(())
	}

	fn delete_payment(&mut self, u: &Uuid) -> Result<(), Error> {
		let key = to_key(PAYMENT_PREFIX, &mut u.as_bytes().to_vec());
		let _ = self.db.borrow().as_ref().unwrap().delete(&key);
		Ok(())
	}

	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error> {
		let key = match mmr_index {
			Some(i) => to_key_u64(OUTPUT_PREFIX, &mut id.to_bytes().to_vec(), *i),
			None => to_key(OUTPUT_PREFIX, &mut id.to_bytes().to_vec()),
		};
		option_to_not_found(
			self.db.borrow().as_ref().unwrap().get_ser(&key),
			&format!("Key ID: {}", id),
		)
		.map_err(|e| e.into())
	}

	fn payment_entries_iter_tx(&self, u: &Uuid) -> Box<dyn Iterator<Item = PaymentData>> {
		let key = to_key(PAYMENT_PREFIX, &mut u.as_bytes().to_vec());
		Box::new(
			self.db
				.borrow()
				.as_ref()
				.unwrap()
				.iter(&key)
				.unwrap()
				.map(|o| o.1),
		)
	}

	fn iter(&self) -> Box<dyn Iterator<Item = OutputData>> {
		Box::new(
			self.db
				.borrow()
				.as_ref()
				.unwrap()
				.iter(&[OUTPUT_PREFIX])
				.unwrap()
				.map(|o| o.1),
		)
	}

	fn delete(&mut self, id: &Identifier, mmr_index: &Option<u64>) -> Result<(), Error> {
		// Delete the output data.
		{
			let key = match mmr_index {
				Some(i) => to_key_u64(OUTPUT_PREFIX, &mut id.to_bytes().to_vec(), *i),
				None => to_key(OUTPUT_PREFIX, &mut id.to_bytes().to_vec()),
			};
			let _ = self.db.borrow().as_ref().unwrap().delete(&key);
		}

		Ok(())
	}

	fn next_tx_log_id(&mut self, parent_key_id: &Identifier) -> Result<u32, Error> {
		let tx_id_key = to_key(TX_LOG_ID_PREFIX, &mut parent_key_id.to_bytes().to_vec());
		let last_tx_log_id = match self.db.borrow().as_ref().unwrap().get_ser(&tx_id_key)? {
			Some(t) => t,
			None => 0,
		};
		self.db
			.borrow()
			.as_ref()
			.unwrap()
			.put_ser(&tx_id_key, &(last_tx_log_id + 1))?;
		Ok(last_tx_log_id)
	}

	fn tx_log_iter(&self) -> Box<dyn Iterator<Item = TxLogEntry>> {
		Box::new(
			self.db
				.borrow()
				.as_ref()
				.unwrap()
				.iter(&[TX_LOG_ENTRY_PREFIX])
				.unwrap()
				.map(|o| o.1),
		)
	}

	fn save_last_confirmed_height(
		&mut self,
		parent_key_id: &Identifier,
		height: u64,
	) -> Result<(), Error> {
		let height_key = to_key(
			CONFIRMED_HEIGHT_PREFIX,
			&mut parent_key_id.to_bytes().to_vec(),
		);
		self.db
			.borrow()
			.as_ref()
			.unwrap()
			.put_ser(&height_key, &height)?;
		Ok(())
	}

	fn get_child_index(&mut self, parent_id: &Identifier) -> Result<u32, Error> {
		let deriv_key = to_key(DERIV_PREFIX, &mut parent_id.to_bytes().to_vec());
		let max_child_index = match self.db.borrow().as_ref().unwrap().get_ser(&deriv_key)? {
			Some(t) => t,
			None => 0,
		};
		Ok(max_child_index)
	}

	fn save_child_index(&mut self, parent_id: &Identifier, child_n: u32) -> Result<(), Error> {
		let deriv_key = to_key(DERIV_PREFIX, &mut parent_id.to_bytes().to_vec());
		self.db
			.borrow()
			.as_ref()
			.unwrap()
			.put_ser(&deriv_key, &child_n)?;
		Ok(())
	}

	fn save_recipient_child_index(&mut self, child_n: u32) -> Result<(), Error> {
		let parent_key_id =
			ExtKeychainPath::new(2, <u32>::max_value(), <u32>::max_value(), 0, 0).to_identifier();
		let deriv_key = to_key(
			RECIPIENT_DERIV_PREFIX,
			&mut parent_key_id.to_bytes().to_vec(),
		);
		self.db
			.borrow()
			.as_ref()
			.unwrap()
			.put_ser(&deriv_key, &child_n)?;
		Ok(())
	}

	fn save_tx_log_entry(
		&mut self,
		tx_in: TxLogEntry,
		parent_id: &Identifier,
	) -> Result<(), Error> {
		let tx_log_key = to_key_u64(
			TX_LOG_ENTRY_PREFIX,
			&mut parent_id.to_bytes().to_vec(),
			tx_in.id as u64,
		);
		self.db
			.borrow()
			.as_ref()
			.unwrap()
			.put_ser(&tx_log_key, &tx_in)?;
		Ok(())
	}

	fn save_acct_path(&mut self, mapping: AcctPathMapping) -> Result<(), Error> {
		let acct_key = to_key(
			ACCOUNT_PATH_MAPPING_PREFIX,
			&mut mapping.label.as_bytes().to_vec(),
		);
		self.db
			.borrow()
			.as_ref()
			.unwrap()
			.put_ser(&acct_key, &mapping)?;
		Ok(())
	}

	fn acct_path_iter(&self) -> Box<dyn Iterator<Item = AcctPathMapping>> {
		Box::new(
			self.db
				.borrow()
				.as_ref()
				.unwrap()
				.iter(&[ACCOUNT_PATH_MAPPING_PREFIX])
				.unwrap()
				.map(|o| o.1),
		)
	}

	fn lock_output(&mut self, out: &mut OutputData) -> Result<(), Error> {
		out.lock();
		self.save(out.clone())
	}

	fn save_private_context(
		&mut self,
		slate_id: &[u8],
		participant_id: usize,
		ctx: &Context,
	) -> Result<(), Error> {
		let ctx_key = to_key_u64(
			PRIVATE_TX_CONTEXT_PREFIX,
			&mut slate_id.to_vec(),
			participant_id as u64,
		);
		let (blind_xor_key, nonce_xor_key) = private_ctx_xor_keys(self.keychain(), slate_id)?;

		let mut s_ctx = ctx.clone();
		for i in 0..SECRET_KEY_SIZE {
			s_ctx.sec_key.0[i] = s_ctx.sec_key.0[i] ^ blind_xor_key[i];
			s_ctx.sec_nonce.0[i] = s_ctx.sec_nonce.0[i] ^ nonce_xor_key[i];
		}

		self.db
			.borrow()
			.as_ref()
			.unwrap()
			.put_ser(&ctx_key, &s_ctx)?;
		Ok(())
	}

	fn delete_private_context(
		&mut self,
		slate_id: &[u8],
		participant_id: usize,
	) -> Result<(), Error> {
		let ctx_key = to_key_u64(
			PRIVATE_TX_CONTEXT_PREFIX,
			&mut slate_id.to_vec(),
			participant_id as u64,
		);
		self.db
			.borrow()
			.as_ref()
			.unwrap()
			.delete(&ctx_key)
			.map_err(|e| e.into())
	}

	fn commit(&self) -> Result<(), Error> {
		let db = self.db.replace(None);
		db.unwrap().commit()?;
		Ok(())
	}
}
