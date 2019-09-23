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

//! Concrete implementations of types found in libwallet, organised this
//! way mostly to avoid any circular dependencies of any kind
//! Functions in this crate should not use the wallet api crate directly

use blake2_rfc as blake2;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
use failure;

use crate::core::global;
use gotts_wallet_libwallet as libwallet;
use gotts_wallet_util::gotts_api as api;
use gotts_wallet_util::gotts_chain as chain;
use gotts_wallet_util::gotts_core as core;
use gotts_wallet_util::gotts_keychain as keychain;
use gotts_wallet_util::gotts_store as store;
use gotts_wallet_util::gotts_util as util;
extern crate gotts_wallet_config as config;

mod adapters;
mod backends;
mod error;
mod node_clients;
mod seed;
pub mod test_framework;

pub use crate::adapters::{
	FileWalletCommAdapter, HTTPWalletCommAdapter, KeybaseWalletCommAdapter, NullWalletCommAdapter,
	WalletCommAdapter,
};
pub use crate::backends::{wallet_db_exists, LMDBBackend};
pub use crate::error::{Error, ErrorKind};
pub use crate::node_clients::HTTPNodeClient;
pub use crate::seed::{EncryptedWalletSeed, WalletSeed, SEED_FILE};

use crate::util::Mutex;
use std::sync::Arc;

use libwallet::{NodeClient, WalletBackend, WalletInst};

/// Helper to create an instance of the LMDB wallet
pub fn instantiate_wallet(
	wallet_config: config::WalletConfig,
	node_client: impl NodeClient + 'static,
	passphrase: &str,
	account: &str,
) -> Result<Arc<Mutex<dyn WalletInst<impl NodeClient, keychain::ExtKeychain>>>, Error> {
	// Set Chain Type
	let chain_type = wallet_config.chain_type.clone();
	if let Some(chain_type) = chain_type {
		global::set_mining_mode(chain_type);
	}

	// First test decryption, so we can abort early if we have the wrong password
	let _ = WalletSeed::from_file(wallet_config.data_file_dir.as_str(), passphrase)?;
	let mut db_wallet = LMDBBackend::new(wallet_config.clone(), passphrase, node_client)?;
	db_wallet.set_parent_key_id_by_name(account)?;
	info!("A Wallet instance instantiated");
	Ok(Arc::new(Mutex::new(db_wallet)))
}
