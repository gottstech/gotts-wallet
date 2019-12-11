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

//! Wallet key management functions
use crate::error::{Error, ErrorKind};
use crate::gotts_keychain::{ChildNumber, ExtKeychain, Identifier, Keychain};
use crate::types::{AcctPathMapping, NodeClient, WalletBackend};

/// Get next available key in the wallet for a given parent
pub fn next_available_key<T: ?Sized, C, K>(wallet: &mut T) -> Result<Identifier, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let child = wallet.next_child()?;
	Ok(child)
}

/// Retrieve an existing key from a wallet
pub fn retrieve_existing_key<T: ?Sized, C, K>(
	wallet: &T,
	key_id: Identifier,
	mmr_index: Option<u64>,
) -> Result<(Identifier, u32), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let existing = wallet.get(&key_id, &mmr_index)?;
	let key_id = existing.key_id.clone();
	let derivation = existing.n_child;
	Ok((key_id, derivation))
}

/// Returns a list of account to BIP32 path mappings
pub fn accounts<T: ?Sized, C, K>(wallet: &mut T) -> Result<Vec<AcctPathMapping>, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	Ok(wallet.acct_path_iter().collect())
}

/// Adds an new parent account path with a given label
pub fn new_acct<T: ?Sized, C, K>(wallet: &mut T, label: &str) -> Result<Identifier, Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let label = label.to_owned();
	if let Some(_) = wallet.acct_path_iter().find(|l| l.label == label) {
		return Err(ErrorKind::AccountLabelAlreadyExists(label.clone()).into());
	}

	// We're always using paths at m/k/0 for parent keys for output derivations
	// so find the highest of those, then increment (to conform with external/internal
	// derivation chains in BIP32 spec)

	let highest_entry = wallet.acct_path_iter().max_by(|a, b| {
		a.path.to_path().path[0]
			.index()
			.cmp(&b.path.to_path().path[0].index())
	});

	let new_path = {
		if let Some(e) = highest_entry {
			let mut p = e.path.to_path();
			p.path[0] = p.path[0].next();

			p.to_identifier()
		} else {
			// Use "m/0/0" non-hardened derivation as the default wallet account.
			ExtKeychain::derive_key_id(
				2,
				u32::from(ChildNumber::from_normal_idx(0)),
				u32::from(ChildNumber::from_normal_idx(0)),
				0,
				0,
			)
		}
	};

	if let Some(_) = wallet.acct_path_iter().find(|l| l.path == new_path) {
		return Err(ErrorKind::AccountPathAlreadyExists(new_path.to_string()).into());
	}

	let mut batch = wallet.batch()?;
	batch.save_acct_path(AcctPathMapping {
		label: label.to_owned(),
		path: new_path.clone(),
	})?;
	batch.commit()?;
	Ok(new_path)
}

/// Adds an new parent account path with a given label
pub fn new_acct_path<T: ?Sized, C, K>(
	wallet: &mut T,
	label: &str,
	path: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let label = label.to_owned();
	if let Some(_) = wallet
		.acct_path_iter()
		.find(|l| l.label == label || l.path == *path)
	{
		return Err(ErrorKind::AccountAlreadyExists.into());
	}

	let mut batch = wallet.batch()?;
	batch.save_acct_path(AcctPathMapping {
		label,
		path: path.clone(),
	})?;
	batch.commit()?;
	Ok(())
}

/// Adds/sets a particular account path with a given label
pub fn set_acct_path<T: ?Sized, C, K>(
	wallet: &mut T,
	label: &str,
	path: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	let mut batch = wallet.batch()?;
	batch.save_acct_path(AcctPathMapping {
		label: label.to_owned(),
		path: path.clone(),
	})?;
	batch.commit()?;
	Ok(())
}
