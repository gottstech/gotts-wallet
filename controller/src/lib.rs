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

//! Library module for the main wallet functionalities provided by Gotts.

#[macro_use]
extern crate prettytable;

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate chrono;

use failure;
use gotts_wallet_api as apiwallet;
use gotts_wallet_config as config;
use gotts_wallet_impls as impls;
use gotts_wallet_libwallet as libwallet;
use gotts_wallet_util::gotts_api as api;
use gotts_wallet_util::gotts_core as core;
use gotts_wallet_util::gotts_keychain as keychain;
use gotts_wallet_util::gotts_util as util;

pub mod command;
pub mod controller;
pub mod display;
mod error;

pub use crate::error::{Error, ErrorKind};
pub use chrono::NaiveDateTime as DateTime;
