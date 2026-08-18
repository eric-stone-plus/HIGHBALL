//! HIGHBALL control plane: route, packet, product bind, authorize.

pub mod auth;
pub mod contracts;
pub mod execution;
pub mod jsonutil;
pub mod measure;
pub mod packet;
pub mod product;
pub mod route;
pub mod trace;

use crate::jsonutil::dump_sorted;
use serde_json::Value;

pub fn print_json(value: &Value, pretty: bool) {
    if pretty {
        println!("{}", serde_json::to_string_pretty(value).unwrap());
    } else {
        println!("{}", dump_sorted(value));
    }
}
