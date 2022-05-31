pub mod assign;
pub mod circuits;
#[cfg(test)]
pub mod test_utils;
pub mod trace;

use lazy_static::lazy_static;
use std::{collections::BTreeSet, sync::RwLock};

lazy_static! {
    static ref LEAKED: RwLock<BTreeSet<&'static str>> = RwLock::new(BTreeSet::new());
}

// TODO add support for naming columns in halo2, so I can make better use of this.
pub fn leak_once<S: Into<String> + AsRef<str> + Ord>(s: S) -> &'static str {
    let l = {
        let leaked = LEAKED.read().unwrap();
        leaked.get(s.as_ref()).map(|s| *s)
    };

    if let Some(l) = l {
        l
    } else {
        let mut leaked = LEAKED.write().unwrap();
        let s = Box::leak(s.into().into_boxed_str());
        leaked.insert(s);
        s
    }
}
