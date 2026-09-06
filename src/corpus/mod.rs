pub mod composition;
pub mod credential;
pub mod evasion;
pub mod injection;
pub mod steganography;
pub mod vault;

use crate::Attack;

pub fn all() -> Vec<Attack> {
    let mut out = Vec::new();
    out.extend(injection::attacks());
    out.extend(steganography::attacks());
    out.extend(composition::attacks());
    out.extend(vault::attacks());
    out.extend(credential::attacks());
    let mut counters: Vec<(crate::Family, u32)> =
        crate::Family::ALL.iter().map(|f| (*f, 0)).collect();
    for a in &mut out {
        let slot = counters
            .iter_mut()
            .find(|(f, _)| *f == a.family)
            .expect("every family is pre-seeded");
        slot.1 += 1;
        a.id = format!("{}-{:04}", a.family.prefix(), slot.1);
    }
    out
}
