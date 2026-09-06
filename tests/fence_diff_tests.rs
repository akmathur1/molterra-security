use molterra_capture::fence::{self, DiffClass, FenceDiff, Mode};
use molterra_security::{corpus, Payload};
use std::collections::BTreeMap;

fn kernel_or_skip() -> bool {
    if fence::kernel_linked() {
        return true;
    }
    assert!(
        std::env::var_os("MOLTERRA_FENCE_REQUIRE_KERNEL").is_none(),
        "MOLTERRA_FENCE_REQUIRE_KERNEL is set but the kernel is not linked: \
         build capture with MOLTERRA_FENCE_LIB pointing at fence/lib"
    );
    eprintln!("fence_diff_tests: kernel not linked, nothing to compare");
    false
}

#[test]
fn the_kernel_never_lets_through_an_attack_rust_blocks() {
    if !kernel_or_skip() {
        return;
    }
    let attacks = corpus::all();
    let mut compared = 0usize;
    let mut histogram: BTreeMap<(&'static str, DiffClass, bool), (usize, String)> = BTreeMap::new();
    let mut unsafe_ascii: Vec<(String, FenceDiff)> = Vec::new();
    let mut note = |id: &str, diff: Option<FenceDiff>| {
        let Some(d) = diff else { return };
        let e = histogram
            .entry((d.function, d.class, d.ascii))
            .or_insert_with(|| (0, id.to_string()));
        e.0 += 1;
        if d.class == DiffClass::Unsafe && d.ascii {
            unsafe_ascii.push((id.to_string(), d));
        }
    };
    for a in &attacks {
        match &a.payload {
            Payload::Text { text, .. } => {
                note(&a.id, fence::injection_line_in(Mode::Shadow, text).diff);
                note(&a.id, fence::sanitize_excerpt_in(Mode::Shadow, text).diff);
                note(&a.id, fence::sanitize_span_in(Mode::Shadow, text).diff);
                note(&a.id, fence::source_label_in(Mode::Shadow, text).diff);
                compared += 4;
            }
            Payload::Composition(case) => {
                let input = corpus::composition::input();
                note(
                    &a.id,
                    fence::verify_composition_in(
                        Mode::Shadow,
                        &case.sentence,
                        &case.citations,
                        &input,
                    )
                    .diff,
                );
                compared += 1;
            }
            Payload::Vault(_) | Payload::Credential(_) => {}
        }
    }
    assert!(
        compared > 900,
        "the corpus shrank: {compared} fence comparisons"
    );
    eprintln!(
        "fence_diff_tests: {compared} comparisons over {} attacks",
        attacks.len()
    );
    for ((function, class, ascii), (n, example)) in &histogram {
        eprintln!(
            "  {function:<20} {:<13} {:<9} {n:>5}  e.g. {example}",
            format!("{class:?}").to_lowercase(),
            if *ascii { "ascii" } else { "non-ascii" }
        );
    }
    assert!(
        unsafe_ascii.is_empty(),
        "{} ASCII attacks the kernel lets through and Rust blocks:\n{}",
        unsafe_ascii.len(),
        unsafe_ascii
            .iter()
            .map(|(id, d)| format!("  {id} {} rust={} spark={}", d.function, d.rust, d.spark))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
