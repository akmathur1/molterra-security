use super::normalize;
use molterra_capture::compose::{verify_composition, ComposeInput};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Death {
    pub check: &'static str,
}

pub fn verify(sentence: &str, citations: &[String], input: &ComposeInput<'_>) -> Result<(), Death> {
    if sentence.chars().any(normalize::is_invisible) {
        return Err(Death {
            check: "invisible_bytes",
        });
    }
    if normalize::injection_line(sentence) {
        return Err(Death {
            check: "model_control_language",
        });
    }
    verify_composition(sentence, citations, input).map_err(|d| Death { check: d.check })
}
