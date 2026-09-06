use molterra_security::{corpus, dossier, findings, run_all, Family, Mode, Verdict};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let write = args.iter().any(|a| a == "--write");
    let list = args.iter().any(|a| a == "--list");

    let attacks = corpus::all();
    if list {
        println!(
            "{:<9} {:<14} {:<8} {:<8} technique",
            "id", "family", "shipped", "hardened"
        );
        for a in &attacks {
            let s = a.execute(Mode::Shipped);
            let h = a.execute(Mode::Hardened);
            let flag = if s != a.shipped || h != a.hardened {
                " DRIFT"
            } else {
                ""
            };
            println!(
                "{:<9} {:<14} {:<8} {:<8} {}{flag}",
                a.id,
                a.family.to_string(),
                s.to_string(),
                h.to_string(),
                a.technique
            );
        }
        println!();
    }

    let report = run_all();
    let register = findings::derive(&attacks);

    println!("molterra red team — {} attacks", report.total);
    println!(
        "  shipped:  {:>4} blocked  {:>4} landed",
        report.shipped_blocked, report.shipped_landed
    );
    println!(
        "  hardened: {:>4} blocked  {:>4} landed",
        report.hardened_blocked, report.hardened_landed
    );
    println!();
    for f in &report.by_family {
        println!(
            "  {:<14} {:>4} attacks  shipped landed {:>4}  hardened landed {:>4}",
            f.family.to_string(),
            f.total,
            f.shipped_landed,
            f.hardened_landed
        );
    }
    println!();
    let open = register
        .iter()
        .filter(|f| f.status == findings::Status::Open)
        .count();
    println!(
        "  {} findings: {} closed by the hardened layer, {} open",
        register.len(),
        register.len() - open,
        open
    );
    for f in &register {
        println!(
            "    {:<9} {:<8} {:<20} {:<3} {}",
            f.id,
            f.severity.to_string(),
            f.status.label(),
            f.witnesses.len(),
            f.technique
        );
    }

    if write {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        std::fs::write(
            dir.join("FINDINGS.md"),
            findings::render(&register, &report),
        )
        .expect("write FINDINGS.md");
        let json = serde_json::to_string_pretty(&register).expect("serialize findings");
        std::fs::write(dir.join("findings.json"), json).expect("write findings.json");

        let entries = dossier::entries(&attacks, &report);
        std::fs::write(
            dir.join("ATTACKS.md"),
            dossier::render_index(&entries, &report),
        )
        .expect("write ATTACKS.md");
        let pages = dir.join("attacks");
        std::fs::create_dir_all(&pages).expect("create attacks/");
        for family in Family::ALL {
            std::fs::write(
                pages.join(format!("{family}.md")),
                dossier::render_family(family, &entries),
            )
            .expect("write attacks/<family>.md");
        }
        let json = serde_json::to_string_pretty(&entries).expect("serialize dossier");
        std::fs::write(dir.join("attacks.json"), json).expect("write attacks.json");
        println!("\n  wrote FINDINGS.md, findings.json, ATTACKS.md, attacks/*.md, attacks.json");
    }

    if !report.drift.is_empty() {
        println!("\n  DRIFT — the register and the code disagree:");
        for d in &report.drift {
            let a = attacks
                .iter()
                .find(|a| a.id == d.id)
                .expect("id from this run");
            let direction = match (d.recorded, d.observed) {
                (Verdict::Blocked, Verdict::Landed) => "REGRESSION",
                (Verdict::Landed, Verdict::Blocked) => "register overstates the hole",
                _ => "?",
            };
            println!(
                "    {} [{}] recorded {} observed {} — {} — {}",
                d.id, d.mode, d.recorded, d.observed, direction, a.technique
            );
        }
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
