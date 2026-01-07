use clap::Parser;
use regex::Regex;
use serde::Serialize;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the log file to analyze
    #[arg(short, long)]
    file: Option<PathBuf>,
}

#[derive(Serialize)]
struct Threat {
    line_number: usize,
    threat_type: String,
    content: String,
    details: String,
}

#[derive(Serialize)]
struct Report {
    file: String,
    threats: Vec<Threat>,
    total_lines: usize,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Define Regex Patterns
    let sqli_pattern = Regex::new(r"(?i)(UNION\s+SELECT|SLEEP\(|OR\s+'1'='1|--|;\s*DROP\s+TABLE)")?;
    let xss_pattern = Regex::new(r"(?i)(<script>|javascript:|onerror=|onload=)")?;
    let lfi_pattern = Regex::new(r"(?i)(\.\./\.\./|/etc/passwd|c:\\windows\\system32)")?;

    let reader: Box<dyn BufRead> = match cli.file.clone() {
        Some(path) => Box::new(BufReader::new(File::open(path)?)),
        None => Box::new(BufReader::new(io::stdin())),
    };

    let mut threats = Vec::new();
    let mut line_count = 0;

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        line_count += 1;
        let line_num = index + 1;

        if sqli_pattern.is_match(&line) {
            threats.push(Threat {
                line_number: line_num,
                threat_type: "SQL Injection".to_string(),
                content: line.trim().to_string(),
                details: "Detected common SQLi signature".to_string(),
            });
            continue;
        }

        if xss_pattern.is_match(&line) {
            threats.push(Threat {
                line_number: line_num,
                threat_type: "XSS".to_string(),
                content: line.trim().to_string(),
                details: "Detected Cross-Site Scripting tag".to_string(),
            });
            continue;
        }

        if lfi_pattern.is_match(&line) {
            threats.push(Threat {
                line_number: line_num,
                threat_type: "Path Traversal".to_string(),
                content: line.trim().to_string(),
                details: "Detected LFI/LFI directory traversal".to_string(),
            });
        }
    }

    let report = Report {
        file: cli.file.map(|p| p.to_string_lossy().to_string()).unwrap_or("stdin".to_string()),
        threats,
        total_lines: line_count,
    };

    println!("{}", serde_json::to_string(&report)?);

    Ok(())
}
