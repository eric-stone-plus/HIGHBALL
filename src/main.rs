//! HIGHBALL shipped control-plane CLI.

use clap::{Parser, Subcommand};
use highball::auth::{consume, default_ledger};
use highball::contracts::{action_binding_sha256, canonical_action_binding_bytes};
use highball::execution::{
    build_report, load_report, validate_recomputable, validate_report,
};
use highball::jsonutil::load_object;
use highball::measure::{combine, load_traces, measure_trace};
use highball::packet::{build_packet, load_packet, validate_packet};
use highball::print_json;
use highball::product::{
    active_quinte_binary, is_canonical_uuid_v7, load_quinte_host_receipt, summarize,
    trusted_runs_root,
};
use highball::route::{route_request, validate_request};
use highball::trace::validate_file;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "highball", about = "HIGHBALL control plane", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a fail-closed Action Packet 2.0 (`request trace`).
    #[command(name = "build-action-packet")]
    BuildActionPacket {
        route_request: PathBuf,
        trace_file: PathBuf,
        #[arg(long = "quinte-result", action = clap::ArgAction::Append)]
        quinte_result: Vec<PathBuf>,
        #[arg(long = "quinte-receipt", action = clap::ArgAction::Append)]
        quinte_receipt: Vec<PathBuf>,
        #[arg(long)]
        authorization: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Validate an Action Packet and recompute derived fields.
    #[command(name = "validate-action-packet")]
    ValidateActionPacket {
        packet_file: PathBuf,
        #[arg(long = "base-dir")]
        base_dir: Option<PathBuf>,
    },
    /// Route a residual-bearing action.
    #[command(name = "route-residual-action")]
    RouteResidualAction {
        request_file: PathBuf,
        #[arg(long)]
        pretty: bool,
    },
    /// Consume a user authorization exactly once.
    #[command(name = "consume-authorization")]
    ConsumeAuthorization {
        route_request: PathBuf,
        authorization: PathBuf,
        #[arg(long = "expected-sha256")]
        expected_sha256: Option<String>,
        #[arg(long, hide = true)]
        ledger: Option<PathBuf>,
    },
    /// Measure residual-trace quality metrics.
    #[command(name = "measure-residual-trace")]
    MeasureResidualTrace {
        trace_file: PathBuf,
        #[arg(long)]
        pretty: bool,
    },
    /// Validate residual-trace 1.1 artifacts.
    #[command(name = "validate-residual-trace")]
    ValidateResidualTrace { verdict_file: PathBuf },
    /// Build a route execution report from Action Packets.
    #[command(name = "build-route-execution-report")]
    BuildRouteExecutionReport {
        action_packets: Vec<PathBuf>,
        #[arg(long = "route-group")]
        route_group: Option<String>,
        #[arg(long)]
        pretty: bool,
    },
    /// Validate a route execution report.
    #[command(name = "validate-route-execution-report")]
    ValidateRouteExecutionReport { report_file: PathBuf },
    /// Print canonical action-binding bytes and digest (test/operator probe).
    #[command(name = "action-binding")]
    ActionBinding { request_file: PathBuf },
    /// Resolve QUINTE runtime pins from the environment.
    #[command(name = "resolve-runtime")]
    ResolveRuntime,
    /// Check whether a string is a canonical UUIDv7.
    #[command(name = "uuid-v7")]
    UuidV7 { value: String },
    /// Load a QUINTE host receipt against a route request.
    #[command(name = "load-host-receipt")]
    LoadHostReceipt {
        receipt: PathBuf,
        request_file: PathBuf,
    },
    /// Summarize a direct QUINTE result.json against a route request.
    #[command(name = "summarize-quinte")]
    SummarizeQuinte {
        result: PathBuf,
        request_file: PathBuf,
        #[arg(long = "verify-cli")]
        verify_cli: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::BuildActionPacket {
            route_request,
            trace_file,
            quinte_result,
            quinte_receipt,
            authorization,
            pretty,
        } => match build_packet(
            &route_request,
            &trace_file,
            &quinte_result,
            authorization.as_deref(),
            &quinte_receipt,
        ) {
            Ok(packet) => {
                print_json(&packet, pretty);
                if packet["action_decision"] == "pass" {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(e) => {
                eprintln!("[HIGHBALL] ERROR: {e}");
                ExitCode::from(2)
            }
        },
        Commands::ValidateActionPacket {
            packet_file,
            base_dir,
        } => match load_packet(&packet_file) {
            Ok(packet) => {
                let base = base_dir
                    .map(|p| p)
                    .unwrap_or_else(|| packet_file.parent().unwrap_or(std::path::Path::new(".")).to_path_buf());
                let errors = validate_packet(&packet, Some(&base));
                if !errors.is_empty() {
                    for e in errors {
                        eprintln!("[HIGHBALL] ERROR: {e}");
                    }
                    return ExitCode::from(2);
                }
                if packet["action_decision"] != "pass" {
                    eprintln!(
                        "[HIGHBALL] Action Packet valid; action decision is {} (non-authorizing)",
                        packet["action_decision"]
                    );
                    ExitCode::from(1)
                } else {
                    println!(
                        "[HIGHBALL] Action Packet valid; action decision is {}",
                        packet["action_decision"]
                    );
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("[HIGHBALL] ERROR: {e}");
                ExitCode::from(2)
            }
        },
        Commands::RouteResidualAction {
            request_file,
            pretty,
        } => match load_object(&request_file) {
            Ok(request) => {
                let errors = validate_request(&request);
                if !errors.is_empty() {
                    for e in errors {
                        eprintln!("[HIGHBALL] ERROR: {e}");
                    }
                    return ExitCode::from(2);
                }
                print_json(&route_request(&request), pretty);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[HIGHBALL] ERROR: cannot read routing request: {e}");
                ExitCode::from(2)
            }
        },
        Commands::ConsumeAuthorization {
            route_request,
            authorization,
            expected_sha256,
            ledger,
        } => {
            let request = match load_object(&route_request) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[AUTHORIZATION] ERROR: {e}");
                    return ExitCode::from(2);
                }
            };
            let raw = match std::fs::read(&authorization) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[AUTHORIZATION] ERROR: {e}");
                    return ExitCode::from(2);
                }
            };
            let testing = std::env::var("HIGHBALL_TESTING").ok().as_deref() == Some("1");
            let ledger_path = if testing {
                ledger.unwrap_or_else(default_ledger)
            } else {
                default_ledger()
            };
            match consume(&request, &raw, expected_sha256.as_deref(), &ledger_path) {
                Ok(claim) => {
                    println!("[AUTHORIZATION] authorization consumed: {}", claim.display());
                    ExitCode::SUCCESS
                }
                Err(e) if e == "ALREADY_CONSUMED" => {
                    eprintln!("[AUTHORIZATION] BLOCK: authorization was already consumed");
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("[AUTHORIZATION] ERROR: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::MeasureResidualTrace { trace_file, pretty } => match load_traces(&trace_file) {
            Ok(traces) => {
                let measured: Vec<_> = traces.iter().map(measure_trace).collect();
                print_json(&combine(&measured), pretty);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[HIGHBALL] ERROR: {e}");
                ExitCode::from(2)
            }
        },
        Commands::ValidateResidualTrace { verdict_file } => match validate_file(&verdict_file) {
            Ok((findings, _)) => {
                for f in &findings {
                    eprintln!("[Protected-Write Guard] {f}");
                }
                if findings.iter().any(|f| f.severity == "ERROR") {
                    ExitCode::from(2)
                } else if findings.iter().any(|f| f.severity == "BLOCK") {
                    ExitCode::from(1)
                } else {
                    println!("[Protected-Write Guard] residual closure ledger verified");
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("[Protected-Write Guard] ERROR: {e}");
                ExitCode::from(2)
            }
        },
        Commands::BuildRouteExecutionReport {
            action_packets,
            route_group,
            pretty,
        } => {
            let missing: Vec<_> = action_packets.iter().filter(|p| !p.exists()).collect();
            if !missing.is_empty() {
                for p in missing {
                    eprintln!("[HIGHBALL] ERROR: action packet does not exist: {}", p.display());
                }
                return ExitCode::from(2);
            }
            let refs: Vec<String> = action_packets
                .iter()
                .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()).display().to_string())
                .collect();
            match build_report(&refs, None, route_group.as_deref()) {
                Ok(report) => {
                    print_json(&report, pretty);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("[HIGHBALL] ERROR: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::ValidateRouteExecutionReport { report_file } => {
            match load_report(&report_file) {
                Ok(report) => {
                    let mut errors = validate_report(&report);
                    if errors.is_empty() {
                        errors.extend(validate_recomputable(&report_file, &report));
                    }
                    if !errors.is_empty() {
                        for e in errors {
                            eprintln!("[HIGHBALL] ERROR: {e}");
                        }
                        return ExitCode::from(2);
                    }
                    let gate = report["execution_gate"].as_str().unwrap_or("");
                    if matches!(gate, "reroute" | "block") {
                        eprintln!("[HIGHBALL] route execution report valid; execution gate is {gate}");
                        ExitCode::from(1)
                    } else {
                        println!("[HIGHBALL] route execution report valid; execution gate is {gate}");
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("[HIGHBALL] ERROR: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::ActionBinding { request_file } => match load_object(&request_file) {
            Ok(req) => {
                let bytes = canonical_action_binding_bytes(&req);
                println!("{}", String::from_utf8_lossy(&bytes));
                println!("{}", action_binding_sha256(&req));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[HIGHBALL] ERROR: {e}");
                ExitCode::from(2)
            }
        },
        Commands::ResolveRuntime => match active_quinte_binary() {
            Ok(bin) => {
                print_json(
                    &json!({
                        "trusted_runs_root": trusted_runs_root().display().to_string(),
                        "active_quinte_binary": bin.map(|p| p.display().to_string()),
                    }),
                    true,
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[HIGHBALL] ERROR: {e}");
                ExitCode::from(2)
            }
        },
        Commands::UuidV7 { value } => {
            if is_canonical_uuid_v7(&value) {
                println!("true");
                ExitCode::SUCCESS
            } else {
                println!("false");
                ExitCode::from(1)
            }
        }
        Commands::LoadHostReceipt {
            receipt,
            request_file,
        } => {
            let request = match load_object(&request_file) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[HIGHBALL] ERROR: {e}");
                    return ExitCode::from(2);
                }
            };
            let (summary, errors) =
                load_quinte_host_receipt(&receipt.display().to_string(), &request, None);
            print_json(&json!({"summary": summary, "errors": errors}), true);
            if summary.is_some() && errors.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Commands::SummarizeQuinte {
            result,
            request_file,
            verify_cli,
        } => {
            let request = match load_object(&request_file) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[HIGHBALL] ERROR: {e}");
                    return ExitCode::from(2);
                }
            };
            let (summary, errors) =
                summarize(&result.display().to_string(), &request, None, verify_cli);
            print_json(&json!({"summary": summary, "errors": errors}), true);
            if summary.is_some() && errors.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
    }
}
