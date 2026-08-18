//! Compatibility entry: same argv as the former `bin/build-action-packet.py`.

use clap::Parser;
use highball::packet::build_packet;
use highball::print_json;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "build-action-packet", about = "Build a fail-closed HIGHBALL Action Packet")]
struct Args {
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
}

fn main() -> ExitCode {
    let args = Args::parse();
    match build_packet(
        &args.route_request,
        &args.trace_file,
        &args.quinte_result,
        args.authorization.as_deref(),
        &args.quinte_receipt,
    ) {
        Ok(packet) => {
            print_json(&packet, args.pretty);
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
    }
}
