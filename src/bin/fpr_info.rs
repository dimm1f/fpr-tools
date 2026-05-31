use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use fpr_tools::fvdl_reader::Fvdl;
use zip::ZipArchive;
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    /// Path to FPR file
    fpr_path: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show FPR statistics
    Info,
    /// Show found issues
    Issues,
}

fn print_fpr_info(fpr: &mut ZipArchive<File>) -> anyhow::Result<()> {
    let mut version = String::new();
    BufReader::new(fpr.by_name("VERSION")?).read_line(&mut version)?;
    println!("FPR version: {}", version.trim_end());

    let fvdl = Fvdl::from_zip_entry(fpr.by_name("audit.fvdl")?)?;
    let meta = fvdl.meta()?;

    println!("FVDL version: {}", meta.version);
    println!("UUID: {}", meta.uuid);

    if let Some(build) = &meta.build {
        if let Some(id) = &build.id {
            println!("Build ID: {}", id);
        }
        if let Some(n) = build.number_files {
            println!("Files scanned: {}", n);
        }
        if let Some(duration) = build.build_duration {
            println!("Build duration: {}s", duration);
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let fpr = File::open(args.fpr_path)?;

    let mut fpr = ZipArchive::new(fpr)?;

    match args.command {
        Command::Info => print_fpr_info(&mut fpr),
        Command::Issues => todo!(),
    }
}
