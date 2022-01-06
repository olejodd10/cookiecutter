use clap::Parser;
use std::path::PathBuf;
use cookiecutter::firefox_cookies;

/// Program to collect Firefox cookies
#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// Path to Firefox profile folder
    profile_path: PathBuf,
    /// Domain substring to filter cookies
    #[clap(short, long)]
    domain: Option<String>,
}

fn main() {
    let args = Args::parse();
    let profile_path = &args.profile_path;
    let domain = args.domain.as_ref().map(|s| &s[..]);
    println!("{}", firefox_cookies(profile_path, domain));
}