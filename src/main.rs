mod trigger;
mod rombuster;
mod cli;

fn main() {
    let cli = cli::RomBusterCLI::new();
    cli.start();
}
