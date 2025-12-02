use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use leansig::serialization::Serializable;
use leansig::signature::{
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8,
    SignatureScheme,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ExportFormat {
    /// Export only SSZ-encoded binary files (`.ssz`)
    Ssz,
    /// Export both SSZ-encoded binaries (`.ssz`) and legacy JSON files
    Both,
}

/// A CLI tool to generate cryptographic keys for hash-based signatures.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate validator key pairs for hash-based signatures
    Generate {
        /// Number of validator keys to generate
        #[arg(long)]
        num_validators: usize,

        /// Log2 of the number of active epochs (e.g., 18 for 2^18 active epochs)
        #[arg(long)]
        log_num_active_epochs: usize,

        /// Directory to save the keys to
        #[arg(long)]
        output_dir: PathBuf,

        /// Export format for keys: `ssz` (binary only) or `both` (SSZ + JSON, legacy)
        #[arg(long, value_enum, default_value_t = ExportFormat::Both)]
        export_format: ExportFormat,

        /// Create a manifest file for validator keys
        #[arg(long, default_value = "true")]
        create_manifest: bool,
    },
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Generate {
            num_validators,
            log_num_active_epochs,
            output_dir,
            export_format,
            create_manifest,
        } => {
            generate_keys(
                num_validators,
                log_num_active_epochs,
                export_format,
                output_dir.clone(),
            )?;
            
            if create_manifest {
                create_validator_manifest(&output_dir, num_validators, log_num_active_epochs)?;
            }
        }
    }

    Ok(())
}

fn generate_keys(
    num_validators: usize,
    log_num_active_epochs: usize,
    export_format: ExportFormat,
    output_dir: PathBuf,
) -> std::io::Result<()> {
    // Create the output directory if it doesn't exist
    fs::create_dir_all(&output_dir)?;

    let activation_duration = 1 << log_num_active_epochs;
    
    println!(
        "Generating {} validator keys with 2^{} active epochs ({} total) in directory: {}\n",
        num_validators,
        log_num_active_epochs,
        activation_duration,
        output_dir.display()
    );

    println!("🔐 Keys will be formatted for validator integration");
    println!("⚠️  Note: Secret keys are large files (~several MB each)\n");

    let mut rng = rand::rng();

    let write_json = matches!(export_format, ExportFormat::Both);

    for i in 0..num_validators {
        let key_prefix = format!("validator_{}", i);
        
        println!("Generating {}...", key_prefix);

        // Generate the key pair
        let (pk, sk) = SIGTopLevelTargetSumLifetime32Dim64Base8::key_gen(
            &mut rng,
            0,
            activation_duration,
        );

        // Serialize the public key to SSZ bytes and write to a binary .ssz file
        let pk_bytes = pk.to_bytes();
        let mut pk_file = File::create(output_dir.join(format!("{}_pk.ssz", key_prefix)))?;
        pk_file.write_all(&pk_bytes)?;

        // Serialize the secret key to SSZ bytes and write to a binary .ssz file
        let sk_bytes = sk.to_bytes();
        let mut sk_file = File::create(output_dir.join(format!("{}_sk.ssz", key_prefix)))?;
        sk_file.write_all(&sk_bytes)?;

        println!("  ✅ {}_pk.ssz", key_prefix);
        println!("  ✅ {}_sk.ssz", key_prefix);

        if write_json {
            // Also export legacy JSON representations for backwards compatibility
            let pk_json =
                serde_json::to_string_pretty(&pk).expect("Failed to serialize public key to JSON");
            let mut pk_json_file =
                File::create(output_dir.join(format!("{}_pk.json", key_prefix)))?;
            pk_json_file.write_all(pk_json.as_bytes())?;

            let sk_json =
                serde_json::to_string_pretty(&sk).expect("Failed to serialize secret key to JSON");
            let mut sk_json_file =
                File::create(output_dir.join(format!("{}_sk.json", key_prefix)))?;
            sk_json_file.write_all(sk_json.as_bytes())?;

            println!("  ⚠️  (legacy) {}_pk.json", key_prefix);
            println!("  ⚠️  (legacy) {}_sk.json", key_prefix);
        }
    }

    println!("\n✅ Successfully generated and saved {} validator key pairs.", num_validators);

    Ok(())
}

/// Convert pubkey SSZ file to hex string
/// Reads the `.ssz` file as raw bytes (already in SSZ/canonical form)
/// and returns a hex string with "0x" prefix.
fn pubkey_ssz_to_hex(pk_file_path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    // Read SSZ bytes from file
    let pubkey_bytes = fs::read(pk_file_path)?;

    // Convert bytes to hex string with "0x" prefix
    let hex_string = format!("0x{}", hex::encode(&pubkey_bytes));

    Ok(hex_string)
}

fn create_validator_manifest(
    output_dir: &PathBuf,
    num_validators: usize,
    log_num_active_epochs: usize,
) -> std::io::Result<()> {
    println!("\n📄 Creating validator manifest...");
    
    let manifest_path = output_dir.join("validator-keys-manifest.yaml");
    let mut manifest_file = File::create(&manifest_path)?;
    
    // Write YAML manifest
    writeln!(manifest_file, "# Hash-Signature Validator Keys Manifest")?;
    writeln!(manifest_file, "# Generated by hash-sig-cli\n")?;
    writeln!(manifest_file, "key_scheme: SIGTopLevelTargetSumLifetime32Dim64Base8")?;
    writeln!(manifest_file, "hash_function: Poseidon2")?;
    writeln!(manifest_file, "encoding: TargetSum")?;
    writeln!(manifest_file, "lifetime: {}", 1u64 << 32)?;
    writeln!(manifest_file, "log_num_active_epochs: {}", log_num_active_epochs)?;
    writeln!(manifest_file, "num_active_epochs: {}", 1 << log_num_active_epochs)?;
    writeln!(manifest_file, "num_validators: {}\n", num_validators)?;
    writeln!(manifest_file, "validators:")?;
    
    for i in 0..num_validators {
        // Read the pubkey SSZ file and convert to hex
        let pk_file_path = output_dir.join(format!("validator_{}_pk.ssz", i));
        let pubkey_hex = pubkey_ssz_to_hex(&pk_file_path)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to convert pubkey to hex for validator {}: {}", i, e)
            ))?;
        
        writeln!(manifest_file, "  - index: {}", i)?;
        writeln!(manifest_file, "    pubkey_hex: {}", pubkey_hex)?;
        writeln!(manifest_file, "    privkey_file: validator_{}_sk.ssz", i)?;
        if i < num_validators - 1 {
            writeln!(manifest_file)?;
        }
    }
    
    println!("  ✅ validator-keys-manifest.yaml");
    println!("\n📋 Manifest created successfully at: {}", manifest_path.display());
    
    Ok(())
}

