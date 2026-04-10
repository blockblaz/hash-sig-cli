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

        /// Use distributed format: name validators with first-3 last-3 bytes of public key
        #[arg(long)]
        distributed: bool,
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
            distributed,
        } => {
            let validator_info = generate_keys(
                num_validators,
                log_num_active_epochs,
                export_format,
                output_dir.clone(),
                distributed,
            )?;
            
            if create_manifest {
                create_validator_manifest(
                    &output_dir,
                    num_validators,
                    log_num_active_epochs,
                    distributed,
                    &validator_info,
                )?;
            }
        }
    }

    Ok(())
}

struct ValidatorInfo {
    proposer_key_pubkey_hex: String,
    proposer_key_privkey_file: String,
    attester_key_pubkey_hex: String,
    attester_key_privkey_file: String,
}

fn generate_keys(
    num_validators: usize,
    log_num_active_epochs: usize,
    export_format: ExportFormat,
    output_dir: PathBuf,
    distributed: bool,
) -> std::io::Result<Vec<ValidatorInfo>> {
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
    let mut validator_info_list = Vec::new();

    for i in 0..num_validators {
        // Generate proposer key pair
        let (proposer_pk, proposer_sk) = SIGTopLevelTargetSumLifetime32Dim64Base8::key_gen(
            &mut rng,
            0,
            activation_duration,
        );

        // Generate attester key pair
        let (attester_pk, attester_sk) = SIGTopLevelTargetSumLifetime32Dim64Base8::key_gen(
            &mut rng,
            0,
            activation_duration,
        );

        // Serialize proposer public key to SSZ bytes (used for prefix derivation)
        let proposer_pk_bytes = proposer_pk.to_bytes();

        // Determine key prefix based on format (always derived from proposer key)
        let key_prefix = if distributed {
            if proposer_pk_bytes.len() < 3 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Public key bytes too short to extract first-3 last-3 bytes"
                ));
            }
            let first_3 = &proposer_pk_bytes[0..3];
            let last_3 = &proposer_pk_bytes[proposer_pk_bytes.len() - 3..];
            format!("validator-{}-{}", hex::encode(first_3), hex::encode(last_3))
        } else {
            format!("validator_{}", i)
        };

        println!("Generating {}...", key_prefix);

        // --- Proposer key files ---
        let mut proposer_pk_file = File::create(output_dir.join(format!("{}_proposer_key_pk.ssz", key_prefix)))?;
        proposer_pk_file.write_all(&proposer_pk_bytes)?;

        let proposer_sk_bytes = proposer_sk.to_bytes();
        let mut proposer_sk_file = File::create(output_dir.join(format!("{}_proposer_key_sk.ssz", key_prefix)))?;
        proposer_sk_file.write_all(&proposer_sk_bytes)?;

        println!("  ✅ {}_proposer_key_pk.ssz", key_prefix);
        println!("  ✅ {}_proposer_key_sk.ssz", key_prefix);

        // --- Attester key files ---
        let attester_pk_bytes = attester_pk.to_bytes();
        let mut attester_pk_file = File::create(output_dir.join(format!("{}_attester_key_pk.ssz", key_prefix)))?;
        attester_pk_file.write_all(&attester_pk_bytes)?;

        let attester_sk_bytes = attester_sk.to_bytes();
        let mut attester_sk_file = File::create(output_dir.join(format!("{}_attester_key_sk.ssz", key_prefix)))?;
        attester_sk_file.write_all(&attester_sk_bytes)?;

        println!("  ✅ {}_attester_key_pk.ssz", key_prefix);
        println!("  ✅ {}_attester_key_sk.ssz", key_prefix);

        if write_json {
            // Proposer key JSON (legacy)
            let proposer_pk_json = serde_json::to_string_pretty(&proposer_pk)
                .expect("Failed to serialize proposer public key to JSON");
            File::create(output_dir.join(format!("{}_proposer_key_pk.json", key_prefix)))?
                .write_all(proposer_pk_json.as_bytes())?;

            let proposer_sk_json = serde_json::to_string_pretty(&proposer_sk)
                .expect("Failed to serialize proposer secret key to JSON");
            File::create(output_dir.join(format!("{}_proposer_key_sk.json", key_prefix)))?
                .write_all(proposer_sk_json.as_bytes())?;

            // Attester key JSON (legacy)
            let attester_pk_json = serde_json::to_string_pretty(&attester_pk)
                .expect("Failed to serialize attester public key to JSON");
            File::create(output_dir.join(format!("{}_attester_key_pk.json", key_prefix)))?
                .write_all(attester_pk_json.as_bytes())?;

            let attester_sk_json = serde_json::to_string_pretty(&attester_sk)
                .expect("Failed to serialize attester secret key to JSON");
            File::create(output_dir.join(format!("{}_attester_key_sk.json", key_prefix)))?
                .write_all(attester_sk_json.as_bytes())?;

            println!("  ⚠️  (legacy) {}_proposer_key_pk.json", key_prefix);
            println!("  ⚠️  (legacy) {}_proposer_key_sk.json", key_prefix);
            println!("  ⚠️  (legacy) {}_attester_key_pk.json", key_prefix);
            println!("  ⚠️  (legacy) {}_attester_key_sk.json", key_prefix);
        }

        // Store validator info for manifest
        validator_info_list.push(ValidatorInfo {
            proposer_key_pubkey_hex: format!("0x{}", hex::encode(&proposer_pk_bytes)),
            proposer_key_privkey_file: format!("{}_proposer_key_sk.ssz", key_prefix),
            attester_key_pubkey_hex: format!("0x{}", hex::encode(&attester_pk_bytes)),
            attester_key_privkey_file: format!("{}_attester_key_sk.ssz", key_prefix),
        });
    }

    println!("\n✅ Successfully generated and saved {} validator key pairs.", num_validators);

    Ok(validator_info_list)
}

fn create_validator_manifest(
    output_dir: &PathBuf,
    num_validators: usize,
    log_num_active_epochs: usize,
    distributed: bool,
    validator_info: &[ValidatorInfo],
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
    
    for (i, info) in validator_info.iter().enumerate() {
        if distributed {
            // Distributed format: no index field
            writeln!(manifest_file, "  - proposer_key_pubkey_hex: {}", info.proposer_key_pubkey_hex)?;
            writeln!(manifest_file, "    proposer_key_privkey_file: {}", info.proposer_key_privkey_file)?;
            writeln!(manifest_file, "    attester_key_pubkey_hex: {}", info.attester_key_pubkey_hex)?;
            writeln!(manifest_file, "    attester_key_privkey_file: {}", info.attester_key_privkey_file)?;
        } else {
            // Indexed format: include index field
            writeln!(manifest_file, "  - index: {}", i)?;
            writeln!(manifest_file, "    proposer_key_pubkey_hex: {}", info.proposer_key_pubkey_hex)?;
            writeln!(manifest_file, "    proposer_key_privkey_file: {}", info.proposer_key_privkey_file)?;
            writeln!(manifest_file, "    attester_key_pubkey_hex: {}", info.attester_key_pubkey_hex)?;
            writeln!(manifest_file, "    attester_key_privkey_file: {}", info.attester_key_privkey_file)?;
        }
        if i < validator_info.len() - 1 {
            writeln!(manifest_file)?;
        }
    }
    
    println!("  ✅ validator-keys-manifest.yaml");
    println!("\n📋 Manifest created successfully at: {}", manifest_path.display());
    
    Ok(())
}

