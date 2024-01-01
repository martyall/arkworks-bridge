mod circuit;
mod header;
mod inputs;
mod r1cs;
mod templates;
mod witness;

use crate::circuit::Circuit;
use crate::inputs::{parse_inputs_file, Inputs};
use crate::witness::Witness; // Import IntoDeserializer trait
use ark_bn254::Bn254;
use ark_circom::ethereum as circom_eth;
use ark_crypto_primitives::snark::*;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use env_logger::Builder;
use log::LevelFilter;
use log::{debug, info};
use r1cs::{parse_r1cs_file, R1CS};
use rand::thread_rng;
use serde_json;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;
use structopt::clap::AppSettings;
use structopt::StructOpt;
use witness::parse_witness_file;

#[derive(StructOpt, Debug)]
#[structopt(name = "arkworks-bridge", global_settings = &[AppSettings::TrailingVarArg])]
struct Cli {
    #[structopt(subcommand)]
    command: Command,

    #[structopt(long, default_value = "info", global = true, possible_values = &["error", "warn", "info", "debug"])]
    log_level: LevelFilter,
}

#[derive(StructOpt, Debug)]
enum Command {
    /// Create a trusted setup given an R1CS file. Currently there is no way to input randomness for the setup, so it is generated using the system's PRNG.
    CreateTrustedSetup {
        /// Path to the R1CS file
        #[structopt(short, long, parse(from_os_str))]
        r1cs: PathBuf,

        /// Write the serialized proving key to this file
        #[structopt(short, long, parse(from_os_str))]
        proving_key: PathBuf,

        /// Write the serialized verifying key to this file
        #[structopt(short, long, parse(from_os_str))]
        verifying_key: PathBuf,

        /// Output the ethereum friendly verifier key as json
        #[structopt(short, long)]
        as_json: bool,
    },
    /// Generate a solidity verifier contract given a verifying key
    GenerateContract {
        /// Path to the serialized verifying key
        #[structopt(short, long, parse(from_os_str))]
        verifying_key: PathBuf,

        /// Write the solidity verifier contract to this file
        #[structopt(short, long, parse(from_os_str))]
        contract: PathBuf,
    },
    /// Create a proof given a proving key, witness, and R1CS file
    CreateProof {
        /// Path to the serialized proving key
        #[structopt(short, long, parse(from_os_str))]
        proving_key: PathBuf,

        // Path to the witness file
        #[structopt(short, long, parse(from_os_str))]
        witness: PathBuf,

        /// Path to the R1CS file
        #[structopt(short, long, parse(from_os_str))]
        r1cs: PathBuf,

        /// Write the serialized proof to this file
        #[structopt(short, long, parse(from_os_str))]
        proof: PathBuf,

        /// Generate an eth-compatible proof and serialize as json
        #[structopt(short, long)]
        ethereum: bool,
    },
    /// Verify a proof given a verifying key, proof, and inputs
    VerifyProof {
        /// Path to the serialized verifying key
        #[structopt(short, long, parse(from_os_str))]
        verifying_key: PathBuf,

        /// Path to the serialized proof
        #[structopt(short, long, parse(from_os_str))]
        proof: PathBuf,

        /// Path to the inputs file
        #[structopt(short, long, parse(from_os_str))]
        inputs: PathBuf,
    },
    /// Generate a trusted setup, proof, and run proof verification without serializing any intermediate files. This is mostly useful for testing.
    RunR1CS {
        /// Path to the R1CS file
        #[structopt(short, long, parse(from_os_str))]
        r1cs: PathBuf,

        // Path to the witness file
        #[structopt(short, long, parse(from_os_str))]
        witness: PathBuf,

        /// Path to the inputs file
        #[structopt(short, long, parse(from_os_str))]
        inputs: PathBuf,
    },
}

fn create_trusted_setup(
    r1cs_path: PathBuf,
    pk_output: PathBuf,
    mut vk_output: PathBuf,
    as_json: bool,
) -> io::Result<()> {
    let file = File::open(r1cs_path.clone())?;
    let reader = BufReader::new(file);

    debug!("Loading R1CS file from {:}", r1cs_path.display());

    let r1cs: R1CS<Bn254> = parse_r1cs_file(reader)?.into();

    let circuit = Circuit {
        r1cs,
        witness: None,
    };

    debug!("Creating trusted setup");

    let setup =
        Groth16::<Bn254>::circuit_specific_setup(circuit, &mut thread_rng()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create trusted setup: {}", err),
            )
        })?;

    info!("Serializing proving key to file {:}", pk_output.display());

    // Serialize the proving key to the output file
    let mut file = File::create(pk_output)?;
    setup.0.serialize_uncompressed(&mut file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to serialize proving key: {}", e),
        )
    })?;

    info!(
        "Serializing verification key to file {:}",
        vk_output.display()
    );

    // Serialize the verifying key to the output file
    let mut file = File::create(vk_output.clone())?;
    setup.1.serialize_uncompressed(&mut file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to serialize verifying key: {}", e),
        )
    })?;

    if as_json {
        let mut file_stem = vk_output.file_stem().unwrap().to_os_string();
        file_stem.push("-eth");
        vk_output.set_file_name(file_stem);
        vk_output.set_extension("json");
        let mut file = File::create(vk_output.clone())?;

        let eth_vk: circom_eth::VerifyingKey = circom_eth::VerifyingKey::from(setup.1);

        info!(
            "Serializing eth-compatible verifying key to file {:}",
            vk_output.display()
        );
        file.write_all(serde_json::to_string(&eth_vk).unwrap().as_bytes())?;
    };

    Ok(())
}

fn create_proof(
    proving_key: PathBuf,
    witness: PathBuf,
    r1cs: PathBuf,
    mut output: PathBuf,
    ethereum: bool,
) -> io::Result<()> {
    let file = File::open(proving_key.clone())?;
    let mut reader = BufReader::new(file);

    debug!("Loading proving key from file {:}", proving_key.display());

    let proving_key =
        <Groth16<Bn254> as ark_crypto_primitives::snark::SNARK<ark_bn254::Fr>>::ProvingKey::deserialize_uncompressed(&mut reader).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to deserialize proving key: {}", e),
            )
        })?;

    let file = File::open(witness.clone())?;
    let reader = BufReader::new(file);

    debug!("Loading witness file from {:}", witness.display());

    let witness: Witness<Bn254> = parse_witness_file(reader)?.into();

    let file = File::open(r1cs.clone())?;
    let reader = BufReader::new(file);

    debug!("Loading R1CS file from {:}", r1cs.display());

    let r1cs: R1CS<Bn254> = parse_r1cs_file(reader)?.into();

    let circuit = Circuit {
        r1cs,
        witness: Some(witness),
    };

    debug!("Creating proof for witness");

    let proof =
        Groth16::<Bn254>::prove(&proving_key, circuit, &mut thread_rng()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create proof: {}", err),
            )
        })?;

    info!("Serializing proof to file {:}", output.display());

    let mut file = File::create(output.clone())?;
    proof.serialize_uncompressed(&mut file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to serialize proof: {}", e),
        )
    })?;

    if ethereum {
        let mut file_stem = output.file_stem().unwrap().to_os_string();
        file_stem.push("-eth");
        output.set_file_name(file_stem);
        output.set_extension("json");
        let mut file = File::create(output.clone())?;

        let eth_proof: circom_eth::Proof = circom_eth::Proof::from(proof);

        info!(
            "Serializing eth-compatible proof to file {:}",
            output.display()
        );
        file.write_all(serde_json::to_string(&eth_proof).unwrap().as_bytes())?;
    };

    Ok(())
}

fn verify_proof(verifying_key: PathBuf, proof: PathBuf, inputs: PathBuf) -> io::Result<bool> {
    let file = File::open(verifying_key.clone())?;
    let mut reader = BufReader::new(file);

    debug!(
        "Loading verifying key from file {:}",
        verifying_key.display()
    );

    let verifying_key =
        <Groth16<Bn254> as ark_crypto_primitives::snark::SNARK<ark_bn254::Fr>>::VerifyingKey::deserialize_uncompressed(&mut reader).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to deserialize verifying key: {}", e),
            )
        })?;

    let file = File::open(proof.clone())?;
    let mut reader = BufReader::new(file);

    debug!("Loading proof from file {:}", proof.display());

    let proof =
        <Groth16<Bn254> as ark_crypto_primitives::snark::SNARK<ark_bn254::Fr>>::Proof::deserialize_uncompressed(&mut reader).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to deserialize proof: {}", e),
            )
        })?;

    let file = File::open(inputs.clone())?;
    let reader = BufReader::new(file);

    debug!("Loading witness file from {:}", inputs.display());

    let inputs: Inputs<Bn254> = parse_inputs_file(reader)?.into();

    let inputs: Vec<ark_bn254::Fr> = inputs.inputs.into_iter().map(|(_, v)| v).collect();

    debug!("Processing verifying key");

    let pvk = Groth16::<Bn254>::process_vk(&verifying_key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to process verifying key: {}", e),
        )
    })?;

    let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();

    info!("Proof verification result: {}", result);

    Ok(result)
}

fn run_r1cs(r1cs: PathBuf, witness: PathBuf, inputs: PathBuf) -> io::Result<()> {
    let file = File::open(r1cs.clone())?;
    let reader = BufReader::new(file);

    debug!("Loading R1CS file from {:}", r1cs.display());

    let r1cs: R1CS<Bn254> = parse_r1cs_file(reader)?.into();

    let file = File::open(witness.clone())?;
    let reader = BufReader::new(file);

    debug!("Loading witness file from {:}", witness.display());

    let witness: Witness<Bn254> = parse_witness_file(reader)?.into();

    let file = File::open(inputs.clone())?;
    let reader = BufReader::new(file);

    debug!("Loading inputs file from {:}", inputs.display());

    let inputs: Inputs<Bn254> = parse_inputs_file(reader)?.into();

    let inputs: Vec<ark_bn254::Fr> = inputs.inputs.into_iter().map(|(_, v)| v).collect();

    let circuit = Circuit {
        r1cs,
        witness: Some(witness),
    };

    let (proving_key, verifying_key) =
        Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut thread_rng()).map_err(
            |err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to create trusted setup: {}", err),
                )
            },
        )?;

    debug!("Creating proof for witness");

    let proof =
        Groth16::<Bn254>::prove(&proving_key, circuit, &mut thread_rng()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create proof: {}", err),
            )
        })?;

    let valid = Groth16::<Bn254>::verify(&verifying_key, &inputs, &proof).unwrap();

    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Proof verification failed",
        ))
    }
}

fn generate_contract(verifying_key: PathBuf, contract: PathBuf) -> io::Result<()> {
    let file = File::open(verifying_key.clone())?;
    let mut reader = BufReader::new(file);

    debug!(
        "Loading verifying key from file {:}",
        verifying_key.display()
    );

    let verifying_key =
        <Groth16<Bn254> as ark_crypto_primitives::snark::SNARK<ark_bn254::Fr>>::VerifyingKey::deserialize_uncompressed(&mut reader).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to deserialize verifying key: {}", e),
            )
        })?;

    let mut file = File::create(contract.clone())?;

    let eth_vk: circom_eth::VerifyingKey = circom_eth::VerifyingKey::from(verifying_key);

    let template = templates::verifier_groth16::render_contract(&eth_vk).unwrap();

    info!("Writing smart contract as {:}", contract.display());

    file.write_all(template.as_bytes())?;

    Ok(())
}

fn main() -> io::Result<()> {
    // Clap to handle command line arguments

    let args = Cli::from_args();

    Builder::new()
        .filter(None, args.log_level)
        .format(|buf, record| {
            // Use `buf`'s write_str or writeln_str methods
            writeln!(buf, "{}: {}", record.level(), record.args())
        })
        .init();

    match args.command {
        Command::CreateTrustedSetup {
            r1cs,
            proving_key,
            verifying_key,
            as_json,
        } => {
            create_trusted_setup(r1cs, proving_key, verifying_key, as_json)?;
        }
        Command::GenerateContract {
            verifying_key,
            contract,
        } => {
            generate_contract(verifying_key, contract)?;
        }
        Command::CreateProof {
            proving_key,
            witness,
            r1cs,
            proof,
            ethereum,
        } => {
            create_proof(proving_key, witness, r1cs, proof, ethereum)?;
        }
        Command::VerifyProof {
            verifying_key,
            proof,
            inputs,
        } => {
            verify_proof(verifying_key, proof, inputs)?;
        }
        Command::RunR1CS {
            r1cs,
            witness,
            inputs,
        } => {
            run_r1cs(r1cs, witness, inputs)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::remove_file;
    use std::path::PathBuf;

    #[test]
    fn test_end_to_end() {
        let r1cs = PathBuf::from("test/resources/prog-r1cs.jsonl");
        let witness = PathBuf::from("test/resources/prog-witness.jsonl");
        let pk = PathBuf::from("test/resources/prog-pk");
        let vk = PathBuf::from("test/resources/prog-vk");
        let proof = PathBuf::from("test/resources/prog-proof");
        let inputs = PathBuf::from("test/resources/prog-inputs.jsonl");

        // ethereum is set to false because the tests aren't picking up the template for some reason?
        create_trusted_setup(r1cs.clone(), pk.clone(), vk.clone(), false).unwrap();
        create_proof(pk.clone(), witness, r1cs, proof.clone(), true).unwrap();
        assert!(verify_proof(vk.clone(), proof.clone(), inputs).unwrap());

        // Clean up
        remove_file(pk).unwrap();
        remove_file(vk).unwrap();
        remove_file(proof).unwrap();
    }
}
