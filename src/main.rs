mod circuit;
mod header;
mod r1cs;
mod witness;

use crate::circuit::Circuit;
use crate::witness::Witness; // Import IntoDeserializer trait
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::*;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use env_logger::Builder;
use log::LevelFilter;
use log::{debug, info};
use r1cs::{parse_r1cs_file, R1CS};
use rand::thread_rng;
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
    CreateTrustedSetup {
        #[structopt(short, long, parse(from_os_str))]
        r1cs_path: PathBuf,

        #[structopt(short, long, parse(from_os_str))]
        pk_output: PathBuf,

        #[structopt(short, long, parse(from_os_str))]
        vk_output: PathBuf,
    },
    /// Read the proving key, witness file, and R1CS file to create a proof
    CreateProof {
        #[structopt(short, long, parse(from_os_str))]
        proving_key: PathBuf,

        #[structopt(short, long, parse(from_os_str))]
        witness: PathBuf,

        #[structopt(short, long, parse(from_os_str))]
        r1cs: PathBuf,

        #[structopt(short, long, parse(from_os_str))]
        output: PathBuf,
    },

    /// Read the verifying key, proof, and witness file to verify the proof
    VerifyProof {
        #[structopt(short, long, parse(from_os_str))]
        verifying_key: PathBuf,

        #[structopt(short, long, parse(from_os_str))]
        proof: PathBuf,

        #[structopt(short, long, parse(from_os_str))]
        inputs: PathBuf,
    },
}

fn create_trusted_setup(
    r1cs_path: PathBuf,
    pk_output: PathBuf,
    vk_output: PathBuf,
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
    let mut file = File::create(vk_output)?;
    setup.1.serialize_uncompressed(&mut file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to serialize verifying key: {}", e),
        )
    })
}

fn create_proof(
    proving_key: PathBuf,
    witness: PathBuf,
    r1cs: PathBuf,
    output: PathBuf,
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

    let mut file = File::create(output)?;
    proof.serialize_uncompressed(&mut file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to serialize proof: {}", e),
        )
    })
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

    let witness: Witness<Bn254> = parse_witness_file(reader)?.into();

    let mut input_tuples: Vec<(usize, ark_bn254::Fr)> =
        witness.input_variables.into_iter().collect();
    input_tuples.sort_by(|(a, _), (b, _)| a.cmp(b));
    let inputs: Vec<ark_bn254::Fr> = input_tuples.into_iter().map(|(_, v)| v).collect();

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
            r1cs_path,
            pk_output,
            vk_output,
        } => {
            create_trusted_setup(r1cs_path, pk_output, vk_output)?;
        }
        Command::CreateProof {
            proving_key,
            witness,
            r1cs,
            output,
        } => {
            create_proof(proving_key, witness, r1cs, output)?;
        }
        Command::VerifyProof {
            verifying_key,
            proof,
            inputs,
        } => {
            verify_proof(verifying_key, proof, inputs)?;
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
        let pk = PathBuf::from("test/resources/pk");
        let vk = PathBuf::from("test/resources/vk");
        let proof = PathBuf::from("test/resources/proof");
        let inputs = PathBuf::from("test/resources/prog-witness.jsonl");

        create_trusted_setup(r1cs.clone(), pk.clone(), vk.clone()).unwrap();
        create_proof(pk.clone(), witness, r1cs, proof.clone()).unwrap();
        assert!(verify_proof(vk.clone(), proof.clone(), inputs).unwrap());

        // Clean up
        remove_file(pk).unwrap();
        remove_file(vk).unwrap();
        remove_file(proof).unwrap();
    }
}
