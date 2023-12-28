use crate::witness::deserialize_coeff_var_tuple;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use serde::de::IntoDeserializer;
use serde_json::Value;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[derive(Debug)]
pub struct Inputs<E: Pairing> {
    pub inputs: Vec<(usize, E::ScalarField)>,
}

pub fn parse_inputs_file(reader: BufReader<File>) -> io::Result<Inputs<Bn254>> {
    let lines = reader.lines();

    let mut inputs_data = Vec::new();
    for line in lines {
        let line = line.expect("Error reading line from inputs file");
        let json = serde_json::from_str::<Value>(&line).expect("Error parsing JSON to Value");
        let deserializer = json.into_deserializer();
        let parsed_data = deserialize_coeff_var_tuple::<_, Bn254>(deserializer)
            .expect("Error in custom deserialization");
        inputs_data.push(parsed_data);
    }

    Ok(Inputs {
        inputs: inputs_data,
    })
}
