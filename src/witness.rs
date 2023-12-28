use crate::header::Header;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::str::FromStr; // Import IntoDeserializer trait

pub fn deserialize_coeff_var_tuple<'de, D, E>(
    deserializer: D,
) -> Result<(usize, E::ScalarField), D::Error>
where
    D: Deserializer<'de>,
    E: Pairing,
    E::ScalarField: FromStr,
{
    let (var, coeff): (usize, String) = Deserialize::deserialize(deserializer)?;
    E::ScalarField::from_str(&coeff)
        .map(|field_element| (var, field_element))
        .map_err(|_| serde::de::Error::custom("Error in ScalarField parser"))
    // Use Debug formatting
}

#[derive(Debug)]
pub struct WitnessFile<E: Pairing> {
    pub header: Header,
    pub witness: Vec<(usize, E::ScalarField)>,
}

#[derive(Debug, Clone)]
pub struct Witness<E: Pairing> {
    pub input_variables: HashMap<usize, E::ScalarField>,
    pub witness_variables: HashMap<usize, E::ScalarField>,
}

impl<E: Pairing> From<WitnessFile<E>> for Witness<E> {
    fn from(file: WitnessFile<E>) -> Self {
        let mut input_variables: HashMap<usize, E::ScalarField> = HashMap::new();
        let mut witness_variables: HashMap<usize, E::ScalarField> = HashMap::new();

        file.witness.into_iter().for_each(|(index, value)| {
            if file.header.input_variables.contains(&index) {
                input_variables.insert(index, value);
            } else if index != 0 {
                witness_variables.insert(index, value);
            }
        });

        Witness {
            input_variables,
            witness_variables,
        }
    }
}

pub fn parse_witness_file(reader: BufReader<File>) -> io::Result<WitnessFile<Bn254>> {
    let mut lines = reader.lines();

    // Read and parse witness header line
    let header_line = lines.next().ok_or(io::Error::new(
        io::ErrorKind::NotFound,
        "Witness header line not found",
    ))??;
    let witness_header: Header =
        serde_json::from_str(&header_line).expect("Error parsing witness header");

    let mut witness_data = Vec::new();
    for line in lines {
        let line = line.expect("Error reading line from witness file");
        let json = serde_json::from_str::<Value>(&line).expect("Error parsing JSON to Value");
        let deserializer = json.into_deserializer();
        let parsed_data = deserialize_coeff_var_tuple::<_, Bn254>(deserializer)
            .expect("Error in custom deserialization");
        witness_data.push(parsed_data);
    }

    Ok(WitnessFile {
        header: witness_header,
        witness: witness_data,
    })
}
