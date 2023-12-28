use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::Debug;
use std::str::FromStr; // Import IntoDeserializer trait

// Custom function to deserialize BigUint from a string
fn deserialize_biguint<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    BigUint::from_str(&s).map_err(serde::de::Error::custom)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    pub extension_degree: usize,
    #[serde(deserialize_with = "deserialize_biguint")]
    pub field_characteristic: BigUint,
    pub input_variables: Vec<usize>,
    pub n_constraints: usize,
    pub n_variables: usize,
    pub output_variables: Vec<usize>,
}
