use std::collections::HashMap;

use crate::{r1cs::R1CS, witness::Witness};
use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

#[derive(Clone, Debug)]
pub struct Circuit<E: Pairing> {
    pub r1cs: R1CS<E>,
    pub witness: Option<Witness<E>>,
}

impl<E: Pairing> ConstraintSynthesizer<E::ScalarField> for Circuit<E> {
    fn generate_constraints(
        self: Self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), SynthesisError> {
        let mut input_mapping: HashMap<usize, Variable> = HashMap::new();
        let mut witness_mapping: HashMap<usize, Variable> = HashMap::new();

        for v in self.r1cs.input_variables {
            let var = cs.new_input_variable(|| {
                Ok(match &self.witness {
                    None => E::ScalarField::ONE,
                    Some(witness) => witness.input_variables.get(&v).unwrap().clone(),
                })
            })?;
            input_mapping.insert(v, var);
        }

        for v in self.r1cs.witness_variables {
            let var = cs.new_witness_variable(|| {
                Ok(match &self.witness {
                    None => E::ScalarField::ONE,
                    Some(witness) => witness.witness_variables.get(&v).unwrap().clone(),
                })
            })?;
            witness_mapping.insert(v, var);
        }

        let make_index = |index| {
            if input_mapping.contains_key(&index) {
                input_mapping.get(&index).unwrap().clone()
            } else if witness_mapping.contains_key(&index) {
                witness_mapping.get(&index).unwrap().clone()
            } else if index == 0 {
                Variable::One
            } else {
                // This isn't possible because we constructed the input and witness mappings
                // from the R1CS file, which should exhaustively list all variables.
                panic!("Index {} is not a valid variable", index);
            }
        };

        let make_lc = |lc_data: &[(E::ScalarField, usize)]| {
            lc_data.iter().fold(
                LinearCombination::<E::ScalarField>::zero(),
                |lc: LinearCombination<E::ScalarField>, (coeff, index)| {
                    lc + (*coeff, make_index(*index))
                },
            )
        };

        for constraint in &self.r1cs.constraints {
            cs.enforce_constraint(
                make_lc(&constraint.a),
                make_lc(&constraint.b),
                make_lc(&constraint.c),
            )?;
        }

        Ok(())
    }
}
