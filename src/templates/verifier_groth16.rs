use ark_circom::ethereum::VerifyingKey;
use ethers_core::abi::AbiEncode;
use serde_json::json;
use std::collections::HashMap;
use tera::{Context, Tera};

fn prepare_data_for_template(
    vk: &VerifyingKey,
    n_inputs: usize,
) -> HashMap<String, serde_json::Value> {
    let mut context = HashMap::new();

    // Convert G1 and G2 types to Tera-compatible format
    let alpha1 = vk.alpha1.as_tuple();
    context.insert(
        "vk_alpha1".to_string(),
        json!([alpha1.0.encode_hex(), alpha1.1.encode_hex(),]),
    );

    context.insert(
        "vk_beta2".to_string(),
        json!([
            vk.beta2.x.map(|a| a.encode_hex()),
            vk.beta2.y.map(|a| a.encode_hex())
        ]),
    );

    context.insert(
        "vk_gamma2".to_string(),
        json!([
            vk.gamma2.x.map(|a| a.encode_hex()),
            vk.gamma2.y.map(|a| a.encode_hex())
        ]),
    );

    context.insert(
        "vk_delta2".to_string(),
        json!([
            vk.delta2.x.map(|a| a.encode_hex()),
            vk.delta2.y.map(|a| a.encode_hex())
        ]),
    );

    let ic: Vec<_> = vk
        .ic
        .iter()
        .map(|i| {
            let i_tuple = i.as_tuple();
            json!([i_tuple.0.encode_hex(), i_tuple.1.encode_hex()])
        })
        .collect();
    context.insert("vk_ic_pts".to_string(), json!(ic));

    context.insert("vk_ic_length".to_string(), json!(ic.len()));

    context.insert("vk_input_length".to_string(), json!(n_inputs));

    context
}

const TEMPLATE: &str = include_str!("./verifier_groth16.sol.tera");

pub fn render_contract(vk: &VerifyingKey, n_inputs: usize) -> tera::Result<String> {
    let mut tera = Tera::default();
    tera.add_raw_template("verifier_groth16", TEMPLATE)?;

    let data = prepare_data_for_template(vk, n_inputs);

    let mut context = Context::new();
    for (key, value) in data {
        context.insert(key, &value);
    }

    tera.render("verifier_groth16", &context)
}
