use ark_circom::ethereum::VerifyingKey;
use ethers_core::abi::AbiEncode;
use serde_json::json;
use std::collections::HashMap;
use tera::{Context, Tera};

fn prepare_data_for_template(vk: &VerifyingKey) -> HashMap<String, serde_json::Value> {
    let mut context = HashMap::new();

    // Convert G1 and G2 types to Tera-compatible format
    context.insert(
        "vk_alpha_1".to_string(),
        json!([vk.alpha1.x.encode_hex(), vk.alpha1.y.encode_hex(),]),
    );

    let beta2 = vk.beta2.as_tuple();
    context.insert(
        "vk_beta_2".to_string(),
        json!([
            [beta2.0[0].encode_hex(), beta2.0[1].encode_hex()],
            [beta2.1[0].encode_hex(), beta2.1[1].encode_hex()],
        ]),
    );

    let gamma2 = vk.gamma2.as_tuple();
    context.insert(
        "vk_gamma_2".to_string(),
        json!([
            [gamma2.0[0].encode_hex(), gamma2.0[1].encode_hex()],
            [gamma2.1[0].encode_hex(), gamma2.1[1].encode_hex()],
        ]),
    );

    let vk_delta_2 = vk.delta2.as_tuple();
    context.insert(
        "vk_delta_2".to_string(),
        json!([
            [vk_delta_2.0[0].encode_hex(), vk_delta_2.0[1].encode_hex()],
            [vk_delta_2.1[0].encode_hex(), vk_delta_2.1[1].encode_hex()],
        ]),
    );

    let ic: Vec<_> = vk
        .ic
        .iter()
        .map(|i| json!([i.x.encode_hex(), i.y.encode_hex()]))
        .collect();
    context.insert("IC".to_string(), json!(ic));

    context.insert("IC_length".to_string(), json!(vk.ic.len()));

    context
}

const TEMPLATE: &str = include_str!("./verifier_groth16.sol.tera");

pub fn render_contract(vk: &VerifyingKey) -> tera::Result<String> {
    let mut tera = Tera::default();
    tera.add_raw_template("verifier_groth16", TEMPLATE)?;

    let data = prepare_data_for_template(vk);

    let mut context = Context::new();
    for (key, value) in data {
        context.insert(key, &value);
    }

    tera.render("verifier_groth16", &context)
}