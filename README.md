# arkworks-bridge

## Purpose

Arkworks contains a powerful set of tools for creating / validating proofs based on R1CS constraint formats. However, if you're arithmetization toolchain is not written in rust, your entry point is likely going to be some serialization of your constraints and witness files. This repo contains a CLI tool for helping bring that data into arkworks.

## Serialization Formats

At this time, the serialization formats are based on [this standards document](https://docs.zkproof.org/pages/standards/accepted-workshop2/proposal--zk-interop-jr1cs.pdf). There is a notable exception involving the variable numbering. The rules for variable numbering are roughly:
1. All variables are non-negative, and the variable `0` is reserved for the constant value `1`.
2. Your header file must provide a list of input variables, as well as the total number of variables. I.e. `n_variables = 1 + #input_variables + #witness_variables`.

See the `test/resources` directory for an example.


## Example Usage

Setup:
```
> cargo install
> mkdir proof
> arkworks-bridge --help
```

Create proving and verification keys for a given r1cs, write the serialized keys to the file system:

```
> arkworks-bridge create-trusted-setup --proving-key proof/pk --r1cs test/resources/prog-r1cs.jsonl --verifying-key proof/vk                                 
```

Create a proof given the proving keys, r1cs, and witness, write the serialized proof to the file system:

```
> arkworks-bridge create-proof --output proof/proof --proving-key proof/pk --r1cs test/resources/prog-r1cs.jsonl --witness test/resources/prog-witness.jsonl
```

Verify the proof using the verification key and public inputs:

```
> arkworks-bridge verify-proof --inputs test/resources/prog-inputs.jsonl --proof proof/proof --verifying-key proof/vk                                       
```

