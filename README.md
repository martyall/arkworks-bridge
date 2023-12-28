# arkworks-bridge

## Usage


Create proving and verification keys for a given r1cs:

```
> cargo install
> mkdir proof
> arkworks-bridge create-trusted-setup --pk-output proof/pk --r1cs-path test/resources/prog-r1cs.jsonl --vk-output proof/vk                                 
```

Create a proof given the proving keys, r1cs, and witness:

```
> arkworks-bridge create-proof --output proof/proof --proving-key proof/pk --r1cs test/resources/prog-r1cs.jsonl --witness test/resources/prog-witness.jsonl
```

Verify the proof using the verification key and public inputs:

```
> arkworks-bridge verify-proof --inputs test/resources/prog-inputs.jsonl --proof proof/proof --verifying-key proof/vk                                       
```

