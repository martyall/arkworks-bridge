# arkworks-bridge

## Usage


setup workspace:
```
> cargo install
> mkdir proof
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

