# State-Diff-Commitment

## Overview

This repository contains a provable cairo program that computes the hash of a state update diff. 

The input format consists of the following components:

- `genesis_state_hash`
- `prev_state_hash`
- `nonce_updates`: A mapping of contract addresses to their updated nonces.
- `storage_updates`: A mapping of contract addresses to their updated storage entries.
- `contract_updates`: A mapping of contract addresses to their updated class hashes.
- `declared_classes`: A mapping of newly declared class hashes to their compiled class hashes.


## Example Input

To illustrate the input format, consider the following JSON representation:

```json
{
    "genesis_state_hash": 12312321313,
    "prev_state_hash": 34343434343,
    "nonce_updates": {
        "7589307": 12,
        " ... "
    },
    "storage_updates": {
        "48732904": {
            "123456789": 89,
            " ... "
        },
        " ... "
    },
    "contract_updates": {
        "58734905": 437267489
    },
    "declared_classes": {
        "1234": 12345,
        " ... "
    }
}
```

## Output

The program outputs two numbers: `(genesis_state_hash, new_state_hash)`.

## How to Run

To execute the program, run the `run.sh` script in the root directory. If you want to modify the input data and observe how the hash changes, alter the `src/input.json` file.

## Example Usage

```bash
./run.sh
```

This command will create a virtual python enviroment, compile, and execute the program with the provided input and display the resulting `genesis_state_hash` and `new_state_hash`.

## Building and publishing the image

```bash
podman build -t stone5-poseidon3 -f prover.dockerfile .
```

```bash
podman push localhost/stone5-poseidon3:latest docker.io/username/stone5-poseidon3:latest
```

```bash
podman build -t example-program -f example-program.dockerfile .
```

```bash
podman run -i --rm example-program < program_input.json > proof.json
```

```bash
podman run -i --rm verifier < proof.json
```

```bash
podman push localhost/verifier:latest docker.io/username/verifier:latest
```