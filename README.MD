# State-Diff-Commitment

## Overview

This repository contains a provable cairo program that computes the hash of a state update diff. 

The input format consists of the following components:

<!-- TODO: Add descruotuib to these fields -->
- `prev_state_root`
- `block_number`
- `block_hash`
- `config_hash`
- `message_to_starknet_segment`
- `message_to_appchain_segment`
- `nonce_updates`: A mapping of contract addresses to their updated nonces.
- `storage_updates`: A mapping of contract addresses to their updated storage entries.
- `contract_updates`: A mapping of contract addresses to their updated class hashes.
- `declared_classes`: A mapping of newly declared class hashes to their compiled class hashes.


## Example Input

To illustrate the input format, consider the following JSON representation:

```json
{
    "prev_state_root": 34343434343,
    "block_number": 123456,
    "block_hash": 1234567890,
    "config_hash": 1234567890,
    "message_to_starknet_segment": [
        123,
        " ... "
    ],
    "message_to_appchain_segment": [
        123,
        " ... "
    ],
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

The program outputs:
```cairo
struct ProgramOutput {
    /// The state commitment before this block.
    prev_state_root: felt252,
    /// The state commitment after this block.
    new_state_root: felt252,
    /// The number (height) of this block.
    block_number: felt252,
    /// The hash of this block.
    block_hash: felt252,
    /// The Starknet chain config hash
    config_hash: felt252,
    /// Currently, as the SNOS output is not using the cairo
    /// serialization, we can only have a felt252 array with the
    /// messages segments.
    message_to_starknet_segment: Array<felt252>,
    message_to_appchain_segment: Array<felt252>,
}
```
serialized to a felt array. 

All the fields except for `new_state_root` are copied from the input. The `new_state_root` is a hash over the input.

## How to Run

To execute the program, run the `run.sh` script in the root directory. If you want to modify the input data and observe how the hash changes, alter the `src/input.json` file.

## Example Usage

```bash
./run.sh
```

This command will create a virtual python enviroment, compile, and execute the program with the provided input and display the resulting `genesis_state_hash` and `new_state_hash`.

## Building and publishing the image

- Build the image:

    ```bash
    podman build -t state-diff-commitment .
    ```

    When asked about the `stone5-poseidon3` image select the `docker.io` version

- Push the image to `dockerhub:
    ```bash
    podman push localhost/state-diff-commitment:latest docker.io/<USERNAME>/state-diff-commitment:latest
    ```