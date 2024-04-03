%builtins output pedersen range_check bitwise
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2

struct InputConfig {
    prev_state_root: felt,
    block_number: felt,
    block_hash: felt,
    config_hash: felt,
}

func get_hashes() -> (
    input_config: InputConfig
) {
    alloc_locals;
    local input_config: InputConfig;
    local prev_state_root: felt;
    local block_number: felt;
    local block_hash: felt;
    local config_hash: felt;
    %{
        ids.prev_state_root = program_input["prev_state_root"]
        ids.block_number = program_input["block_number"]
        ids.block_hash = program_input["block_hash"]
        ids.config_hash = program_input["config_hash"]
    %}
    return (
        input_config=InputConfig(
            prev_state_root=prev_state_root,
            block_number=block_number,
            block_hash=block_hash,
            config_hash=config_hash
        )
    );
}

func get_messages() -> (
    message_to_starknet_segment: felt*, 
    message_to_starknet_segment_len: felt,
    message_to_appchain_segment: felt*, 
    message_to_appchain_segment_len: felt
) {
    alloc_locals;
    local message_to_starknet_segment: felt*;
    local message_to_starknet_segment_len: felt;
    local message_to_appchain_segment: felt*;
    local message_to_appchain_segment_len: felt;
    %{
        message_to_starknet_segment = \
            program_input["message_to_starknet_segment"]
        message_to_appchain_segment = \
            program_input["message_to_appchain_segment"]

        ids.message_to_starknet_segment = \
            segments.gen_arg(message_to_starknet_segment)
        ids.message_to_starknet_segment_len = \
            len(message_to_starknet_segment)
        ids.message_to_appchain_segment = \
            segments.gen_arg(message_to_appchain_segment)
        ids.message_to_appchain_segment_len = \
            len(message_to_appchain_segment)
    %}
    return (
        message_to_starknet_segment=message_to_starknet_segment,
        message_to_starknet_segment_len=message_to_starknet_segment_len,
        message_to_appchain_segment=message_to_appchain_segment,
        message_to_appchain_segment_len=message_to_appchain_segment_len
    );
}

struct NonceUpdate {
    contract_address: felt,
    nonce: felt,
}

func get_nonce_updates() -> (nonce_updates: NonceUpdate**, nonce_updates_len: felt) {
    alloc_locals;
    local nonce_updates: NonceUpdate**;
    local nonce_updates_len: felt;
    %{
        program_input_nonce_updates = program_input["nonce_updates"]

        nonce_updates = [
            (
                int(key),
                int(value),
            )
            for key, value in program_input_nonce_updates.items()
        ]
        ids.nonce_updates = segments.gen_arg(nonce_updates)
        ids.nonce_updates_len = len(nonce_updates)
    %}
    return (nonce_updates=nonce_updates, nonce_updates_len=nonce_updates_len);
}

func hash_nonce_update{pedersen_ptr: HashBuiltin*}(
    nonce_update: NonceUpdate*
) -> (res: felt) {
    let res = nonce_update.contract_address;
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, nonce_update.nonce
    );
    return (res=res);
}

func hash_nonce_updates_loop{pedersen_ptr: HashBuiltin*}(
    res: felt, nonce_updates: NonceUpdate**, nonce_updates_len
) -> (res: felt) {
    if (nonce_updates_len == 0) {
        return (res=res);
    }
    alloc_locals;
    let nonce_update = [nonce_updates];
    let (hash) = hash_nonce_update{pedersen_ptr=pedersen_ptr}(nonce_update);
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, hash
    );
    return hash_nonce_updates_loop{pedersen_ptr=pedersen_ptr}(
        res=res, 
        nonce_updates=nonce_updates + 1, 
        nonce_updates_len=nonce_updates_len - 1
    );
}

struct StorageUpdate {
    contract_address: felt,
    storage_key: felt,
    storage_value: felt,
}

func get_storage_updates() -> (storage_updates: StorageUpdate**, storage_updates_len: felt) {
    alloc_locals;
    local storage_updates: StorageUpdate**;
    local storage_updates_len: felt;
    %{
        program_input_storage_updates = program_input["storage_updates"]

        storage_updates = [
            (
                int(contract),
                int(key),
                int(value),
            )
            for 
                contract, update in 
                    program_input_storage_updates.items() 
                for 
                    key, value in update.items()
        ]
        ids.storage_updates = segments.gen_arg(storage_updates)
        ids.storage_updates_len = len(storage_updates)
    %}
    return (storage_updates=storage_updates, storage_updates_len=storage_updates_len);
}

func hash_storage_update{pedersen_ptr: HashBuiltin*}(
    storage_update: StorageUpdate*
) -> (res: felt) {
    let res = storage_update.contract_address;
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, storage_update.storage_key
    );
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, storage_update.storage_value
    );
    return (res=res);
}

func hash_storage_updates_loop{pedersen_ptr: HashBuiltin*}(
    res: felt, storage_updates: StorageUpdate**, storage_updates_len
) -> (res: felt) {
    if (storage_updates_len == 0) {
        return (res=res);
    }
    alloc_locals;
    let storage_update = [storage_updates];
    let (hash) = hash_storage_update{pedersen_ptr=pedersen_ptr}(storage_update);
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, hash
    );
    return hash_storage_updates_loop{pedersen_ptr=pedersen_ptr}(
        res=res, 
        storage_updates=storage_updates + 1, 
        storage_updates_len=storage_updates_len - 1
    );
}


struct ContractUpdate {
    contract_address: felt,
    class_hash: felt,
}

func get_contract_updates() -> (contract_updates: ContractUpdate**, contract_updates_len: felt) {
    alloc_locals;
    local contract_updates: ContractUpdate**;
    local contract_updates_len: felt;
    %{
        program_input_contract_updates = program_input["contract_updates"]

        contract_updates = [
            (
                int(key),
                int(value),
            )
            for key, value in program_input_contract_updates.items()
        ]
        ids.contract_updates = segments.gen_arg(contract_updates)
        ids.contract_updates_len = len(contract_updates)
    %}
    return (contract_updates=contract_updates, contract_updates_len=contract_updates_len);
}

func hash_contract_update{pedersen_ptr: HashBuiltin*}(
    contract_update: ContractUpdate*
) -> (res: felt) {
    let res = contract_update.contract_address;
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, contract_update.class_hash
    );
    return (res=res);
}

func hash_contract_updates_loop{pedersen_ptr: HashBuiltin*}(
    res: felt, contract_updates: ContractUpdate**, contract_updates_len
) -> (res: felt) {
    if (contract_updates_len == 0) {
        return (res=res);
    }
    alloc_locals;
    let contract_update = [contract_updates];
    let (hash) = hash_contract_update{pedersen_ptr=pedersen_ptr}(contract_update);
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, hash
    );
    return hash_contract_updates_loop{pedersen_ptr=pedersen_ptr}(
        res=res, 
        contract_updates=contract_updates + 1, 
        contract_updates_len=contract_updates_len - 1
    );
}

struct DeclaredClass {
    class_hash: felt,
    compiled_class_hash: felt,
}

func get_declared_classes() -> (declared_classes: DeclaredClass**, declared_classes_len: felt) {
    alloc_locals;
    local declared_classes: DeclaredClass**;
    local declared_classes_len: felt;
    %{
        program_input_declared_classes = program_input["declared_classes"]

        declared_classes = [
            (
                int(key),
                int(value),
            )
            for key, value in program_input_declared_classes.items()
        ]
        ids.declared_classes = segments.gen_arg(declared_classes)
        ids.declared_classes_len = len(declared_classes)
    %}
    return (declared_classes=declared_classes, declared_classes_len=declared_classes_len);
}

func hash_declared_class{pedersen_ptr: HashBuiltin*}(
    declared_class: DeclaredClass*
) -> (res: felt) {
    let res = declared_class.class_hash;
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, declared_class.compiled_class_hash
    );
    return (res=res);
}

func hash_declared_classes_loop{pedersen_ptr: HashBuiltin*}(
    res: felt, declared_classes: DeclaredClass**, declared_classes_len
) -> (res: felt) {
    if (declared_classes_len == 0) {
        return (res=res);
    }
    alloc_locals;
    let declared_class = [declared_classes];
    let (hash) = hash_declared_class{pedersen_ptr=pedersen_ptr}(declared_class);
    let (res) = hash2{hash_ptr=pedersen_ptr}(
        res, hash
    );
    return hash_declared_classes_loop{pedersen_ptr=pedersen_ptr}(
        res=res, 
        declared_classes=declared_classes + 1, 
        declared_classes_len=declared_classes_len - 1
    );
}

func output_array{output_ptr: felt*}(array: felt*, len: felt) -> () {
    if (len == 0) {
        return ();
    }
    alloc_locals;
    let value = [array];
    assert output_ptr[0] = value;
    let output_ptr = output_ptr + 1;
    return output_array{output_ptr=output_ptr}(array + 1, len - 1);
}

func main{output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr: felt, bitwise_ptr: felt*}() -> () {
    alloc_locals;

    let (
        input_config: InputConfig
    ) = get_hashes();
    let (
        nonce_updates: NonceUpdate**, 
        nonce_updates_len: felt
    ) = get_nonce_updates();
    let (
        storage_updates: StorageUpdate**, 
        storage_updates_len: felt
    ) = get_storage_updates();
    let (
        contract_updates: ContractUpdate**, 
        contract_updates_len: felt
    ) = get_contract_updates();
    let (
        declared_classes: DeclaredClass**, 
        declared_classes_len: felt
    ) = get_declared_classes();
    
    let(res) = hash2{hash_ptr=pedersen_ptr}(
        input_config.prev_state_root, input_config.block_number
    );
    let(res) = hash2{hash_ptr=pedersen_ptr}(
        res, input_config.block_hash
    );
    let(res) = hash2{hash_ptr=pedersen_ptr}(
        res, input_config.config_hash
    );
    let(res) = hash_nonce_updates_loop{pedersen_ptr=pedersen_ptr}(
        res, 
        nonce_updates, 
        nonce_updates_len
    );
    let(res) = hash_storage_updates_loop{pedersen_ptr=pedersen_ptr}(
        res, 
        storage_updates, 
        storage_updates_len
    );
    let(res) = hash_contract_updates_loop{pedersen_ptr=pedersen_ptr}(
        res, 
        contract_updates, 
        contract_updates_len
    );
    let(res) = hash_declared_classes_loop{pedersen_ptr=pedersen_ptr}(
        res, 
        declared_classes, 
        declared_classes_len
    );

    assert output_ptr[0] = input_config.prev_state_root;
    assert output_ptr[1] = res; // new_state_root
    assert output_ptr[2] = input_config.block_number;
    assert output_ptr[3] = input_config.block_hash;
    assert output_ptr[4] = input_config.config_hash;
    let output_ptr = output_ptr + 5;

    let (
        message_to_starknet_segment: felt*, 
        message_to_starknet_segment_len: felt,
        message_to_appchain_segment: felt*, 
        message_to_appchain_segment_len: felt
    ) = get_messages();
    
    assert output_ptr[0] = message_to_starknet_segment_len;
    let output_ptr = output_ptr + 1;
    output_array{output_ptr=output_ptr}(message_to_starknet_segment, message_to_starknet_segment_len);
    assert output_ptr[0] = message_to_appchain_segment_len;
    let output_ptr = output_ptr + 1;
    output_array{output_ptr=output_ptr}(message_to_appchain_segment, message_to_appchain_segment_len);

    return ();
}