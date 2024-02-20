%builtins output pedersen range_check bitwise
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2

func get_hashes() -> (
    genesis_state_hash: felt, 
    prev_state_hash: felt
) {
    alloc_locals;
    local genesis_state_hash: felt;
    local prev_state_hash: felt;
    %{
        ids.genesis_state_hash = program_input["genesis_state_hash"]
        ids.prev_state_hash = program_input["prev_state_hash"]
    %}
    return (
        genesis_state_hash=genesis_state_hash, 
        prev_state_hash=prev_state_hash
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

func main{output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr: felt, bitwise_ptr: felt*}() -> () {
    alloc_locals;

    let (
        genesis_state_hash: felt, 
        prev_state_hash: felt
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
        genesis_state_hash, prev_state_hash
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

    assert output_ptr[0] = genesis_state_hash;
    assert output_ptr[1] = res;
    let output_ptr = output_ptr + 2;

    return ();
}