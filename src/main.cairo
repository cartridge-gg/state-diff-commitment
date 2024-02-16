%builtins output pedersen range_check bitwise
from starkware.cairo.common.dict import dict_new, dict_read, dict_update, dict_squash
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.math import assert_nn_le
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.small_merkle_tree import (
    small_merkle_tree_update,
)
from starkware.cairo.common.cairo_builtins import HashBuiltin

const MAX_BALANCE = 2 ** 128 - 1;

struct Transaction {
    from_valut_id: felt,
    to_valut_id: felt,
    amount: felt,
}

struct State {
    account_dict_start: DictAccess*,
    account_dict_end: DictAccess*,
}

struct OutputEntry {
    valut_id: felt,
    amount_before: felt,
    amount_after: felt,
}

func transaction_loop{range_check_ptr: felt}(
    state: State, transactions: Transaction**, transactions_len
) -> (state: State) {
    if (transactions_len == 0) {
        return (state=state);
    }
    alloc_locals;

    let first_transaction: Transaction* = [transactions];

    let account_dict_end = state.account_dict_end;
    
    let from_account_id = first_transaction.from_valut_id;
    let to_account_id = first_transaction.to_valut_id;

    let (old_from_account_balance: felt) = dict_read{dict_ptr=account_dict_end}(key=from_account_id);
    let (old_to_account_balance: felt) = dict_read{dict_ptr=account_dict_end}(key=to_account_id);
    tempvar new_from_account_balance = (old_from_account_balance - first_transaction.amount);
    tempvar new_to_account_balance = (old_to_account_balance + first_transaction.amount);
    assert_nn_le(new_from_account_balance, MAX_BALANCE);
    assert_nn_le(new_to_account_balance, MAX_BALANCE);
    
    let (__fp__, _) = get_fp_and_pc();
    dict_update{dict_ptr=account_dict_end}(
        key=from_account_id, 
        prev_value=old_from_account_balance, 
        new_value=new_from_account_balance
    );
    dict_update{dict_ptr=account_dict_end}(
        key=to_account_id, 
        prev_value=old_to_account_balance,
        new_value=new_to_account_balance
    );

    local new_state: State;
    new_state.account_dict_start = state.account_dict_start;
    new_state.account_dict_end = account_dict_end;

    return transaction_loop(
        state=new_state, transactions=transactions + 1, transactions_len=transactions_len - 1
    );
}

func get_accounts() -> (account_ids: felt*, account_ids_len: felt, account_ids_len_log: felt) {
    alloc_locals;
    local account_ids: felt*;
    local account_ids_len: felt;
    local account_ids_len_log: felt;
    %{
        program_input_accounts = program_input["accounts"]

        account_ids = [
            int(account_id)
            for account_id in program_input_accounts.keys()
        ]
        ids.account_ids = segments.gen_arg(account_ids)
        ids.account_ids_len = len(account_ids)
        import math 
        ids.account_ids_len_log = math.ceil(math.log(len(account_ids), 2)) + 1
    %}
    return (
        account_ids=account_ids, 
        account_ids_len=account_ids_len, 
        account_ids_len_log=account_ids_len_log
    );
}

func get_transactions() -> (transactions: Transaction**, transactions_len: felt) {
    alloc_locals;
    local transactions: Transaction**;
    local transactions_len: felt;
    %{
        program_input_transactions = program_input["transactions"]

        transactions = [
            (
                int(transaction["from_account_id"]),
                int(transaction["to_account_id"]),
                int(transaction["amount"]),
            )
            for transaction in program_input_transactions
        ]
        ids.transactions = segments.gen_arg(transactions)
        ids.transactions_len = len(transactions)
    %}
    return (transactions=transactions, transactions_len=transactions_len);
}

func get_accounts_dict() -> (account_dict: DictAccess*) {
    alloc_locals;
    %{
        program_input_accounts = program_input["accounts"]

        initial_dict = {
            int(account_id): int(info["balance"])
            for account_id, info in program_input_accounts.items()
        }
    %}

    let (account_dict) = dict_new();
    return (account_dict=account_dict);
}

func write_output{output_ptr: felt*}(state: State, account_ids: felt*, account_ids_len: felt) -> (output_ptr: felt*, state: State) {
    if (account_ids_len == 0) {
        return (output_ptr=output_ptr, state=state);
    }
    alloc_locals;
    local new_state: State;
    new_state.account_dict_start = state.account_dict_start;
    
    let account_id = account_ids[0];
    let account_dict_end = state.account_dict_end;
    let (balance: felt) = dict_read{dict_ptr=account_dict_end}(key=account_id);
    new_state.account_dict_end = account_dict_end;

    assert output_ptr[0] = account_id;
    assert output_ptr[1] = balance;
    let output_ptr = output_ptr + 2;
    
    return write_output(new_state, account_ids + 1, account_ids_len - 1);
}


func main{output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr: felt, bitwise_ptr: felt*}() -> () {
    alloc_locals;

    let (
        account_ids: felt*, 
        account_ids_len: felt, 
        account_ids_len_log: felt
    ) = get_accounts();
    let (account_dict: DictAccess*) = get_accounts_dict();

    local state: State;
    assert state.account_dict_start = account_dict;
    assert state.account_dict_end = account_dict;

    let (transactions: Transaction**, transactions_len: felt) = get_transactions();

    let (state: State) = transaction_loop(state, transactions, transactions_len);

    let (output_ptr, state) = write_output(state, account_ids, account_ids_len);

    let (squashed_dict_start, squashed_dict_end) = dict_squash(
        dict_accesses_start=state.account_dict_start,
        dict_accesses_end=state.account_dict_end,
    );
    local range_check_ptr = range_check_ptr;

    let (root_before, root_after) = small_merkle_tree_update{
        hash_ptr=pedersen_ptr
    }(
        squashed_dict_start=squashed_dict_start,
        squashed_dict_end=squashed_dict_end,
        height=account_ids_len_log,
    );

    assert output_ptr[0] = root_before;
    assert output_ptr[1] = root_after;
    let output_ptr = output_ptr + 2;

    return ();
}
