#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define TEMP_SIZE 32768

#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65
#define CELL_INPUT_SIZE 44 // molecule encoded size

#define MAX_INPUTS 64
#define MAX_OUTPUTS 64

#define ERROR_TOO_MANY_INPUTS -51
#define ERROR_TOO_MANY_OUTPUTS -52
#define ERROR_ISSUE_TX -53
#define ERROR_ISSUE_SCRIPT_ARGS -54
#define ERROR_INVALID_POOL_DATA -55
#define ERROR_TX_FORMULA -56;

// 1  bytes for state
// 8  bytes for amount
// 20 bytes for muta address
#define DATA_SIZE 29
#define MUTA_ADDRESS_SIZE 20

#define STATE_FREE 0x1     // free
#define STATE_CHARGE 0x2   // charge-proposed
#define STATE_POOL 0x4     // charged
#define STATE_WITHDRAW 0x8 // withdraw-proposed

typedef struct {
    unsigned char state;
    uint64_t amount;
    char muta_address[MUTA_ADDRESS_SIZE];
} udt_t;

int basic_check_cell_data(unsigned char *cell_data) {
    // FIXME: check cell data
    return 0;
}

udt_t parse_cell_data(unsigned char *cell_data) {
    udt_t item;
    item.state = cell_data[0];
    item.amount = *((uint64_t*)(cell_data + 1));
    for (size_t i = 0; i < MUTA_ADDRESS_SIZE; i++) {
        item.muta_address[i] = cell_data[i+1+8];
    }
    // Little endian
    return item;
}

int load_udts(udt_t *items, uint64_t *total_coins, size_t *length, size_t source) {
    int ret;
    uint64_t len = 0;
    udt_t current_udt;
    unsigned char cell_data[DATA_SIZE];

    size_t index = 0;
    while (1) {
        if (source == CKB_SOURCE_GROUP_INPUT && index >= MAX_INPUTS) {
            return ERROR_TOO_MANY_INPUTS;
        }
        if (source == CKB_SOURCE_GROUP_OUTPUT && index >= MAX_OUTPUTS) {
            return ERROR_TOO_MANY_OUTPUTS;
        }

        len = DATA_SIZE;
        ret = ckb_load_cell_data(cell_data, &len, 0, index, source);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        if (len != DATA_SIZE) {
            return ERROR_SYSCALL;
        }
        ret = basic_check_cell_data(cell_data);
        if (ret != 0) {
            return ret;
        }
        current_udt = parse_cell_data(cell_data);
        *total_coins += current_udt.amount;
        items[index] = current_udt;
        index += 1;
    }
    *length = index;
    return 0;
}

int get_script_args(unsigned char *script, mol_seg_t *args_bytes_seg) {
    uint64_t len = SCRIPT_SIZE;
    mol_seg_t script_seg;
    script_seg.ptr = (uint8_t *)script;
    script_seg.size = len;

    if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
        return ERROR_ENCODING;
    }

    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    *args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
    if (args_bytes_seg->size != BLAKE160_SIZE) {
        return ERROR_ARGUMENTS_LEN;
    }
    return 0;
}

int load_script_args(mol_seg_t *args_bytes_seg) {
    int ret;
    uint64_t len = 0;
    unsigned char script[SCRIPT_SIZE];
    len = SCRIPT_SIZE;
    ret = ckb_load_script(script, &len, 0);
    if (ret != CKB_SUCCESS) {
        return ERROR_SYSCALL;
    }
    if (len > SCRIPT_SIZE) {
        return ERROR_SCRIPT_TOO_LONG;
    }
    return get_script_args(script, args_bytes_seg);
}

int check_tx_formula(udt_t *inputs, size_t input_len, udt_t *outputs, size_t output_len) {
    unsigned char empty_muta_address[MUTA_ADDRESS_SIZE];
    memset(empty_muta_address, 0x0, MUTA_ADDRESS_SIZE);
    udt_t *current;

    unsigned char input_states = 0x0;
    for (size_t i = 0; i < input_len; i++) {
        current = &inputs[i];
        input_states &= current->state;
    }

    unsigned char output_states = 0x0;
    for (size_t i = 0; i < output_len; i++) {
        current = &outputs[i];
        output_states &= current->state;
        if (current->state == STATE_POOL) {
            // FIXME: uncomment this to ensure muta address is empty? (may not necessary)
            /* if (memcmp(current->muta_address, empty_muta_address, MUTA_ADDRESS_SIZE) != 0) { */
            /*     return ERROR_INVALID_POOL_DATA; */
            /* } */
        }
        if (current->state == STATE_CHARGE) {
            // FIXME: Lock script MUST be <time-locked-sighash or muta-create-receipt>
        }
        if (current->state == STATE_WITHDRAW) {
            // FIXME: Lock script MUST be <time-locked-sighash or muta-burn-receipt>
        }
    }

    if (input_states == STATE_FREE && output_states == STATE_FREE) {
        // case 0.1: transfer
    } else if (input_states == STATE_FREE && output_states == STATE_CHARGE) {
        // case 1.1: charge
    } else if (input_states == STATE_CHARGE && output_states == STATE_POOL) {
        // case 1.2: charge success
    } else if (input_states == STATE_CHARGE && output_states == STATE_FREE) {
        // case 1.3: charge timeout
    } else if (input_states == (STATE_FREE & STATE_POOL) && output_states == (STATE_WITHDRAW & STATE_POOL)) {
        // case 2.1: withdraw
        // FIXME:
        //   [CHECK]: free-total / (withdraw-total - free-total) >= 0.1
    } else if (input_states == STATE_WITHDRAW && output_states == STATE_FREE) {
        // case 2.2: withdraw success
    } else if (input_states == STATE_WITHDRAW && output_states == STATE_POOL) {
        // case 2.3: withdraw failed
    } else if (input_states == STATE_WITHDRAW && output_states == (STATE_FREE & STATE_POOL)) {
        // case 2.3: withdraw timeout
    } else {
        return ERROR_TX_FORMULA;
    }

    return 0;
}

int main() {
    int ret;
    uint64_t len = 0;

    // load inputs
    udt_t input_udts[MAX_INPUTS];
    uint64_t input_coins = 0;
    size_t input_length;
    ret = load_udts(input_udts, &input_coins, &input_length, CKB_SOURCE_GROUP_INPUT);
    if (ret != 0) {
        return ret;
    }

    // load outputs
    udt_t output_udts[MAX_OUTPUTS];
    uint64_t output_coins = 0;
    size_t output_length;
    ret = load_udts(output_udts, &output_coins, &output_length, CKB_SOURCE_GROUP_OUTPUT);
    if (ret != 0) {
        return ret;
    }

    blake2b_state blake2b_ctx;
    // Only issue token is allowed
    if (input_coins != output_coins) {
        if (!((input_length == 0) && (output_length == 1))) {
            // FIXME: issue token
            return ERROR_ISSUE_TX;
        }

        if (output_udts[0].state != STATE_FREE) {
            return ERROR_ISSUE_TX;
        }

        unsigned char first_input[CELL_INPUT_SIZE];
        unsigned char input_hash[BLAKE2B_BLOCK_SIZE];
        len = CELL_INPUT_SIZE;
        ret = ckb_load_input(first_input, &len, 0, 0, CKB_SOURCE_INPUT);
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        if (len != CELL_INPUT_SIZE) {
            return ERROR_SYSCALL;
        }
        blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
        blake2b_update(&blake2b_ctx, first_input, CELL_INPUT_SIZE);
        blake2b_final(&blake2b_ctx, input_hash, BLAKE2B_BLOCK_SIZE);

        mol_seg_t args_bytes_seg;
        ret = load_script_args(&args_bytes_seg);
        if (ret != 0) {
            return ret;
        }
        if (memcmp(args_bytes_seg.ptr, input_hash, BLAKE160_SIZE) != 0) {
            return ERROR_ISSUE_SCRIPT_ARGS;
        }
    } else {
        // UDT state change
        ret = check_tx_formula(input_udts, input_length, output_udts, output_length);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}
