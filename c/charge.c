#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"

#define TEMP_SIZE 32768

#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

#define MAX_INPUTS 64
#define MAX_OUTPUTS 64
#define ERROR_TOO_MANY_INPUTS -51
#define ERROR_TOO_MANY_OUTPUTS -52

// 1  bytes for state
// 20 bytes for muta address
// 8  bytes for amount
#define DATA_SIZE 29
#define MUTA_ADDRESS_SIZE 20

#define STATE_FREE 0     // free
#define STATE_CHARGE 1   // charge-proposed
#define STATE_POOL 2     // charged
#define STATE_WITHDRAW 3 // withdraw-proposed

typedef struct {
    char state;
    char muta_address[MUTA_ADDRESS_SIZE];
    uint64_t amount;
} udt_t;

int basic_check_cell_data(unsigned char *cell_data) {
    // FIXME: check cell data
    return 0;
}

udt_t parse_cell_data(unsigned char *cell_data) {
    udt_t item;
    item.state = cell_data[0];
    for (size_t i = 0; i < MUTA_ADDRESS_SIZE; i++) {
        item.muta_address[i] = cell_data[i+1];
    }
    // Little endian
    unsigned char *c = cell_data + 1 + MUTA_ADDRESS_SIZE;
    uint64_t *p = (uint64_t*)c;
    item.amount = *p;
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

int main() {
    int ret;
    /* uint64_t len = 0; */
    /* unsigned char temp[TEMP_SIZE]; */
    /* unsigned char lock_bytes[SIGNATURE_SIZE]; */
    /* unsigned char script[SCRIPT_SIZE]; */

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

    if (input_coins != output_coins) {
        if ((input_length == 0) && (output_length == 1)) {
            // FIXME: issue token
        }
    }
    return 0;
}
