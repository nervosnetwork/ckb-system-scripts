#include "secp256k1_blake160.h"

/*
 * Arguments are listed in the following order:
 * 0. program name
 * 1. pubkey blake160 hash, blake2b hash of pubkey first 20 bytes, used to shield the real
 * pubkey in lock script.
 *
 * Witness:
 * 2. pubkey, real pubkey used to identify token owner
 * 3. signature, signature used to present ownership
 * 4. signature size
 */
int main(int argc, char* argv[])
{
  uint64_t length = 0;
  if (argc != 5) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  length = *((uint64_t *) argv[4]);
  return verify_sighash_all(argv[1], argv[2], argv[3], length);
}
