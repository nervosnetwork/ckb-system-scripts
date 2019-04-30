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
 */
int main(int argc, char* argv[])
{
  if (argc != 4) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  return verify_sighash_all(argv[1], argv[2], argv[3]);
}
