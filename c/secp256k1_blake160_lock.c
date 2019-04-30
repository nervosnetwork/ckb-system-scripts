#include "secp256k1_blake160.h"

int main(int argc, char* argv[])
{
  return verify_bitcoin_sighash(argc, argv);
}
