/*
 * randombytes() stub for the mlkem-native vendored build.
 *
 * mlkem-native's *randomized* keypair and encapsulate functions reference
 * randombytes(), so the symbol must exist to link the compilation unit. The
 * differential harness only ever calls the *derandomized* API (keypair_derand +
 * dec) with explicit seeds, so this is never invoked. Abort loudly if it ever is,
 * so a test can never silently run on non-random "randomness".
 */
#include <stdint.h>
#include <stdlib.h>

int randombytes(uint8_t *out, size_t outlen) {
    (void)out;
    (void)outlen;
    abort();
}
