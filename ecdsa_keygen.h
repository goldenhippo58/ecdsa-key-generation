#ifndef ECDSA_KEYGEN_H
#define ECDSA_KEYGEN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int generate_compressed_public_key(const uint8_t *private_key, uint8_t *compressed_public_key);

#ifdef __cplusplus
}
#endif

#endif // ECDSA_KEYGEN_H