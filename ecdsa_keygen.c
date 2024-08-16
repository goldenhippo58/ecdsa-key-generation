#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

int generate_compressed_public_key(const uint8_t *private_key, uint8_t *compressed_public_key) {
    int ret = -1;
    EC_KEY *eckey = NULL;
    BIGNUM *priv_bn = NULL;
    EC_GROUP *group = NULL;
    const EC_POINT *pub_key = NULL;
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;

    OpenSSL_add_all_algorithms();

    // Create a new EC_KEY object
    if (!(eckey = EC_KEY_new_by_curve_name(NID_secp256k1))) {
        fprintf(stderr, "Failed to create new EC Key\n");
        goto cleanup;
    }

    // Convert private key bytes to BIGNUM
    if (!(priv_bn = BN_bin2bn(private_key, 32, NULL))) {
        fprintf(stderr, "Failed to convert private key to BIGNUM\n");
        goto cleanup;
    }

    // Set private key
    if (!EC_KEY_set_private_key(eckey, priv_bn)) {
        fprintf(stderr, "Failed to set private key\n");
        goto cleanup;
    }

    // Get the group
    if (!(group = (EC_GROUP *)EC_KEY_get0_group(eckey))) {
        fprintf(stderr, "Failed to get group\n");
        goto cleanup;
    }

    // Derive the public key from the private key
    if (!(pub_key = EC_POINT_new(group))) {
        fprintf(stderr, "Failed to create new EC Point\n");
        goto cleanup;
    }
    if (!EC_POINT_mul(group, (EC_POINT *)pub_key, priv_bn, NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to derive public key\n");
        goto cleanup;
    }
    if (!EC_KEY_set_public_key(eckey, pub_key)) {
        fprintf(stderr, "Failed to set public key\n");
        goto cleanup;
    }

    // Convert public key to compressed form
    if (!(ret = EC_KEY_key2buf(eckey, form, &compressed_public_key, NULL))) {
        fprintf(stderr, "Failed to get compressed public key\n");
        ret = -1;
        goto cleanup;
    }

cleanup:
    if (eckey) EC_KEY_free(eckey);
    if (priv_bn) BN_free(priv_bn);
    if (pub_key) EC_POINT_free((EC_POINT *)pub_key);
    return ret;
}

int main() {
    uint8_t private_key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    uint8_t compressed_public_key[33] = {0};
    int len = generate_compressed_public_key(private_key, compressed_public_key);
    if (len <= 0) {
        fprintf(stderr, "Failed to generate compressed public key\n");
        return 1;
    }

    printf("Compressed Public Key: ");
    for (int i = 0; i < len; i++) {
        printf("%02x", compressed_public_key[i]);
    }
    printf("\n");

    return 0;
}
