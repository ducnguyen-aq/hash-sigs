#include <oqs/rand.h>
#include <stdio.h>
#include "api.h"
#include "hss.h"
#include "hss_verify.h"
#include "hss_internal.h"
#include "endian.h"
#include "params.h"

#define DEBUG 0

/* A simple wrapper around OQS randombytes to return True */
static bool LMS_randombytes(void *output, size_t len)
{
    OQS_randombytes(output, len);
    return true;
}

/*************************************************
 * Name:        crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - uint8_t *pk: pointer to output public key (allocated
 *                             array of LMS_CRYPTO_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key (allocated
 *                             array of LMS_CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    uint8_t buf[48];
    OQS_randombytes(buf, 48);
    /* Select NIST KAT as random generator*/
    if (OQS_randombytes_switch_algorithm("NIST-KAT") != OQS_SUCCESS)
    {
        return OQS_ERROR;
    }

    /* Initialize NIST KAT, this time it reads from /dev/urandom */
    OQS_randombytes_nist_kat_init_256bit(buf, NULL);

#if NIST_LEVEL < 2
    param_set_t lm_type[] = {PARAM_LM_HEIGHT};
    param_set_t ots_type[] = {PARAM_OTS_WIDTH};
#elif NIST_LEVEL < 5
    param_set_t lm_type[] = {PARAM_LM_HEIGHT0, PARAM_LM_HEIGHT1};
    param_set_t ots_type[] = {PARAM_OTS_WIDTH, PARAM_OTS_WIDTH};
#else
    param_set_t lm_type[] = {PARAM_LM_HEIGHT0, PARAM_LM_HEIGHT1, PARAM_LM_HEIGHT2};
    param_set_t ots_type[] = {PARAM_OTS_WIDTH, PARAM_OTS_WIDTH, PARAM_OTS_WIDTH};
#endif
    unsigned levels = PARAM_LEVEL;
    /* Generate keypair using LMS API */

    /* Maximum size of aux data for optimal performance */
    const unsigned long aux_data_max_length = 4096 * 10;
    unsigned long aux_data_len = hss_get_aux_data_len(aux_data_max_length, levels, lm_type, ots_type);
    unsigned char *aux_data = malloc(aux_data_len);

    unsigned long pubkey_size = hss_get_public_key_len(levels, lm_type, ots_type);

#if DEBUG
    struct hss_extra_info info = {0};

    bool success = hss_generate_private_key(LMS_randombytes, levels, lm_type, ots_type,
                                            NULL, sk, pk, pubkey_size, aux_data, aux_data_len, &info);

    printf("error = %d\n", info.error_code);
    printf("aux_data_len =  %lu\n", aux_data_len);
#else
    bool success = hss_generate_private_key(LMS_randombytes, levels, lm_type, ots_type,
                                            NULL, sk, pk, pubkey_size, aux_data, aux_data_len, NULL);
#endif

    free(aux_data);
    if (!success)
    {
#if DEBUG
        printf("Error generating keypair\n");
#endif
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

/*************************************************
 * Name:        crypto_sign
 *
 * Description: Computes signature.
 *
 * Arguments:   - uint8_t *sm:   pointer to output signature (of length CRYPTO_BYTES)
 *              - uint8_t *m:    pointer to message to be signed
 *              - uint8_t *sk:   pointer to bit-packed secret key
 *              - unsigned long long *smlen: pointer to output length of signature
 *              - unsigned long long mlen:   length of message
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk)
{
    unsigned char aux_data[1024];

#if DEBUG
    struct hss_extra_info info = {0};

    struct hss_working_key *working_key = hss_load_private_key(NULL, sk,
                                                               100000, aux_data, sizeof aux_data, &info);
    printf("error = %d\n", info.error_code);
#else
    struct hss_working_key *working_key = hss_load_private_key(NULL, sk,
                                                               100000, aux_data, sizeof aux_data, NULL);
#endif

    if (!working_key)
    {
        printf("Error loading working key\n");
        return OQS_ERROR;
    }
    unsigned long long siglen = hss_get_signature_len_from_working_key(working_key);
    if (siglen == 0)
    {
#if DEBUG
        printf("Error getting signature len\n");
#endif
        hss_free_working_key(working_key);
        return OQS_ERROR;
    }
#if DEUBG
    bool success = hss_generate_signature(working_key, NULL, sk, m, mlen, sig, siglen, &info);
    printf("error = %d\n", info.error_code);
    printf("siglen = %ld\n", siglen);
#else
    bool success = hss_generate_signature(working_key, NULL, sk, m, mlen, sm, siglen, NULL);
#endif

    hss_free_working_key(working_key);

    if (!success)
    {
#if DEBUG
        printf("Error generating signature\n");
#endif
        *smlen = 0;
        return OQS_ERROR;
    }

    *smlen = siglen;

    return OQS_SUCCESS;
}

/*************************************************
 * Name:        crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:   - uint8_t *m: pointer to output message (allocated
 *                            array with smlen bytes), can be equal to sm
 *              - const uint8_t *sm: pointer to signed message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *              - unsigned long long *mlen: pointer to output length of message
 *              - unsigned long long smlen: length of signed message
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
    bool success = hss_validate_signature(pk, m, *mlen, sm, smlen, 0);

    if (!success)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

/*************************************************
 * Name:        crypto_remain_signatures
 *
 * Description: Return number of signature left
 *
 * Arguments:   - unsigned long long *remain: remaining signatures
 *              - unsigned long long *max: maximum number of possibile signature
 *              - const uint8_t *sk: pointer to bit-packed private key
 *
 * Returns 0 (sucess), -1 otherwise
 **************************************************/
int crypto_remain_signatures(unsigned long long *remain,
                             unsigned long long *max, unsigned char *sk)
{
    unsigned char aux_data[10240];
    struct hss_working_key *working_key = hss_load_private_key(NULL, sk, 10240,
                                                               aux_data, sizeof aux_data, NULL);

    if (!working_key)
    {
#if DEBUG
        printf("Error loading working key\n");
#endif
        return OQS_ERROR;
    }
    *max = working_key->max_count;
    *remain = working_key->max_count - get_bigendian(sk + PRIVATE_KEY_INDEX, PRIVATE_KEY_INDEX_LEN);

    hss_free_working_key(working_key);
    return OQS_SUCCESS;
}
