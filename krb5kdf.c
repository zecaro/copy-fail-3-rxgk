/* gcc -O2 -Wall krb5kdf.c -c
 * net/crypto/krb5/rfc3961_simplified.c, RFC 3961, RFC 4402,
 * draft-wilkinson-afs3-rxgk-11 sec 8.3. */
#include "krb5kdf.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <arpa/inet.h>

int aes128_cbc_block(const uint8_t key[16],
                     const uint8_t in[16], uint8_t out[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int outl = 0, totl = 0, rc = -1;
    uint8_t zero_iv[16] = {0};
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, zero_iv)) goto out;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!EVP_EncryptUpdate(ctx, out, &outl, in, 16)) goto out;
    totl = outl;
    if (!EVP_EncryptFinal_ex(ctx, out + totl, &outl)) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static unsigned long lcm_ul(unsigned long a, unsigned long b)
{
    unsigned long x = a, y = b;
    while (y) { unsigned long t = y; y = x % y; x = t; }
    return (a / x) * b;
}

void rfc3961_nfold(const uint8_t *in, size_t in_len_bytes,
                   uint8_t *out, size_t out_len_bytes)
{
    unsigned int inbits  = (unsigned)in_len_bytes;
    unsigned int outbits = (unsigned)out_len_bytes;
    unsigned long ulcm = lcm_ul(inbits, outbits);
    int i, msbit, byte = 0;

    memset(out, 0, outbits);
    for (i = (int)ulcm - 1; i >= 0; i--) {
        msbit = (
            ((inbits << 3) - 1) +
            (((inbits << 3) + 13) * (i / inbits)) +
            ((inbits - (i % inbits)) << 3)
        ) % (inbits << 3);
        byte += (((in[((inbits - 1) - (msbit >> 3)) % inbits] << 8) |
                  (in[((inbits)     - (msbit >> 3)) % inbits]))
                 >> ((msbit & 7) + 1)) & 0xff;
        byte += out[i % outbits];
        out[i % outbits] = byte & 0xff;
        byte >>= 8;
    }
    if (byte) {
        for (i = (int)outbits - 1; i >= 0; i--) {
            byte += out[i];
            out[i] = byte & 0xff;
            byte >>= 8;
        }
    }
}

int rfc3961_DK_aes128(const uint8_t inkey[16],
                      const uint8_t *constant, size_t constant_len,
                      uint8_t outkey[16])
{
    uint8_t inblock[16];
    if (constant_len == 16) memcpy(inblock, constant, 16);
    else rfc3961_nfold(constant, constant_len, inblock, 16);
    return aes128_cbc_block(inkey, inblock, outkey);
}

/* PRF = E(DK(K, "prf"), trunc_len(SHA1(input), block_len)).
 * trunc is a length truncation, not a bit-mask. */
int rfc3961_PRF_aes128_sha1(const uint8_t key[16],
                            const uint8_t *octets, size_t octets_len,
                            uint8_t out[16])
{
    uint8_t hash[SHA_DIGEST_LENGTH];
    SHA1(octets, octets_len, hash);

    uint8_t tmp2[16];
    memcpy(tmp2, hash, 16);

    uint8_t Kp[16];
    if (rfc3961_DK_aes128(key, (uint8_t*)"prf", 3, Kp) < 0) return -1;
    return aes128_cbc_block(Kp, tmp2, out);
}

/* T_n = PRF(K, htonl(n) || pepper). n is 4-byte BE. */
int rfc3961_PRFplus_aes128_sha1(const uint8_t key[16],
                                const uint8_t *pepper, size_t pepper_len,
                                uint8_t *out, size_t wanted_len)
{
    size_t off = 0;
    uint8_t buf[4 + 4096];
    if (pepper_len > sizeof(buf) - 4) return -1;
    memcpy(buf + 4, pepper, pepper_len);
    uint32_t n = 1;
    while (off < wanted_len) {
        uint8_t T[16];
        uint32_t n_be = htonl(n);
        memcpy(buf, &n_be, 4);
        if (rfc3961_PRF_aes128_sha1(key, buf, 4 + pepper_len, T) < 0) return -1;
        size_t take = wanted_len - off;
        if (take > 16) take = 16;
        memcpy(out + off, T, take);
        off += take;
        n++;
    }
    return 0;
}

/* TK = PRF+(K0, 16, epoch || cid || start_time || key_number).
 * Pepper is 4+4+8+4 = 20 BE bytes. */
int rxgk_derive_TK(const uint8_t K0[16],
                   uint32_t epoch, uint32_t cid,
                   uint64_t start_time, uint32_t key_number,
                   uint8_t TK[16])
{
    uint8_t pepper[20];
    uint32_t be;
    be = htonl(epoch);                                 memcpy(pepper +  0, &be, 4);
    be = htonl(cid);                                   memcpy(pepper +  4, &be, 4);
    be = htonl((uint32_t)(start_time >> 32));          memcpy(pepper +  8, &be, 4);
    be = htonl((uint32_t)(start_time & 0xffffffffu));  memcpy(pepper + 12, &be, 4);
    be = htonl(key_number);                            memcpy(pepper + 16, &be, 4);
    return rfc3961_PRFplus_aes128_sha1(K0, pepper, sizeof(pepper), TK, 16);
}

/* Ke = DK(TK, htonl(usage) || 0xAA). */
int rxgk_derive_Ke(const uint8_t K0[16],
                   uint32_t epoch, uint32_t cid,
                   uint64_t start_time, uint32_t key_number,
                   uint32_t usage, uint8_t Ke[16])
{
    uint8_t TK[16];
    if (rxgk_derive_TK(K0, epoch, cid, start_time, key_number, TK) < 0)
        return -1;
    uint8_t usage5[5];
    uint32_t usage_be = htonl(usage);
    memcpy(usage5, &usage_be, 4);
    usage5[4] = 0xAA;
    return rfc3961_DK_aes128(TK, usage5, 5, Ke);
}
