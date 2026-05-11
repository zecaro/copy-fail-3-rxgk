/* RFC 3961 / RFC 4402 / draft-wilkinson-afs3-rxgk KDF, userspace.
 * Built on OpenSSL libcrypto for AES-128-CBC. Higher-level constructs
 * (nfold, DK, PRF, PRF+) are local. Mirrors net/crypto/krb5/. */
#ifndef KRB5KDF_H
#define KRB5KDF_H

#include <stdint.h>
#include <stddef.h>

#define KRB5_AES128_KEY_LEN     16
#define KRB5_AES128_BLOCK_LEN   16

void rfc3961_nfold(const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t out_len);

int aes128_cbc_block(const uint8_t key[16],
                     const uint8_t in[16], uint8_t out[16]);

int rfc3961_DK_aes128(const uint8_t inkey[16],
                      const uint8_t *constant, size_t constant_len,
                      uint8_t outkey[16]);

int rfc3961_PRF_aes128_sha1(const uint8_t key[16],
                            const uint8_t *octets, size_t octets_len,
                            uint8_t out[16]);

int rfc3961_PRFplus_aes128_sha1(const uint8_t key[16],
                                const uint8_t *pepper, size_t pepper_len,
                                uint8_t *out, size_t wanted_len);

int rxgk_derive_TK(const uint8_t K0[16],
                   uint32_t epoch, uint32_t cid,
                   uint64_t start_time, uint32_t key_number,
                   uint8_t TK[16]);

#define RXGK_CLIENT_ENC_PACKET     1026U
#define RXGK_CLIENT_MIC_PACKET     1027U
#define RXGK_SERVER_ENC_PACKET     1028U
#define RXGK_SERVER_MIC_PACKET     1029U
#define RXGK_CLIENT_ENC_RESPONSE   1030U

int rxgk_derive_Ke(const uint8_t K0[16],
                   uint32_t epoch, uint32_t cid,
                   uint64_t start_time, uint32_t key_number,
                   uint32_t usage, uint8_t Ke[16]);

#endif
