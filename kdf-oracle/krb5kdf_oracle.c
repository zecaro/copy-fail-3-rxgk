// SPDX-License-Identifier: GPL-2.0
/* Drives crypto_krb5_calc_PRFplus on fixed inputs and prints TK.
 * Refuses to load (returns -EINVAL) so it auto-unloads after printing. */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/krb5.h>

static u8 K0[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static u32 epoch_v       = 0x11223344;
static u32 cid_v         = 0x55667788;
static u64 start_time_v  = 0xaabbccddeeff0011ULL;
static u32 key_number_v  = 0;

static const char *to_hex(const u8 *b, size_t n)
{
	static char buf[256];
	size_t i;
	for (i = 0; i < n && i < sizeof(buf)/2 - 1; i++)
		snprintf(buf + i*2, 3, "%02x", b[i]);
	buf[n*2] = 0;
	return buf;
}

static int __init kdf_oracle_init(void)
{
	const struct krb5_enctype *krb5;
	struct krb5_buffer K0buf, Sbuf, TKbuf;
	__be32 info[5];
	u8 TK[16];
	int ret;

	pr_info("krb5kdf_oracle: K0=%s epoch=0x%08x cid=0x%08x start=0x%016llx kvno=%u\n",
		to_hex(K0, 16), epoch_v, cid_v, start_time_v, key_number_v);

	krb5 = crypto_krb5_find_enctype(17);
	if (!krb5) { pr_err("enctype 17 not registered\n"); return -ENOENT; }

	K0buf.data = K0; K0buf.len = sizeof(K0);
	info[0] = cpu_to_be32(epoch_v);
	info[1] = cpu_to_be32(cid_v);
	info[2] = cpu_to_be32((u32)(start_time_v >> 32));
	info[3] = cpu_to_be32((u32)(start_time_v & 0xffffffffULL));
	info[4] = cpu_to_be32(key_number_v);
	Sbuf.data = info; Sbuf.len = sizeof(info);
	TKbuf.data = TK;  TKbuf.len = sizeof(TK);

	ret = crypto_krb5_calc_PRFplus(krb5, &K0buf, sizeof(TK), &Sbuf, &TKbuf, GFP_KERNEL);
	if (ret) { pr_err("PRFplus failed: %d\n", ret); return ret; }
	pr_info("krb5kdf_oracle: TK=%s\n", to_hex(TK, 16));

	return -EINVAL;
}

static void __exit kdf_oracle_exit(void) { }

module_init(kdf_oracle_init);
module_exit(kdf_oracle_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("rxgk KDF oracle");
