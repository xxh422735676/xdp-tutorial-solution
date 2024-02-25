/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Notice how this XDP/BPF-program contains several programs in the same source
 * file. These will each get their own section in the ELF file, and via libbpf
 * they can be selected individually, and via their file-descriptor attached to
 * a given kernel BPF-hook.
 *
 * The libbpf bpf_object__find_program_by_title() refers to SEC names below.
 * The iproute2 utility also use section name.
 *
 * Slightly confusing, the names that gets listed by "bpftool prog" are the
 * C-function names (below the SEC define).
 */

SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
        int ingress_ifindex = ctx->ingress_ifindex;
        // int egress_ifindex = ctx->egress_ifindex;
        char ingress_outstr[] = "ingress_index is %d";
        // char egress_ourstr[] = "egress_index is %d";
        bpf_trace_printk(ingress_outstr,sizeof(ingress_outstr),ingress_ifindex);
        // bpf_trace_printk(egress_ourstr,sizeof(egress_ourstr),egress_ifindex);
	return XDP_PASS;
}

SEC("xdp")
int  xdp_drop_func(struct xdp_md *ctx)
{
	return XDP_DROP;
}

/* Assignment#2: Add new XDP program section that use XDP_ABORTED */
SEC("xdp")
int  xdp_abort_func(struct xdp_md *ctx)
{
        return XDP_ABORTED;
}
char _license[] SEC("license") = "GPL";

/* Hint the avail XDP action return codes are:

enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
};
*/
