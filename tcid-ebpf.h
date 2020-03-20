/*
 * This file is part of the tcid project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <sys/types.h>
#include <stddef.h>

#define SKB(a)		offsetof(struct __sk_buff,a)

static struct bpf_insn tc_8021p_push[]={
{0xbf,6,1,0,0},
{0x61,0,6,SKB(vlan_present),0},
{0x55,0,0,16,0},
{0x61,0,6,SKB(priority),0},
{0x54,0,0,0,0xf},
{0x18,1,1,0,(u_int32_t)(0)},
{0x00,0,0,0,((u_int64_t)(0))>>32},
{0x63,10,0,-4,0},
{0xbf,2,10,0,0},
{0x07,2,0,0,-4},
{0x85,0,0,0,BPF_FUNC_map_lookup_elem},
{0x15,0,0,7,0},
{0x61,3,0,0,0},
{0xa5,3,0,5,1},
{0x25,3,0,4,7},
{0x64,3,0,0,13},
{0xbf,1,6,0,0},
{0xb4,2,0,0,ETH_P_8021Q},
{0x85,0,0,0,BPF_FUNC_skb_vlan_push},
{0xb7,0,0,0,TC_ACT_OK},
{0x95,0,0,0,0},
};
#define TC_8021P_PUSH_SIZE 21
#define TC_8021P_MAP_L 5
#define TC_8021P_MAP_H 6
