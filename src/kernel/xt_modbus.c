#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "xt_modbus.h"

static int modbus_mt_checkentry(const struct xt_mtchk_param *par);

static bool modbus_mt_match(const struct sk_buff *skb, struct xt_action_param *par);

static inline bool modbus_mt_match_value(u16 value, u16 min, u16 max, bool invert);


static int 
modbus_mt_checkentry(const struct xt_mtchk_param *par) {
    const struct xt_modbus *modbusinfo = par->matchinfo;

    if ((modbusinfo->set & ~XT_MODBUS_FLAG_MASK) ||
        (modbusinfo->invert & ~XT_MODBUS_FLAG_MASK)) {
        return -EINVAL;
    }
    return 0;
}

static bool 
modbus_mt_match(const struct sk_buff *skb, struct xt_action_param *par) {
    const struct xt_modbus *modbusinfo = par->matchinfo;
    const struct iphdr *iph = ip_hdr(skb);
    const struct tcphdr *tcph;
    struct tcphdr tcph_buf;
    const struct pkt_modbus *pkt;
    struct pkt_modbus pkt_buf;
    unsigned int offset = par->thoff;
    unsigned int hdrlen;
    u16 count, reg, val;
    u32 last_reg;
    bool retval;

    if (par->fragoff != 0) {
        return false;
    }
    if (offset > skb->len) {
        return false;
    }
    
    switch (iph->protocol) {
        case IPPROTO_TCP:
            tcph = skb_header_pointer(skb, offset, sizeof(tcph_buf), &tcph_buf);
            if (!tcph) {
                return false;
            }
            hdrlen = tcph->doff * 4;
            if (hdrlen < sizeof(tcph_buf)) {
                return false;
            }
            break;

        case IPPROTO_UDP:
            hdrlen = sizeof(struct udphdr);
            break;

        default:
            return false;
    }

    if (hdrlen > skb->len - offset) {
        return false;
    }
    offset += hdrlen;

    pkt = skb_header_pointer(skb, offset, sizeof(pkt_buf), &pkt_buf);
    if (!pkt) {
        return false;
    }
    if (modbusinfo->set & XT_MODBUS_FLAG_ID) {
        val = ntohs(pkt->id);
        if (!modbus_mt_match_value(val, 
                modbusinfo->id[0],
                modbusinfo->id[1],
                !!(modbusinfo->invert & XT_MODBUS_FLAG_ID))) {
            return false;
        }
    }

    if (modbusinfo->set & XT_MODBUS_FLAG_PROTOCOL) {
        val = ntohs(pkt->protocol);
        if (!modbus_mt_match_value(val, 
                modbusinfo->protocol,
                modbusinfo->protocol,
                !!(modbusinfo->invert & XT_MODBUS_FLAG_PROTOCOL))) {
            return false;
        }
    }

    if (modbusinfo->set & XT_MODBUS_FLAG_LENGTH) {
        val = ntohs(pkt->length);
        if (!modbus_mt_match_value(val, 
                modbusinfo->length,
                modbusinfo->length,
                !!(modbusinfo->invert & XT_MODBUS_FLAG_LENGTH))) {
            return false;
        }
    }

    if (modbusinfo->set & XT_MODBUS_FLAG_UNIT) {
        if (!modbus_mt_match_value(pkt->unit, 
                modbusinfo->unit[0],
                modbusinfo->unit[1],
                !!(modbusinfo->invert & XT_MODBUS_FLAG_UNIT))) {
            return false;
        }
    }

    if (modbusinfo->set & XT_MODBUS_FLAG_FC) {
        if (!modbus_mt_match_value(pkt->fc, 
                modbusinfo->fc[0],
                modbusinfo->fc[1],
                !!(modbusinfo->invert & XT_MODBUS_FLAG_FC))) {
            return false;
        }
    }

    if (modbusinfo->set & XT_MODBUS_FLAG_REG) {
        reg = ntohs(pkt->reg);
        count = ntohs(pkt->count);
        if (count == 0) {
            return false;
        }

        last_reg = (u32)reg + count - 1;
        if (last_reg > 0xffffU) {
            return false;
        }
        retval = (modbusinfo->reg[0] <= last_reg) &&
                (reg <= modbusinfo->reg[1]);
        retval ^= !!(modbusinfo->invert & XT_MODBUS_FLAG_REG);
        if (!retval) {
            return false;
        }
    }

    return true;
}

static inline bool 
modbus_mt_match_value(u16 value, u16 min, u16 max, bool invert) {
    return (value >= min && value <= max) ^ invert;
}

static struct xt_match 
modbus_mt_reg[] __read_mostly = {
    {
        .name           = "modbus",
        .family         = NFPROTO_IPV4,
        .checkentry     = modbus_mt_checkentry,
        .match          = modbus_mt_match,
        .matchsize      = sizeof(struct xt_modbus),
        .me             = THIS_MODULE,
    },
};

static int __init 
modbus_mt_init(void) {
    return xt_register_matches(modbus_mt_reg, ARRAY_SIZE(modbus_mt_reg));
}

static void __exit 
modbus_mt_exit(void) {
    xt_unregister_matches(modbus_mt_reg, ARRAY_SIZE(modbus_mt_reg));
}

module_init(modbus_mt_init);
module_exit(modbus_mt_exit);

MODULE_AUTHOR("Rob Casey <rcasey@gmail.com>");
MODULE_LICENSE("GPL");
