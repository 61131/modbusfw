#ifndef _XT_MODBUS_H
#define _XT_MODBUS_H


#include <linux/types.h>


struct pkt_modbus {
    __u16 id;           /* Transaction identifier */
    __u16 protocol;     /* Protocol identifier */
    __u16 length;       /* Length */
    __u8 unit;          /* Unit identifier */
    __u8 fc;            /* Function code */
    __u16 reg;          /* Start register */
    __u16 count;        /* Count */
};


struct xt_modbus {
    __u16 id[2];        /* Transaction identifier */
    __u16 protocol;     /* Protocol identifier */
    __u16 length;       /* Length */
    __u8 unit[2];       /* Unit identifier */
    __u8 fc[2];         /* Function code */
    __u16 reg[2];       /* Registers range */
    __u8 set;           /* Set flags */
    __u8 invert;        /* Invert flags */
};

#define XT_MODBUS_FLAG_ID              (0x01)
#define XT_MODBUS_FLAG_PROTOCOL        (0x02)
#define XT_MODBUS_FLAG_LENGTH          (0x04)
#define XT_MODBUS_FLAG_UNIT            (0x08)
#define XT_MODBUS_FLAG_FC              (0x10)
#define XT_MODBUS_FLAG_REG             (0x20)
#define XT_MODBUS_FLAG_MASK            (0x3f)


#endif
