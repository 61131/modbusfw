#include <stdio.h>
#include <stdint.h>
#include <netdb.h>
#include <xtables.h>

#include <linux/netfilter/xt_modbus.h>


enum {
    O_ID = 0,
    O_PROTOCOL,
    O_LENGTH,
    O_UNIT,
    O_FC,
    O_REG,
};

static const struct xt_option_entry modbus_opts[] = {
    { .name = "id", .id = O_ID, .type = XTTYPE_UINT16RC,
            .flags = XTOPT_INVERT | XTOPT_PUT,
            XTOPT_POINTER(struct xt_modbus, id) },
    { .name = "prot", .id = O_PROTOCOL, .type = XTTYPE_UINT16,
            .flags = XTOPT_INVERT | XTOPT_PUT,
            XTOPT_POINTER(struct xt_modbus, protocol) }, 
    { .name = "len", .id = O_LENGTH, .type = XTTYPE_UINT16,
            .flags = XTOPT_INVERT | XTOPT_PUT,
            XTOPT_POINTER(struct xt_modbus, length) },
    { .name = "unit", .id = O_UNIT, .type = XTTYPE_UINT8RC,
            .flags = XTOPT_INVERT | XTOPT_PUT,
            XTOPT_POINTER(struct xt_modbus, unit) },
    { .name = "fc", .id = O_FC, .type = XTTYPE_UINT8RC,
            .flags = XTOPT_INVERT | XTOPT_PUT,
            XTOPT_POINTER(struct xt_modbus, fc) },
    { .name = "reg", .id = O_REG, .type = XTTYPE_UINT16RC,
            .flags = XTOPT_INVERT | XTOPT_PUT,
            XTOPT_POINTER(struct xt_modbus, reg) },
    XTOPT_TABLEEND,
};


static void 
modbus_help(void) {
    printf("modbus match options:\n"
            "[!] --id transaction[:transaction]\n"
            "\t\t\t\ttransaction identifier(s)\n"
            "[!] --prot protocol\n"
            "\t\t\t\tprotocol identifier\n"
            "[!] --len length\n"
            "\t\t\t\tnumber of bytes\n"
            "[!] --unit addr[:addr]\n"
            "\t\t\t\tunit identifier(s)\n"
            "[!] --fc function[:function]\n"
            "\t\t\t\tfunction code(s)\n"
            "[!] --reg register[:register]\n"
            "\t\t\t\tregister(s)\n");
}


static void 
modbus_init(struct xt_entry_match *m) {
    struct xt_modbus *modbusinfo = (struct xt_modbus *) m->data;

    modbusinfo->id[1] = modbusinfo->unit[1]
            = modbusinfo->fc[1]
            = modbusinfo->reg[1]
            = (uint16_t) ~0U;
    modbusinfo->set = modbusinfo->invert = 0;
}


static void 
modbus_parse(struct xt_option_call *cb) {
    struct xt_modbus *modbusinfo = cb->data;
    uint8_t flag;

    flag = 0;
    xtables_option_parse(cb);
    switch (cb->entry->id) {
        case O_ID:
            if (cb->nvals == 1) {
                modbusinfo->id[1] = modbusinfo->id[0];
            }
            flag = XT_MODBUS_FLAG_ID;
            break;
        case O_PROTOCOL:
            flag = XT_MODBUS_FLAG_PROTOCOL;
            break;
        case O_LENGTH:
            flag = XT_MODBUS_FLAG_LENGTH;
            break;
        case O_UNIT:
            if (cb->nvals == 1) {
                modbusinfo->unit[1] = modbusinfo->unit[0];
            }
            flag = XT_MODBUS_FLAG_UNIT;
            break;
        case O_FC:
            if (cb->nvals == 1) {
                modbusinfo->fc[1] = modbusinfo->fc[0];
            }
            flag = XT_MODBUS_FLAG_FC;
            break;
        case O_REG:
            if (cb->nvals == 1) {
                modbusinfo->reg[1] = modbusinfo->reg[0];
            }
            flag = XT_MODBUS_FLAG_REG;
            break;
    }
    if (cb->invert) {
        modbusinfo->invert |= flag;
    }
    modbusinfo->set |= flag;
}


static void
modbus_output(const char *name, uint16_t min, uint16_t max, int invert, int flag) {
    if (flag) {
        printf(" %s%s ", invert ? "! " : "", name);
    
        if (min != max) {
            printf("%u:%u", min, max);
        }
        else {
            printf("%u", min);
        }
    }
}


static void
modbus_print(const void *ip, const struct xt_entry_match *match, int numeric) {
    const struct xt_modbus *modbusinfo = (struct xt_modbus *) match->data;

    printf(" modbus");

    modbus_output("id",
            modbusinfo->id[0],
            modbusinfo->id[1],
            modbusinfo->invert & XT_MODBUS_FLAG_ID,
            modbusinfo->set & XT_MODBUS_FLAG_ID);
    modbus_output("prot",
            modbusinfo->protocol,
            modbusinfo->protocol,
            modbusinfo->invert & XT_MODBUS_FLAG_PROTOCOL,
            modbusinfo->set & XT_MODBUS_FLAG_PROTOCOL);
    modbus_output("len",
            modbusinfo->length,
            modbusinfo->length,
            modbusinfo->invert & XT_MODBUS_FLAG_LENGTH,
            modbusinfo->set & XT_MODBUS_FLAG_LENGTH);
    modbus_output("unit",
            modbusinfo->unit[0],
            modbusinfo->unit[1],
            modbusinfo->invert & XT_MODBUS_FLAG_UNIT,
            modbusinfo->set & XT_MODBUS_FLAG_UNIT);
    modbus_output("fc",
            modbusinfo->fc[0],
            modbusinfo->fc[1],
            modbusinfo->invert & XT_MODBUS_FLAG_FC,
            modbusinfo->set & XT_MODBUS_FLAG_FC);
    modbus_output("reg",
            modbusinfo->reg[0],
            modbusinfo->reg[1],
            modbusinfo->invert & XT_MODBUS_FLAG_REG,
            modbusinfo->set & XT_MODBUS_FLAG_REG);
}


static void 
modbus_save(const void *ip, const struct xt_entry_match *match) {
    const struct xt_modbus *modbusinfo = (struct xt_modbus *) match->data;

    modbus_output("--id",
            modbusinfo->id[0],
            modbusinfo->id[1],
            modbusinfo->invert & XT_MODBUS_FLAG_ID,
            modbusinfo->set & XT_MODBUS_FLAG_ID);
    modbus_output("--prot",
            modbusinfo->protocol,
            modbusinfo->protocol,
            modbusinfo->invert & XT_MODBUS_FLAG_PROTOCOL,
            modbusinfo->set & XT_MODBUS_FLAG_PROTOCOL);
    modbus_output("--len",
            modbusinfo->length,
            modbusinfo->length,
            modbusinfo->invert & XT_MODBUS_FLAG_LENGTH,
            modbusinfo->set & XT_MODBUS_FLAG_LENGTH);
    modbus_output("--unit",
            modbusinfo->unit[0],
            modbusinfo->unit[1],
            modbusinfo->invert & XT_MODBUS_FLAG_UNIT,
            modbusinfo->set & XT_MODBUS_FLAG_UNIT);
    modbus_output("--fc",
            modbusinfo->fc[0],
            modbusinfo->fc[1],
            modbusinfo->invert & XT_MODBUS_FLAG_FC,
            modbusinfo->set & XT_MODBUS_FLAG_FC);
    modbus_output("--reg",
            modbusinfo->reg[0],
            modbusinfo->reg[1],
            modbusinfo->invert & XT_MODBUS_FLAG_REG,
            modbusinfo->set & XT_MODBUS_FLAG_REG);
}


static struct xtables_match modbus_match = {
    .family             = NFPROTO_UNSPEC,
    .name               = "modbus",
    .version            = XTABLES_VERSION,
    .size               = XT_ALIGN(sizeof(struct xt_modbus)),
    .userspacesize      = XT_ALIGN(sizeof(struct xt_modbus)),
    .help               = modbus_help,
    .init               = modbus_init,
    .print              = modbus_print,
    .save               = modbus_save,
    .x6_parse           = modbus_parse,
    .x6_options         = modbus_opts,
};


void
_init(void) {
    xtables_register_match(&modbus_match);
}
