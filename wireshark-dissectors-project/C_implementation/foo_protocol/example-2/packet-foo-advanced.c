#include "config.h"
#include <epan/packet.h>

#define FOO_PORT 1234

static int proto_foo;

static dissector_handle_t foo_handle;

static int hf_foo_pdu_type;
static int hf_foo_flags;
static int hf_foo_sequenceno;
static int hf_foo_initialip;

static int ett_foo;

// tvb : packet data is held in a special buffer referenced here as tvb
// packet_info : structure contains data about the protocol
// tree : where the detail dissection takes place
// data : 
static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO"); //set Wireshark's Protocol column to "FOO"
    col_clear(pinfo->cinfo, COL_INFO);

    //prot_tree_add_item : add the new subtree
    //as FOO prtocol does not encapsulate another protcol we consie all the tvb's data from 0 to the end -1
    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    //final parameter: ENC_NA ("not applicable")
    //As the protocol item doesn't have specific encoding
    //When we start dissecting the values of fields in the protocl data we will have to tell Wireshark about their encoding
        // example: ENC_BIG_ENDIAN, ENC_LITTLE_ENDIAN

    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);

    proto_tree_add_item(foo_tree, hf_foo_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(foo_tree, hf_foo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(foo_tree, hf_foo_sequenceno, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(foo_tree, hf_foo_initialip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return tvb_captured_length(tvb);
}

void
proto_register_foo(void)
{
    static hf_register_info hf[] = {
        { &hf_foo_pdu_type,
            { "FOO PDU Type", "foo.type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_flags,
            { "FOO PDU Flags", "foo.flags",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_sequenceno,
            { "FOO PDU Sequence Number", "foo.seqn",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_initialip,
            { "FOO PDU Initial IP", "foo.initialip",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_foo
    };

    proto_foo = proto_register_protocol(
        "FOO Protocol",
        "FOO",
        "foo"
    );

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    foo_handle = register_dissector_with_description(
        "foo",              // dissector name
        "Foo Protocol",     // disector description
        dissect_foo,        // dissector function (pointer to the dissection function)
        proto_foo           // protocol being dissected
    );
}


//To associate traffic on UPD port FOO_PRT 1234 with foo protocol
void
proto_reg_handoff_foo(void)
{
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
#include <stdio.h>
}
