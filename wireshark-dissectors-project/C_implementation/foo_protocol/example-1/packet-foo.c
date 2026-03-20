//Dissector Installation

//Required wireshark headers give acess to dissector APIs
#include "config.h"
#include <epan/packet.h>

//my protocol runs on UDP port 1234
#define FOO_PORT 1234

//protocol handle
//ID for the protocol
//see it when adding fields to the UI
static int proto_foo;

//dissector handle
//this connects dissector function -> wireshark
//this is the function that will decode packets
static dissector_handle_t foo_handle;

//Regestering data structures
static int hf_foo_pdu_type;
static int ett_foo;

//Wrapping up the packet dissection
static int hf_foo_flags;
static int hf_foo_sequenceno;
static int hf_foo_initialip;

//Dissector Function
static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    //add the new subtree
    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);

    //Dissector starting to dissect the packets
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);
    proto_tree_add_item(foo_tree, hf_foo_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(foo_tree, hf_foo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_sequenceno, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(foo_tree, hf_foo_initialip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;



    return tvb_captured_length(tvb);
}

//Dissector Registration
void
proto_register_foo(void)
{
    //Regestering data structures
    static hf_register_info hf[] = {
        { &hf_foo_pdu_type,
            { "FOO PDU Type", "foo.type",
            FT_UINT8, BASE_DEC,
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

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_foo
    };

    proto_foo = proto_register_protocol (
        "FOO Protocol", /* protocol name        */
        "FOO",          /* protocol short name  */
        "foo"           /* protocol filter_name */
        );

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    foo_handle = register_dissector_with_description (
        "foo",          /* dissector name           */
        "Foo Protocol", /* dissector description    */
        dissect_foo,    /* dissector function       */
        proto_foo       /* protocol being dissected */
        );
}

//Dissector Handoff
void
proto_reg_handoff_foo(void)
{
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}


























