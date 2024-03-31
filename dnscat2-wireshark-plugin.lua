print("DNSCat2 dissector loading")


proto = Proto("DNSCat2", "DNSCat2 dissector")


field_dns_qry_name = Field.new("dns.qry.name")

fields = {}
fields.request = ProtoField.none("dnscat2.request","Request")

fields.packet_id = ProtoField.uint16("dnscat2.packet_id", "Packet Id")
fields.packet_type = ProtoField.uint8("dnscat2.packet_type", "Packet Type", base.HEX, {
    [0] = "SYN",
    [1] = "MSG",
    [2] = "FIN",
    [3] = "ENC",
    [0xff] = "PING",
})
fields.session_id = ProtoField.uint16("dnscat2.session_id", "Session Id")

fields.packet_data = ProtoField.bytes("dnscat2.payload", "Packet Data")

fields.msg = ProtoField.none("dnscat2.msg", "Msg")
fields.msg_seq = ProtoField.uint16("dnscat2.msg.seq", "Sequence")
fields.msg_ack = ProtoField.uint16("dnscat2.msg.ack", "Ack")
fields.msg_data = ProtoField.bytes("dnscat2.msg.data","Data")

fields.syn = ProtoField.none("dnscat2.syn", "Syn")
fields.syn_seq = ProtoField.uint16("dnscat2.syn.seq", "Sequence")
fields.syn_options = ProtoField.uint16("dnscat2.syn.seq", "Options")
fields.syn_name = ProtoField.string("dnscat2.syn.name", "Name")

fields.fin = ProtoField.none("dnscat2.fin", "Syn")
fields.fin_reason = ProtoField.string("dnscat2.fin.reason", "Reason")

fields.enc = ProtoField.none("dnscat2.enc", "Enc")
fields.enc_subtype = ProtoField.uint16("dnscat2.enc.subtype", "Subtype")
fields.enc_flags = ProtoField.uint16("dnscat2.enc.flags", "Flags")
fields.enc_init = ProtoField.bytes("dnscat2.enc.init", "Init")
fields.enc_auth = ProtoField.bytes("dnscat2.enc.auth", "Auth")

proto.fields = fields

function proto.dissector(buffer, pinfo, tree)
    local dns_qry_name = field_dns_qry_name()
    if not dns_qry_name then
        return
    end

    local subtree = tree:add(proto, "DNSCat2")

    data = tostring(dns_qry_name)
    --data = dns_qry_name

    -- drop prefix
    data = data:gsub("^dnscat.", "")

    -- drop suffix (domain.tld)
    data = data:gsub("[.][^%.]+[.][^%.]+$", "")

    -- any . are noop data
    data = data:gsub("[.]", "")


    -- get the binary data
    local raw = ByteArray.new(data)
    local tvb = ByteArray.tvb(raw, "Request")
    local request = subtree:add(fields.request, tvb())

    local packet_id   = tvb(0, 2)
    local packet_type = tvb(2, 1)
    local session_id  = tvb(3, 2)

    request:add(fields.packet_id, packet_id)
    request:add(fields.packet_type, packet_type)
    request:add(fields.session_id, session_id)

    if packet_type:uint() == 0 then
        local syn = request:add(fields.syn, tvb(5))
        syn:add(fields.syn_seq,     tvb(5, 2))
        syn:add(fields.syn_options, tvb(7, 2))
        syn:add(fields.syn_name,    tvb(9))
    elseif packet_type:uint() == 1 then
        local msg = request:add(fields.msg, tvb(5))
        msg:add(fields.msg_seq,  tvb(5, 2))
        msg:add(fields.msg_ack,  tvb(7, 2))
        msg:add(fields.msg_data, tvb(9))
    elseif packet_type:uint() == 2 then
        local fin = request:add(fields.fin, tvb(5))
        fin:add(fields.fin_reason,  tvb(5))
    elseif packet_type:uint() == 3 then
        local enc = request:add(fields.enc, tvb(5))
        enc:add(fields.enc_subtype,  tvb(5, 2))
        enc:add(fields.enc_flags,  tvb(7, 2))
        if tvb(5, 2):uint() == 0 then
            enc:add(fields.enc_init, tvb(9))
        elseif tvb(5, 2):uint() == 1 then
            enc:add(fields.enc_auth, tvb(9))
        end
    else
        request:add(fields.packet_data, tvb(5))        
    end
 
end

register_postdissector(proto)
