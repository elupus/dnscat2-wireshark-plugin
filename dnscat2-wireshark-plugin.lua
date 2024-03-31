print("dnscat2 dissector loading")


proto = Proto("dnscat2", "dnscat2 dissector")


field_dns_qry_name = Field.new("dns.qry.name")

field_dns_resp_type = Field.new("dns.resp.type")
field_dns_resp_cname = Field.new("dns.cname")
field_dns_resp_mx = Field.new("dns.mx.mail_exchange")
field_dns_resp_txt = Field.new("dns.txt")


fields = {}

fields.packet_raw = ProtoField.bytes("dnscat2.packet_raw","Packet")
fields.packet_id = ProtoField.uint16("dnscat2.packet_id", "Id")
fields.packet_type = ProtoField.uint8("dnscat2.packet_type", "Type", base.HEX, {
    [0] = "SYN",
    [1] = "MSG",
    [2] = "FIN",
    [3] = "ENC",
    [0xff] = "PING",
})
fields.session_id = ProtoField.uint16("dnscat2.session_id", "Session")

fields.msg = ProtoField.none("dnscat2.msg", "Msg")
fields.msg_seq = ProtoField.uint16("dnscat2.msg.seq", "Seq")
fields.msg_ack = ProtoField.uint16("dnscat2.msg.ack", "Ack")
fields.msg_ack_for = ProtoField.framenum("dnscat2.msg.ack_for", "Ack for", base.NONE, frametype.ACK)
fields.msg_data = ProtoField.bytes("dnscat2.msg.data","Data")

fields.syn = ProtoField.none("dnscat2.syn", "Syn")
fields.syn_seq = ProtoField.uint16("dnscat2.syn.seq", "Seq")
fields.syn_options = ProtoField.uint16("dnscat2.syn.seq", "Options", base.HEX)
fields.syn_name = ProtoField.string("dnscat2.syn.name", "Name")

fields.fin = ProtoField.none("dnscat2.fin", "Syn")
fields.fin_reason = ProtoField.string("dnscat2.fin.reason", "Reason")

fields.enc = ProtoField.none("dnscat2.enc", "Enc")
fields.enc_subtype = ProtoField.uint16("dnscat2.enc.subtype", "Subtype")
fields.enc_flags = ProtoField.uint16("dnscat2.enc.flags", "Flags", base.HEX)
fields.enc_init = ProtoField.bytes("dnscat2.enc.init", "Init")
fields.enc_auth = ProtoField.bytes("dnscat2.enc.auth", "Auth")

proto.fields = fields

local sessions = {}

function extract_from_name(data)
    -- make sure it's a string
    data = tostring(data)

    -- drop prefix
    data = data:gsub("^dnscat.", "")

    -- drop suffix (domain.tld)
    data = data:gsub("[.][^%.]+[.][^%.]+$", "")

    -- any . are noop data
    data = data:gsub("[.]", "")

    -- get the binary data
    return ByteArray.tvb(ByteArray.new(data))
end

function parse_packet(parent, tvb, pinfo, request)

    local packet_id   = tvb(0, 2)
    local packet_type = tvb(2, 1)
    local session_id  = tvb(3, 2)

    parent:add(fields.packet_raw, tvb())
    parent:add(fields.packet_id, packet_id)
    parent:add(fields.packet_type, packet_type)
    parent:add(fields.session_id, session_id)

    if not sessions[session_id:uint()] then
        sessions[session_id:uint()] = {}
        sessions[session_id:uint()].request = {}
        sessions[session_id:uint()].response = {}
    end
    local session
    local peer

    if request then
        session = sessions[session_id:uint()].request
        peer = sessions[session_id:uint()].response
    else
        session = sessions[session_id:uint()].response
        peer = sessions[session_id:uint()].request
    end

    if packet_type:uint() == 0 then
        local syn = parent:add(fields.syn, tvb(5))
        local seq = tvb(5, 2)
        syn:add(fields.syn_seq,     seq)
        syn:add(fields.syn_options, tvb(7, 2))
        syn:add(fields.syn_name,    tvb(9))

        session.seq = seq
        session.pkt = {}

    elseif packet_type:uint() == 1 then
        local msg = parent:add(fields.msg, tvb(5))
        local seq = tvb(5, 2)
        local ack = tvb(7, 2)
        local len = tvb:len() - 9
        msg:add(fields.msg_seq, seq)
        msg:add(fields.msg_ack, ack)
        if len > 0 then
            msg:add(fields.msg_data, tvb(9))
        end

        if not seq:uint() == session.seq then
            msg:add_expert_info(PI_MALFORMED, PI_ERROR, "sequence errer!")
        end
        session.seq = seq:uint() + len
        session.pkt[session.seq] = pinfo.number

        local ack_for = peer.pkt[ack:uint()]
        if peer.pkt[ack:uint()] then
            msg:add(fields.msg_ack_for, ack_for)
        end

    elseif packet_type:uint() == 2 then
        local fin = parent:add(fields.fin, tvb(5))
        fin:add(fields.fin_reason,  tvb(5))

        session.seq = nil

    elseif packet_type:uint() == 3 then
        local enc = parent:add(fields.enc, tvb(5))
        enc:add(fields.enc_subtype,  tvb(5, 2))
        enc:add(fields.enc_flags,  tvb(7, 2))
        if tvb(5, 2):uint() == 0 then
            enc:add(fields.enc_init, tvb(9))
        elseif tvb(5, 2):uint() == 1 then
            enc:add(fields.enc_auth, tvb(9))
        end
    end

end

function proto.dissector(buffer, pinfo, tree)
    local dns_qry_name = field_dns_qry_name()
    if not dns_qry_name then
        return
    end

    local response_type = field_dns_resp_type()
    if response_type then
        local subtree = tree:add(proto, "dnscat2 (response)")
        response_type = tostring(response_type)
        local tvb
        local response
        if response_type == "16" then
            tvb = ByteArray.tvb(ByteArray.new(tostring(field_dns_resp_txt())))
        elseif response_type == "15" then
            tvb = extract_from_name(field_dns_resp_mx())
        elseif response_type == "5" then
            tvb = extract_from_name(field_dns_resp_cname())
        end

        if tvb then
            parse_packet(subtree, tvb, pinfo, false)
        end
    else
        local subtree = tree:add(proto, "dnscat2 (request)")
        local tvb = extract_from_name(dns_qry_name)
        parse_packet(subtree, tvb, pinfo, true)
    end

end

register_postdissector(proto)
