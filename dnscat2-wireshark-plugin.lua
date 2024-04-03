print("dnscat2 dissector loading")


proto = Proto("dnscat2", "dnscat2 dissector")


field_dns_qry_name = Field.new("dns.qry.name")

field_dns_resp_type = Field.new("dns.resp.type")
field_dns_resp_cname = Field.new("dns.cname")
field_dns_resp_mx = Field.new("dns.mx.mail_exchange")
field_dns_resp_txt = Field.new("dns.txt")


fields = {}

local packet_type_table = {
    [0] = "SYN",
    [1] = "MSG",
    [2] = "FIN",
    [3] = "ENC",
    [0xff] = "PING",
}

local request_type_table = {
    [true] = "Q",
    [false] = "R"
}

fields.packet_raw = ProtoField.bytes("dnscat2.packet_raw","Packet")
fields.packet_id = ProtoField.uint16("dnscat2.packet_id", "Id")
fields.packet_type = ProtoField.uint8("dnscat2.packet_type", "Type", base.HEX, packet_type_table)
fields.session_id = ProtoField.uint16("dnscat2.session_id", "Session")
fields.packet_req = ProtoField.bool("dnscat2.packet_req","Request")

fields.msg = ProtoField.none("dnscat2.msg", "Msg")
fields.msg_seq = ProtoField.uint16("dnscat2.msg.seq", "Seq")
fields.msg_ack = ProtoField.uint16("dnscat2.msg.ack", "Ack")
fields.msg_ack_for = ProtoField.framenum("dnscat2.msg.ack_for", "Ack for", base.NONE, frametype.ACK)
fields.msg_data = ProtoField.string("dnscat2.msg.data","Data")

fields.syn = ProtoField.none("dnscat2.syn", "Syn")
fields.syn_seq = ProtoField.uint16("dnscat2.syn.seq", "Seq")
fields.syn_options = ProtoField.uint16("dnscat2.syn.seq", "Options", base.HEX)
fields.syn_name = ProtoField.string("dnscat2.syn.name", "Name")

SYN_OPT_NAME = 0x01
SYN_OPT_COMMAND = 0x20

fields.fin = ProtoField.none("dnscat2.fin", "Syn")
fields.fin_reason = ProtoField.string("dnscat2.fin.reason", "Reason")

fields.enc = ProtoField.none("dnscat2.enc", "Enc")
fields.enc_subtype = ProtoField.uint16("dnscat2.enc.subtype", "Subtype")
fields.enc_flags = ProtoField.uint16("dnscat2.enc.flags", "Flags", base.HEX)
fields.enc_init = ProtoField.bytes("dnscat2.enc.init", "Init")
fields.enc_auth = ProtoField.bytes("dnscat2.enc.auth", "Auth")

fields.cmd = ProtoField.none("dnscat2.cmd", "Command")
fields.cmd_packed_id = ProtoField.uint16("dnscat2.cmd.packed_id", "Packed Id", base.HEX)

local command_id_table = {
    [0] = "Ping",
    [1] = "Shell",
    [2] = "Exec",
    [3] = "Download",
    [4] = "Uplaod",
    [5] = "Shutdown",
    [6] = "Delay"
}

fields.cmd_command_id = ProtoField.uint16("dnscat2.cmd.command_id", "Command", base.HEX, command_id_table)
fields.cmd_data = ProtoField.bytes("dnscat2.cmd.data", "Data")

fields.segment = ProtoField.none("dnscat2.segment", "Segment")
fields.segment_data = ProtoField.bytes("dnscat2.segment.data", "Data")
fields.segment_len = ProtoField.uint32("dnscat2.segment.len", "Length")
fields.segment_pos = ProtoField.uint32("dnscat2.segment.pos", "Position")

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

function parse_cmd_complete(parent, conn, tvb, pinfo)
    local cmd = parent:add(fields.cmd, tvb())
    local packed_id = tvb(0, 2)
    local command_id = tvb(2, 2)
    local data = tvb(4)
    cmd:add(fields.cmd_packed_id, packed_id)
    cmd:add(fields.cmd_command_id, command_id)
    cmd:add(fields.cmd_data, data)

    local command = command_id:uint()
    pinfo.cols.info:append(": " .. command_id_table[command_id:uint()])
    if bit32.band(packed_id:uint(), 0x8000) == 0 then
        if command == 3 then
            pinfo.cols.info:append(": " .. data:string():gsub("[\n\r]", " "))
        end
    else
        pinfo.cols.info:append(" Response: ...")
    end
end

function parse_cmd(parent, conn, tvb, pinfo)    

    local prev = conn.pkt.prev
    local pkt = conn.pkt

    if pkt.seq_next == prev.seq_next then
        pkt.len = prev.len
        pkt.pos = prev.pos
        pkt.data = prev.data
    elseif prev.pos + prev.data:len() >= prev.len then
        pkt.len = tvb(0, 4):uint()
        pkt.pos = 0
        pkt.data = tvb(4):bytes()
    else
        pkt.len = prev.len
        pkt.pos = prev.pos + prev.data:len()
        pkt.data = tvb():bytes()
    end

    local seg = parent:add(fields.segment, tvb())
    seg:add(fields.segment_len, pkt.len)
    seg:add(fields.segment_pos, pkt.pos)

    if pkt.pos + pkt.data:len() >= pkt.len then
        local data = ByteArray.new()
        data:prepend(pkt.data)
        while pkt.pos ~= 0 do
            local seq = pkt.seq_next
            repeat
                pkt = pkt.prev
            until seq ~= pkt.seq_next

            data:prepend(pkt.data)
        end
        
        tvb = data:tvb()
        parse_cmd_complete(parent, conn, tvb, pinfo)
    else
        pinfo.cols.info:append(": Segment")
    end
end

function new_packet(prev)
    return {
        prev = prev,
        pos = 0,
        len = 0,
        data = ByteArray.new(),
        seq_next = nil,
    }
end

function new_conn()
    return {
        seq = nil,
        seq_seen = {},
        pkt_seen = {},
        pkt = new_packet(nil)
    }
end

function parse_packet(parent, tvb, pinfo, request)

    local packet_id   = tvb(0, 2)
    local packet_type = tvb(2, 1)
    local session_id  = tvb(3, 2)

    parent:add(fields.packet_raw, tvb())
    parent:add(fields.packet_id, packet_id)
    parent:add(fields.packet_type, packet_type)
    parent:add(fields.packet_req, request)
    parent:add(fields.session_id, session_id)

    local session = sessions[session_id:uint()]
    if not session then
        session = {
            request = new_conn(),
            response = new_conn(),
            opt = 0
        }
        sessions[session_id:uint()] = session
    end

    pinfo.cols.info = request_type_table[request] .. ": " .. packet_type_table[packet_type:uint()]

    local conn
    local peer
    if request then
        conn = session.request
        peer = session.response
    else
        conn = session.response
        peer = session.request
    end

    if pinfo.visited then
        conn.pkt = conn.pkt_seen[pinfo.number]
    else
        local pkt = new_packet(conn.pkt)
        conn.pkt_seen[pinfo.number] = pkt
        conn.pkt = pkt
    end

    if packet_type:uint() == 0 then
        local syn = parent:add(fields.syn, tvb(5))
        local seq = tvb(5, 2)
        local opt = tvb(7, 2)
        local name = tvb(9)
        syn:add(fields.syn_seq,     seq)
        syn:add(fields.syn_options, opt)
        syn:add(fields.syn_name,    tvb(9))

        conn.pkt.seq_next = seq:uint()
        if request then
            session.opt = opt:uint()
        end
        pinfo.cols.info:append(": " .. name:string())

    elseif packet_type:uint() == 1 then
        local msg = parent:add(fields.msg, tvb(5))
        local seq = tvb(5, 2)
        local ack = tvb(7, 2)
        local len = tvb:len() - 9
        msg:add(fields.msg_seq, seq)
        msg:add(fields.msg_ack, ack)

        conn.pkt.seq_next = seq:uint() + len
        if conn.pkt.seq_next == conn.pkt.prev.seq_next then
            msg:add_expert_info(PI_SEQUENCE, PI_NOTE, "sequence resend")
        elseif seq:uint() ~= conn.pkt.prev.seq_next then
            msg:add_expert_info(PI_SEQUENCE, PI_ERROR, "sequence error!")
        end

        if len > 0 then
            msg:add(fields.msg_data, tvb(9))
            if bit32.band(session.opt, SYN_OPT_COMMAND) ~= 0 then
                parse_cmd(parent, conn, tvb(9):tvb(), pinfo)
            end
        end

        conn.seq_seen[conn.pkt.seq_next] = pinfo.number
        local ack_for = peer.seq_seen[ack:uint()]
        if ack_for then
            msg:add(fields.msg_ack_for, ack_for)
        end

    elseif packet_type:uint() == 2 then
        local fin = parent:add(fields.fin, tvb(5))
        fin:add(fields.fin_reason,  tvb(5))

        conn.seq = nil

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

    pinfo.cols.protocol = "DNSCAT2"

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
