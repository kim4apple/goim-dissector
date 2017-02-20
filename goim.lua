do
  -- GOIM 定义协议
  local op_codes = {
    [0] = "OP_HANDSHAKE",
    [1] = "OP_HANDSHAKE_REPLY",
    [2] = "OP_HEARTBEAT",
    [3] = "OP_HEARTBEAT_REPLY",
    [4] = "OP_SEND_SMS",
    [5] = "OP_SEND_SMS_REPLY",
    [7] = "OP_AUTH",
    [8] = "OP_AUTH_REPLY",
    [100] = "OP_REPORT_VIEW_ID",
    [101] = "OP_REPORT_VIEW_ID_REPLY",
    [102] = "OP_CLIENT_CMD",
    [103] = "OP_CLIENT_CMD_REPLY"}

  local goim_proto = Proto("GOIM-Bin", "GO IM Binary Protocol.");

  local p_len = ProtoField.uint32("Goim.length", "Package Length", base.DEC)
  local p_header_len = ProtoField.uint16("Goim.header_len", "Header Length", base.DEC)
  local p_version = ProtoField.uint16("Goim.version", "Version", base.DEC)
  local p_op = ProtoField.uint32("Goim.op", "Operation", base.DEC, op_codes)
  local p_seq = ProtoField.uint32("Goim.squence", "Sequence", base.DEC)
  local p_payload = ProtoField.string("Goim.payload","Payload")

  goim_proto.fields = {p_len, p_header_len, p_version, p_op, p_seq, p_payload}


  -- 协议分析函数
  function goim_proto.dissector(buf, pkt, root)
    -- 是否可以解析package_length
    local buf_len = buf:len();
    if buf_len < 4 then return false end

    -- 是否包是否完整
    local package_length = buf(0, 4):uint();
    if package_length < buf:len() then return false end

    local t = root:add(goim_proto, buf(0,package_length), "GoIM Binary")
    pkt.cols.protocol = "GOIM"
    pkt.cols.info = "seq="..buf(12,4):uint()..", op=" .. op_codes[buf(8,4):uint()]

    -- 协议解析
    t:add(p_len, buf(0,4))
    t:add(p_header_len, buf(4,2))
    t:add(p_version, buf(6,2))
    t:add(p_op, buf(8,4))
    t:add(p_seq, buf(12,4))
    t:add(p_payload, buf(16, package_length - 16))

    return true
  end

  local tcp_encap_table = DissectorTable.get("tcp.port")
  tcp_encap_table:add(8071, go_proto)
end
