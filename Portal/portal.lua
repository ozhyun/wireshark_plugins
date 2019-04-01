-- @brief CMCC Portal Protocol dissector plugin
-- @author ou,zhongyun
-- @date 2018.11.22

do
	-- create a new dissector
	local NAME = "Portal"
	local PORT = 2000
	local portal = Proto(NAME, "Abloomy Portal Protocol")

	-- create fields of protocol
	local f_Ver = ProtoField.uint8("Ver", "Version", base.DEC, {[1] = "V1.0", [2] = "V2.0", [3] = "V3.0"})
	
	local portal_types = {
		[0x01] = "REQ_CHALLENGE", 
		[0x02] = "ACK_CHALLENGE", 
		[0x03] = "REQ_AUTH",
		[0x04] = "ACK_AUTH",
		[0x05] = "REQ_LOGOUT",
		[0x06] = "ACK_LOGOUT", 
		[0x07] = "AFF_ACK_AUTH", 
		[0x08] = "NTF_LOGOUT",
		[0x09] = "REQ_INFO",
		[0x0a] = "ACK_INFO"
	}
	local f_Type = ProtoField.uint8("Type", "Type", base.HEX, portal_types)
	
	local f_Papchap = ProtoField.uint8("PapChap", "PAP/CHAP", base.DEC, {[0] = "CHAP", [1] = "PAP"})
	local f_Rsv = ProtoField.uint8("Rsv", "Reserved", base.DEC)
	local f_SN = ProtoField.uint16("SerialNo", "SerialNo", base.DEC)
	local f_ReqID = ProtoField.uint16("ReqID", "ReqD", base.DEC)
	local f_UserIP = ProtoField.ipv4("UserIP", "UserIP", "STA's IP address")
	local f_UserPort = ProtoField.uint16("UserPort", "UserPort", base.DEC)
	local f_ErrCode = ProtoField.uint8("ErrCode", "ErrCode", base.DEC)
	local f_AttrNum = ProtoField.uint8("AttrNum", "AttrNum", base.DEC)
	
	portal.fields = {f_Ver, f_Type, f_Papchap, f_Rsv, f_SN, f_ReqID, f_UserIP, f_UserPort, f_ErrCode, f_AttrNum}
	
	local fields = portal.fields
	
	--[[
	fields.type = ProtoField.uint8 (NAME .. ".type", "Type")
	fields.flags = ProtoField.uint8 (NAME .. ".flags", "Flags")
	fields.seqno = ProtoField.uint16(NAME .. ".seqno", "Seq No.")
	fields.ipaddr = ProtoField.ipv4(NAME .. ".ipaddr", "IPv4 Address")
	]]
	
	-- dissect packet
	function portal.dissector (tvb, pinfo, tree)
		local subtree = tree:add(portal, tvb())
		local offset = 0
		
		-- show protocol name in protocol column
		pinfo.cols.protocol = portal.name
		
		-- dissect field one by one, and add to protocol tree
		--local type = tvb(offset, 1)
		subtree:add(f_Ver, tvb(offset, 1))
		--subtree:append_text(", type: " .. type:uint())
		offset = offset + 1
		
		subtree:add(f_Type, tvb(offset, 1))
		offset = offset + 1
		
		subtree:add(f_Papchap, tvb(offset, 1))
		offset = offset + 1
		
		subtree:add(f_Rsv, tvb(offset, 1))
		offset = offset + 1
		
		subtree:add(f_SN, tvb(offset, 2))
		offset = offset + 2
		
		subtree:add(f_ReqID, tvb(offset, 2))
		offset = offset + 2
		
		subtree:add(f_UserIP, tvb(offset, 4))
		offset = offset + 4
		
		subtree:add(f_UserPort, tvb(offset, 2))
		offset = offset + 2
		
		subtree:add(f_ErrCode, tvb(offset, 1))
		offset = offset + 1
		
		subtree:add(f_AttrNum, tvb(offset, 1))
		offset = offset + 1
		
	end

	-- register this dissector
	DissectorTable.get("udp.port"):add(PORT, portal)
end
