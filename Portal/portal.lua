-- @brief CMCC Portal Protocol dissector plugin
-- @author ou,zhongyun
-- @date 2019.4.4

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
	
	-- Attributes
	local f_attr_type = ProtoField.uint8("Type", "AttrType", base.HEX)
	local f_attr_len = ProtoField.uint8("Length", "AttrLength", base.DEC)
	local f_attr_value = ProtoField.string("Value", "AttrValue")
	
	-- Attr 0x01
	local f_attr_username = ProtoField.string("UserName", "UserName")
	
	-- Attr 0x02
	local f_attr_password = ProtoField.string("Password", "Password")
	
	-- Attr 0x03
	local f_attr_challenge = ProtoField.ubytes("Challenge", "Challenge")

	-- Attr 0x04
	local f_attr_chappassword = ProtoField.ubytes("ChapPassword", "ChapPassword")

	-- Attr 0x05
	local f_attr_textinfo = ProtoField.string("TextInfo", "TextInfo")
	
	-- Attr 0x0A
	local f_attr_acip = ProtoField.ipv4("AC-IP", "AC-IP", "AC's IP address")
	
	-- Attr 0x0B & 0xEE
	local f_attr_usermac = ProtoField.ether("UserMAC", "UserMAC")
	
	-- Attr 0xEF
	local f_attr_url = ProtoField.string("URL", "URL")
	
	-- Attr 0xF0 DirectAuth
	local f_attr_directauth_authtype = ProtoField.uint16("DirectAuth.AuthType", "DirectAuth.AuthType", base.DEC,
										{[0] = "NULL",
										 [1] = "UsernamePassword",
										 [4] = "SMS",
										 [5] = "APP",
										 [7] = "RealName",
										 [8] = "RoomNumber",
										 [12] = "WeChat",
										 [13] = "AuthCode",
										 [14] = "QRCode",
										 [5000] = "QQ",
										 [5001] = "QQWeibo",
										 [5002] = "SinaWeibo",
										 [5003] = "Google+",
										 [5004] = "Facebook",
										 [5005] = "Member",
										 [9999] = "TmpAuth",})
	local f_attr_directauth_rsv = ProtoField.uint16("DirectAuth.Rsv", "DirectAuth.Rsv", base.DEC)
	local f_attr_directauth_expire = ProtoField.uint32("DirectAuth.Expire", "DirectAuth.Expire", base.DEC)
	local f_attr_directauth_timestamp = ProtoField.absolute_time("DirectAuth.TimeStamp", "DirectAuth.TimeStamp", base.LOCAL)
	local f_attr_directauth_openid = ProtoField.string("DirectAuth.OpenID", "DirectAuth.OpenID")
	local f_attr_directauth_sessionsecret = ProtoField.string("DirectAuth.SessionSecret", "DirectAuth.SessionSecret")
	local f_attr_directauth_padding = ProtoField.ubytes("Padding", "Padding")
	
	-- Attr 0xF1 IdInfo
	local f_attr_idinfo_fullname = ProtoField.string("IdInfo.Fullname", "IdInfo.Fullname")
	local f_attr_idinfo_nation = ProtoField.uint16("IdInfo.Nation", "IdInfo.Nation", base.DEC)
	local f_attr_idinfo_idtype = ProtoField.uint16("IdInfo.IDType", "IdInfo.IDType", base.DEC)
	local f_attr_idinfo_id = ProtoField.string("IdInfo.ID", "IdInfo.ID")
	local f_attr_idinfo_cardtype = ProtoField.uint32("IdInfo.CardType", "IdInfo.CardType", base.DEC)
	local f_attr_idinfo_cardnumber = ProtoField.string("IdInfo.CardNumber", "IdInfo.CardNumber")
	local f_attr_idinfo_phone = ProtoField.string("IdInfo.Phone", "IdInfo.Phone")
	
	portal.fields = {f_Ver, f_Type, f_Papchap, f_Rsv, 
					f_SN, f_ReqID, 
					f_UserIP, 
					f_UserPort, f_ErrCode, f_AttrNum,
					f_attr_type, f_attr_len, f_attr_value,
					f_attr_username,
					f_attr_password,
					f_attr_challenge,
					f_attr_chappassword,
					f_attr_textinfo,
					f_attr_acip,
					f_attr_usermac,
					f_attr_url,
					f_attr_directauth_authtype, f_attr_directauth_rsv,
					f_attr_directauth_expire, f_attr_directauth_timestamp,
					f_attr_directauth_openid, f_attr_directauth_sessionsecret, f_attr_directauth_padding,
					f_attr_idinfo_fullname, f_attr_idinfo_nation, f_attr_idinfo_nation_x, f_attr_idinfo_idtype,
					f_attr_idinfo_idtype_x, f_attr_idinfo_id, f_attr_idinfo_cardtype, f_attr_idinfo_cardnumber, f_attr_idinfo_phone}
	
	local fields = portal.fields
	
	-- dissect packet
	function portal.dissector (tvb, pinfo, tree)
		local tvb_len = tvb:len()
		
		-- less than portal header
		if (tvb_len < 16) then
			return 0
		end
		
		local subtree = tree:add(portal, tvb())
		local offset = 0
		
		-- show protocol name in protocol column
		pinfo.cols.protocol = portal.name
		
		-- dissect field one by one, and add to protocol tree
		--local type = tvb(offset, 1)
		subtree:add(f_Ver, tvb(offset, 1))
		subtree:append_text("(extend CMCC V1/V2)")
		
		offset = offset + 1
		
		-- show type in 'info' column
		local pkg_type = tvb(offset, 1):uint()
		pinfo.cols.info = portal_types[pkg_type]
	
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
		
		local attrNum = tvb(offset, 1):uint()
		subtree:add(f_AttrNum, tvb(offset, 1))
		offset = offset + 1
		
		-- process Attributes
		if (attrNum > 0) then
			local attrtree = subtree:add(portal, tvb(offset, tvb_len-offset):tvb(),"Attribute Value Pairs")
			attrtree:set_text("Attribute Value Pairs")
			
			
			while (offset < tvb_len) do 
				-- TLV
				local attr_type = tvb(offset, 1):uint()
				local attr_len = tvb(offset+1, 1):uint()
				local attr_value_len = attr_len - 2
			
				if (attr_type == 0x01) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "UserName")
					tlvtree:set_text("UserName")
					tlvtree:append_text(" (" .. "CMCC V1)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_username, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
				
				elseif (attr_type == 0x02) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "Password")
					tlvtree:set_text("Password")
					tlvtree:append_text(" (" .. "CMCC V1)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_password, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
				
				elseif (attr_type == 0x03) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "Challenge")
					tlvtree:set_text("Challenge")
					tlvtree:append_text(" (" .. "CMCC V1)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_challenge, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
					
				elseif (attr_type == 0x04) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "ChapPassword")
					tlvtree:set_text("ChapPassword")
					tlvtree:append_text(" (" .. "CMCC V1)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_chappassword, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
					
				elseif (attr_type == 0x05) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "TextInfo")
					tlvtree:set_text("TextInfo")
					tlvtree:append_text(" (" .. "CMCC V2)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_textinfo, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
				
				elseif (attr_type == 0x0a) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "AC-IP")
					tlvtree:set_text("AC-IP")
					tlvtree:append_text(" (" .. "CMCC V2)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_acip, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
					
				elseif (attr_type == 0x0b) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "UserMAC")
					tlvtree:set_text("UserMAC")
					tlvtree:append_text(" (" .. "CMCC V2)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_usermac, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
					
				elseif (attr_type == 0xee) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "UserMAC")
					tlvtree:set_text("UserMAC")
					tlvtree:append_text(" (" .. "Abloomy V1, obsolete in V2)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_usermac, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
				
				elseif (attr_type == 0xef) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "URL")
					tlvtree:set_text("URL")
					tlvtree:append_text(" (" .. "Abloomy)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_url, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
					
				elseif (attr_type == 0xf0) then
					-- ugly, this attribute IS NOT match the protocol sepecification
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "DirectAuth")
					tlvtree:set_text("DirectAuth")
					tlvtree:append_text(" (" .. "Abloomy)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					
					-- Issues:
					--     1. use little-endian in protocol, unhappy
					--     2. not compile with the specification
					tlvtree:add_le(f_attr_directauth_authtype, tvb(offset, 2))
					offset = offset + 2
					tlvtree:add(f_attr_directauth_rsv, tvb(offset, 2))
					offset = offset + 2
					tlvtree:add_le(f_attr_directauth_expire, tvb(offset, 4))
					offset = offset + 4
					tlvtree:add_le(f_attr_directauth_timestamp, tvb(offset, 4))
					offset = offset + 4
					tlvtree:add(f_attr_directauth_openid, tvb(offset, 33))
					offset = offset + 33
					tlvtree:add(f_attr_directauth_sessionsecret, tvb(offset, 33))
					offset = offset + 33
					tlvtree:add(f_attr_directauth_padding, tvb(offset, 2))
					offset = offset + 2
					
					
				elseif (attr_type == 0xf1) then
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "IdInfo")
					tlvtree:set_text("IdInfo")
					tlvtree:append_text(" (" .. "Abloomy)")
					
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1

					tlvtree:add(f_attr_idinfo_nation, tvb(offset, 2))
					offset = offset + 2
					tlvtree:add(f_attr_idinfo_idtype, tvb(offset, 2))
					offset = offset + 2
					tlvtree:add(f_attr_idinfo_cardtype, tvb(offset, 4))
					offset = offset + 4
					tlvtree:add(f_attr_idinfo_fullname, tvb(offset, 65))
					offset = offset + 65
					tlvtree:add(f_attr_idinfo_id, tvb(offset, 21))
					offset = offset + 21
					tlvtree:add(f_attr_idinfo_cardnumber, tvb(offset, 33))
					offset = offset + 33
					tlvtree:add(f_attr_idinfo_phone, tvb(offset, 17))
					offset = offset + 17
					
				else
					local tlvtree = attrtree:add(portal, tvb(offset, attr_len):tvb(), "Unknown")
					tlvtree:set_text("Unknown")
					tlvtree:add(f_attr_type, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_len, tvb(offset, 1))
					offset = offset + 1
					tlvtree:add(f_attr_value, tvb(offset, attr_value_len))
					offset = offset + attr_value_len
				end
			end
			
		end
		
	end

	-- register this dissector
	DissectorTable.get("udp.port"):add(PORT, portal)
end
