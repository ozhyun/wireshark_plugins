-- @brief Abloomy Positioning Engine Protocol
-- @author ou,zhongyun
-- @date 2019.4.25

do
	-- create a new dissector
	local NAME = "Position"
	local PORT = 9999
	local protocol = Proto(NAME, "Abloomy Positioning Protocol")

	
	-- create fields of protocol
	local f_type = ProtoField.uint8("Type", "Type", base.DEC)
	local f_len = ProtoField.uint8("Len", "Length", base.DEC)
	local f_rsv = ProtoField.uint8("Rsv", "Rsv", base.DEC)
	local f_stamac = ProtoField.ether("STAMAC", "StationMAC")
	local f_sid = ProtoField.uint32("SID", "SequenceID", base.DEC)
	local f_apmac = ProtoField.ether("APMAC", "APMAC")
	local f_x = ProtoField.double("X-axle", "X-axle")
	local f_y = ProtoField.double("Y-axle", "Y-axle")
	local f_z = ProtoField.double("Z-axle", "Z-axle")
	local f_mapid = ProtoField.uint32("MapID", "MapID", base.HEX)
	local f_crc = ProtoField.string("CRC", "CRC")
	
	protocol.fields = {f_type, f_len, f_rsv, 
					f_stamac, f_sid, 
					f_apmac, 
					f_x, f_y,
					f_z,
					f_mapid,
					f_crc}
	
	
	
-- dissect packet
	function protocol.dissector (tvb, pinfo, tree)
		local tvb_len = tvb:len()
		
		-- less than protocol header
		if (tvb_len < 16) then
			return 0
		end
		
		local subtree = tree:add(protocol, tvb())
		local offset = 0
		
		-- show protocol name in protocol column
		pinfo.cols.protocol = protocol.name
		
		-- dissect field one by one, and add to protocol tree
		--local type = tvb(offset, 1)
		subtree:add(f_type, tvb(offset, 1))
		--subtree:append_text("(Abloomy private)")
		offset = offset + 1
	
		subtree:add(f_len, tvb(offset, 1))
		offset = offset + 1
		
		subtree:add(f_rsv, tvb(offset, 1))
		offset = offset + 1
		
		subtree:add(f_stamac, tvb(offset, 6))
		local stamac = tvb(offset, 6):ether()
		-- show type in 'info' column
		-- pinfo.cols.info = 'STA:' .. stamac
		offset = offset + 6
		
		subtree:add(f_sid, tvb(offset, 4))
		offset = offset + 4
		
		subtree:add(f_apmac, tvb(offset, 6))
		offset = offset + 6
		
		subtree:add_le(f_x, tvb(offset, 8))
		offset = offset + 8
		
		subtree:add_le(f_y, tvb(offset, 8))
		offset = offset + 8
	
		subtree:add_le(f_z, tvb(offset, 8))
		offset = offset + 8
		
		subtree:add(f_mapid, tvb(offset, 4))
		offset = offset + 4
		
		subtree:add(f_crc, tvb(offset, 4))
		offset = offset + 4
	end
	

	-- register this dissector
	DissectorTable.get("udp.port"):add(PORT, protocol)
end
