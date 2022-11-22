do
    --协议名称为DT，在Packet Details窗格显示为Nselab.Zachary DT
    local p_DT = Proto("VCI8","KunYi VCI")
    --协议的各个字段,client 
    local f_framesize = ProtoField.uint16("VCI.framesize","Frame Size", base.DEC)
    --这里的base是显示的时候的进制，详细可参考https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField
    local f_frameid = ProtoField.uint16("VCI.frameid", "Frame Id", base.HEX)
    local f_canrsvd = ProtoField.uint16("VCI.cansvd", "CAN RSVD", base.HEX)
    local f_canid = ProtoField.uint16("VCI.canid", "CAN ID", base.HEX)
    local f_candatalen = ProtoField.uint16("VCI.candatalen", "CAN Data Length", base.HEX)
    local f_candata = ProtoField.bytes("VCI.candata", "CAN Data", base.SPACE)

    --协议的各个字段,server
    --协议的各个字段
    local f_sn = ProtoField.uint32("VCIS.sn","Serial Number", base.HEX)

    --这里把DT协议的全部字段都加到p_DT这个变量的fields字段里
    p_DT.fields = {f_framesize, f_frameid, f_data, f_canrsvd, f_canid, f_candatalen, f_candata, f_sn}    
    --这里是获取data这个解析器
    local data_dis = Dissector.get("data")
    
    local function int16swap(num)
        res=0
        for var=2,1,-1 do
            res=res*256+num%256
            num=math.floor(num/256)
        end
        return res
    end

    local function int32swap(num)
        res=0
        for var=4,1,-1 do
            res=res*256+num%256
            num=math.floor(num/256)
        end
        return res  
    end

    local function DT_dissector_client(buf, pkt, root)

        local buf_len = buf:len();
        --先检查报文长度，太短的不是我的协议
        if buf_len < 2 then
            return false
        end

        local v_framesize_d = buf(0,2)
        local v_framesize = buf(0, 2):uint()
        local v_frameid_d = buf(2,2)
        local v_frameid = buf(2, 2):uint()
        local v_data
        if v_framesize  > 2 then
            v_canrsvd = buf(4, 2)
            v_canid = buf(6, 2)
            v_candatalen = buf(8, 2)
            v_candatalen_d = int16swap(buf(8,2):uint())
            v_candata = buf(10, v_framesize - 8)
        end

        --现在知道是我的协议了，放心大胆添加Packet Details
        local t = root:add(p_DT,buf)
        --在Packet List窗格的Protocol列可以展示出协议的名称
        pkt.cols.protocol = "VCI8"
        --这里是把对应的字段的值填写正确，只有t:add过的才会显示在Packet Details信息里. 所以在之前定义fields的时候要把所有可能出现的都写上，但是实际解析的时候，如果某些字段没出现，就不要在这里add
        t:add(f_framesize,v_framesize_d)
        if v_frameid == 0x0110 then
            t:add(f_frameid,v_frameid_d):append_text(" (Heartbeat)")
        else
            if v_frameid >= 5 and v_frameid <= 9 then
                t:add(f_frameid,v_frameid_d):append_text(" (Can Channel "..(v_frameid - 5)..")")
            else
                t:add(f_frameid,v_frameid_d)
            end
        end
        if v_framesize  > 2 then
            t:add(f_canrsvd, v_canrsvd)
            t:add(f_canid, v_canid)
            t:add(f_candatalen, v_candatalen):append_text(" ("..v_candatalen_d.." bytes)")
            t:add(f_candata, v_candata)
        end
        return true    
    end

    local function DT_dissector_server(buf, pkt, root)
        local v_sn = buf(0,4)
        local v_sn_d = int32swap(buf(0, 4):uint())
   
        --现在知道是我的协议了，放心大胆添加Packet Details
        local t = root:add(p_DT,buf)
        --在Packet List窗格的Protocol列可以展示出协议的名称
        pkt.cols.protocol = "VCI8"
        --这里是把对应的字段的值填写正确，只有t:add过的才会显示在Packet Details信息里. 所以在之前定义fields的时候要把所有可能出现的都写上，但是实际解析的时候，如果某些字段没出现，就不要在这里add
        t:add(f_sn,v_sn):append_text(" ("..v_sn_d..")")
        return true
    end

    local function DT_dissector(buf,pkt,root)
        --过滤目的端口
        if pkt.dst_port == 8183 then
            return DT_dissector_client(buf,pkt,root)
        end

        if pkt.src_port == 8183 then
            return DT_dissector_server(buf,pkt,root)
        end

        return true
    end
    
    --这段代码是目的Packet符合条件时，被Wireshark自动调用的，是p_DT的成员方法
    function p_DT.dissector(buf,pkt,root) 
        if DT_dissector(buf,pkt,root) then
            --valid DT diagram
        else
            --data这个dissector几乎是必不可少的；当发现不是我的协议时，就应该调用data
            data_dis:call(buf,pkt,root)
        end
    end
    
    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(8183, p_DT)
end