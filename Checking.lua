Arch = gg.getTargetInfo()
local p_size = Arch.x64 and 0x8 or 0x4
local p_type = Arch.x64 and 32 or 4
    function FindLib()
        local libil2cpp_ranges = gg.getRangesList("libil2cpp")
        if #libil2cpp_ranges > 0 and #libil2cpp_ranges <= 2 then
            for i,v in ipairs(libil2cpp_ranges) do
                if gg.getValues({{address = v.start,flags = 4}})[1].value == 0x464C457F then
                    return {Start = v.start, End = v["end"]}
                end
            end
        end
        
        local valid_range = { ["Cd"] = true, ["Xa"] = true }
        local cluster_store, seen = {}, {}
        local rangesList = gg.getRangesList()
        local min_size = 3
        for i, v in ipairs(rangesList) do
            if valid_range[v.state] and v.name:find("libil2cpp") then
                local count = 0
                for offs = -5, 5 do
                    if offs ~= 0 and rangesList[i + offs]
                    and rangesList[i + offs].name:find("libil2cpp") and valid_range[rangesList[i + offs].state] then
                    count = count + 1
                    end
                end
                if count >= min_size and not seen[v.start] then
                    seen[v.start] = true
                    table.insert(cluster_store, v)
                end
            end
        end
        for _,v in ipairs(cluster_store) do
            local val = gg.getValues({{address = v.start, flags = gg.TYPE_DWORD}})[1].value
            if val == 0x464C457F then
                e_phnum = gg.getValues({{address = v.start + (Arch.x64 and 0x38 or 0x2C), flags = 2}})[1].value
                e_phoff = gg.getValues({{address = v.start + (Arch.x64 and 0x20 or 0x1C), flags = 4}})[1].value
                local PHstart = v["start"] + e_phoff
                local PHcount = e_phnum
                for index=1, PHcount do
                    local offsetDiff =  (index-1)*(Arch.x64 and 0x38 or 0x20)
                    local programHeader = {
                        ["p_type"]   = {address = PHstart + offsetDiff, flags = 4},
                        ["p_flags"]  = {address = PHstart + offsetDiff + (Arch.x64 and 0x4 or 0x18), flags = 4},
                        ["p_vaddr"]  = {address = PHstart + offsetDiff + (Arch.x64 and 0x10 or 0x8), flags = p_type},
                        ["p_filesz"] = {address = PHstart + offsetDiff + (Arch.x64 and 0x20 or 0x10), flags = p_type},
                        ["p_memsz"]  = {address = PHstart + offsetDiff + (Arch.x64 and 0x28 or 0x14), flags = p_type},
                    }
                    programHeader = gg.getValues(programHeader)
                    local programType = programHeader["p_type"].value
                    local virtualAddr = programHeader["p_vaddr"].value
                    local fileSize = programHeader["p_filesz"].value
                    local virtualSize = programHeader["p_memsz"].value
                    local programFlags = programHeader["p_flags"].value
                    if programType == 1 and programFlags == 6 and fileSize<virtualSize then
                        end_point = v["start"] + virtualAddr + fileSize
                        return {Start = v.start, End = end_point}
                    end
                end
                return {Start = v.start, End = cluster_store[#cluster_store]["end"]}
            end
        end
        local biggest_split = nil
        for i,v in ipairs(gg.getRangesList()) do
            if v.state == "Xa" and v.name:find("split_config") then
                if not biggest_split or (v["end"] - v.start) > (biggest_split["end"] - biggest_split.start) then
                    biggest_split = v
                end
            end
        end
        if biggest_split then 
            return {Start = biggest_split.start, End = biggest_split["end"]}
        end
        
        gg.toast("⛔ Can't Find Libil2cpp. Exiting....")
        os.exit()
    end
    Lib = FindLib()
-- ===================================================================
    function FindMetadata()
        gg.clearResults()
        local candidate = {}
        gg.setRanges(gg.REGION_C_ALLOC | gg.REGION_ANONYMOUS | gg.REGION_OTHER)
        if next(gg.getRangesList("global-metadata.dat")) then
            candidate[1] =  {Start = gg.getRangesList("global-metadata.dat")[1].start, 
            End = gg.getRangesList("global-metadata.dat")[1]["end"]}
            gg.searchNumber("h 00 67 65 74 5F 66 69 65 6C 64 4F 66 56 69 65 77 00", 1, false, gg.SIGN_EQUAL,
            candidate[1].Start, candidate[1].End)
            if gg.getResultsCount() > 0 then
                return candidate[1]
            end
        end
    
        local searchMemoryRange = {
            gg.REGION_C_ALLOC,
            gg.REGION_ANONYMOUS,
            gg.REGION_OTHER,
            gg.REGION_C_HEAP,
        } --if you want to search all regions, use following value -1.
        
        for i, v in ipairs(searchMemoryRange) do
            gg.setRanges(v)
            gg.setVisible(false)
            gg.searchNumber("h 00 67 65 74 5F 66 69 65 6C 64 4F 66 56 69 65 77 00", 1)
            local res = gg.getResults(gg.getResultsCount())
            gg.clearResults()
            if #res>0 then
                for ii, vv in ipairs(gg.getRangesList()) do
                    if res[1].address < vv["end"] and res[1].address > vv["start"] then
                        candidate[2] = {Start = vv.start, End = vv["end"]}
                        return candidate[2]
                    end
                end
            end
        end
        
        return nil
    end
    Metadata = FindMetadata()
    function FixAddress(val)
        if not Arch.x64 then
            return val & 0xFFFFFFFF
        end
        if val < 0 or (val & 0xFFFF000000000000) == 0xFFFF000000000000 then
            return val & 0x00FFFFFFFFFFFFFF
        end
        return val
    end
-- ======================================================== 
if Metadata.Start and Metadata.End then print("Found Metadata") end
if Lib.Start and Lib.End then print("Found Libil2cpp.so") end

if Metadata.Start then
    local Region = {
            ["Ch"] = gg.REGION_C_HEAP,
            ['Cd'] = gg.REGION_C_DATA,
            ['Cb'] = gg.REGION_C_BSS,
            ['Ca'] = gg.REGION_C_ALLOC,
            ['A']  = gg.REGION_ANONYMOUS,
            ['O']  = gg.REGION_OTHER,
            ['Xa'] = gg.REGION_CODE_APP,
    }
    gg.setRanges(Region["Ch"] | Region["Cd"] | Region["Cb"] | Region["Ca"] | Region["A"] | Region["O"] | Region["Xa"])
    member = "get_price_type"
    gg.searchNumber(string.format("Q 00 '%s' 00", member), gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 
        Metadata and Metadata.Start or 0, Metadata and Metadata.End or -1)
    local str = gg.getResults(gg.getResultsCount(gg.refineNumber(member:byte(), 1)))
    gg.clearResults()
    if #str > 0 then
        print("Found String")
    else
        print("Found No String")
        gg.setVisible(true)
        return
    end
    gg.searchNumber(FixAddress(str[1].address), p_type) -- gg.searchPointer(0)
    local ptr = gg.getResults(gg.getResultsCount())
    gg.clearResults()
    if #ptr == 0 then
        if gg.getResultsCount() < 1 and Arch.x64 then
            gg.searchNumber(FixAddress(str[1].address) | 0xB400000000000000, p_type)
        end
        if gg.getResultsCount() < 1 then
            print("Found No Pointer")
            gg.setVisible(true)
            return
        end      
    end
    print("Found Pointer")
    gg.setVisible(true)
end