Arch = gg.getTargetInfo()
local p_size = Arch.x64 and 0x8 or 0x4
local p_type = Arch.x64 and 32 or 4
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
