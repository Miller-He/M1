Arch = gg.getTargetInfo()
local p_size = Arch.x64 and 0x8 or 0x4
local p_type = Arch.x64 and 32 or 4
gg.clearResults()
-- ===================================================================
local Region = {
    ["Ch"] = gg.REGION_C_HEAP,
    ['Cd'] = gg.REGION_C_DATA,
    ['Cb'] = gg.REGION_C_BSS,
    ['Ca'] = gg.REGION_C_ALLOC,
    ['A']  = gg.REGION_ANONYMOUS,
    ['O']  = gg.REGION_OTHER,
    ['Xa'] = gg.REGION_CODE_APP,
}
gg.setRanges(Region["Ca"] | Region["A"] | Region["O"] | Region["Cd"] | Region["Xa"])
--[[
member = "get_price_type"
gg.searchNumber(string.format("Q 00 '%s' 00", member), gg.TYPE_BYTE)
local a = gg.getResults(gg.getResultsCount((gg.refineNumber(member:byte(), 1))))

gg.clearResults()

for i,v in ipairs(a) do
    gg.searchNumber(v.address, p_type)
    if gg.getResultsCount() > 0 then
        v.name = "This is it"
        gg.addListItems({v})
        gg.clearResults()
    end
end
--]]
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
                and rangesList[i + offs].name:find("libil2cpp") and
                valid_range[rangesList[i + offs].state] then
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

    function Process_Text(address_, compare, is_byte, strict)
        address_ = is_byte and address_ or (Arch.x64 and address_  + 0x14 or address_ + 0x10)
        local result = {check = false, sees = ""}
        local string_size = is_byte and 1 or 2
        local extracted_byte, extracted_string = {}, {}
        for c = 0, 50 do
            extracted_byte[c] = {
                address = address_ + c * string_size,
                flags = 1,
            }
        end
        extracted_byte = gg.getValues(extracted_byte)
        for c = 0, 50 do
            if extracted_byte[c].value >= 32 and extracted_byte[c].value < 127 then
                table.insert(extracted_string, string.char(extracted_byte[c].value))
            else
                local extracted_string = table.concat(extracted_string)
                local match = (strict and extracted_string == compare) 
                or (not strict and string.match(extracted_string, compare))
                local text_length = #extracted_string * string_size
                result.check = match and gg.getValues({{address = address_ + text_length, flags = 1}})[1].value == 0
                result.sees = extracted_string
                break
            end
        end
        return result
    end
    
local method_address = Lib.Start + 0x34bc070
gg.setValues({{address = method_address, flags = 4, value = "~A8 MOV X0, #1"}})
gg.setValues({{address = method_address + 0x4, flags = 4, value = "~A8 RET"}})
gg.addListItems({{address = method_address, flags = 4}})

gg.setVisible(false)
gg.alert("Check the shop prices")

while not gg.isVisible() do gg.sleep(10) end

answer = gg.alert("Did the prices changed?", "Yes", "", "No")

if answer > 0 then
    gg.setRanges(Region["Ca"] | Region["A"] | Region["O"] | Region["Cd"] | Region["Xa"])
    gg.searchNumber(method_address, p_type)
    if gg.getResultsCount() > 0 then
        for i,v in ipairs(gg.getResults(gg.getResultsCount())) do
            local string_address_0 = gg.getValues({{address = v.address + (p_size * 2), flags = p_type}})[1].value
            local string_address_1 = gg.getValues({{address = v.address + (p_size * 3), flags = p_type}})[1].value
            local string_address_2 = gg.getValues({{address = v.address + (p_size * 4), flags = p_type}})[1].value
            gg.addListItems({{address = v.address + (p_size * 3), flags = 4}})
            result_0 = Process_Text(string_address_0, "[AEIOUaeiou]", true, false)
            result_1 = Process_Text(string_address_1, "[AEIOUaeiou]", true, false)
            result_2 = Process_Text(string_address_2, "[AEIOUaeiou]", true, false)
            print(result_0)
            print(result_1)
            print(result_2)
        end
    end
end