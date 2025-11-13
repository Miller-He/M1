Arch = gg.getTargetInfo()
local p_size = Arch.x64 and 0x8 or 0x4
local p_type = Arch.x64 and 32 or 4
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
gg.setRanges(Region["Ca"], Region["A"], Region["O"])
member = "get_price_type"
gg.searchNumber(string.format("Q 00 '%s' 00", member), gg.TYPE_BYTE)