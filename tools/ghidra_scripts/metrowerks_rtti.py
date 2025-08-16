#TODO write a description for this script
#@author Swyter <swyterzone+ghidra@gmail.com>
#@category Games
#@keybinding Ctrl + Alt + 1
#@menupath 
#@toolbar 

'''
>>> currentProgram.getMemory().getBlock(currentProgram.getAddressFactory().getAddress("0x8080b600")).isExecute()
False
>>> currentProgram.getMemory().getBlock(currentProgram.getAddressFactory().getAddress("0x80799500")).isExecute()
True
>>> c=currentProgram.getDataTypeManager().createCategory(ghidra.program.model.data.CategoryPath("/_LOL"))
djinn.elf/_LOL
>>> currentProgram.getDataTypeManager().getRootCategory().removeEmptyCategory("_LOL", None)
True
>>> p=ghidra.program.model.data.PointerDataType(getFunctionAt(getReferencesFrom(currentAddress)[0].getToAddress()).getSignature())
>>> getFunctionAt(currentAddress).setCallingConvention("__thiscall")
>>> s=ghidra.program.model.data.StructureDataType("test", 0) # swy: create a struct; name and size
>>> ss=c.addDataType(s, ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER) # swy: returns the added clone handle, we need to edit that one from now on
>>> s.add(p)
'''


# https://github.com/ghidraninja/ghidra_scripts/blob/master/golang_renamer.py
addressFactory = currentProgram.getAddressFactory()

def addressToInt(ghidra_addr):
    return int(ghidra_addr.toString(), 16)

def intToAddress(addr):
    return addressFactory.getAddress("%x" % addr)

blocks = currentProgram.getMemory().getBlocks()
#for block in blocks:
#	print("Name: {}, Size: {}".format(block.getName(), block.getSize()))

# https://github.com/NationalSecurityAgency/ghidra/issues/1969#issuecomment-1221655969
def getUByte(address):  return getByte(address)  & 0xFF
def getUShort(address): return getShort(address) & 0xFFFF
def getUInt(address):   return getInt(address)   & 0xFFFFFFFF
def getULong(address):  return getLong(address)  & 0xFFFFFFFFFFFFFFFF

#TODO Add User Code Here

dt = getDataTypes("pointer")[0]
addr = currentAddress; max_addr = None

if currentSelection:
	addr     = currentSelection.minAddress
	max_addr = currentSelection.maxAddress.add(1)


categ = currentProgram.getDataTypeManager().createCategory(ghidra.program.model.data.CategoryPath("/_LOL"))
class_name = getSymbolAt(addr).getParentSymbol()
struc = ghidra.program.model.data.StructureDataType("%s_vtbl" % class_name, 0)
struc = categ.addDataType(struc, ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER)
struc.add(dt, "rtti", None)
struc.add(ghidra.program.model.data.IntegerDataType(), "offset", None)

i = 0
while True:
	p_addr_int = getUInt(addr)
	p_addr = currentProgram.getAddressFactory().getAddress("%x" % (p_addr_int))
	p_addr_block = currentProgram.getMemory().getBlock(p_addr)
	print(i, "%x" % (p_addr_int), p_addr, p_addr_block)

	# swy: the first entry of the vtable is the RTTI pointer (or NULL when none)
	#      the second one seems to be NULL, and the third one tends to be the
	#      destructor; any functions after that are optional.
	#      e.g. vtable[0] -> rtti[0] -> C string with class name
	#                        rtti[1] -> hierarchy[0] -> rtti_parent_a[0] -> ...
	#                                                   rtti_parent_a[1] -> ...
	#                                   hierarchy[1] = 0
	#                                   hierarchy[2] -> rtti_parent_b[0] -> C string...
	#                                                   rtti_parent_b[1] -> hierarchy_parent_b[0]
	#                                   hierarchy[1] = 0
	#                                   hierarchy[3] -> NULL (end marker, no more parent classes)
	if i == 0 and p_addr and p_addr_int != 0 and p_addr_block and not p_addr_block.isExecute():
		def fill_out_rtti_at(p_rtti_addr, level = 0):
			rtti_name = None
			def print_indent(args):
				args = ("  " * level) + args
				print(args)
			
			rtti_str_addr = intToAddress(getUInt(p_rtti_addr))
			rtti_hie_addr = intToAddress(getUInt(p_rtti_addr.add(4)))
			clearListing(p_rtti_addr, p_rtti_addr.add(4 + 4))
			createData(p_rtti_addr,        dt);
			createData(p_rtti_addr.add(4), dt);

			if addressToInt(rtti_str_addr) != 0:
				rtti_str_addr_tmp = rtti_str_addr; j = 32
				while getUByte(rtti_str_addr_tmp) != 0 or j > 0:
					clearListing(rtti_str_addr_tmp)
					rtti_str_addr_tmp = rtti_str_addr_tmp.add(1); j -= 1

				createAsciiString(rtti_str_addr)
				rtti_name = getDataAt(rtti_str_addr).getValue()
				safe_rtti_name = rtti_name.replace(' ','_')
				print_indent("  |- Found RTTI name: %s" % rtti_name)
			else:
				print_indent("  |- Empty RTTI name")

			if addressToInt(rtti_hie_addr) != 0:
				print_indent("  |- Found RTTI hierarchy at %x" % addressToInt(rtti_hie_addr))

				if rtti_name: # and not getSymbolAt(rtti_hie_addr):
					createLabel(rtti_hie_addr, safe_rtti_name + "::rtti::__hier", True) # swy: this name is fan-made

				rtti_hie_addr_tmp = rtti_hie_addr; h = 0
				while getUInt(rtti_hie_addr_tmp) != 0:
					clearListing(rtti_hie_addr_tmp, rtti_hie_addr_tmp.add(4))
					createData(rtti_hie_addr_tmp,        dt);
					createData(rtti_hie_addr_tmp.add(4), dt);

					target_addr = getUInt(rtti_hie_addr_tmp)
					print_indent("  \_ Scanning RTTI at %x (%u)" % (target_addr, h)); h += 1
					fill_out_rtti_at(intToAddress(target_addr), level + 2)
					rtti_hie_addr_tmp = rtti_hie_addr_tmp.add(4 + 4)
			else:
				print_indent("  |- Empty RTTI hierarchy")

			if rtti_name and not getSymbolAt(p_rtti_addr):
				createLabel(p_rtti_addr, safe_rtti_name + "::rtti::typeinfo", True)
			return safe_rtti_name

		print("[i] Scanning RTTI at %x" % addressToInt(p_addr))
		name = fill_out_rtti_at(p_addr)

		if name and not getSymbolAt(p_addr):
			createLabel(p_addr, name + "::__vt", True)
                break
			
	if i >= 2 and not max_addr and not p_addr_block and not p_addr_int == 0:
		print("[!] pointer points somewhere outside the valid memory range, not a pointer, bailing out...")
		break;
	if i >= 2 and not max_addr and p_addr_block and not p_addr_block.isExecute() and not p_addr_int == 0:
		print("[!] pointer points to non-executable memory; not a function, bailing out...")
		break;

	# swy: to ensure that we're the first instruction of a function we could check if the previous uint has zero/padding
	#      or a blr/bctr instruction from the end of the previous function (only if they are both perfectly aligned)
	#      unfortunately that got a lot of false negatives, and in most cases we're just trying to avoid switch case look-up pointers
	#      another property of vtables is that they shouldn't be referenced by anything directly
	if i >= 2 and not max_addr and len(getReferencesTo(addr)) > 0:
			print("[!] pointer does not seem to point to the first instruction of a function block...")
			break

	clearListing(addr, addr.add(3)) # swy: the end range must be 4 minus one to clean 4 bytes :)
	createData(addr, dt)

	if p_addr_block and p_addr_block.isExecute():

		fun = getFunctionAt(p_addr)
		print(fun,p_addr)

		if fun and fun.getName().startswith("FUN_"):
			fun.setName("vFUN_%x" % p_addr_int, ghidra.program.model.symbol.SourceType.ANALYSIS)
		
		if not fun:
			fun = createFunction(p_addr, "vFUN_%x" % p_addr_int)

		if fun.getCallingConventionName() != "__thiscall":
			fun.setCallingConvention("__thiscall")

		fun_ptr_sig = ghidra.program.model.data.PointerDataType(fun.getSignature())
		struc.add(fun_ptr_sig, fun.getName(), None)

	addr = addr.add(4); i+=1

	if i >= 2 and not max_addr and getUInt(addr) == 0 and getUInt(addr.add(4)) == 0:
		print("[!] too many upcoming NULL fields, bailing out...")
		break

	if max_addr and addr >= max_addr:
		print("[!] reached end of user selection")
		break
