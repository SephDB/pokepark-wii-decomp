#TODO write a description for this script
#@author 
#@category GameCube/Wii
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra


#TODO Add User Code Here

import typing

from ghidra.program.model.address import Address
from ghidra.program.model.listing import GhidraClass

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
from ghidra.program.model.symbol import SourceType

blocks = currentProgram.getMemory().getBlocks()

addr = currentAddress
max_addr = None

if currentSelection:
    addr = currentSelection.minAddress
    max_addr = currentSelection.maxAddress.add(1)

def get_class(vtable:Address):
    try:
        return getSymbolAt(vtable).getParentSymbol().getObject()
    except:
        return getSymbolAt(getReferencesFrom(vtable)[0].toAddress).getParentSymbol().getObject()

class_ns:GhidraClass = get_class(addr)

offset = abs(getInt(addr.add(4)))

createLabel(addr,"__vt" if offset == 0 else f"__vt0x{offset:0x}",class_ns,True,SourceType.ANALYSIS)

prefix = "virt0x" if offset == 0 else f"virt0x{offset:0x}_0x"

addr = addr.add(8)
while True:
    p_addr = None if len(getReferencesFrom(addr)) == 0 else getReferencesFrom(addr)[0].toAddress
    if p_addr is None:
        addr = addr.add(4)
        continue
    p_addr_block = currentProgram.getMemory().getBlock(p_addr)

    if not max_addr and not p_addr_block and p_addr is not None:
        print("[!] pointer points somewhere outside the valid memory range, not a pointer, bailing out...")
        break
    if not max_addr and p_addr_block and not p_addr_block.isExecute() and p_addr is not None:
        print("[!] pointer points to non-executable memory; not a function, bailing out...")
        break

    if p_addr_block and p_addr_block.isExecute():

        fun = getFunctionAt(p_addr)

        if fun.getParentNamespace().isGlobal():
            fun.setParentNamespace(class_ns)

        if fun and fun.getName().startswith(("fn_","FUN_")):
            fun.setName(f"{prefix}{addr.subtract(currentSelection.minAddress):0X}", SourceType.ANALYSIS)

        if fun.getCallingConventionName() != "__thiscall":
            fun.setCallingConvention("__thiscall")

    addr = addr.add(4)

    if max_addr and addr >= max_addr:
        print("[!] reached end of user selection")
        break