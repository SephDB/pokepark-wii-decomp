# Aggressively finds data references to symbols known to dtk
# @author SephDB
# @category GameCube/Wii
# @runtime PyGhidra
from typing import Optional

import re
from pathlib import Path
import typing
from datetime import datetime, timezone

from docking.widgets.filechooser import GhidraFile
from ghidra.app.plugin.core.analysis import ReferenceAddressPair
from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.data import Pointer, PointerDataType
from ghidra.program.util import ProgramMemoryUtil
from ghidra.util.datastruct import CallbackAccumulator
from java.util import ArrayList #type: ignore

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *


sym_re = re.compile("(.+) = \\.?([a-z0-9]+):0x([0-9A-Fa-f]{8}).*type:([^ ]*).*")

def get_sym_address(symbol:str) -> Address:
    decomp_name, section, raw_addr, symboltype = re.match(sym_re, symbol).groups()
    return getAddressFactory().getAddress(raw_addr)

symbols:GhidraFile = askFile("symbols.txt","OK")

def handle_found_ref(ref: ReferenceAddressPair):
    source = ref.getSource()

    if currentProgram.getMemory().getBlock(source).execute:
        # Don't pick up false references in code
        return

    if len(getReferencesFrom(source)) == 0:
        print(f"{ref.getSource()} -> {ref.getDestination()}")
        clearListing(source,source.add(4))
        createData(source,getDataTypes("pointer")[0])

def find_references():
    addresses = AddressSet()

    with open(symbols.getAbsolutePath()) as f:
        lines = f.readlines()
        monitor.initialize(len(lines),f"Parsing symbols.txt")
        for line in lines:
            monitor.increment()
            addr = get_sym_address(line.rstrip('\n'))
            addresses.add(addr)

    accum = CallbackAccumulator(handle_found_ref)

    monitor.setMessage("Scanning for references")
    ProgramMemoryUtil.loadDirectReferenceList(currentProgram,4, addresses.minAddress, addresses, accum, monitor)


find_references()


