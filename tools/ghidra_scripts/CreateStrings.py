# Hard recreates all strings known by dtk
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


sym_re = re.compile("(.+) = \\.?([a-z0-9]+):0x([0-9A-Fa-f]{8}).*type:([^ ]*).*size:([^ ]+).*")

def get_sym_address(symbol:str) -> tuple[Address, int]:
    decomp_name, section, raw_addr, symboltype, length = re.match(sym_re, symbol).groups()
    return getAddressFactory().getAddress(raw_addr), int(length,16)

symbols:GhidraFile = askFile("symbols.txt","OK")

def find_strings():
    with open(symbols.getAbsolutePath()) as f:
        lines = f.readlines()
        for line in lines:
            if "data:string" not in line:
                continue
            addr, l = get_sym_address(line.rstrip('\n'))
            clearListing(addr,addr.add(l))
            createAsciiString(addr,l)


find_strings()


