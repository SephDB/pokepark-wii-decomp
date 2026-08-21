# Copies symbols between ghidra and symbols.txt so they match
# @author KooShnoo, robojumper, SephDB
# @category GameCube/Wii
# @runtime PyGhidra
from typing import Optional

# This script is based on zeldaret/ss' and KooshNoo/mkw's ghidra scripts. Thank you robojumper and KooshNoo!

DUMP_LOG = False

import re
import os
from pathlib import Path
import typing
from datetime import datetime, timezone


if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
from ghidra.app.util import NamespaceUtils
from ghidra.program.model.symbol import SymbolUtilities, SourceType, SymbolType, Symbol
from java.util import ArrayList

AddressFactory = currentProgram.getAddressFactory()

import demangle
demangle.mode = "demangle"
import postprocess_symbol

sym_re = re.compile("(.+) = \\.?([a-z0-9]+):0x([0-9A-Fa-f]{8}).*type:([^ ]*).*")
name_re = re.compile(".+( = \\.?[a-z0-9]+:0x[0-9A-Fa-f]{8}.*)")
default_name_re = re.compile("(?:lbl|fn|FUN|DAT|jumptable)(?:_[0-9]+_[a-z]+)?_[0-9A-Fa-f_]+")

def parse_sym_line(line:str) -> tuple[str,str,int,str]:
    decomp_name, section, raw_addr, symboltype = re.match(sym_re, line).groups()
    return decomp_name,section,int(raw_addr, 16),symboltype

def do_demangle(name):
    # try demangling
    if "__" in name:
        try:
            output = demangle.demangle_try(name)
            output = output.strip()
            if output != name:
                return output
        except Exception:
            pass
    # otherwise we try to undo the effects of the original
    # ghidra -> symbols.txt export here
    if "$" not in name and "arraydtor" not in name and not name.startswith("__"):
        name = name.replace("__", "::")
        name = name.replace("::::", "::__")
    return name

def is_default_name(name: str, address: int):
    if '::' in name:
        return False
    return re.search(default_name_re, name) or name.startswith("@") or name.endswith(f"_{address:x}") or name.endswith(f"_{address:X}")

def ghidra_name_of_symbol(symbol: Symbol):
    name = symbol.getName(True)

    # ghidra allows these, dtk doesn't
    name = name.replace("=", "_eq_")

    return name


# edits the symbol name for one line of symbols.txt
def rename_decomp_symbol(symbols_txt_line: str, new_name: str):
    replacement = new_name.replace('\\',r'\\')
    return re.sub(name_re, f"{replacement}\\1", symbols_txt_line)


def rename_ghidra_symbol(mangled_name: str, addr: int, create_function=False):
    demangled_name = do_demangle(mangled_name)
    name_list = postprocess_symbol.postprocess_demangled_name(demangled_name)
    name_list = [SymbolUtilities.replaceInvalidChars(part, True) for part in name_list]
    symbol_str = name_list[-1]
    namespace = None
    if len(name_list) > 1:
        namespace_str = "::".join(name_list[:-1])
        namespace = NamespaceUtils.createNamespaceHierarchy(
            namespace_str, None, currentProgram, SourceType.IMPORTED
        )

    addr_string = f"0x{addr:x}"
    addr_obj = AddressFactory.getAddress(addr_string)
    symbol = getSymbolAt(addr_obj)

    if namespace is None:
        namespace = currentProgram.getGlobalNamespace()
    if symbol:
        log.append(f"renaming at 0x{addr:x}: {symbol.name} -> {mangled_name}")
        try: 
            symbol.setNameAndNamespace(symbol_str, namespace, SourceType.IMPORTED)
        except:
            log.append(f"couldn't rename at 0x{addr:x}: {symbol.name} -> {mangled_name}")
    else:
        log.append(f"adding at 0x{addr:x}: {mangled_name}")
        createLabel(addr_obj, symbol_str, namespace, True, SourceType.IMPORTED)

    if create_function:
        createFunction(addr_obj, None)

def is_equal(mangled_name, ghidra_name):
    if mangled_name == ghidra_name:
        return True
    demangled_name = do_demangle(mangled_name)
    name_list = postprocess_symbol.postprocess_demangled_name(demangled_name)
    name_list = [SymbolUtilities.replaceInvalidChars(part, True) for part in name_list]
    name = '::'.join(name_list)
    return name == ghidra_name

always_ghidra:Optional[bool] = None

# syncs one line of symbols.txt with ghidra
# returns the updated line
def sync_symbols_txt_line(line: str):
    if len(line) < 10:
        return line
    if line[0] == "@":
        return line

    decomp_name, section, addr, symboltype = parse_sym_line(line)

    addr_string = f"0x{addr:x}"
    addr_obj = AddressFactory.getAddress(addr_string)
    symbol = getSymbolAt(addr_obj)

    if symbol is None:
        ghidra_name = None
    else:
        ghidra_name = ghidra_name_of_symbol(symbol)

    decomp_has_name = not is_default_name(decomp_name,addr)
    ghidra_has_name = ghidra_name is not None and not is_default_name(ghidra_name,addr)

    is_function = symboltype == "function"
    if is_function and (symbol is None or symbol.symbolType != SymbolType.FUNCTION):
        # dtk found a function, but ghidra didn't.
        # dtk's analysis is better than ghidra's, so we trust dtk and create a function
        log.append(f"making fn {decomp_name} at 0x{addr:x}")
        createFunction(addr_obj, decomp_name if decomp_has_name else None)

    if not decomp_has_name and not ghidra_has_name:
        # unnamed symbol, do nothing
        pass
    elif not decomp_has_name and ghidra_has_name:
        # ghidra has a name for this but symbols.txt doesn't; copy from ghidra to symbols.txt
        return rename_decomp_symbol(line, ghidra_name)
    elif decomp_has_name and not ghidra_has_name:
        # ghidra doesn't have a name for this but symbols.txt does; copy from symbols.txt to ghidra
        rename_ghidra_symbol(decomp_name, addr, create_function=is_function)
    elif decomp_has_name and ghidra_has_name and not is_equal(decomp_name,ghidra_name):
        # conflict!
        global always_ghidra
        if always_ghidra is None:
            choice = askChoice("Resolve conflict",f"Conflict at 0x{addr:x}:\ndecomp({decomp_name})\nghidra({ghidra_name})",
                               ArrayList(["Always DTK", "DTK", "Ghidra", "Always Ghidra"]), "Ghidra")
            pick_ghidra = choice.endswith("Ghidra")
            if choice.startswith("Always"):
                always_ghidra = pick_ghidra
        else:
            pick_ghidra = always_ghidra
        if pick_ghidra:
            return rename_decomp_symbol(line,ghidra_name)
        else:
            rename_ghidra_symbol(decomp_name,addr,create_function=is_function)
        log.append(f"Conflict at 0x{addr:x}: decomp({decomp_name}) ghidra({ghidra_name}) {do_demangle(decomp_name)}")

    return line


def sync_symbols_txt(symbols_txt_path):
    with open(symbols_txt_path) as f:
        symbols_txt = f.readlines()

    all_symbols = set()
    priority_symbols:dict[int,tuple[str,str]] = dict()
    for line in symbols_txt:
        symbol_name, section, addr, symboltype = parse_sym_line(line)
        all_symbols.add(symbol_name)
        _,oldsymtype = priority_symbols.get(addr,("","label"))
        if symboltype == "function" or oldsymtype != "function":
            priority_symbols[addr] = (symbol_name,symboltype)

    for i, line in enumerate(symbols_txt):
        symbol_name, section, addr, symboltype = parse_sym_line(line)
        if priority_symbols[addr][0] != symbol_name:
            # Don't sync symbols with more than one symbol per address
            continue

        updated_line = sync_symbols_txt_line(line)

        if line == updated_line:
            continue

        # skip duplicate symbols
        re_result = re.match(sym_re, updated_line)
        if re_result is None:
            print(f"Broken line output: {line} -> {updated_line}")
        new_symbol_name = re_result.groups(1)
        if new_symbol_name in all_symbols:
            continue
        all_symbols.add(new_symbol_name)
        
        symbols_txt[i] = updated_line

    with open(symbols_txt_path, "w") as f:
        f.writelines(symbols_txt)


log = []

dol_symbols_txt_path = Path(str(askFile("Select the symbols.txt to sync", "Sync Symbols")))

sync_symbols_txt(dol_symbols_txt_path)

