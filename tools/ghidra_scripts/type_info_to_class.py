#Turns all type_info_struct instances into a class with their own name and properly namespaced.
#@author 
#@category GameCube/Wii
#@keybinding 
#@menupath 
#@toolbar

import typing

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
from ghidra.app.util import NamespaceUtils
from ghidra.program.model.symbol import SourceType

def get_all_defined_data():
   data = getFirstData()
   while data:
      yield data
      data = getDataAfter(data)

def get_defined_structures(structure_name):
    return [data for data in get_all_defined_data() if data.isStructure() and data.getDataType().getName() == structure_name]


for a in get_defined_structures('type_info_struct'):
   sym = getSymbolAt(a.getAddress())
   if sym is None:
     sym = createLabel(a.getAddress(),"type_info_struct",True,SourceType.ANALYSIS)
   if sym.name.startswith("type_info_struct"):
     namespace = NamespaceUtils.createNamespaceHierarchy(getDataAt(a.getComponentAt(0).getValue()).getValue().replace(' ',''),None,currentProgram,SourceType.ANALYSIS)
     namespace = NamespaceUtils.convertNamespaceToClass(namespace)
     sym.doSetNameAndNamespace('__RTTI',namespace,SourceType.ANALYSIS,True)


