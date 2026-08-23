#Turns all type_info_struct instances into a class with their own name and properly namespaced.
#@author 
#@category GameCube/Wii
#@keybinding 
#@menupath 
#@toolbar

import typing

from ghidra.program.model.address import Address

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
from ghidra.app.util import NamespaceUtils
from ghidra.program.model.listing import Data
from ghidra.program.model.symbol import SourceType

class TypeInfo:
    def __init__(self, data:Data):
        self.data = data

    def typename_address(self) -> Address:
        return typing.cast(Address,self.data.getComponent(0).getValue())

    def typename(self):
        return getDataAt(self.typename_address()).getValue()

    def has_bases(self):
        return typing.cast(Address,self.data.getComponent(1).getValue()) != toAddr(0)

    def namespace(self):
        return NamespaceUtils.createNamespaceHierarchy(self.typename().replace(' ',''),None,currentProgram,SourceType.ANALYSIS)



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


