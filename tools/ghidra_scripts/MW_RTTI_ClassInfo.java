//
//@author Seph De Busser
//@category GameCube/Wii
//@keybinding
//@menupath
//@toolbar

import java.util.HashMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolUtilities;
import mw_rtti.MWClassInfo;

public class MW_RTTI_ClassInfo extends GhidraScript {
	
	private static final String RTTI_Category = "RTTI";
	private static final CategoryPath RTTI_Path = new CategoryPath(CategoryPath.ROOT, RTTI_Category); 
	
	private HashMap<Address, MWClassInfo> FoundClasses = new HashMap<Address, MWClassInfo>();
	
	@Override
	protected void run() throws Exception {
		var dtm = currentProgram.getDataTypeManager();
		
		var RTTI = dtm.getCategory(RTTI_Path);
		
		if(RTTI == null || RTTI.getDataTypes().length == 0) {
			RTTI = dtm.createCategory(RTTI_Path);
			var VtableType = new StructureDataType(RTTI_Path, "VTableHeader", 0, dtm);
			var TypeInfo = new StructureDataType(RTTI_Path, "type_info_struct",0,dtm);
			var TypeInfoBase = new StructureDataType(RTTI_Path, "type_info_base_list",0,dtm);
			
			TypeInfoBase.add(new PointerDataType(TypeInfo,dtm),"baseTypeInfo","");
			TypeInfoBase.add(SignedDWordDataType.dataType,"offset","");
			
			TypeInfo.add(new PointerDataType(TerminatedStringDataType.dataType,dtm), "typeName", "");
			TypeInfo.add(new PointerDataType(TypeInfoBase,dtm), "baseList", "0-terminated list of bases");			

			VtableType.add(new PointerDataType(TypeInfo,dtm),"typeInfo","");
			VtableType.add(SignedDWordDataType.dataType,"offset","");
			
			//Commit by adding the top-level VtableType to dtm explicitly
			dtm.addDataType(VtableType, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		
		TryAddVtable(currentAddress);
	}
	
	private MWClassInfo TryAddVtable(Address address) {
		if(!isDataMemory(address)) {
			println(address.toString("Trying to parse vtable not in constant memory:"));
			return null;
		}
		Address type_info_ptr = TryGetPointer(address);
		if(type_info_ptr == null) {
			println(address.toString("Invalid pointer at"));
			return null;
		}
		TryAddTypeInfo(type_info_ptr);
		return null;
	}
	
	private MWClassInfo TryAddTypeInfo(Address address) {
		if(!isDataMemory(address)) {
			println(address.toString("Trying to parse type info not in constant memory:"));
			return null;
		}
		MWClassInfo ret = FoundClasses.get(address);
		if(ret != null) {
			return ret;
		}
		Address name_ptr = TryGetPointer(address);
		if(name_ptr == null) {
			println("Couldn't find type info at "+address.toString());
			return null;
		}
		String name = TryGetName(name_ptr);
		if(name == null) {
			println("Failed to parse class name at "+name_ptr.toString());
			return null;
		}
		println("Found typeinfo for "+name);
		return null;
	}
	
	private String TryGetName(Address address) {
		if(!isDataMemory(address)) {
			println(address.toString("Trying to parse string not in constant memory"));
			return null;
		}
		
		StringBuilder builder = new StringBuilder();
		while(true) {
			char c;
			try {
				c = (char) getByte(address);
			} catch (MemoryAccessException e) {
				println("Invalid address for string! "+address.toString());
				return null;
			}
			
			if(c == 0) {
				return builder.toString();
			}
			
			if(SymbolUtilities.isInvalidChar(c) && c != ' ') {
				println("Encountered invalid character! "+address.toString());
			}
			builder.append(c);
			address = address.add(1);
		}
	}
	
	private Address TryGetPointer(Address address) {
		 int name_ptr = 0;
		try {
			name_ptr = getInt(address);
			writer.println(name_ptr);
		} catch (MemoryAccessException e) {
			return null;
		}
		if(name_ptr == 0) {
			return null;
		}
		return toAddr(name_ptr);
	}
	
	private boolean isDataMemory(Address address) {
		MemoryBlock block = currentProgram.getMemory().getBlock(address);
		return block != null && !block.isExecute() && block.isRead();
	}
}
