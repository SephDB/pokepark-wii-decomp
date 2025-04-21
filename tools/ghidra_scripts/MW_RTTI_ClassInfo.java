//
//@author Seph De Busser
//@category GameCube/Wii
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;

public class MW_RTTI_ClassInfo extends GhidraScript {
	
	private static final String RTTI_Category = "RTTI";
	private static final CategoryPath RTTI_Path = new CategoryPath(CategoryPath.ROOT, RTTI_Category); 
	
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
		
		
	}
}
