//
//@author Seph De Busser
//@category GameCube/Wii
//@keybinding
//@menupath
//@toolbar

import java.util.HashMap;

import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayOptions;
import ghidra.service.graph.GraphDisplayOptionsBuilder;
import ghidra.service.graph.GraphDisplayProvider;
import ghidra.service.graph.GraphTypeBuilder;
import ghidra.service.graph.VertexShape;
import ghidra.util.task.TaskMonitor;
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
		
		if(FoundClasses.isEmpty()) {
			println("No classes found!");
			return;
		}
		
		ShowGraph();
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
		ret = new MWClassInfo(name,address);
		
		try {
			AddBases(ret);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
		FoundClasses.put(address, ret);
		
		return ret;
	}
	
	private void AddBases(MWClassInfo c) throws Exception {
		Address base_list = TryGetPointer(c.address.add(4));
		if(base_list == null) return;
		Address base_type_info = TryGetPointer(base_list);
		while(base_type_info != null) {
			Address offset = base_list.add(4);
			if(!isDataMemory(offset)) {
				println("Invalid read of offset at: "+offset.toString());
				return;
			}
			int offset_value = getInt(offset);
			if(offset_value < 0) {
				println("Found ambig_list! TODO: figure out what to do with this! "+offset.toString());
				goTo(offset);
				return;
			}
			var type = TryAddTypeInfo(base_type_info);
			if(type == null) return;
			c.AddBase(type, offset_value);
			println("Found base type of "+c.name+" at offset "+String.valueOf(offset_value) + ": "+type.name);
			base_list = base_list.add(8);
			base_type_info = TryGetPointer(base_list);
		}
		print("Bases of ");
		print(c.name);
		print(":\n");
		c.direct_bases.forEach(b -> {
			print(String.valueOf(b.offset));
			print(":");
			print(b.base.name);
			if(b.virtual) {
				print(" (virtual)");
			}
			print("\n");
			});
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
		return block != null && !block.isExecute() && block.isRead() && address.isLoadedMemoryAddress();
	}
	
	private void ShowGraph() throws Exception {
		AttributedGraph graph = new AttributedGraph("Class diagram",new GraphTypeBuilder("Class diagram")
				.vertexType("V")
				.edgeType("E")
				.build());
		
		FoundClasses.forEach((_address,c) -> {
			var this_v = graph.addVertex(c.name);
			this_v.setVertexType("V");
			c.direct_bases.forEach(base -> {
				var target_v = graph.addVertex(base.base.name);
				graph.addEdge(this_v, target_v).setEdgeType("E");
			});
		});
		
		GraphDisplay display;
		PluginTool tool = state.getTool();
		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider service = broker.getGraphDisplayProvider("Default Graph Display");
		display = service.getGraphDisplay(false, TaskMonitor.DUMMY);

		GraphDisplayOptions graphOptions = new GraphDisplayOptionsBuilder(graph.getGraphType())
				.vertex("V", VertexShape.RECTANGLE, Palette.BLUE)
				.edge("E", Palette.LIME)
				.defaultVertexColor(Palette.PURPLE)
				.defaultEdgeColor(Palette.PURPLE)
				.defaultLayoutAlgorithm("Compact Hierarchical")
				.maxNodeCount(1000)
				.build();

		display.setGraph(graph, graphOptions,
			"Recovered Classes Graph", false, TaskMonitor.DUMMY);
	}
}
