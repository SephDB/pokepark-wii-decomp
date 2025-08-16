package mw_rtti;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.util.Msg;

public class MWClassInfo {
	public String name;
	public Address address;
	
	public ArrayList<BaseInfo> convertible_bases = new ArrayList<BaseInfo>();
	private HashMap<Address,BaseInfo> base_map = new HashMap<Address,BaseInfo>();
	
	public TreeSet<BaseInfo> direct_bases = new TreeSet<BaseInfo>(new BaseInfoOffsetComparator());

	public MWClassInfo(String name, Address typeinfo_address) {
		this.name = name;
		this.address = typeinfo_address;
	}
	
	public void AddBase(MWClassInfo base, int offset) {
		BaseInfo info = new BaseInfo(base,offset);
		convertible_bases.add(info);
		base_map.put(base.address, info);
		
		if(!direct_bases.add(info)) {
			//Direct conflict with existing base, need to figure out which is a base of which
			BaseInfo conflict = direct_bases.floor(info);
			if(conflict.base.HasBase(info.base, 0)) {
				//The already existing direct base has the new class as its own base, no further work necessary
				return;
			}
			else if(info.base.HasBase(conflict.base, 0)) {
				direct_bases.remove(conflict);
				direct_bases.add(info);
			}
			else {
				Msg.error(this, "Conflicting base addresses! "+name+": ("+info.base.name+","+conflict.base.name+")\n");
				return;
			}
		}
		direct_bases.tailSet(info, false).removeIf(b -> info.base.HasBase(b.base, b.offset - info.offset));
		
		if(direct_bases.headSet(info).stream().mapToLong(b -> b.base.HasBase(info.base, info.offset - b.offset) ? 1 : 0).count() > 0) {
			direct_bases.remove(info);
		}
	}
	
	public boolean HasBase(MWClassInfo base, int calculated_offset) {
		BaseInfo info = base_map.get(base.address);
		if(info != null) {
			if(info.offset != calculated_offset) {
				SetVirtual(base.address);
			}
			return true;
		}
		return false;
	}
	
	private void SetVirtual(Address addr) {
		BaseInfo info = base_map.get(addr);
		if(info != null) {
			info.virtual = true;
			BaseInfo parent = direct_bases.floor(info);
			if(parent != info) {
				
			}
		}
	}
	
	static public class BaseInfoOffsetComparator implements Comparator<BaseInfo> {

		@Override
		public int compare(BaseInfo o1, BaseInfo o2) {
			return Integer.compare(o1.offset, o2.offset);
		}
		
	}
	
	static public class BaseInfo {
		public MWClassInfo base;
		public int offset;
		public boolean virtual = false;

		public BaseInfo(MWClassInfo base, int offset) {
			super();
			this.base = base;
			this.offset = offset;
		}
	}
}
