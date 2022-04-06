package amigaasm.export;

import java.util.HashMap;
import java.util.Map;

final class ControlRegisters {
	public static final Map<Integer, String> Names;
	
	static
	{
		Names = new HashMap<Integer, String>();
		
		Names.put(0x000, "SFC");
		Names.put(0x001, "DFC");
		Names.put(0x800, "USP");
		Names.put(0x801, "VBR");
		Names.put(0x002, "CACR");
		Names.put(0x802, "CAAR");
		Names.put(0x803, "MSP");
		Names.put(0x804, "ISP");
		Names.put(0x003, "TC");
		Names.put(0x004, "ITT0 / IACR0");
		Names.put(0x005, "ITT1 / IACR1");
		Names.put(0x006, "DTT0 / DACR0");
		Names.put(0x007, "DTT1 / DACR1");
		Names.put(0x805, "MMUSR");
		Names.put(0x806, "URP");
		Names.put(0x807, "SRP");
	}
}
