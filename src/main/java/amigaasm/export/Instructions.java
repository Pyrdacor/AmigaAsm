package amigaasm.export;

final class Instructions {
	public static final String[] Names = new String[] {
		"abcd",
		"add",
		"adda",
		"addi",
		"addq",
		"addx",
		"and",
		"andi",	
		"asl",
		"asr",
		"bcc",
		"bchg",
		"bclr",	
		"bcs",
		"beq",
		"bge",
		"bgt",
		"bhi",
		"ble",
		"bls",
		"blt",
		"bmi",
		"bne",
		"bpl",
		"bra",
		"bset",
		"bsr",
		"btst",
		"bvc",
		"bvs",
		"chk",
		"clr",
		"cmp",
		"cmpa",
		"cmpi",
		"cmpm",
		"dbcc",
		"dbcs",
		"dbeq",
		"dbf",
		"dbge",
		"dbgt",
		"dbhi",
		"dble",
		"dbls",
		"dblt",
		"dbmi",
		"dbne",
		"dbpl",
		"dbt",
		"dbvc",
		"dbvs",	
		"divs",
		"divu",
		"eor",
		"eori",
		"exg",
		"ext",
		"illegal",
		"jmp",
		"jsr",		
		"lea",
		"link",
		"lsl",
		"lsr",
		"move",
		"movea",
		"movem",
		"movep",
		"moveq",
		"muls",
		"mulu",
		"nbcd",
		"neg",
		"negx",
		"nop",
		"not",
		"or",
		"ori",	
		"pea",
		"reset",
		"rol",
		"ror",
		"roxl",
		"roxr",
		"rte",
		"rtr",
		"rts",
		"sbcd",
		"scc",
		"scs",
		"seq",
		"sf",
		"sge",
		"sgt",
		"shi",
		"sle",
		"sls",
		"slt",
		"smi",
		"sne",
		"spl",
		"st",
		"stop",
		"sub",
		"suba",
		"subi",		
		"subq",
		"subx",
		"svc",
		"svs",
		"swap",		
		"tas",
		"trap",
		"trapv",
		"tst",
		"unlk"
	};
	
	public static final String[] NamesWithPCAddressMode = new String[] {
		"add",
		"adda",
		"and",
		"btst",
		"cmp",
		"cmpa",
		"cmpi",
		"divs",
		"divu",
		"jmp",
		"jsr",
		"lea",
		"move",
		"movea",
		"movem",
		"muls",
		"mulu",
		"or",
		"pea",
		"sub",
		"suba",
		"tst"
	};
}
