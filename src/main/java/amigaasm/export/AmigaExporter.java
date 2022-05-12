package amigaasm.export;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.python.antlr.ast.Tuple;

import amigaasm.AmigaAsmExporter;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.data.SignedWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.StackReference;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

public class AmigaExporter implements CancelledListener {
	
	// Options
	private boolean exportComments = true;
	private boolean writeComments = true;
	private boolean m68000 = false;
	private String newline = "\r\n";
	
	// State
	private static final Charset charset = StandardCharsets.ISO_8859_1; // TODO: Amiga charset
	private boolean exportCancelled = false;
	private Listing listing = null;
	private int lastBlockIndex = -1;
	private int lastHunkIndex = -1;
	private String currentHunkType = "";
	private Map<Long, AsmReference> references = new HashMap<Long, AsmReference>();
	private Map<Integer, String> customLabels = new HashMap<Integer, String>();
	private Map<Address, String> customLabelsByAddress = new HashMap<Address, String>();
	private Map<Address, Integer> lineNumbersByAddress = new HashMap<Address, Integer>();
	private Map<Integer, Address> addressesAtLineNumbers = new HashMap<Integer, Address>();
	private List<String> lines = new ArrayList<String>();
	private String currentLine = "";
	// TODO: REMOVE, Ambermoon specific
	private boolean addedBssWord = false;
	
	public void cancelled() {
		exportCancelled = true;
	}
	
	
	public void setOptions(List<Option> options) {
		
		for (int i = 0; i < options.size(); ++i) {
			Option option = options.get(i);
			switch (option.getName()) {
				case AmigaAsmExporter.OptionExportComments:
					exportComments = (boolean)option.getValue();
					break;
				case AmigaAsmExporter.OptionWriteComments:
					writeComments = (boolean)option.getValue();
					break;
				case AmigaAsmExporter.OptionExport68000:
					m68000 = (boolean)option.getValue();
					break;
				case AmigaAsmExporter.OptionExportNewline: {
					int newlineOption = (Integer)option.getValue();
					switch (newlineOption) {
						case 1:
							newline = "\n";
							break;
						case 2:
							newline = "\r";
							break;
						default:
							newline = "\r\n";
							break;
						}
						break;
					}
			}
		}
	}
	
	public boolean export(File file, ProgramDB programDB,
			TaskMonitor monitor) throws ExporterException, IOException {
		
		if (file.exists() && !file.canWrite())
			throw new IOException("The given file is not writeable.");
		
		// initialize
		exportCancelled = false;
		lastBlockIndex = -1;
		lastHunkIndex = -1;
		currentHunkType = "";
		references.clear();
		customLabels.clear();
		customLabelsByAddress.clear();
		lineNumbersByAddress.clear();
		lines.clear();
		currentLine = "";
		
		// TODO: REMOVE, Ambermoon specific
		addedBssWord = false;
			
		monitor.addCancelledListener(this);
		
		ProgramDataTypeManager typeManager = programDB.getDataTypeManager();		
		
		Memory memory = programDB.getMemory();
		AddressIterator addressIter = memory.getAddresses(true);
		listing = programDB.getListing();
		MemoryBlock[] blocks = memory.getBlocks();
		
		while (!exportCancelled && addressIter.hasNext()) {
			
			Address address = addressIter.next();
			MemoryBlock block = memory.getBlock(address);
			int blockIndex = Arrays.binarySearch(blocks, block);
			
			try {			
				processAddress(address, memory, typeManager,
						blockIndex, block.getName(), block.getSize(), monitor);
			} catch (Exception e) {
				
				throw new RuntimeException(String.format("Exception at address %08x: ", address.getUnsignedOffset()) + e.getMessage(), e);
			}
		}
		
		if (writeComments && lastBlockIndex != -1) {
			writeLine(";   }"); // end of section
		}
		
		// If custom labels are inside structs or arrays,
		// it can happen that they are not correctly tracked
		// in 'customLabels' but only in 'customLabelsByAddress'.
		// So move them over now.
		
		
		List<AbstractMap.SimpleEntry<String, String>> labelReplacements = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
		
		customLabelsByAddress.forEach((Address addr, String label) -> {
			
			int offset = 0;
			Address initialAddress = addr;
			
			while (true) {
				
				Integer line = this.lineNumbersByAddress.get(addr);

				if (line != null) {
					
					Address nextLineAddress = addressesAtLineNumbers.get(line + 1);
					
					while (nextLineAddress != null && nextLineAddress.getUnsignedOffset() < initialAddress.getUnsignedOffset()) {
						++line;
						nextLineAddress = addressesAtLineNumbers.get(line + 1);
					}
					
					Address lineAddress = addr;
					long offsetInLine = initialAddress.getUnsignedOffset() - lineAddress.getUnsignedOffset();
					
					if (offsetInLine == 0) {
					
						if (!customLabels.containsKey(line)) {
							customLabels.put(line + offset, label);
						}
					} else { // the label is inside the line (e.g. partial string)
					
						// In this case we have to replace the label by <LineLabel+N>
						AsmReference ref = references.get(lineAddress.getUnsignedOffset());
						String baseLabel;
						
						if (ref == null) {
							baseLabel = String.format("LAB_%08x", lineAddress.getUnsignedOffset());
							customLabels.put(line, baseLabel);
						} else {
							baseLabel = ref.Label;
						}
						labelReplacements.add(new AbstractMap.SimpleEntry<String, String>(label, baseLabel + String.format("+%d", offsetInLine)));
					}
					
					break;
				}
				
				addr = addr.subtract(1);
				++offset;
				
				if (addr.getUnsignedOffset() == 0) {
					break;
				}					
			}
		});
		
		OutputStreamWriter writer = new OutputStreamWriter(
            new FileOutputStream(file.getPath()), "UTF-8");
		
		// TODO: REMOVE, Ambermoon specific
		labelReplacements.add(new AbstractMap.SimpleEntry<String, String>("_AbsExecBase", "$4"));
		labelReplacements.add(new AbstractMap.SimpleEntry<String, String>("DAT_0000006c", "$6c"));
		labelReplacements.add(new AbstractMap.SimpleEntry<String, String>("_ciaa", "$bfe001"));
		labelReplacements.add(new AbstractMap.SimpleEntry<String, String>("_ciab", "$bfd000"));
		labelReplacements.add(new AbstractMap.SimpleEntry<String, String>("_custom", "$dff000"));
		
		for (int i = 0; i < lines.size(); ++i) {
			int lineNumber = i + 1;
			String customLabel = customLabels.get(lineNumber);
			if (customLabel != null) {
				writer.write(customLabel + ":" + newline);
			}
			String line = lines.get(i);
			for (int r = 0; r < labelReplacements.size(); ++r) {
				AbstractMap.SimpleEntry<String, String> labelReplacement = labelReplacements.get(r);
				// Don't replace real labels like <label>:
				line = line.replace(labelReplacement.getKey() + ":", "%%%%");
				line = line.replace(labelReplacement.getKey(), labelReplacement.getValue());
				line = line.replace("%%%%", labelReplacement.getKey() + ":");
			}
			writer.write(line + newline);
		}
		
		writer.flush();
		writer.close();
		
		return true;
	}
	
	static final String headerBar = "#######################";
	
	private String getHeaderTitle(String text) {
	
		int textSpace = headerBar.length() - 3;
		
		if (text.length() == textSpace) {
			return "# " + text + "#";
		}
		
		if (text.length() > textSpace) {
			return "# " + text;
		}
	
		return "# " + text + String.join("", Collections.nCopies(textSpace - text.length(), " ")) + "#";
	}
	
	private boolean processAddress(Address address, Memory memory, ProgramDataTypeManager typeManager,
			int blockIndex, String hunkName, long blockSize, TaskMonitor monitor) {
		
		if (lastBlockIndex != blockIndex) {
			int hunkIndex = -1;
			if (address.getUnsignedOffset() < 0x21f000 || address.getUnsignedOffset() >= 0x31f000) {
				currentHunkType = hunkName; // should be "EXEC"
				if (currentHunkType.equals("EXEC")) {
					System.out.println("Skipping EXEC section.");
				} else {
					System.out.println("Unrecognized section: " + currentHunkType);
				}
			} else {
				Pattern hunkNamePattern = Pattern.compile("([A-Z]+)_([0-9]+)");
				Matcher matcher = hunkNamePattern.matcher(hunkName);
				// TODO: REMOVE, Ambermoon specific
				if (!addedBssWord && currentHunkType.equals("BSS")) {
					
					writeLine("DAT_ScrollOffset:");
					writeLine("\tdx.w 1");
					addedBssWord = true;
				}
				if (lastHunkIndex != -1) {
					writeLine(";   }"); // end of section
				}				
				if (writeComments) {
					writeLine();
					writeLine("; " + headerBar);
				}
				if (!matcher.matches()) {
					if (writeComments) {
						writeLine("; " + getHeaderTitle(hunkName));
					}
				} else {
					currentHunkType = matcher.group(1);
					boolean isBss = currentHunkType.equals("BSS");
					hunkIndex = Integer.parseInt(matcher.group(2));
					if (writeComments) {
						writeLine("; " + getHeaderTitle(String.format("HUNK%s - %s", matcher.group(2), isBss ? "BSS " : currentHunkType)));
					}
				}
				if (writeComments) {
					writeLine("; " + headerBar);
				}
			}

			if (hunkIndex != -1) {
				String section = String.format("\tsection\thunk%02d,%s", hunkIndex, currentHunkType);
				// TODO: REMOVE, Ambermoon specific
				// TODO: Only for AM2_CPU!
				if (memory.getProgram().getExecutablePath().contains("AM2_CPU")) {
					if (hunkIndex == 1 || hunkIndex == 3 || hunkIndex == 10) {
						section += ",chip"; // force chip on first BSS and first data hunk (and on new blit code hunk)
					}
				}
				writeLine(section);
				if (writeComments) {
					writeLine(";   {"); // begin section
				}
			}
			
			lastBlockIndex = blockIndex;
			lastHunkIndex = hunkIndex;
		}
		
		if (!currentHunkType.equals("DATA") && !currentHunkType.equals("BSS") && !currentHunkType.equals("CODE")) {
			return false;
		}

		CodeUnit codeUnit = listing.getCodeUnitAt(address);
		
		if (codeUnit != null) {
			if (exportComments) {
				exportCodeAndComments(address, codeUnit, memory, typeManager, blockIndex, monitor);
			} else {
				writeCode(address, codeUnit, memory, typeManager, blockIndex, monitor);
				writeLine();
			}
			return true;
		}
		
		Data data = listing.getDataAt(address);
		
		if (data != null) {
			if (exportComments) {
				exportCodeAndComments(address, data, memory, typeManager, blockIndex, monitor);
			} else {
				writeCode(address, data, memory, typeManager, blockIndex, monitor);
				writeLine();
			}
			return true;
		}
		
		return false;
	}
	
	private void exportCodeAndComments(Address address,	CodeUnit codeUnit, Memory memory,
			ProgramDataTypeManager typeManager,	int hunkIndex, TaskMonitor monitor) {

		String comment = codeUnit.getComment(CodeUnit.PRE_COMMENT);
		
		if (comment != null) {
			writeLine("\t; " + comment.replace("\n", "\n\t; "));
		}
		
		comment = codeUnit.getComment(CodeUnit.REPEATABLE_COMMENT);
		
		if (comment != null) {
			writeLine("\t; " + comment.replace("\n", "\n\t; "));
		}
		
		boolean codeWritten = writeCode(address, codeUnit, memory, typeManager, hunkIndex, monitor);
		
		comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
		
		if (comment != null) {
			String prefix = codeWritten ? " " : "\t";
			write(prefix + "; " + comment.replace("\n", "\n\t\t\t; "));
			codeWritten = true;
		}
		
		if (codeWritten) {
			writeLine();
		}
		
		comment = codeUnit.getComment(CodeUnit.POST_COMMENT);
		
		if (comment != null) {
			writeLine("\t; " + comment.replace("\n", "\n\t; "));
		}
	}
	
	private void write(String text) {
		currentLine += text;
	}
	
	private void writeLine() {
		lines.add(currentLine);
		currentLine = "";
	}
	
	private void writeLine(String text) {
		write(text);
		writeLine();
	}
	
	private int getLineNumber() {
		return lines.size() + 1;
	}
	
	private static String getAddrRegisterName(int n) {
		return n == 7 ? "SP" : String.format("A%d", n);
	}
	
	private static String trimRegSuffix(String reg) {
		if (reg.endsWith("w") || reg.endsWith("b")) {
			return reg.substring(0, reg.length() - 1);
		}
		return reg;
	}
	
	private int getExtensionSizeByMode(int mode, int reg, int immediateValueBytes) {

		switch (mode) {
			case 5:
			case 6:
				return 2;
			case 7:
				switch (reg) {
					case 0:
					case 2:
					case 3:
						return 2;
					case 1:
						return 4;
					case 4:
						return immediateValueBytes;
					default:
						return 0;
				}
			default:
				return 0;
		}
	}
	
	private String parseAddressMode(Address address, int mode, int reg, byte[] data,
		int extensionOffset, int immediateValueBytes) {
		
		switch (mode) {
			case 0:
				return String.format("D%d", reg);
			case 1:
				return getAddrRegisterName(reg);
			case 2:
				return "(" + getAddrRegisterName(reg) + ")";
			case 3:
				return "(" + getAddrRegisterName(reg) + ")+";
			case 4:
				return "-(" + getAddrRegisterName(reg) + ")";
			case 5:
				return "(" + getDisplacement(address, readShort(data, extensionOffset), 2, false) + "," + getAddrRegisterName(reg) + ")";
			case 6:
				return this.getIndexExpression(address, getAddrRegisterName(reg), data, extensionOffset, false);
			case 7:
			{
				switch (reg) {
					case 0:
					case 1:
						return this.getLabelForAddress(address, data, extensionOffset, reg == 0);
					case 2:
						return "(" + getDisplacement(address, readShort(data, extensionOffset), 2, true) + ",PC)";
					case 3:
						return this.getIndexExpression(address, "PC", data, extensionOffset, true);
					case 4:
					{
						switch (immediateValueBytes) {
							case 1:
							case 2:
							case 4:
								return toHex(data, extensionOffset, immediateValueBytes);
							case 8:
								// we support divsl/divul with 64 bit but will only read the 32 bit portion
								return toHex(data, extensionOffset + 4, immediateValueBytes);
							default:
								throw new RuntimeException("Invalid immediate value size.");
						}
					}
				}
			}
		}
		
		throw new RuntimeException("Invalid address mode.");
	}
	
	private String getDisplacement(Address callAddress, int displacement, int numBytes, boolean allowLabel) {
		
		if (numBytes < 1 || numBytes > 2) {
			throw new RuntimeException("Only displacements of size 1 or 2 are allowed.");
		}
		
		if (allowLabel) {
			Address targetAddress = callAddress.add(2 + displacement); // 2 because it starts after the instruction word
			return getLabelForAddress(targetAddress, null);
		}
		
		String d = toHex(Math.abs(displacement), numBytes);
		
		if (displacement < 0) {
			return "-" + d;
		}
		
		return d;
	}
	
	private boolean writeCode(Address address, CodeUnit codeUnit, Memory memory,
			ProgramDataTypeManager typeManager,	int hunkIndex, TaskMonitor monitor) {
		
		long addressOffset = address.getUnsignedOffset();
		if (addressOffset == 0x002901f6 - 8) {
			int x = 0; // TODO: REMOVE
		}
		String label = codeUnit.getLabel();
		
		if (label != null) {
			writeLine(label + ":");
			
			// If there is a label, add this as a reference.
			references.put(addressOffset, new AsmReference(getLineNumber(), label));
		} else {
			
			String customLabel = customLabelsByAddress.get(address);
			
			if (customLabel != null) {
				customLabels.put(getLineNumber(), customLabel);
			}
		}
		
		int lineNumber = getLineNumber();
		lineNumbersByAddress.put(address, lineNumber);
		addressesAtLineNumbers.put(lineNumber, address);
		
		if (currentHunkType.equals("CODE") && !(codeUnit instanceof Data)) {

			// Try to process code instructions (data sections are handled later)
			String mnemonic = codeUnit.getMnemonicString(); // THIS is only the instruction without params
			
			byte[] bytes = null;
			try {
				bytes = codeUnit.getBytes();
			} catch (MemoryAccessException e) {
				// Unable to read
				throw new RuntimeException("Unable to read instruction data.");
			}
			
			if (mnemonic != null) {
				
				String opcode = mnemonic.toLowerCase();
				int dotIndex = opcode.indexOf('.');
				
				if (dotIndex >= 0) {
					opcode = opcode.substring(0, dotIndex);
				}
				
				if (Arrays.binarySearch(Instructions.Names, opcode) >= 0) {
					
					// TODO: There is also 'moves', 'pack', etc
					if (m68000 && opcode.equals("movec")) {
					
						// This isn't available on 68000
						
						int crCode = ((bytes[2] & 0xf) << 8) | bytes[3];
						String crName = ControlRegisters.Names.get(crCode);
						
						if (crName == null) {
							if (writeComments) {
								writeLine(String.format("; WARNING: movec was used with unknown control register code $%03x", crCode));
							}
							return true;
						}
						
						int reg = (bytes[2] >> 4) & 0x7;
						boolean dataRegister = (bytes[2] & 0x80) == 0;
						String regName = dataRegister
							? String.format("D%d", reg)
							: getAddrRegisterName(reg);

						if ((bytes[1] & 0x1) == 0) { // CR to R
							
							if (writeComments) {
								writeLine("; WARNING: Replaced movec writing from " + crName + " to " + regName);
							}
							if (dataRegister) {
								// move 0 to Dn
								write("\tmoveq #$0," + regName);
							} else {
								// clear An
								write("\tsuba.l " + regName + "," + regName);
							}
						} else { // R to CR
							// Ignore writing to control register
							if (writeComments) {
								writeLine("; WARNING: Removed movec writing from " + regName + " to " + crName);
							}
						}
						
						return true;
					}
					if (m68000 && (opcode.equals("divsl") || opcode.equals("divul"))) {
						
						int dq = (bytes[2] >> 4) & 0x7;
						int dr = bytes[3] & 0x7;
						
						if (dq != dr) {
							throw new RuntimeException(opcode + " is not supported for mismatching dq and dr.");
						}
						
						if (writeComments) {
							writeLine("; WARNING: Replaced " + mnemonic);
						}
						
						write("\t" + opcode.substring(0, opcode.length() - 1) + ".w ");
						
						int mode = (bytes[1] >> 3) & 0x7;
						int reg = bytes[1] & 0x7;
						int immediateBytes = (bytes[2] & 0x4) != 0 ? 8 : 4; // 64 or 32 bits
						String arg = parseAddressMode(address, mode, reg, bytes, 4, immediateBytes);
						
						write(String.format("%s,D%d", arg, dq));
						
						return true;
					}
					
					write("\t" + mnemonic);
					
					// movem reg lists are sometimes treated as data refs which we will disallow
					int disallowRefOperandIndex = -1;
					if (opcode.equals("movem")) {
						
						boolean toRegister = (bytes[0] & 0x4) != 0;
						disallowRefOperandIndex = toRegister ? 1 : 0;						
					}
					
					// movem and movep need some special care in Ghidra sometimes ...
					// we just parse them manually
					
					if (opcode.equals("movem")) {
						
						// reg list
						String code = codeUnit.toString();
						Pattern pattern = Pattern.compile("\\{.*\\}");
						Matcher matcher = pattern.matcher(code);
						
						if (matcher.find()) {
							
							String regList = code.substring(matcher.start() + 1, matcher.end() - 1)
								.trim() // trim leading and trailing spaces
								.replace(' ', '/') // convert "D0 D1" to "D0/D1"
								.replace("w", ""); // remove 'w' suffix for "D0w" etc
							
							int mode = (bytes[1] >> 3) & 0x7;
							int reg = bytes[1] & 0x7;
							String arg = parseAddressMode(address, mode, reg, bytes, 4, 0);							
							boolean toRegister = (bytes[0] & 0x4) != 0;
							
							if (toRegister) {
								write(String.format(" %s,%s", arg, regList));
							} else {
								write(String.format(" %s,%s", regList, arg));
							}
									
							return true;
						}

						throw new RuntimeException(String.format("Invalid movem command at address %08x.", address.getUnsignedOffset()));
						
					} else if (opcode.equals("movep")) {
						
						int dreg = (bytes[0] >> 1) & 0x7;
						String areg = getAddrRegisterName(bytes[1] & 0x7);
						int opmode = (bytes[1] >> 6) & 0x3;						
						boolean toRegister = opmode < 2;
						String d = getDisplacement(address, readShort(bytes, 2), 2, false);
						
						if (toRegister) {
							write(String.format(" (%s,%s),D%d", d, areg, dreg));
						} else {
							write(String.format(" D%d,(%s,%s)", dreg, d, areg));
						}
						
						return true;
					}
					
					int numOps = codeUnit.getNumOperands();
					
					if (numOps >= 3) {
						
						throw new RuntimeException(String.format("Ghidra reported 3 operands at address %08x which is disallowed.", address.getUnsignedOffset()));
					}
					
					if (numOps > 1 && (opcode.equals("jmp") || opcode.equals("jsr")) ) {
						
						// Ghidra sometimes expresses displacements here as two operands
						// In that case we have to parse the operand manually
						int mode = (bytes[1] >> 3) & 0x7;
						int reg = bytes[1] & 0x7;
						String arg = parseAddressMode(address, mode, reg, bytes, 2, 0);	
						write(String.format(" %s", arg));
						return true;
					}
					
					int byteOffset = 2;
					String prefix = " ";
					for (int i = 0; i < numOps; ++i) {
						if (codeUnit instanceof Instruction) {
							Instruction inst = (Instruction)codeUnit;
							int type = inst.getOperandType(i);
							if (type == OperandType.DYNAMIC ||
								type == (OperandType.DYNAMIC | OperandType.ADDRESS) ||
								type == (OperandType.DYNAMIC | OperandType.INDIRECT)) { // (A0)+ etc
								int mode = (bytes[1] >> 3) & 0x7;
								int reg = bytes[1] & 0x7;
								if (i == 1 && (opcode.equals("move"))) {
									// Note: move encodes the destination first but it is the second operand (i == 1)
									short fullInstruction = readShort(bytes, 0); // get a full short of the instruction
									mode = (fullInstruction >> 6) & 0x7;
									reg = (fullInstruction >> 9) & 0x7;
								}
								// Some instructions need some special treatment
								if (mode >= 4 && (mnemonic.startsWith("as") ||
									mnemonic.startsWith("ls") || mnemonic.startsWith("ro"))) {
									// Shifts and rolls with mode > 4 are Dn
									reg = (bytes[0] >> 1) & 0x7;
									write(prefix + "D" + Integer.toString(reg));
								} else {
									// TODO: I guess there are more special commands which always use dynamic addressing
									String arg = parseAddressMode(address, mode, reg, bytes, byteOffset, 0); // immediate won't work with 0, which is ok
									write(prefix + arg);
									byteOffset += getExtensionSizeByMode(mode, reg, 0);
								}
							} else if (type == OperandType.SCALAR) {
								if (mnemonic.endsWith(".l") && (opcode.equals("cmpa") || opcode.equals("adda") ||
									opcode.equals("suba") || opcode.equals("movea"))) {
									// The address instructions often use immediate values but as
									// they always work with addresses, they are subject to relocations
									// and therefore are treated as labels.
									long offset = inst.getScalar(i).getUnsignedValue();
									Address addr = memory.getProgram().getAddressMap().getImageBase().add(offset);
									String targetLabel = getLabelForAddress(addr, offset);
									write(prefix + "#" + targetLabel);
								} else {
									boolean handled = false;
									if (mnemonic.equals("move.l")) {
										// Sometimes Ghidra also encodes addresses as immediate values for move instructions
										// TODO: This is not safe as it is totally valid to move such values
										//       Here the opcode has to be parsed manually.
										long offset = inst.getScalar(i).getUnsignedValue();
										if (offset >= 0x21f000 && offset < 0x31f000) {
											Address addr = memory.getProgram().getAddressMap().getImageBase().add(offset);
											String targetLabel = getLabelForAddress(addr, offset);
											write(prefix + "#" + targetLabel);
											handled = true;
										}
									}
									if (!handled) {
										String p = prefix;
										if (!opcode.equals("lea") && !opcode.equals("pea")) {
											write(p + "#" + inst.getScalar(i).toString(16, true, true, "$", ""));
										} else {
											// this is always a reference!
											long value = inst.getScalar(i).getSignedValue();
											if (value >= 0x20f000 && value < 0x21f000) {
												value -= 0x21f000;
												write(p + String.format("start%d", value)); // e.g. start-4
											} else if (value < 0) {
												write(p + String.format("%d", value));
											} else if (value < 0x21f000 || value >= 0x31f000) {
												write(p + this.toHex(value, 4));
											} else {
												this.getLabelForAddress(address, value);
											}
										}
									}
								}
								if (!opcode.endsWith("q")) {
									// quick instructions store the scalar inside the instruction word
									if (mnemonic.toLowerCase().endsWith("b") || mnemonic.toLowerCase().endsWith("w")) {
										byteOffset += 2;
									} else {
										byteOffset += 4;
									}
								}
							} else if ((type & OperandType.REGISTER) != 0) {
								String reg = trimRegSuffix(inst.getRegister(i).toString());
								if ((type & OperandType.INDIRECT) != 0) {
									write(prefix + "(" + reg + ")");
								} else if (opcode.equals("cmpm")) { // special treatment
									write(prefix + "(" + reg + ")+"); // cmpm always uses (An)+
								} else if (i == 0 && opcode.equals("lea")) { // special treatment
									write(prefix + "(" + reg + ")"); // first arg of lea always uses (An) and never An
								} else {
									write(prefix + reg);
								}
							} else {
								
								boolean found = false;
								Reference[] opRefs = codeUnit.getOperandReferences(i);
								if (disallowRefOperandIndex != i && opRefs != null && opRefs.length != 0) {				
									for (int j = 0; j < opRefs.length; ++j) {
										Reference op = opRefs[j];
										if (opRefs.length > 1 && !op.isPrimary()) {
											continue;
										}
										if (op.isMemoryReference()) {
											// Ghidra messes up PC related addresses
											if (Arrays.binarySearch(Instructions.NamesWithPCAddressMode, opcode) >= 0) {
												
												if (i == 1 && (opcode.equals("move"))) {
													
													// Note: move encodes the destination first but it is the second operand (i == 1)
													short fullInstruction = readShort(bytes, 0); // get a full short of the instruction
													int mode = (fullInstruction >> 6) & 0x7;
													
													if (mode == 7) {
														
														mode = (fullInstruction >> 9) & 0x7;
														
														if ((mode & 0x2) != 0) {
																												
															// PC relative reference
															if (mode == 2) {
																int displacement = readShort(bytes, byteOffset);
																String d = getDisplacement(address, displacement, 2, true);
																write(prefix + String.format("(%s,PC)", d));
															} else { // mode 3
																write(prefix + getIndexExpression(address, "PC", bytes, byteOffset, true));
															}
															
															byteOffset += 2;
															prefix = ",";
															found = true;
															continue;	
														}
													}
													
												} else {
													
													int mode = (bytes[1] >> 3) & 0x7;
													
													if (mode == 7) {
														
														mode = bytes[1] & 0x7;
														
														if ((mode & 0x2) != 0) {
															
															// PC relative reference
															if (mode == 2) {
																int displacement = readShort(bytes, byteOffset);
																String d = getDisplacement(address, displacement, 2, true);
																write(prefix + String.format("(%s,PC)", d));
															} else { // mode 3
																write(prefix + getIndexExpression(address, "PC", bytes, byteOffset, true));
															}
															
															byteOffset += 2;
															prefix = ",";
															found = true;
															continue;	
														}
													}
												}
												
											}
											
											if (type == (OperandType.DYNAMIC | OperandType.ADDRESS | OperandType.INDIRECT) &&
												(opcode.equals("jsr") || opcode.equals("jmp"))) {
												
												// handle jump towers
												
												int mode = (bytes[1] >> 3) & 0x7;
												int reg = bytes[1] & 0x7;
												
												if (mode == 5) { // address with displacements
													
													int displacement = readShort(bytes, byteOffset);
													String d = getDisplacement(address, displacement, 2, false);
													write(prefix + String.format("(%s,%s)", d, getAddrRegisterName(reg)));
													byteOffset += 2;
													prefix = ",";
													found = true;
													continue;	
													
												} else if (mode == 6) { // address with index
													
													write(prefix + getIndexExpression(address, getAddrRegisterName(reg), bytes, byteOffset, false));
													byteOffset += 2;
													prefix = ",";
													found = true;
													continue;	
												}
											}
									
											Address addr = op.getToAddress();		
											String targetLabel = getLabelForAddress(addr, null);
											if (i == 0 && mnemonic.equals("move.l") && (bytes[1] & 0x3f) == 0x3c) {
												// move.l in immediate mode might move #label to something
												write(prefix + "#" + targetLabel);
											} else {
												write(prefix + targetLabel);
											}
											byteOffset += 4;
											found = true;

										} else if (op.isStackReference()) {
											StackReference sr = (StackReference)op;
											
											if (sr.getStackOffset() < 0) {
												write(prefix + "-(SP)");
											} else {
												write(prefix + "(SP)+");
											}
											
											found = true;
										} else {
											throw new RuntimeException(String.format("Unsupported operand '%s' at address %08x.", op.getReferenceType().getName(), address.getUnsignedOffset()));
										}
									}
								}
								
								if (!found) {
									throw new RuntimeException(String.format("Unsupported operand type $%08x at address %08x.", type, address.getUnsignedOffset()));
								}
							}

						} else {

							throw new RuntimeException(String.format("Couldn't read operands at address %08x.", address.getUnsignedOffset()));
						}

						prefix = ",";
					}

					return true;
				}
			}
		}
		
		String mnemonic = codeUnit.getMnemonicString();
			
		byte[] bytes = null;
		try {
			bytes = codeUnit.getBytes();
		} catch (MemoryAccessException e) {
			// Unable to read
			throw new RuntimeException("Unable to read data bytes.");
		}
		
		if (mnemonic.trim().endsWith("*")) {
			writeLine("\t; " + mnemonic);
		}
		
		writeData(mnemonic, bytes, 0, typeManager, monitor, address, hunkIndex, memory);
		
		return true;
	}
	
	private void writeArray(String arrayIndexPattern, String typeName, ProgramDataTypeManager typeManager,
			byte[] data, int dataOffset, TaskMonitor monitor, Address address, int hunkIndex, Memory memory) {
		
		Pattern pattern = Pattern.compile("\\[[0-9]+\\]");
		Matcher matcher = pattern.matcher(arrayIndexPattern);
		int matchOffset = 0;
		int totalAmount = 0;
		
		while (true) {
						
			if (!matcher.find(matchOffset)) {
				
				if (matchOffset == 0) {
					throw new RuntimeException("Array index pattern did not match.");
				}
				break;
			}
			
			matchOffset = matcher.end();
			String value = matcher.group();
			int dim = Integer.parseInt(value.substring(1, value.length() - 1));
			totalAmount = totalAmount == 0 ? dim : totalAmount * dim;
			
			if (matchOffset >= arrayIndexPattern.length()) {
				break;
			}
		}
		
		DataType dataType = findFirstDataType(typeManager, typeName);
		
		if (dataType != null) {
			data = ensureData(data, memory, address, totalAmount * dataType.getLength());
		} else {
			// TODO: ensure data size for primitive type arrays
		}
		
		if (currentHunkType.equals("BSS")) {
			write(String.format("\tdx.b %d", data.length));
		} else {
			for (int n = 0; n < totalAmount; ++n) {
			
				int size = writeData(typeName, data, dataOffset, typeManager, monitor, address, hunkIndex, memory);
				dataOffset += size;
				address = address.add(size);
				
				if (n != totalAmount - 1) {
					writeLine();
				}
			}
		}
	}
	
	private void writePointerLabel(String label) {
		
		if (label.equals("0")) {
			write("\tdc.l $00000000");
			if (writeComments) {		
				write(" ; null pointer address");
			}
		} else if (label.equals("-1")) {
			write("\tdc.l $ffffffff");
			if (writeComments) {
				write(" ; invalid address marker");
			}
		} else {
			write("\tdc.l " + label);
		}
	}
	
	private static DataType findFirstDataType(ProgramDataTypeManager typeManager, String name) {
		
		List<DataType> types = new ArrayList<DataType>();
		typeManager.findDataTypes(name, types, false, null);
		
		return types.isEmpty() ? null : types.get(0);
	}
	
	private byte[] ensureData(byte[] data, Memory memory, Address address, int size) {
		
		if (data.length >= size) {
			return data;
		}
		
		byte[] bytes = new byte[size];
		
		try {
			memory.getBytes(address, bytes, 0, size);
		} catch (MemoryAccessException e) {
			// Unable to read
			throw new RuntimeException("Unable to read data bytes.");
		}
		
		return bytes;
	}
	
	private int writeData(String mnemonic, byte[] data, int dataOffset,
			ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex, Memory memory) {
		
		boolean isBss = currentHunkType.equals("BSS");
		
		if (mnemonic.equals("ds")) {
			data = ensureData(data, memory, address, 1);
			write("\tdc.b " + getStringLiteralFromData(data, dataOffset, false));
			return data.length - dataOffset;
		} else if (mnemonic.equals("db")) {
			if (isBss) {
				write("\tdx.b 1");
			} else {
				data = ensureData(data, memory, address, 1);
				write("\tdc.b " + toHex(data[dataOffset], 1));
			}
			return 1;
		} else if (mnemonic.equals("sdb")) {
			if (isBss) {
				write("\tdx.b 1");
			} else {
				data = ensureData(data, memory, address, 1);
				write(String.format("\tdc.b %d", data[dataOffset]));
			}
			return 1;
		} else if (mnemonic.equals("dw")) {
			if (isBss) {
				write("\tdx.w 1");
			} else {
				data = ensureData(data, memory, address, 2);
				write("\tdc.w " + toHex(data, dataOffset, 2));
			}
			return 2;
		} else if (mnemonic.equals("sdw")) {
			if (isBss) {
				write("\tdx.w 1");
			} else {
				data = ensureData(data, memory, address, 2);
				write(String.format("\tdc.w %d", readShort(data, dataOffset)));
			}
			return 2;
		} else if (mnemonic.equals("ddw") || mnemonic.equals("dl")) {
			if (isBss) {
				write("\tdx.l 1");
			} else {
				data = ensureData(data, memory, address, 4);
				write("\tdc.l " + toHex(data, dataOffset, 4));
			}
			return 4;
		} else if (mnemonic.equals("addr") || mnemonic.trim().endsWith("*")) {
			if (isBss) {
				write("\tdx.l 1");
			} else {
				data = ensureData(data, memory, address, 4);
				String label = this.getLabelForAddress(memory, data, dataOffset);
				writePointerLabel(label);
			}
			return 4;
		} else if (mnemonic.equals("dq")) {
			if (isBss) {
				write("\tdx.l 2");
			} else {
				data = ensureData(data, memory, address, 8);
				write("\tdc.l " + toHex(data, dataOffset, 4));
				write("\tdc.l " + toHex(data, dataOffset + 4, 4));
			}
			return 4;
		} else if (mnemonic.equals("char")) {
			if (isBss) {
				write("\tdx.b 1");
			} else {
				data = ensureData(data, memory, address, 1);
				write("\tdc.b " + (data[dataOffset] < 0x20 ? String.format("%x", data[dataOffset]) : "'" + (char)data[dataOffset] + "'"));
			}
			return 1;
		} else {
			// Expect mnemonic to be the typename
			if (mnemonic.endsWith("]")) { // array
				
				DataType arrType = findFirstDataType(typeManager, mnemonic);
				
				if (arrType != null) {
					
					if (writeComments) {
						writeLine("\t; " + mnemonic);
					}
					Array arr = (Array)arrType;
					int length = arr.getNumElements();
					DataType elemType = arr.getDataType();
					
					if (isBss) {
						int size = length * elemType.getLength();
						write(String.format("\tdx.b %d", size));
						return size;
					} else {
						data = ensureData(data, memory, address, length * elemType.getLength());
						if (mnemonic.startsWith("char[") && !mnemonic.contains("][")) {
							write("\tdc.b " + getStringLiteralFromData(data, dataOffset, true));
						} else {
							writeArray(length, elemType, typeManager, data,
									   dataOffset, monitor, address, hunkIndex);
						}
						return data.length;
					}
					
				} else {

					int arrIndex = mnemonic.indexOf('[');
					String typeName = mnemonic.substring(0, arrIndex);
					
					DataType dataType = findFirstDataType(typeManager, typeName);
					
					if (dataType == null) {
						
						if (typeName.equals("ds") || typeName.equals("db") ||
							typeName.equals("dw") || typeName.equals("ddw") ||
							typeName.equals("dl") || typeName.equals("addr") ||
							typeName.equals("char") || typeName.equals("dq") ||
							typeName.equals("sdw") || typeName.equals("sdb") ||
							typeName.trim().endsWith("*")) {
							if (writeComments) {
								writeLine("\t; " + mnemonic);
							}
						} else {					
							monitor.setMessage(String.format("Unrecognized data type or mnemonic found in hunk %d at address %08x: %s", hunkIndex, address.getUnsignedOffset(), mnemonic));
							monitor.cancel();
							return 0;
						}
					}
					else {
						if (writeComments) {
							writeLine("\t; " + toCTypeName(dataType, typeName) + mnemonic.substring(arrIndex));
						}
					}
					
					writeArray(mnemonic.substring(arrIndex), typeName, typeManager, data,
						dataOffset, monitor, address, hunkIndex, memory);
					
					return data.length;
				}
				
			} else {

				if (mnemonic.equals("??")) {
					if (writeComments) {
						writeLine(String.format("; Unknown data at address %08x.", address.getUnsignedOffset()));
					}
					if (isBss) {
						write(String.format("\tdx.b %d", data.length));
					} else {
						write("\tdc.b ");
						for (int i = 0; i < data.length; ++i) {
							if (i != 0) {
								write(",");
								if (i % 8 == 0) {
									writeLine();
									write("\t\t");
								}
							}
							write(toHex(data[i], 1));
						}
					}
					return data.length;
				}
				
				DataType dataType = findFirstDataType(typeManager, mnemonic);
				
				if (dataType == null) {
					monitor.setMessage(String.format("Unrecognized data type or mnemonic found in hunk %d at address %08x: %s", hunkIndex, address.getUnsignedOffset(), mnemonic));
					monitor.cancel();
					return 0;
				}
				
				if (writeComments) {
					writeLine("\t; " + toCTypeName(dataType, mnemonic));
				}
				
				if (dataType instanceof Structure) {
					Structure s = (Structure)dataType;
					data = ensureData(data, memory, address, s.getLength());
					writeStruct(s, data, dataOffset, typeManager, monitor, address, hunkIndex);
					return s.getLength();					
				} else if (dataType instanceof ghidra.program.model.data.Enum) {
					ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum)dataType;
					data = ensureData(data, memory, address, e.getLength());
					writeEnum(e, data, dataOffset, e.getLength(), typeManager, monitor, address, hunkIndex);
					return e.getLength();					
				} else if (dataType instanceof Pointer) {
					if (isBss) {
						write("\tdx.l 1");
					} else {
						data = ensureData(data, memory, address, 4);
						writePointerLabel(getLabelForAddress(memory, data, dataOffset));
					}
					return 4;				
				} else if (dataType instanceof TypeDef) {
					TypeDef td = (TypeDef)dataType;
					DataType baseType = td.getBaseDataType();
					writeData(baseType.getDisplayName(), data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return baseType.getLength();
				} else if (dataType instanceof Undefined1DataType) {
					writeData("db", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 1;
				} else if (dataType instanceof Undefined2DataType) {
					writeData("dw", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 2;
				} else if (dataType instanceof UnsignedShortDataType) {
					writeData("dw", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 2;
				} else if (dataType instanceof Undefined4DataType) {
					writeData("dl", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 4;
				} else if (dataType instanceof UnsignedIntegerDataType) {
					writeData("dl", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 4;
				} else if (dataType instanceof UnsignedLongDataType) {
					writeData("dl", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 4;
				} else if (dataType instanceof QWordDataType) {
					writeData("dq", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 8;
				}  else if (dataType instanceof CharDataType) {
					writeData("char", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 1;
				}
			}
		}		
		
		monitor.setMessage(String.format("Unrecognized data type or mnemonic found in hunk %d at address %08x: %s", hunkIndex, address.getUnsignedOffset(), mnemonic));
		monitor.cancel();
		return 0;
	}
	
	private String getLabelForAddress(Address address, Long fallback) {
		
		String customLabel = customLabelsByAddress.get(address);
		
		if (customLabel != null) {
			return customLabel;
		}
		
		if (fallback == null) {
			fallback = address.getUnsignedOffset();
		}
		
		AsmReference ref = references.get(fallback);
		
		if (ref != null) {
			return ref.Label;
		}
		
		String suffix = "";
		Address initialAddress = address;
		
		for (int i = 0; i < 5; ++i) { // look if there is a label at the next 4 bytes as well
			
			CodeUnit codeUnit = listing.getCodeUnitAt(address);
			
			if (codeUnit != null) {
				
				String label = codeUnit.getLabel();
				
				if (label != null) {
					return label + suffix;
				}
			}
			
			Data data = listing.getDataAt(address);
			
			if (data != null) {

				String label = data.getLabel();
				
				if (label != null) {
					return label + suffix;
				}
			}
			
			if (i != 4) {
				suffix = String.format("-%d", i + 1);
				address = address.add(1);
			}
		}
			
		// If no label was found, add one
		if (fallback >= 0x21f000 && fallback < 0x31f000) {		
			customLabel = String.format("LAB_" + toHex(fallback, 4, false));
			customLabelsByAddress.put(initialAddress, customLabel);
			
			Integer lineNumberOfAddress = lineNumbersByAddress.get(initialAddress);
			
			if (lineNumberOfAddress != null) {
				customLabels.put(lineNumberOfAddress, customLabel);
			}
			
			return customLabel;
		} else {
			// If the address is out of range, just use the hex representation
			return toHex(fallback, 4, true);
		}
	}
	
	private static String toHex(long value, int sizeInBytes) {
		
		return toHex(value, sizeInBytes, true);
	}
	
	private static String toHex(long value, int sizeInBytes, boolean withPrefix) {
		
		String result;
		
		switch (sizeInBytes) {
			case 1:
				result = String.format("%02x", value & 0xff);
				break;
			case 2:
				result = String.format("%04x", value & 0xffff);
				break;
			case 4:
				result = String.format("%08x", value & 0xffffffff);
				break;
			default:
				throw new RuntimeException("Invalid sizeInBytes value for toHex function.");
		}
		
		int length = sizeInBytes * 2;
		
		result = result.substring(result.length() - length);
		
		if (withPrefix) {
			return "$" + result;
		}
		
		return result;
	}
	
	private static String toHex(byte[] data, int dataOffset, int length) {

		String result = "";
		
		for (int i = 0; i < length; ++i) {
			
			result += toHex(data[dataOffset + i], 1, false);
		}
		
		return "$" + result;
	}
	
	private String getLabelForAddress(Address currentAddress, byte[] addressData,
			int dataOffset, boolean is16BitAddress) {
		
		long offset = is16BitAddress
			? readShort(addressData, dataOffset)
			: bytesToBigEndianLong(addressData, dataOffset);
		
		if (offset == 0) {
			return "0";
		} else if (offset == -1) {
			return "-1";
		}
		
		long current = currentAddress.getOffset();
		long add = offset - current;
		
		try {
			currentAddress = currentAddress.add(add);
		} catch (Exception e) {
			String offsetString = toHex(offset, 4);
			System.out.println(String.format("Label couldn't be determined for offset %s. Referenced at address %08x.",
				offsetString, current));
			return offsetString;
		}

		return getLabelForAddress(currentAddress, offset);
	}
	
	private String getLabelForAddress(Memory memory, byte[] addressData, int dataOffset) {
		
		long offset = bytesToBigEndianLong(addressData, dataOffset);
		
		if (offset == 0) {
			return "0";
		} else if (offset == -1) {
			return "-1";
		}
		
		Address address = memory.getProgram().getAddressMap().getImageBase().add(offset);

		return getLabelForAddress(address, offset);
	}
	
	private static long toUnsignedByte(byte b) {
		
		long result = b;
		
		return result < 0 ? result + 256 : result;		
	}
	
	private static long bytesToBigEndianLong(byte[] bytes, int offset) {
		
		long result = toUnsignedByte(bytes[offset]);
		result <<= 8;
		result += toUnsignedByte(bytes[offset + 1]);
		result <<= 8;
		result += toUnsignedByte(bytes[offset + 2]);
		result <<= 8;
		result += toUnsignedByte(bytes[offset + 3]);
		
		if (result == Integer.MAX_VALUE + 1) {
			return Integer.MIN_VALUE;
		} else if (result > Integer.MAX_VALUE) {
			result = -(1 + ((~result) & Integer.MAX_VALUE));
		}
		
		return result;
	}
	
	private static short readShort(byte[] bytes, int offset) {
		
		long result = toUnsignedByte(bytes[offset]);
		result <<= 8;
		result += toUnsignedByte(bytes[offset + 1]);
		
		if (result == Short.MAX_VALUE + 1) {
			return Short.MIN_VALUE;
		} else if (result > Short.MAX_VALUE) {
			result = -(1 + ((~result) & Short.MAX_VALUE));
		}
		
		return (short)result;
	}
	
	private static short readIndexDisplacement(byte[] bytes, int offset) {
		return bytes[offset + 1];
	}
	
	private String getIndexExpression(Address address, String baseRegister, byte[] bytes,
		int extensionWordOffset, boolean allowLabelForDisplacement) {
		
		int displacement = bytes[extensionWordOffset + 1];
		String d = getDisplacement(address, displacement, 1, allowLabelForDisplacement);
		int flags = bytes[extensionWordOffset];
		
		String reg = (flags & 0x80) == 0 ? "D" : "A";
			
		reg += String.format("%d", (flags >> 4) & 0x7);
		
		if ((flags & 0x08) == 0) { // word sized index
			reg += ".w";
		} else { // long sized index
			reg += ".l";
		}
		
		return String.format("(%s,%s,%s)", d, baseRegister, reg);
	}
	
	private void writeStruct(Structure dataType, byte[] data, int dataOffset,
			ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex) {

		if (currentHunkType.equals("BSS")) {
			write(String.format("\tdx.b %d", dataType.getLength()));
		} else {
		
			String name = dataType.getName();
			int offset = 0;
			
			while (true) {
				
				DataTypeComponent component = dataType.getDefinedComponentAtOrAfterOffset(offset);
				
				if (component == null) {
					break;
				}
				
				if (offset != 0) {
					writeLine();
				}
				
				DataType componentDataType = component.getDataType();
				
				writeStructComponent(componentDataType, data, dataOffset + offset, typeManager, monitor, address, hunkIndex);
				
				int length = component.getLength();
				offset += length;
				address = address.add(length);
				
				String comment = exportComments ? component.getComment() : null;
				
				if (comment == null && writeComments) {
					comment = component.getFieldName();
					
					if (comment != null) {
						comment = name + "." + comment;
					}
				}
				
				if (comment != null) {
					write(" ; " + comment);
				}
			}
		}
	}
	
	private void writeArray(int dimension, DataType elementType, ProgramDataTypeManager typeManager,
			byte[] data, int dataOffset, TaskMonitor monitor, Address address, int hunkIndex) {
		
		if (currentHunkType.equals("BSS")) {
			write(String.format("\tdx.b %d", dimension * elementType.getLength()));
		} else {
			if (elementType instanceof CharDataType) {
				byte[] buffer = new byte[dimension];
				for (int i = 0; i < dimension; ++i) {
					buffer[i] = data[dataOffset + i];
				}
				write("\tdc.b " + getStringLiteralFromData(buffer, 0, true));
			} else {
				for (int i = 0; i < dimension; ++i) {
					writeStructComponent(elementType, data, dataOffset, typeManager, monitor, address, hunkIndex);
					int size = elementType.getLength();
					dataOffset += size;
					address = address.add(size);
					
					if (i != dimension - 1) {
						writeLine();
					}
				}
			}
		}
	}
	
	private void writeStructComponent(DataType dataType, byte[] data, int dataOffset,
			ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex) {

		if (dataType instanceof Structure) {
			writeStruct((Structure)dataType, data, dataOffset, typeManager, monitor,
				address, hunkIndex);
			return;					
		} else if (dataType instanceof ghidra.program.model.data.Enum) {
			writeEnum((ghidra.program.model.data.Enum)dataType, data, dataOffset, dataType.getLength(),
				typeManager, monitor, address, hunkIndex);
			return;					
		} else if (dataType instanceof Array) {
			Array arr = (Array)dataType;
			DataType elementType = arr.getDataType();
			writeArray(arr.getNumElements(), elementType, typeManager, data, dataOffset, monitor, address, hunkIndex);
			return;					
		} else if (dataType instanceof Pointer) {
			writePointerLabel(getLabelForAddress(address, data, dataOffset, false));
			return;				
		} else if (dataType instanceof TypeDef) {
			TypeDef td = (TypeDef)dataType;
			DataType baseType = td.getBaseDataType();
			writeStructComponent(baseType, data, dataOffset, typeManager, monitor, address, hunkIndex);
			return;
		} else if (dataType instanceof Undefined1DataType ||
				   dataType instanceof ByteDataType) {
			write("\tdc.b " + toHex(data[dataOffset], 1));
		} else if (dataType instanceof SignedByteDataType) {
			write(String.format("\tdc.b %d", data[dataOffset]));
		} else if (dataType instanceof Undefined2DataType ||
				   dataType instanceof WordDataType ||
				   dataType instanceof UnsignedShortDataType) {
			write("\tdc.w " + toHex(readShort(data, dataOffset), 2));
		} else if (dataType instanceof SignedWordDataType ||
				   dataType instanceof ShortDataType) {
			write(String.format("\tdc.w %d", readShort(data, dataOffset)));
		} else if (dataType instanceof Undefined4DataType ||
				   dataType instanceof DWordDataType ||
				   dataType instanceof UnsignedIntegerDataType ||
				   dataType instanceof UnsignedLongDataType) {
			write("\tdc.l " + toHex(bytesToBigEndianLong(data, dataOffset), 4));
		} else if (dataType instanceof SignedDWordDataType) {
			write(String.format("\tdc.l %d", bytesToBigEndianLong(data, dataOffset)));
		} else if (dataType instanceof QWordDataType) {
			write(String.format("\tdc.l %d", bytesToBigEndianLong(data, dataOffset)));
			write(String.format("\tdc.l %d", bytesToBigEndianLong(data, dataOffset + 4)));
		} else if (dataType instanceof CharDataType) {
			byte ch = data[dataOffset];
			if (ch < 0x20) {
				write(String.format("\tdc.b %d", ch));
			} else {
				write(String.format("\tdc.b '%s'", new String(data, dataOffset, 1, charset)));
			}
		} else {
			throw new RuntimeException(String.format("Unrecognize data type '%s' at address %08x.", dataType.getClass().getName(), address.getUnsignedOffset()));
		}
	}
	
	private void writeEnum(ghidra.program.model.data.Enum dataType, byte[] data,
			int dataOffset, int size, ProgramDataTypeManager typeManager,
			TaskMonitor monitor, Address address, int hunkIndex) {

		long value = 0;
		boolean isBss = currentHunkType.equals("BSS");
		
		if (size == 1) {
			if (isBss) {
				write("\tdx.b 1");
			} else {
				value = data[dataOffset];
				write("\tdc.b " + toHex(value, 1));
			}
		} else if (size == 2) {
			if (isBss) {
				write("\tdx.w 1");
			} else {
				value = readShort(data, dataOffset);
				write("\tdc.w " + toHex(value, 2));
			}
		} else if (size == 4) {
			if (isBss) {
				write("\tdx.l 1");
			} else {
				value = bytesToBigEndianLong(data, dataOffset);
				write("\tdc.l " + toHex(value, 4));
			}
		} else {
			throw new RuntimeException(String.format("Invalid enum value size %d at address %08x.", size, address.getUnsignedOffset()));
		}
		
		if (writeComments) {

			String name = dataType.getName(value);
			
			if (name == null) {
				// Try flag values (EnumValue1 | EnumValue2)
				name = getFlagEnumNames(dataType, value);
			}

			if (name != null) {
				write(" ; = " + name);
			} else {
				write(String.format(" ; Invalid enum value: %d", value));
			}
		}
	}
	
	private String getFlagEnumNames(ghidra.program.model.data.Enum enumType, long value) {
		
		int bits = enumType.getLength() * 8;
		String names = "";
		
		for (int i = 0; i < bits; ++i) {
			
			long bitValue = 1 << i;
			
			if ((value & bitValue) != 0) {
				
				String name = enumType.getName(bitValue);
				
				if (name == null) {
					return null;
				}
				
				if (names.isEmpty()) {
					names = name;
				} else {
					names += " | " + name;
				}
			}
		}
		
		return names;
	}
	
	private String toCTypeName(DataType dataType, String mnemonic) {
		
		if (dataType instanceof Structure) {
			return "struct " + mnemonic;					
		} else if (dataType instanceof ghidra.program.model.data.Enum) {
			return "enum " + mnemonic;					
		} else if (dataType instanceof Pointer) {
			Pointer p = (Pointer)dataType;
			DataType innerType = p.getDataType();
			return toCTypeName(innerType, mnemonic) + "*";					
		} else if (dataType instanceof TypeDef) {
			TypeDef td = (TypeDef)dataType;
			DataType baseType = td.getBaseDataType();
			writeLine("\t; typedef " + baseType.getDisplayName() + " " + dataType.getDisplayName());
			return mnemonic;
		} else if (dataType instanceof Undefined1DataType) {
			return "undefined1";
		} else if (dataType instanceof Undefined2DataType) {
			return "undefined2";
		} else if (dataType instanceof UnsignedShortDataType) {
			return "unsigned short"; // 16 bit unsigned integer
		} else if (dataType instanceof Undefined4DataType) {
			return "undefined4";
		} else if (dataType instanceof UnsignedIntegerDataType) {
			return "unsigned long"; // 32 bit unsigned integer
		} else if (dataType instanceof UnsignedLongDataType) {
			return "unsigned long"; // 32 bit unsigned integer
		} else if (dataType instanceof CharDataType) {
			return "char";
		}
		
		throw new RuntimeException("Invalid data type of Java type " + dataType.getClass().getName());
	}
	
	private static String getStringLiteralFromData(byte[] data, int offset, boolean charArray) {
		
		int len = data.length - offset;
		if (!charArray) {
			--len;
		}
		String str = new String(data, offset, len, charset);
		len = str.length();
		
		if (len == 0) {
			if (charArray) {
				return "\"\"";
			} else {
				return "\"\",0";
			}
		}
		
		String output = "";
		boolean wasControlChar = false;
		
		for (int i = 0; i < len; ++i) {
			
			char ch = str.charAt(i);
			String replacement = null;
			
			if (ch == '\r') {
				replacement = "$d";
			} else if (ch == '\n') {
				replacement = "$a";
			} else if (ch == '\0') {
				replacement = "0";
			} else if (ch == '"') {
				replacement = "'\"'";
			}
			
			if (replacement != null) {
								
				if (i == 0) {
					output += replacement;
				} else {
					if (!wasControlChar) {
						output += "\"";
					}
					output += "," + replacement;
				}
				
				wasControlChar = true;

			} else {
				
				if (wasControlChar) {					
					output += ",\"";
				} else if (i == 0) {
					output += "\"";
				}
				
				output += ch;
				
				wasControlChar = false;
			}
		}
		
		if (!wasControlChar) {
			output += "\"";
		}
		
		return charArray ? output : output + ",0";
	}
}
