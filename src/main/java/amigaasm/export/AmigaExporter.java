package amigaasm.export;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.StackReference;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

public class AmigaExporter implements CancelledListener {
	
	// Options
	private boolean exportComments = true;
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
	private List<String> lines = new ArrayList<String>();
	private String currentLine = "";
	
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
		
		if (lastBlockIndex != -1) {
			writeLine(";   }"); // end of section
		}
		
		OutputStreamWriter writer = new OutputStreamWriter(
            new FileOutputStream(file.getPath()), "UTF-8");
		
		for (int i = 0; i < lines.size(); ++i) {
			int lineNumber = i + 1;
			String customLabel = customLabels.get(lineNumber);
			if (customLabel != null) {
				writer.write(customLabel + ":" + newline);
			}
			writer.write(lines.get(i) + newline);
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
				if (lastHunkIndex != -1) {
					writeLine(";   }"); // end of section
				}
				writeLine();
				writeLine("; " + headerBar);
				if (!matcher.matches()) {
					writeLine("; " + getHeaderTitle(hunkName));
				} else {
					currentHunkType = matcher.group(1);
					boolean isBss = currentHunkType.equals("BSS");
					hunkIndex = Integer.parseInt(matcher.group(2));
					writeLine("; " + getHeaderTitle(String.format("HUNK%s - %s", matcher.group(2), isBss ? "BSS " : currentHunkType)));
				}
				writeLine("; " + headerBar);
			}

			if (hunkIndex != -1) {
				writeLine(String.format("\tsection\thunk%02d,%s", hunkIndex, currentHunkType));
				writeLine(";   {"); // begin section
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
	
	private boolean writeCode(Address address, CodeUnit codeUnit, Memory memory,
			ProgramDataTypeManager typeManager,	int hunkIndex, TaskMonitor monitor) {
		
		long addressOffset = address.getUnsignedOffset();
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
		
		lineNumbersByAddress.put(address, getLineNumber());
		
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
							writeLine(String.format("; WARNING: movec was used with unknown control register code $%03x", crCode));
							return true;
						}
						
						int reg = (bytes[2] >> 4) & 0x7;
						boolean dataRegister = (bytes[2] & 0x80) == 0;
						String regName = dataRegister
							? String.format("D%d", reg)
							: getAddrRegisterName(reg);

						if ((bytes[1] & 0x1) == 0) { // CR to R
							
							writeLine("; WARNING: Replaced movec writing from " + crName + " to " + regName);
							if (dataRegister) {
								// move 0 to Dn
								write("\tmoveq #$0," + regName);
							} else {
								// clear An
								write("\tsuba.l " + regName + "," + regName);
							}
						} else { // R to CR
							// Ignore writing to control register
							writeLine("; WARNING: Removed movec writing from " + regName + " to " + crName);
						}
						
						return true;
					}
					
					write("\t" + mnemonic);
					
					// movem reg lists are sometimes treated as data refs which we will disallow
					int disallowRefOperandIndex = -1;
					if (opcode.equals("movem")) {
						
						boolean toRegister = (bytes[0] & 0x4) != 0;
						disallowRefOperandIndex = toRegister ? 1 : 0;						
					}
					
					int numOps = codeUnit.getNumOperands();
					int byteOffset = 2;
					String prefix = " ";
					for (int i = 0; i < numOps; ++i) {
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
										
										if (i == 1 && (mnemonic.equals("move") || mnemonic.startsWith("move."))) {
											
											// Note: move encodes the destination first but it is the second operand (i == 1)
											short fullInstruction = readDisplacement(bytes, 0); // we abuse this method to get a full short of the instruction
											int mode = (fullInstruction >> 6) & 0x7;
											
											if (mode == 7) {
												
												mode = (fullInstruction >> 9) & 0x7;
												
												if ((mode & 0x2) != 0) {
													
													Address targetAddr = address.add(2); // skip the opcode bytes
													
													// PC relative reference
													if (mode == 2) {
														targetAddr = address.add(readDisplacement(bytes, byteOffset));
														write(prefix + "(" + this.getLabelForAddress(targetAddr, null) + ",PC)");
													} else { // mode 3
														targetAddr = address.add(readIndexDisplacement(bytes, byteOffset));
														write(prefix + "(" + this.getLabelForAddress(targetAddr, null) + String.format(",PC,D%d)", (bytes[byteOffset] >> 4) & 0x7));
													}
													
													prefix = ",";
													continue;	
												}
											}
											
										} else {
											
											int mode = (bytes[1] >> 3) & 0x7;
											
											if (mode == 7) {
												
												mode = bytes[1] & 0x7;
												
												if ((mode & 0x2) != 0) {
													
													Address targetAddr = address.add(2); // skip the opcode bytes
													
													// PC relative reference
													if (mode == 2) {
														targetAddr = address.add(readDisplacement(bytes, byteOffset));
														write(prefix + "(" + this.getLabelForAddress(targetAddr, null) + ",PC)");
													} else { // mode 3
														targetAddr = address.add(readIndexDisplacement(bytes, byteOffset));
														write(prefix + "(" + this.getLabelForAddress(targetAddr, null) + String.format(",PC,D%d)", (bytes[byteOffset] >> 4) & 0x7));
													}
													
													prefix = ",";
													continue;	
												}
											}
										}
										
									}
							
									Address addr = op.getToAddress();		
									String targetLabel = this.getLabelForAddress(addr, null);
									if (targetLabel != null) {
										write(prefix + targetLabel);
									} else {
										// TODO: maybe use address?
										throw new RuntimeException(String.format("Missing label for target address %08x.", addr.getUnsignedOffset()));
									}
								} else if (op.isStackReference()) {
									StackReference sr = (StackReference)op;
									
									if (mnemonic.startsWith("movem")) {
										if (i == 1) {
											write(prefix + "-(SP)");
										} else {
											write(prefix + "(SP)+");
										}
									} else {
										if (sr.getStackOffset() < 0) {
											write(prefix + "-(SP)");
										} else {
											write(prefix + "(SP)+");
										}
									}
								} else {
									throw new RuntimeException(String.format("Unsupported operand '%s' at address %08x.", op.getReferenceType().getName(), address.getUnsignedOffset()));
								}
							}
						} else {
							if (codeUnit instanceof Instruction) {
								Instruction inst = (Instruction)codeUnit;
								int type = inst.getOperandType(i);
								if (type == OperandType.DYNAMIC) { // (A0)+ etc
									if (mnemonic.startsWith("movem")) {
										boolean toRegister = (bytes[0] & 0x4) != 0;
										
										if (toRegister && i == 1 ||
											!toRegister && i == 0) {
											// reg list
											String code = codeUnit.toString();
											Pattern pattern = Pattern.compile("\\{.*\\}");
											Matcher matcher = pattern.matcher(code);
											
											if (matcher.find()) {
												
												write(prefix + code.substring(matcher.start() + 1, matcher.end() - 1).trim().replace(' ', '/'));
												prefix = ",";
												continue;												
											}

											throw new RuntimeException(String.format("Invalid movem command at address %08x.", address.getUnsignedOffset()));
										}
									}
									int mode = (bytes[1] >> 3) & 0x7;
									int reg = bytes[1] & 0x7;
									if (i == 1 && (mnemonic.equals("move") || mnemonic.startsWith("move."))) {
										// Note: move encodes the destination first but it is the second operand (i == 1)
										short fullInstruction = readDisplacement(bytes, 0); // we abuse this method to get a full short of the instruction
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
										switch (mode) {
											case 0: // Dn (should be not dynamic)
											case 1: // An (should be not dynamic)
												System.out.println("Unexpected address mode");
												break;
											case 2: // (An), should be already handled
												write(prefix + "(" + getAddrRegisterName(reg) + ")");
												break;
											case 3: // (An)+
												write(prefix + "(" + getAddrRegisterName(reg) + ")+");
												break;
											case 4: // -(An)
												write(prefix + "-(" + getAddrRegisterName(reg) + ")");
												break;
											case 5: // (d,An)
												write(prefix + String.format("($%04x,%s)", readDisplacement(bytes, byteOffset), getAddrRegisterName(reg)));
												byteOffset += 2;
												break;
											case 6: // (d,An,Xn)
												write(prefix + getIndexExpression(getAddrRegisterName(reg), bytes, byteOffset));
												byteOffset += 2;
												break;
											case 7: {
												switch (reg) {
													case 0: // absolute short
													case 1: // absolute long
													case 4: // immediate
														// all of them should be handled elsewhere (scalar, reference)
														System.out.println("Unexpected address mode");
														break;
													case 2: // (d,PC)
														write(prefix + String.format("($%04x,PC)", readDisplacement(bytes, byteOffset)));
														byteOffset += 2;
														break;
													case 3: // (d,PC,Xn)
														write(prefix + getIndexExpression("PC", bytes, byteOffset));
														byteOffset += 2;
														break;
												}
											}
										}
									}
								} else if (type == OperandType.SCALAR) {
									write(prefix + inst.getScalar(i).toString(16, true, true, "#$", ""));
								} else if (type == OperandType.REGISTER) {
									String reg = trimRegSuffix(inst.getRegister(i).toString());
									if (reg.equals("SP") && mnemonic.startsWith("movem")) {
										// -(SP) is stored as SP for movem for some reason
										// but it is never used directly as SP so
										// we can safely replace it with -(SP) here.
										reg = "-(SP)";
									}
									write(prefix + reg);
								} else if (type == (OperandType.REGISTER | OperandType.INDIRECT)) {
									write(prefix + "(" + trimRegSuffix(inst.getRegister(i).toString()) + ")");
								} else if (type == (OperandType.ADDRESS | OperandType.DYNAMIC)) {
									// Sometimes used for movem reg list
									if (mnemonic.startsWith("movem")) {
										boolean toRegister = (bytes[0] & 0x4) != 0;
										
										if (toRegister && i == 1 ||
											!toRegister && i == 0) {
											// reg list
											String code = codeUnit.toString();
											Pattern pattern = Pattern.compile("\\{.*\\}");
											Matcher matcher = pattern.matcher(code);
											
											if (matcher.find()) {
												
												write(prefix + code.substring(matcher.start() + 1, matcher.end() - 1).trim().replace(' ', '/'));
												prefix = ",";
												continue;												
											}

											throw new RuntimeException(String.format("Invalid movem command at address %08x.", address.getUnsignedOffset()));
										}
									}
									
									throw new RuntimeException(String.format("Unsupported operand type $%08x at address %08x.", type, address.getUnsignedOffset()));

								} else {
									throw new RuntimeException(String.format("Unsupported operand type $%08x at address %08x.", type, address.getUnsignedOffset()));
								}
							} else {
								
								throw new RuntimeException(String.format("Couldn't read operands at address %08x.", address.getUnsignedOffset()));
								// TODO: error
							}
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
		
		for (int n = 0; n < totalAmount; ++n) {
			
			int size = writeData(typeName, data, dataOffset, typeManager, monitor, address, hunkIndex, memory);
			dataOffset += size;
			address = address.add(size);
			
			if (n != totalAmount - 1) {
				writeLine();
			}
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
		
		if (mnemonic.equals("ds")) {
			data = ensureData(data, memory, address, 1);
			write("\tdc.b \"" + getStringFromData(data, dataOffset) + "\",0");
			return data.length - dataOffset;
		} else if (mnemonic.equals("db")) {
			data = ensureData(data, memory, address, 1);
			write(String.format("\tdc.b $%02x", data[dataOffset]));
			return 1;
		} else if (mnemonic.equals("dw")) {
			data = ensureData(data, memory, address, 2);
			write(String.format("\tdc.w $%02x%02x", data[dataOffset], data[dataOffset + 1]));
			return 2;
		} else if (mnemonic.equals("ddw") || mnemonic.equals("dl")) {
			data = ensureData(data, memory, address, 4);
			write(String.format("\tdc.l $%02x%02x%02x%02x", data[dataOffset], data[dataOffset + 1],
				data[dataOffset + 2], data[dataOffset + 3]));
			return 4;
		} else if (mnemonic.equals("addr")) {
			data = ensureData(data, memory, address, 4);
			write("\tdc.l " + this.getLabelForAddress(memory, data, dataOffset));
			return 4;
		} else if (mnemonic.equals("dq")) {
			data = ensureData(data, memory, address, 8);
			writeLine(String.format("\tdc.l $%02x%02x%02x%02x", data[dataOffset], data[dataOffset + 1],
				data[dataOffset + 2], data[dataOffset + 3]));
			write(String.format("\tdc.l $%02x%02x%02x%02x", data[dataOffset + 4], data[dataOffset + 5],
				data[dataOffset + 6], data[dataOffset + 7]));
			return 4;
		} else if (mnemonic.equals("char")) {
			data = ensureData(data, memory, address, 1);
			write("\tdc.b " + (data[dataOffset] < 0x20 ? String.format("%x", data[dataOffset]) : "'" + (char)data[dataOffset] + "'"));
			return 1;
		} else {
			// Expect mnemonic to be the typename
			if (mnemonic.endsWith("]")) { // array
				
				DataType arrType = findFirstDataType(typeManager, mnemonic);
				
				if (arrType != null) {
					
					writeLine("\t; " + mnemonic);
					Array arr = (Array)arrType;
					int length = arr.getNumElements();
					DataType elemType = arr.getDataType();
					
					data = ensureData(data, memory, address, length * elemType.getLength());
					writeArray(length, elemType, typeManager, data,
							   dataOffset, monitor, address, hunkIndex);
					return data.length;
					
				} else {

					int arrIndex = mnemonic.indexOf('[');
					String typeName = mnemonic.substring(0, arrIndex);
					
					DataType dataType = findFirstDataType(typeManager, typeName);
					
					if (dataType == null) {
						
						if (typeName.equals("ds") || typeName.equals("db") ||
							typeName.equals("dw") || typeName.equals("ddw") ||
							typeName.equals("dl") || typeName.equals("addr") ||
							typeName.equals("char") || typeName.equals("dq")) {						
							writeLine("\t; " + mnemonic);
						} else {					
							monitor.setMessage(String.format("Unrecognized data type or mnemonic found in hunk %d at address %08x: %s", hunkIndex, address.getUnsignedOffset(), mnemonic));
							monitor.cancel();
							return 0;
						}
					}
					else {
						writeLine("\t; " + toCTypeName(dataType, typeName) + mnemonic.substring(arrIndex));
					}
					
					writeArray(mnemonic.substring(arrIndex), typeName, typeManager, data,
						dataOffset, monitor, address, hunkIndex, memory);
					
					return data.length;
				}
				
			} else {

				if (mnemonic.equals("??")) {
					writeLine(String.format("; Unknown data at address %08x.", address.getUnsignedOffset()));
					write("\tdc.b ");
					for (int i = 0; i < data.length; ++i) {
						if (i != 0) {
							write(",");
							if (i % 8 == 0) {
								writeLine();
								write("\t\t");
							}
						}
						write(String.format("$%02x", data[i]));
					}
					return data.length;
				}
				
				DataType dataType = findFirstDataType(typeManager, mnemonic);
				
				if (dataType == null) {
					monitor.setMessage(String.format("Unrecognized data type or mnemonic found in hunk %d at address %08x: %s", hunkIndex, address.getUnsignedOffset(), mnemonic));
					monitor.cancel();
					return 0;
				}
				
				writeLine("\t; " + toCTypeName(dataType, mnemonic));
				
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
					data = ensureData(data, memory, address, 4);
					write("dc.l " + getLabelForAddress(memory, data, dataOffset));
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
		customLabel = String.format("LAB_%08x", fallback);
		customLabelsByAddress.put(address, customLabel);
		
		Integer lineNumberOfAddress = lineNumbersByAddress.get(address);
		
		if (lineNumberOfAddress != null) {
			customLabels.put(lineNumberOfAddress, customLabel);
		}
		
		return customLabel;
	}
	
	private String getLabelForAddress(Address address, byte[] addressData, int dataOffset) {
		
		long offset = bytesToBigEndianLong(addressData, dataOffset);
		
		if (offset == 0) {
			return "0";
		} else if (offset == -1) {
			return "-1";
		}
		
		long current = address.getOffset();
		long add = offset - current;
		
		try {
			address = address.add(add);
		} catch (Exception e) {
			System.out.println(String.format("Label couldn't be determined for offset $%08x. Referenced at address %08x.", offset & 0xffffffff, current));
			return String.format("$%08x", offset & 0xffffffff);
		}

		return getLabelForAddress(address, offset);
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
	
	private static short readDisplacement(byte[] bytes, int offset) {
		
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
	
	private static String getIndexExpression(String baseRegister, byte[] bytes,
		int extensionWordOffset) {
		
		byte displacement = bytes[extensionWordOffset + 1];
		int flags = bytes[extensionWordOffset];
		
		String reg = (flags & 0x80) == 0 ? "D" : "A";
			
		reg += String.format("%d", (flags >> 4) & 0x7);
		
		String d = String.format("$%02x", Math.abs((int)displacement) & 0xff);
		
		if (displacement < 0) {
			d = "-" + d;
		}
		
		return String.format("(%s,%s,%s)", d, baseRegister, reg);
	}
	
	private void writeStruct(Structure dataType, byte[] data, int dataOffset,
			ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex) {

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
			
			String comment = component.getComment();
			
			if (comment == null) {
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
	
	private void writeArray(int dimension, DataType elementType, ProgramDataTypeManager typeManager,
			byte[] data, int dataOffset, TaskMonitor monitor, Address address, int hunkIndex) {
		
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
			write("\tdc.l " + getLabelForAddress(address, data, dataOffset));
			return;				
		} else if (dataType instanceof TypeDef) {
			TypeDef td = (TypeDef)dataType;
			DataType baseType = td.getBaseDataType();
			writeStructComponent(baseType, data, dataOffset, typeManager, monitor, address, hunkIndex);
			return;
		} else if (dataType instanceof Undefined1DataType ||
				   dataType instanceof ByteDataType) {
			write(String.format("\tdc.b $%02x", data[dataOffset]));
		} else if (dataType instanceof SignedByteDataType) {
			write(String.format("\tdc.b %d", data[dataOffset]));
		} else if (dataType instanceof Undefined2DataType ||
				   dataType instanceof WordDataType ||
				   dataType instanceof UnsignedShortDataType) {
			write(String.format("\tdc.w $%04x", readDisplacement(data, dataOffset) & 0xffff));
		} else if (dataType instanceof SignedWordDataType ||
				   dataType instanceof ShortDataType) {
			write(String.format("\tdc.w %d", readDisplacement(data, dataOffset)));
		} else if (dataType instanceof Undefined4DataType ||
				   dataType instanceof DWordDataType ||
				   dataType instanceof UnsignedIntegerDataType ||
				   dataType instanceof UnsignedLongDataType) {
			write(String.format("\tdc.l $%08x", bytesToBigEndianLong(data, dataOffset) & 0xffffffff));
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
		
		if (size == 1) {
			value = data[dataOffset];
			write(String.format("\tdc.b $%02x", value & 0xff));
		} else if (size == 2) {
			value = readDisplacement(data, dataOffset);
			write(String.format("\tdc.w $%04x", value & 0xffff));
		} else if (size == 4) {
			value = bytesToBigEndianLong(data, dataOffset);
			write(String.format("\tdc.l $%08x", value & 0xffffffff));
		} else {
			throw new RuntimeException(String.format("Invalid enum value size %d at address %08x.", size, address.getUnsignedOffset()));
		}
		
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
	
	private static String getStringFromData(byte[] data, int offset) {
		
		return new String(data, offset, data.length - offset - 1, charset);
	}
}
