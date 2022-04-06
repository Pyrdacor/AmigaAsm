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
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import amigaasm.AmigaAsmExporter;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.data.SignedWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
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
	
	// State
	private static final Charset charset = StandardCharsets.ISO_8859_1; // TODO: Amiga charset
	private boolean exportCancelled = false;
	private Listing listing = null;
	private int lastBlockIndex = -1;
	private String currentHunkType = "";
	private Dictionary<Long, String> references = new Hashtable<Long, String>();
	
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
			}
		}
	}
	
	public boolean export(File file, ProgramDB programDB,
			TaskMonitor monitor) throws ExporterException, IOException {
		
		if (file.exists() && !file.canWrite())
			throw new IOException("The given file is not writeable.");
		
		monitor.addCancelledListener(this);
			
		OutputStreamWriter writer = new OutputStreamWriter(
            new FileOutputStream(file.getPath()), "UTF-8");
		ProgramDataTypeManager typeManager = programDB.getDataTypeManager();		
		
		Memory memory = programDB.getMemory();
		AddressIterator addressIter = memory.getAddresses(true);
		listing = programDB.getListing();
		MemoryBlock[] blocks = memory.getBlocks();
		
		while (!exportCancelled && addressIter.hasNext()) {
			
			Address address = addressIter.next();
			MemoryBlock block = memory.getBlock(address);
			int blockIndex = Arrays.binarySearch(blocks, block);
			processAddress(writer, listing, address, memory, typeManager,
				blockIndex, block.getName(), block.getSize(), monitor);
		}
		
		if (lastBlockIndex != -1) {
			writeLine(writer, ";   }"); // end of section
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
	
	private boolean processAddress(OutputStreamWriter writer, Listing listing,
			Address address, Memory memory, ProgramDataTypeManager typeManager,
			int blockIndex, String hunkName, long blockSize, TaskMonitor monitor) throws IOException {
		
		if (lastBlockIndex != blockIndex) {
			int hunkIndex = -1;
			if (address.getUnsignedOffset() < 0x21f000) {
				currentHunkType = hunkName; // should be "EXEC"
				if (currentHunkType.equals("EXEC")) {
					System.out.println("Skipping EXEC section.");
				} else {
					System.out.println("Unrecognized section: " + currentHunkType);
				}
			} else {
				Pattern hunkNamePattern = Pattern.compile("([A-Z]+)_([0-9]+)");
				Matcher matcher = hunkNamePattern.matcher(hunkName);
				writeLine(writer);
				writeLine(writer, "; " + headerBar);
				if (!matcher.matches()) {
					writeLine(writer, "; " + getHeaderTitle(hunkName));
				} else {
					currentHunkType = matcher.group(1);
					boolean isBss = currentHunkType.equals("BSS");
					hunkIndex = Integer.parseInt(matcher.group(2));
					writeLine(writer, "; " + getHeaderTitle(String.format("HUNK%s - %s", matcher.group(2), isBss ? "BSS " : currentHunkType)));
				}
				writeLine(writer, "; " + headerBar);
			}			

			if (hunkIndex != -1) {
				if (hunkIndex != 0) {
					writeLine(writer, ";   }"); // end of section
				}
				writeLine(writer, String.format("\tsection\thunk%02d,%s", hunkIndex, currentHunkType));
				writeLine(writer, ";   {"); // begin section
			}
			
			lastBlockIndex = blockIndex;
		}
		
		if (!currentHunkType.equals("DATA") && !currentHunkType.equals("BSS") && !currentHunkType.equals("CODE")) {
			return false;
		}

		CodeUnit codeUnit = listing.getCodeUnitAt(address);
		
		if (codeUnit != null) {
			if (exportComments) {
				exportCodeAndComments(writer, address, codeUnit, memory, typeManager, blockIndex, monitor);
			} else {
				writeCode(writer, address, codeUnit, memory, typeManager, blockIndex, monitor);
				writeLine(writer);
			}
			return true;
		}
		
		Data data = listing.getDataAt(address);
		
		if (data != null) {
			if (exportComments) {
				exportCodeAndComments(writer, address, data, memory, typeManager, blockIndex, monitor);
			} else {
				writeCode(writer, address, data, memory, typeManager, blockIndex, monitor);
				writeLine(writer);
			}
			return true;
		}
		
		return false;
	}
	
	private void exportCodeAndComments(OutputStreamWriter writer, Address address,
			CodeUnit codeUnit, Memory memory, ProgramDataTypeManager typeManager,
			int hunkIndex, TaskMonitor monitor) throws IOException {

		String comment = codeUnit.getComment(CodeUnit.PRE_COMMENT);
		
		if (comment != null) {
			writeLine(writer, "\t; " + comment.replace("\n", "\n\t; "));
		}
		
		comment = codeUnit.getComment(CodeUnit.REPEATABLE_COMMENT);
		
		if (comment != null) {
			writeLine(writer, "\t; " + comment.replace("\n", "\n\t; "));
		}
		
		boolean codeWritten = writeCode(writer, address, codeUnit, memory, typeManager, hunkIndex, monitor);
		
		comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
		
		if (comment != null) {
			String prefix = codeWritten ? " " : "\t";
			writer.write(prefix + "; " + comment.replace("\n", "\n\t\t\t; "));
			codeWritten = true;
		}
		
		if (codeWritten) {
			writeLine(writer);
		}
		
		comment = codeUnit.getComment(CodeUnit.POST_COMMENT);
		
		if (comment != null) {
			writeLine(writer, "\t; " + comment.replace("\n", "\n\t; "));
		}
	}
	
	private static void writeLine(OutputStreamWriter writer) throws IOException {
		writer.write("\r\n");
	}
	
	private static void writeLine(OutputStreamWriter writer, String text) throws IOException {
		writer.write(text + "\r\n");
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
	
	private boolean writeCode(OutputStreamWriter writer, Address address,
			CodeUnit codeUnit, Memory memory, ProgramDataTypeManager typeManager,
			int hunkIndex, TaskMonitor monitor) throws IOException {
		
		long addressOffset = address.getUnsignedOffset();
		
		// TODO: REMOVE
		if (addressOffset == 0x0022d31a) {
			int x = 0;
		}
		
		String label = codeUnit.getLabel();
		
		if (label != null) {
			// TODO: REMOVE
			if (label.equals("LAB_0021f1bc")) {
				int x = 0;
			}
			writeLine(writer, label + ":");
			
			// If there is a label, add this as a reference.
			references.put(addressOffset, label);
		}
		
		if (currentHunkType.equals("CODE") && !(codeUnit instanceof Data)) {

			// Try to process code instructions (data sections are handled later)
			String mnemonic = codeUnit.getMnemonicString(); // THIS is only the instruction without params
			
			byte[] bytes = null;
			try {
				bytes = codeUnit.getBytes();
			} catch (MemoryAccessException e) {
				// Unable to read
			}
			
			if (mnemonic != null) {
				
				String opcode = mnemonic.toLowerCase();
				int dotIndex = opcode.indexOf('.');
				
				if (dotIndex >= 0) {
					opcode = opcode.substring(0, dotIndex);
				}
				
				if (Arrays.binarySearch(Instructions.Names, opcode) >= 0) {
					writer.write("\t" + mnemonic);
					
					int numOps = codeUnit.getNumOperands();
					int byteOffset = 2;
					String prefix = " ";
					for (int i = 0; i < numOps; ++i) {
						Reference[] opRefs = codeUnit.getOperandReferences(i);
						if (opRefs != null && opRefs.length != 0) {
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
														writer.write(prefix + "(" + this.getLabelForAddress(targetAddr, null) + ",PC)");
													} else { // mode 3
														targetAddr = address.add(readIndexDisplacement(bytes, byteOffset));
														writer.write(prefix + "(" + this.getLabelForAddress(targetAddr, null) + String.format(",PC,D%d)", (bytes[byteOffset] >> 4) & 0x7));
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
														writer.write(prefix + "(" + this.getLabelForAddress(targetAddr, null) + ",PC)");
													} else { // mode 3
														targetAddr = address.add(readIndexDisplacement(bytes, byteOffset));
														writer.write(prefix + "(" + this.getLabelForAddress(targetAddr, null) + String.format(",PC,D%d)", (bytes[byteOffset] >> 4) & 0x7));
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
										writer.write(prefix + targetLabel);
									} else {
										// TODO: maybe use address?
										throw new RuntimeException(String.format("Missing label for target address %08x.", addr.getUnsignedOffset()));
									}
									} else if (op.isRegisterReference()) {
									System.out.println("foo");
								} else if (op.isStackReference()) {
									StackReference sr = (StackReference)op;
									
									if (mnemonic.startsWith("movem")) {
										if (i == 1) {
											writer.write(prefix + "-(SP)");
										} else {
											writer.write(prefix + "(SP)+");
										}
									} else {
										if (sr.getStackOffset() < 0) {
											writer.write(prefix + "-(SP)");
										} else {
											writer.write(prefix + "(SP)+");
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
												
												writer.write(prefix + code.substring(matcher.start() + 1, matcher.end() - 1).trim().replace(' ', '/'));
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
										writer.write(prefix + "D" + Integer.toString(reg));
									} else {
										// TODO: I guess there are more special commands which always use dynamic addressing									
										switch (mode) {
											case 0: // Dn (should be not dynamic)
											case 1: // An (should be not dynamic)
												System.out.println("Unexpected address mode");
												break;
											case 2: // (An), should be already handled
												writer.write(prefix + "(" + getAddrRegisterName(reg) + ")");
												break;
											case 3: // (An)+
												writer.write(prefix + "(" + getAddrRegisterName(reg) + ")+");
												break;
											case 4: // -(An)
												writer.write(prefix + "-(" + getAddrRegisterName(reg) + ")");
												break;
											case 5: // (d,An)
												writer.write(prefix + String.format("($%04x,%s)", readDisplacement(bytes, byteOffset), getAddrRegisterName(reg)));
												byteOffset += 2;
												break;
											case 6: // (d,An,Xn)
												writer.write(prefix + getIndexExpression(getAddrRegisterName(reg), bytes, byteOffset));
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
														writer.write(prefix + String.format("($%04x,PC)", readDisplacement(bytes, byteOffset)));
														byteOffset += 2;
														break;
													case 3: // (d,PC,Xn)
														writer.write(prefix + getIndexExpression("PC", bytes, byteOffset));
														byteOffset += 2;
														break;
												}
											}
										}
									}
								} else if (type == OperandType.SCALAR) {
									writer.write(prefix + inst.getScalar(i).toString(16, true, true, "#$", ""));
								} else if (type == OperandType.REGISTER) {
									String reg = trimRegSuffix(inst.getRegister(i).toString());
									if (reg.equals("SP") && mnemonic.startsWith("movem")) {
										// -(SP) is stored as SP for movem for some reason
										// but it is never used directly as SP so
										// we can safely replace it with -(SP) here.
										reg = "-(SP)";
									}
									writer.write(prefix + reg);
								} else if (type == (OperandType.REGISTER | OperandType.INDIRECT)) {
									writer.write(prefix + "(" + trimRegSuffix(inst.getRegister(i).toString()) + ")");
								} else {
									System.out.println("foo");
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
		}
		
		writeData(writer, mnemonic, bytes, 0, typeManager, monitor, address, hunkIndex, memory);
		
		return true;
	}
	
	private void writeArray(OutputStreamWriter writer, String arrayIndexPattern, String typeName,
			ProgramDataTypeManager typeManager, byte[] data, int dataOffset, TaskMonitor monitor,
			Address address, int hunkIndex, Memory memory) throws IOException {
		
		Pattern pattern = Pattern.compile("(\\[[0-9]+\\])+");
		Matcher matcher = pattern.matcher(arrayIndexPattern);
		
		if (!matcher.matches() ) {
			// TODO
			throw new RuntimeException("Array index pattern did not match.");
		}
		
		int totalAmount = 0;

		for (int i = 0; i < matcher.groupCount(); ++i) {
			
			String value = matcher.group(i);
			int dim = Integer.parseInt(value.substring(1, value.length() - 1));
			totalAmount = totalAmount == 0 ? dim : totalAmount * dim;
		}
		
		for (int n = 0; n < totalAmount; ++n) {
			
			int size = writeData(writer, typeName, data, dataOffset, typeManager, monitor, address, hunkIndex, memory);
			dataOffset += size;
			address = address.add(size);
			
			if (n != totalAmount - 1) {
				writeLine(writer);
			}
		}
	}
	
	private static DataType findFirstDataType(ProgramDataTypeManager typeManager, String name) {
		
		List<DataType> types = new ArrayList<DataType>();
		typeManager.findDataTypes(name, types, false, null);
		
		return types.isEmpty() ? null : types.get(0);
	}
	
	private int writeData(OutputStreamWriter writer, String mnemonic, byte[] data,
			int dataOffset, ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex, Memory memory) throws IOException {
		
		if (mnemonic.equals("ds")) {
			writer.write("\tdc.b \"" + getStringFromData(data, dataOffset) + "\",0");
			return data.length - dataOffset;
		} else if (mnemonic.equals("db")) {
			writer.write(String.format("\tdc.b $%02x", data[dataOffset]));
			return 1;
		} else if (mnemonic.equals("dw")) {
			writer.write(String.format("\tdc.w $%02x%02x", data[dataOffset], data[dataOffset + 1]));
			return 2;
		} else if (mnemonic.equals("ddw") || mnemonic.equals("dl")) {
			writer.write(String.format("\tdc.l $%02x%02x%02x%02x", data[dataOffset], data[dataOffset + 1],
				data[dataOffset + 2], data[dataOffset + 3]));
			return 4;
		} else if (mnemonic.equals("addr")) {
			writer.write("\tdc.l " + this.getLabelForAddress(memory, data, dataOffset));
			return 4;
		} else if (mnemonic.equals("char")) {
			writer.write("\tdc.b " + (data[dataOffset] < 0x20 ? String.format("%x", data[dataOffset]) : "'" + (char)data[dataOffset] + "'"));
			return 1;
		} else {
			// Expect mnemonic to be the typename
			if (mnemonic.endsWith("]")) { // array
				
				DataType arrType = findFirstDataType(typeManager, mnemonic);
				
				if (arrType != null) {
					
					writeLine(writer, "\t; " + mnemonic);
					Array arr = (Array)arrType;
					
					writeArray(writer, arr.getNumElements(), arr.getDataType(), typeManager, data, dataOffset, monitor, address, hunkIndex);
					return data.length;
					
				} else {

					int arrIndex = mnemonic.indexOf('[');
					String typeName = mnemonic.substring(0, arrIndex);
					
					DataType dataType = findFirstDataType(typeManager, typeName);
					
					if (dataType == null) {
						
						if (typeName.equals("ds") || typeName.equals("db") ||
							typeName.equals("dw") || typeName.equals("ddw") ||
							typeName.equals("dl") || typeName.equals("addr") ||
							typeName.equals("char")) {						
							writeLine(writer, "\t; " + mnemonic);
						} else {					
							monitor.setMessage(String.format("Unrecognized data type or mnemonic found in hunk %d at address %08x: %s", hunkIndex, address.getUnsignedOffset(), mnemonic));
							monitor.cancel();
							return 0;
						}
					}
					else {
						writeLine(writer, "\t; " + toCTypeName(writer, dataType, typeName) + mnemonic.substring(arrIndex));
					}
					
					writeArray(writer, mnemonic.substring(arrIndex), typeName, typeManager, data,
						dataOffset, monitor, address, hunkIndex, memory);
					
					return data.length;
				}
				
			} else {

				if (mnemonic.equals("??")) {
					monitor.setMessage(String.format("Unresolved data in hunk %d at address %08x", hunkIndex, address.getUnsignedOffset()));
					monitor.cancel();
					return 0;
				}
				
				DataType dataType = findFirstDataType(typeManager, mnemonic);
				
				if (dataType == null) {
					monitor.setMessage(String.format("Unrecognized data type or mnemonic found in hunk %d at address %08x: %s", hunkIndex, address.getUnsignedOffset(), mnemonic));
					monitor.cancel();
					return 0;
				}
				
				writeLine(writer, "\t; " + toCTypeName(writer, dataType, mnemonic));
				
				if (dataType instanceof Structure) {
					Structure s = (Structure)dataType;
					writeStruct(writer, s, data, dataOffset, typeManager, monitor,
						address, hunkIndex);
					return s.getLength();					
				} else if (dataType instanceof ghidra.program.model.data.Enum) {
					ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum)dataType;
					writeEnum(writer, e, data, dataOffset, e.getLength(),
						typeManager, monitor, address, hunkIndex);
					return e.getLength();					
				} else if (dataType instanceof Pointer) {
					writer.write("dc.l " + getLabelForAddress(memory, data, dataOffset));
					return 4;				
				} else if (dataType instanceof TypeDef) {
					TypeDef td = (TypeDef)dataType;
					DataType baseType = td.getBaseDataType();
					writeData(writer, baseType.getDisplayName(), data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return baseType.getLength();
				} else if (dataType instanceof Undefined1DataType) {
					writeData(writer, "db", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 1;
				} else if (dataType instanceof Undefined2DataType) {
					writeData(writer, "dw", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 2;
				} else if (dataType instanceof Undefined4DataType) {
					writeData(writer, "dl", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 4;
				} else if (dataType instanceof UnsignedIntegerDataType) {
					writeData(writer, "dl", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 4;
				} else if (dataType instanceof CharDataType) {
					writeData(writer, "char", data, dataOffset, typeManager, monitor,
						address, hunkIndex, memory);
					return 1;
				}
			}
		}		
		
		// TODO: throw
		
		return 0;
	}
	
	private String getLabelForAddress(Address address, Long fallback) {
		
		if (fallback == null) {
			fallback = address.getUnsignedOffset();
		}
		
		CodeUnit codeUnit = listing.getCodeUnitAt(address);
		
		if (codeUnit == null) {
			
			Data data = listing.getDataAt(address);
			
			if (data != null) {

				String label = data.getLabel();
				
				if (label != null) {
					return label;
				}
			}
			
			for (int i = 0; i < 4; ++i) {
			
				address = address.add(1);				
				codeUnit = listing.getCodeUnitAt(address);
				
				if (codeUnit == null) {
					
					data = listing.getDataAt(address);
					
					if (data != null) {

						String label = data.getLabel();
						
						if (label != null) {
							return label + String.format("-%d", i + 1);
						}
					}
				} else {
				
					String label = codeUnit.getLabel();
					
					if (label != null) {
						return label + String.format("-%d", 2 + i + 1);
					}
				}
			}
			
			
			// TODO: throw, maybe external target like Amiga system calls?
			
			return String.format("$%08x", fallback);
		}

		String label = codeUnit.getLabel();
		
		if (label != null) {
			return label;
		}
		
		// TODO: add a label in output at that offset and return it here (this might need a second pass)
		return String.format("$%08x", fallback);
	}
	
	private String getLabelForAddress(Address address, byte[] addressData, int dataOffset) {
		
		long offset = bytesToBigEndianLong(addressData, dataOffset);
		long current = address.getOffset();
		long add = offset - current;
		address = address.add(add);

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
		
		if (result > Integer.MAX_VALUE) {
			result = -(result & Integer.MAX_VALUE);
		}
		
		return result;
	}
	
	private static short readDisplacement(byte[] bytes, int offset) {
		
		long result = toUnsignedByte(bytes[offset]);
		result <<= 8;
		result += toUnsignedByte(bytes[offset + 1]);
		
		if (result > Short.MAX_VALUE) {
			result = -(result & Short.MAX_VALUE);
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
		
		String d = String.format("$%02x", Math.abs(displacement));
		
		if (displacement < 0) {
			d = "-" + d;
		}
		
		return String.format("(%s,%s,%s)", d, baseRegister, reg);
	}
	
	private void writeStruct(OutputStreamWriter writer, Structure dataType, byte[] data,
			int dataOffset, ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex) throws IOException {

		String name = dataType.getName();
		int offset = 0;
		
		while (true) {
			
			DataTypeComponent component = dataType.getDefinedComponentAtOrAfterOffset(offset);
			
			if (component == null) {
				break;
			}
			
			if (offset != 0) {
				writeLine(writer);
			}
			
			DataType componentDataType = component.getDataType();
			
			writeStructComponent(writer, componentDataType, data, dataOffset + offset, typeManager, monitor, address, hunkIndex);
			
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
				writer.write(" ; " + comment);
			}
		}
	}
	
	private void writeArray(OutputStreamWriter writer, int dimension, DataType elementType,
			ProgramDataTypeManager typeManager, byte[] data, int dataOffset, TaskMonitor monitor,
			Address address, int hunkIndex) throws IOException {
		
		for (int i = 0; i < dimension; ++i) {
			writeStructComponent(writer, elementType, data, dataOffset, typeManager, monitor, address, hunkIndex);
			int size = elementType.getLength();
			dataOffset += size;
			address = address.add(size);
			
			if (i != dimension - 1) {
				writeLine(writer);
			}
		}
	}
	
	private void writeStructComponent(OutputStreamWriter writer, DataType dataType,
			byte[] data, int dataOffset, ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex) throws IOException {

		if (dataType instanceof Structure) {
			writeStruct(writer, (Structure)dataType, data, dataOffset, typeManager, monitor,
				address, hunkIndex);
			return;					
		} else if (dataType instanceof ghidra.program.model.data.Enum) {
			writeEnum(writer, (ghidra.program.model.data.Enum)dataType, data, dataOffset, dataType.getLength(),
				typeManager, monitor, address, hunkIndex);
			return;					
		} else if (dataType instanceof Array) {
			Array arr = (Array)dataType;
			DataType elementType = arr.getDataType();
			writeArray(writer, arr.getNumElements(), elementType, typeManager, data, dataOffset, monitor, address, hunkIndex);
			return;					
		} else if (dataType instanceof Pointer) {
			writer.write("\tdc.l " + getLabelForAddress(address, data, dataOffset));
			return;				
		} else if (dataType instanceof TypeDef) {
			TypeDef td = (TypeDef)dataType;
			DataType baseType = td.getBaseDataType();
			writeStructComponent(writer, baseType, data, dataOffset, typeManager, monitor, address, hunkIndex);
			return;
		} else if (dataType instanceof Undefined1DataType ||
				   dataType instanceof ByteDataType) {
			writer.write(String.format("\tdc.b $%02x", data[dataOffset]));
		} else if (dataType instanceof SignedByteDataType) {
			writer.write(String.format("\tdc.b %d", data[dataOffset]));
		} else if (dataType instanceof Undefined2DataType ||
				   dataType instanceof WordDataType) {
			writer.write(String.format("\tdc.w $%04x", readDisplacement(data, dataOffset)));
		} else if (dataType instanceof SignedWordDataType) {
			writer.write(String.format("\tdc.w %d", readDisplacement(data, dataOffset)));
		} else if (dataType instanceof Undefined4DataType ||
				   dataType instanceof DWordDataType ||
				   dataType instanceof UnsignedIntegerDataType) {
			writer.write(String.format("\tdc.l $%04x", bytesToBigEndianLong(data, dataOffset)));
		} else if (dataType instanceof SignedDWordDataType) {
			writer.write(String.format("\tdc.l %d", bytesToBigEndianLong(data, dataOffset)));
		} else if (dataType instanceof CharDataType) {
			byte ch = data[dataOffset];
			if (ch < 0x20) {
				writer.write(String.format("\tdc.b %d", ch));
			} else {
				writer.write(String.format("\tdc.b '%s'", new String(data, dataOffset, 1, charset)));
			}
		} else {
			throw new RuntimeException(String.format("Unrecognize data type '%s' at address %08x.", dataType.getClass().getName(), address.getUnsignedOffset()));
		}
	}
	
	private void writeEnum(OutputStreamWriter writer, ghidra.program.model.data.Enum dataType, byte[] data,
			int dataOffset, int size, ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex) throws IOException {

		long value = 0;
		
		if (size == 1) {
			value = data[dataOffset];
			writer.write(String.format("\tdc.b %02x", value));
		} else if (size == 2) {
			value = readDisplacement(data, dataOffset);
			writer.write(String.format("\tdc.w %04x", value));
		} else if (size == 4) {
			value = bytesToBigEndianLong(data, dataOffset);
			writer.write(String.format("\tdc.l %08x", value));
		} else {
			throw new RuntimeException(String.format("Invalid enum value size %d at address %08x.", size, address.getUnsignedOffset()));
		}
		
		String name = dataType.getName(value);
		
		if (name != null) {
			writer.write(" ; " + name);
		}
	}
	
	private static String toCTypeName(OutputStreamWriter writer, DataType dataType,
			String mnemonic) throws IOException {
		
		if (dataType instanceof Structure) {
			return "struct " + mnemonic;					
		} else if (dataType instanceof ghidra.program.model.data.Enum) {
			return "enum " + mnemonic;					
		} else if (dataType instanceof Pointer) {
			Pointer p = (Pointer)dataType;
			DataType innerType = p.getDataType();
			return toCTypeName(writer, innerType, mnemonic) + "*";					
		} else if (dataType instanceof TypeDef) {
			TypeDef td = (TypeDef)dataType;
			DataType baseType = td.getBaseDataType();
			writeLine(writer, "\t; typedef " + baseType.getDisplayName() + " " + dataType.getDisplayName());
			return mnemonic;
		} else if (dataType instanceof Undefined1DataType) {
			return "undefined1";
		} else if (dataType instanceof Undefined2DataType) {
			return "undefined2";
		} else if (dataType instanceof Undefined4DataType) {
			return "undefined4";
		} else if (dataType instanceof UnsignedIntegerDataType) {
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
