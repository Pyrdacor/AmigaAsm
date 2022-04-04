package amigaasm.export;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

public class AmigaExporter implements CancelledListener {
	
	// Options
	private boolean exportComments = true;
	
	// State
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
			writeLine(writer, "; }"); // end of section
		}
		writer.flush();
		writer.close();
		
		return true;
	}
	
	private boolean processAddress(OutputStreamWriter writer, Listing listing,
			Address address, Memory memory, ProgramDataTypeManager typeManager,
			int blockIndex, String hunkName, long blockSize, TaskMonitor monitor) throws IOException {
		
		if (lastBlockIndex != blockIndex) {
			int hunkIndex = -1;
			writeLine(writer);
			writeLine(writer, "; #################");
			if (address.getUnsignedOffset() < 0x21f000) {
				currentHunkType = hunkName; // should be "EXEC"
				writeLine(writer, String.format("; # %s          #", hunkName));
			} else {
				Pattern hunkNamePattern = Pattern.compile("([A-Z]+)_([0-9]+)");
				Matcher matcher = hunkNamePattern.matcher(hunkName);
				if (!matcher.matches()) {
					writeLine(writer, String.format("; # %s          #", hunkName));
				} else {
					currentHunkType = matcher.group(1);
					boolean isBss = currentHunkType.equals("BSS");
					hunkIndex = Integer.parseInt(matcher.group(2));
					writeLine(writer, String.format("; # HUNK%s - %s #", matcher.group(2), isBss ? "BSS " : currentHunkType));
				}
			}
			writeLine(writer, "; #################");
			
			if (hunkIndex != -1) {
				if (hunkIndex != 0) {
					writeLine(writer, "; }"); // end of section
				}
				writeLine(writer, String.format("\tsection\thunk%02d,%s", hunkIndex, currentHunkType));
				writeLine(writer, "; {"); // begin section
			}
			
			lastBlockIndex = blockIndex;
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
	
	private boolean writeCode(OutputStreamWriter writer, Address address,
			CodeUnit codeUnit, Memory memory, ProgramDataTypeManager typeManager,
			int hunkIndex, TaskMonitor monitor) throws IOException {
		
		long addressOffset = address.getUnsignedOffset();
		String label = codeUnit.getLabel();
		
		if (label != null) {
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
				
				if (Arrays.binarySearch(Instructions.Names, mnemonic.toLowerCase()) != -1) {
					writer.write("\t" + mnemonic);
					
					/*Symbol[] symbols = codeUnit.getSymbols();
					
					if (symbols != null) {

						for (int i = 0; i < symbols.length; ++i) {

							writer.write(" " + symbols[i].getName());
						}
					}*/
					
					int numOps = codeUnit.getNumOperands();
					String prefix = " ";
					for (int i = 0; i < numOps; ++i) {
						Reference[] opRefs = codeUnit.getOperandReferences(i);
						if (opRefs != null && opRefs.length != 0) {
							for (int j = 0; j < opRefs.length; ++j) {
								Reference op = opRefs[j];
								if (op.isMemoryReference()) {
									Address addr = op.getToAddress();		
									String targetLabel = this.getLabelForAddress(address, null);
									if (targetLabel != null) {
										writer.write(prefix + targetLabel);
									} else {
										// TODO: maybe use address?
										System.out.println(String.format("Missing label for target address %08x.", address.getUnsignedOffset()));
									}
								} else if (op.isRegisterReference()) {
									System.out.println("foo");
								} else {
									System.out.println(String.format("Unsupported operand '%s' at address %08x.", op.getReferenceType().getName(), address.getUnsignedOffset()));
								}
							}
						} else {
							if (codeUnit instanceof Instruction) {
								Instruction inst = (Instruction)codeUnit;
								int type = inst.getOperandType(i);
								if (type == OperandType.DYNAMIC) { // (A0)+ etc
									if (i == 1 && mnemonic.equals("move") || mnemonic.startsWith("move.")) {
										// Note: move encodes the destination first but it is the second operand (i == 1)
										// TODO
									} else {
										// move's source and all others encode the address mode the same way
										// TODO: I guess there are some special commands which always use dynamic addressing
										int mode = (bytes[1] >> 3) & 0x7;
										int reg = bytes[1] & 0x7;
																				
										// TODO ...
										// TODO: maybe use regex, some like (A0)+ can be used "as is"
										// TODO: I guess only index and displacement should be converted (e.g. use label displacements etc)
									}
									// TODO: maybe we have to parse the mode from the opcode (is easy for all but move)
									System.out.println("foo");
								} else if (type == OperandType.SCALAR) {
									writer.write(prefix + inst.getScalar(i).toString(16, true, true, "$", ""));
								} else if (type == OperandType.REGISTER) {
									// TODO: is SP already displayed this way or as A7? if so, adjust
									writer.write(prefix + inst.getRegister(i).toString());
								} else {
									System.out.println("foo");
								}
							} else {
								// TODO: error
							}
						}
						prefix = ",";
					}

					return true;
				}
			}
		}
		
		if (currentHunkType.equals("DATA") || currentHunkType.equals("BSS") || currentHunkType.equals("CODE")) {

			String mnemonic = codeUnit.getMnemonicString();
				
			byte[] bytes = null;
			try {
				bytes = codeUnit.getBytes();
			} catch (MemoryAccessException e) {
				// Unable to read
			}
			
			writeData(writer, mnemonic, bytes, typeManager, monitor, address, hunkIndex, memory);
			
			return true;
			
		}

		if (currentHunkType.equals("EXEC")) {
			// TODO
		} else {
			System.out.println("Unrecognized hunk type: " + currentHunkType);
		}

		return false;
	}
	
	private void writeArray(OutputStreamWriter writer, String arrayIndexPattern, String typeName,
			ProgramDataTypeManager typeManager, byte[] data, TaskMonitor monitor,
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
			
			writeData(writer, typeName, data, typeManager, monitor, address, hunkIndex, memory);
			address.add(data.length);
			
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
	
	private void writeData(OutputStreamWriter writer, String mnemonic, byte[] data,
			ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex, Memory memory) throws IOException {
		
		if (mnemonic.equals("ds")) {
			writer.write("\tdc.b \"" + getStringFromData(data) + "\",0");
		} else if (mnemonic.equals("db")) {
			writer.write(String.format("\tdc.b $%02x", data[0]));
		} else if (mnemonic.equals("dw")) {
			writer.write(String.format("\tdc.w $%02x%02x", data[0], data[1]));
		} else if (mnemonic.equals("ddw") || mnemonic.equals("dl")) {
			writer.write(String.format("\tdc.l $%02x%02x%02x%02x", data[0], data[1], data[2], data[3]));
		} else if (mnemonic.equals("addr")) {
			writer.write("\tdc.l " + this.getLabelForAddress(memory, data));
			return;
		} else if (mnemonic.equals("char")) {
			writer.write("\tdc.b " + (data[0] < 0x20 ? String.format("%x", data[0]) : "'" + (char)data[0] + "'"));
			return;
		} else {
			// Expect mnemonic to be the typename
			if (mnemonic.endsWith("]")) { // array
				
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
						return;
					}
				}
				else {
					writeLine(writer, "\t; " + toCTypeName(writer, dataType, typeName) + mnemonic.substring(arrIndex));
				}
				
				writeArray(writer, mnemonic.substring(arrIndex), typeName, typeManager, data,
					monitor, address, hunkIndex, memory);
				
			} else {

				if (mnemonic.equals("??")) {
					monitor.setMessage(String.format("Unresolved data in hunk %d at address %08x", hunkIndex, address.getUnsignedOffset()));
					monitor.cancel();
					return;
				}
				
				DataType dataType = findFirstDataType(typeManager, mnemonic);
				
				if (dataType == null) {
					monitor.setMessage(String.format("Unrecognized data type or mnemonic found in hunk %d at address %08x: %s", hunkIndex, address.getUnsignedOffset(), mnemonic));
					monitor.cancel();
					return;
				}
				
				writeLine(writer, "\t; " + toCTypeName(writer, dataType, mnemonic));
				
				if (dataType instanceof Structure) {
					writeStruct(writer, (Structure)dataType, data, typeManager, monitor,
							address, hunkIndex);
					return;					
				} else if (dataType instanceof ghidra.program.model.data.Enum) {
					writeEnum(writer, (ghidra.program.model.data.Enum)dataType, data, typeManager, monitor,
						address, hunkIndex);
					return;					
				} else if (dataType instanceof Pointer) {
					writer.write("dc.l " + getLabelForAddress(memory, data));
					return;				
				} else if (dataType instanceof TypeDef) {
					TypeDef td = (TypeDef)dataType;
					DataType baseType = td.getBaseDataType();
					writeData(writer, baseType.getDisplayName(), data, typeManager, monitor,
						address, hunkIndex, memory);
					return;
				} else if (dataType instanceof Undefined1DataType) {
					writeData(writer, "db", data, typeManager, monitor,
						address, hunkIndex, memory);
				} else if (dataType instanceof Undefined2DataType) {
					writeData(writer, "dw", data, typeManager, monitor,
						address, hunkIndex, memory);
				} else if (dataType instanceof Undefined4DataType) {
					writeData(writer, "dl", data, typeManager, monitor,
						address, hunkIndex, memory);
				} else if (dataType instanceof UnsignedIntegerDataType) {
					writeData(writer, "dl", data, typeManager, monitor,
						address, hunkIndex, memory);
				} else if (dataType instanceof CharDataType) {
					writeData(writer, "char", data, typeManager, monitor,
						address, hunkIndex, memory);
				}
			}
		}
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
	
	private static long toUnsignedByte(byte b) {
		
		long result = b;
		
		return result < 0 ? result + 256 : result;		
	}
	
	private static long bytesToBigEndianLong(byte[] bytes) {
		
		long result = toUnsignedByte(bytes[0]);
		result <<= 8;
		result += toUnsignedByte(bytes[1]);
		result <<= 8;
		result += toUnsignedByte(bytes[2]);
		result <<= 8;
		result += toUnsignedByte(bytes[3]);
		
		if (result > Integer.MAX_VALUE) {
			result = -(result & Integer.MAX_VALUE);
		}
		
		return result;
	}
	
	
	private String getLabelForAddress(Memory memory, byte[] addressData) {
		
		long offset = bytesToBigEndianLong(addressData);
		Address address = memory.getProgram().getAddressMap().getImageBase().add(offset);

		return getLabelForAddress(address, offset);
	}
	
	private void writeStruct(OutputStreamWriter writer, Structure dataType, byte[] data,
			ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex) throws IOException {

	}
	
	private void writeEnum(OutputStreamWriter writer, ghidra.program.model.data.Enum dataType, byte[] data,
			ProgramDataTypeManager typeManager, TaskMonitor monitor,
			Address address, int hunkIndex) throws IOException {

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
	
	private static String getStringFromData(byte[] data) {
		
		// TODO: Amiga charset
		return new String(data, 0, data.length - 1, StandardCharsets.ISO_8859_1);
	}
}
