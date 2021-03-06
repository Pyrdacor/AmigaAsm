/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package amigaasm;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import amigaasm.export.*;
import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * Exports Amiga m68k assembler
 */
public class AmigaAsmExporter extends Exporter {

	private AmigaExporter exporter = new AmigaExporter();
	public static final String OptionExportComments = "Export comments";
	public static final String OptionWriteComments = "Generate doc comments";
	public static final String OptionExport68000 = "68000 compatible";
	public static final String OptionExportNewline = "Newline";
	public static final String OptionExportNewlineCarriageReturn = "\\r";
	public static final String OptionExportNewlineLineFeed = "\\n";
	public static final String OptionExportNewlineBoth = "\\r\\n";
	
	/**
	 * Exporter constructor.
	 */
	public AmigaAsmExporter() {

		super("AmigaAsm", "s", null);
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws ExporterException, IOException {

		if (domainObj instanceof ProgramDB) {
			
			return exporter.export(file, (ProgramDB)domainObj, monitor);
		}

		return false;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		List<Option> list = new ArrayList<>();

		list.add(new Option(OptionExportComments, true));
		list.add(new Option(OptionWriteComments, true));
		list.add(new Option(OptionExport68000, false));
		
		List<String> newlineOptions = new ArrayList<String>();
		newlineOptions.add(OptionExportNewlineBoth);
		newlineOptions.add(OptionExportNewlineLineFeed);
		newlineOptions.add(OptionExportNewlineCarriageReturn);
		list.add(new ChoiceOptions(OptionExportNewline, newlineOptions, 0));

		return list;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {

		exporter.setOptions(options);
	}
}
