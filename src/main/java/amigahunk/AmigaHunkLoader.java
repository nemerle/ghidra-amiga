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
package amigahunk;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.reloc.InstructionStasher;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import hunk.BinFmtHunk;
import hunk.BinImage;
import hunk.HunkBlockFile;
import hunk.HunkBlockType;
import hunk.HunkParseError;
import hunk.Reloc;
import hunk.Relocate;
import hunk.Segment;
import hunk.SegmentType;
import hunk.XDefinition;
import hunk.XReference;
import structs.InitData_Type;
import structs.InitTable;

public class AmigaHunkLoader extends AbstractLibrarySupportLoader {
	static final String AMIGA_HUNK = "Amiga Executable Hunks loader";
	public static final int DEF_IMAGE_BASE = 0x21F000;

	static final String OPTION_NAME = "ImageBase";
	public static Address imageBase = null;

	static final byte[] RTC_MATCHWORD = new byte[] { 0x4A, (byte) 0xFC };
	static final byte RTF_AUTOINIT = (byte) (1 << 7);

	static final String defsSegmName = "DEFS";
	static final String refsSegmName = "REFS";
	static final int defsSegmImageBaseOffset = 0x10000;
	static int refsLastIndex = 0;
	static int defsLastIndex = 0;

	@Override
	public String getName() {
		return AMIGA_HUNK;
	}
	
	public static int getImageBase(int offset) {
		return (int) (((imageBase != null) ? imageBase.getOffset() : DEF_IMAGE_BASE) + offset);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		var langComp = new LanguageCompilerSpecPair("68000:BE:32:default", "default");

		try {
			if(HunkBlockFile.isHunkBlockFile(new BinaryReader(provider, false)))
				loadSpecs.add(new LoadSpec(this, 0, langComp, true));
			else if(provider.readByte(0) == 0x11 && provider.readByte(1) == 0x11)
				loadSpecs.add(new LoadSpec(this, 0x100_0000 - provider.length(), langComp, true));
		} catch(Exception e) {
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws IOException {
		refsLastIndex = 0;
		defsLastIndex = 0;
		
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Memory mem = program.getMemory();

		BinaryReader reader = new BinaryReader(provider, false);

		// executable
		if(loadSpec.getDesiredImageBase() == 0) {
			HunkBlockType type = HunkBlockFile.peekType(reader);
			HunkBlockFile hbf = new HunkBlockFile(reader, type == HunkBlockType.TYPE_LOADSEG);
			switch (type) {
			case TYPE_LOADSEG: 
			case TYPE_UNIT:
				try {
					loadExecutable(imageBase, type == HunkBlockType.TYPE_LOADSEG, hbf, fpa, monitor, mem, log);
				} catch (Throwable e) {
					e.printStackTrace();
					log.appendException(e);
				}
			break;
			case TYPE_LIB:
			break;
			default:
			break;
			}
		} else {
			try {
				loadKickstart(provider, loadSpec.getDesiredImageBase(), fpa, monitor, mem, log);
			} catch (Throwable e) {
				e.printStackTrace();
				log.appendException(e);
			}

		}
	}

	private static void loadKickstart(ByteProvider provider, long imageBase, FlatProgramAPI fpa, TaskMonitor monitor, Memory mem, MessageLog log) throws Throwable {
		var block = createSegment(new ByteProviderInputStream(provider), fpa, "ROM", imageBase, provider.length(), false, true, log);
		var startAddr = block.getStart().add(2);

		var fdm = fpa.openDataTypeArchive(Application.getModuleDataFile("amiga_ndk39.gdt").getFile(false), true);
		createCustomSegment(fpa, fdm, log);

		analyzeResident(mem, fpa, fdm, startAddr, log);
		
		setFunction(fpa, startAddr, "start", log);
	}

	private static void loadExecutable(Address imageBase, boolean isExecutable, HunkBlockFile hbf, FlatProgramAPI fpa, TaskMonitor monitor, Memory mem, MessageLog log) throws Throwable {
		BinImage bi = BinFmtHunk.loadImage(hbf, log);
		
		if (bi == null) {
			return;
		}
		
		int _imageBase = getImageBase(0);

		Relocate rel = new Relocate(bi);
		int[] addrs = rel.getSeqAddresses(_imageBase);
		List<byte[]> datas;
		try {
			datas = rel.relocate(addrs);
		} catch (HunkParseError e1) {
			log.appendException(e1);
			return;
		}
		
		int lastSectAddress = 0;

		for (Segment seg : bi.getSegments()) {
			int segOffset = addrs[seg.getId()];
			int size = seg.getSize();
			
			if (segOffset + size > lastSectAddress) {
				lastSectAddress = segOffset + size;
			}

			ByteArrayInputStream segBytes = new ByteArrayInputStream(datas.get(seg.getId()));

			if (segBytes.available() == 0) {
				continue;
			}

			boolean exec = seg.getType() == SegmentType.SEGMENT_TYPE_CODE;
			boolean write = seg.getType() == SegmentType.SEGMENT_TYPE_DATA;

			createSegment(segBytes, fpa, seg.getName(), segOffset, size, write, exec, log);
			relocateSegment(seg, segOffset, datas, mem, fpa, log);
		}
		
		for (Segment seg : bi.getSegments()) {
			int segOffset = addrs[seg.getId()];

			applySegmentDefs(seg, segOffset, fpa, fpa.getCurrentProgram().getSymbolTable(), log, lastSectAddress);
		}
		
		Address startAddr = fpa.toAddr(addrs[0]);
		
		var fdm = fpa.openDataTypeArchive(Application.getModuleDataFile("amiga_ndk39.gdt").getFile(false), true);
		createBaseSegment(fpa, fdm, log);
		createCustomSegment(fpa, fdm, log);
		analyzeResident(mem, fpa, fdm, startAddr, log);
		
		if(isExecutable)
			setFunction(fpa, startAddr, "start", log);
		
		addSymbols(bi.getSegments(), fpa.getCurrentProgram().getSymbolTable(), addrs, fpa);
	}

	private static DataType getAmigaDataType(FileDataTypeManager fdm, String type) {
		var list = new ArrayList<DataType>();
		fdm.findDataTypes(type, list);
		return !list.isEmpty() ? list.get(0) : null;
	}

	private static void createCustomSegment(FlatProgramAPI fpa, FileDataTypeManager fdm, MessageLog log) {
		// TODO: CIA
		log.appendMsg("Creating custom chips memory block");
		var block = createSegment(null, fpa, "Custom", 0xdff000, 0x200, true, false, log);
		var program = fpa.getCurrentProgram();
		try {
			var regs = getAmigaDataType(fdm, "Custom");
			DataUtilities.createData(program, block.getStart(), regs, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			fpa.createLabel(block.getStart(), "Custom", false);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private static void addSymbols(Segment segs[], SymbolTable st, int addrs[], FlatProgramAPI fpa) throws Throwable {
		for (Segment seg : segs) {
			hunk.Symbol[] symbols = seg.getSymbols(seg);
			if(symbols.length > 0) {
				for(hunk.Symbol symbol : symbols) {
					String name = symbol.getName();
					int offset = symbol.getOffset();
					st.createLabel(fpa.toAddr(addrs[seg.getId()]+offset), name, SourceType.IMPORTED);
				}
			}
		}
	}

	private static void relocateSegment(Segment seg, int segOffset, final List<byte[]> datas, Memory mem, FlatProgramAPI fpa, MessageLog log) {
		Segment[] toSegs = seg.getRelocationsToSegments();

		for (Segment toSeg : toSegs) {
			Reloc[] reloc = seg.getRelocations(toSeg);

			for (Reloc r : reloc) {
				int dataOffset = r.getOffset();

				ByteBuffer buf = ByteBuffer.wrap(datas.get(seg.getId()));
				int newAddr = 0;
				
				try {
					switch (r.getWidth()) {
					case 4:
						newAddr = buf.getInt(dataOffset) + r.getAddend();
						break;
					case 2:
						newAddr = buf.getShort(dataOffset) + r.getAddend();
						break;
					case 1:
						newAddr = buf.get(dataOffset) + r.getAddend();
						break;
					}
					patchReference(mem, fpa.toAddr(segOffset + dataOffset), newAddr, r.getWidth());
				} catch (MemoryAccessException | CodeUnitInsertionException e) {
					log.appendException(e);
					return;
				}
			}
		}
	}
	
	private static void applySegmentDefs(Segment seg, int segOffset, FlatProgramAPI fpa, SymbolTable st, MessageLog log, int lastSectAddress) throws Throwable {
		if (seg.getSegmentInfo().getDefinitions() == null) {
			return;
		}
		
		Memory mem = fpa.getCurrentProgram().getMemory();
		
		for (final XDefinition entry : seg.getSegmentInfo().getDefinitions()) {
			Address defAddr = fpa.toAddr(entry.getOffset());
			
			if (!entry.isAbsolute()) {
				defAddr = fpa.toAddr(segOffset + entry.getOffset());
			}
			
			if (mem.contains(defAddr)) {
				st.createLabel(defAddr, entry.getName(), SourceType.USER_DEFINED);
				
				if (entry.getName().equals("___startup")) {
					setFunction(fpa, defAddr, entry.getName(), log);
				}
			} else {
				addDefinition(mem, fpa, st, entry.getName(), entry.getOffset());
			}
		}
		
		if (seg.getSegmentInfo().getReferences() == null) {
			return;
		}
		
		for (final XReference entry : seg.getSegmentInfo().getReferences()) {
			for (Integer offset : entry.getOffsets()) {
				Address fromAddr = fpa.toAddr(segOffset + offset);
				int newAddr = 0;
				
				switch (entry.getType()) {
				case R_ABS: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, newAddr, entry.getWidth());
				} break;
				case R_SD: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, (int) (newAddr - lastSectAddress), entry.getWidth());
				} break;
				case R_PC: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, (int) (newAddr - fromAddr.getOffset()), entry.getWidth());
				} break;
				}
				
			}
		}
	}
	
	private static void patchReference(Memory mem, Address fromAddr, int toAddr, int width) throws MemoryAccessException, CodeUnitInsertionException {
		InstructionStasher instructionStasher = new InstructionStasher(mem.getProgram(), fromAddr);
		switch (width) {
		case 4:
			mem.setBytes(fromAddr, intToBytes(toAddr));
			break;
		case 2:
			mem.setBytes(fromAddr, shortToBytes((short) toAddr));
			break;
		case 1:
			mem.setBytes(fromAddr, new byte[] {(byte) toAddr});
			break;
		}
		instructionStasher.restore();
	}

	private static int addReference(Memory mem, FlatProgramAPI fpa, SymbolTable st, String name, int lastSectAddress) throws Throwable {
		List<Symbol> syms = st.getGlobalSymbols(name);
		
		if (syms.size() > 0) {
			return (int) syms.get(0).getAddress().getOffset();
		}
		
		MemoryBlock block = mem.getBlock(refsSegmName);
		
		if (block == null) {
			int transId = mem.getProgram().startTransaction(String.format("Create %s block", refsSegmName));
			block = mem.createUninitializedBlock(refsSegmName, fpa.toAddr(lastSectAddress), 4, false);
			mem.getProgram().endTransaction(transId, true);
		}
		
		Address newAddress = block.getStart().add(refsLastIndex * 4);
		expandBlockByDword(mem, block, newAddress, false);
		
		st.createLabel(newAddress, name, SourceType.IMPORTED);
		refsLastIndex++;
		
		return (int) newAddress.getOffset();
	}
	
	private static int addDefinition(Memory mem, FlatProgramAPI fpa, SymbolTable st, String name, int value) throws Throwable {
		List<Symbol> syms = st.getGlobalSymbols(name);
		
		if (syms.size() > 0) {
			return (int) syms.get(0).getAddress().getOffset();
		}
		
		MemoryBlock block = mem.getBlock(defsSegmName);

		if (block == null) {
			int transId = mem.getProgram().startTransaction(String.format("Create %s block", defsSegmName));
			block = mem.createInitializedBlock(defsSegmName, fpa.toAddr(getImageBase(defsSegmImageBaseOffset)), 4, (byte) 0x00, TaskMonitor.DUMMY, false);
			mem.getProgram().endTransaction(transId, true);
		}
		
		Address newAddress = block.getStart().add(defsLastIndex * 4);
		expandBlockByDword(mem, block, newAddress, true);
		
		st.createLabel(newAddress, name, SourceType.USER_DEFINED);
		mem.setInt(newAddress, value);
		DataUtilities.createData(mem.getProgram(), newAddress, DWordDataType.dataType, -1, true, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		defsLastIndex++;
		
		return (int) newAddress.getOffset();
	}
	
	private static void expandBlockByDword(Memory mem, MemoryBlock block, Address appendAddress, boolean initialized) throws Throwable {
		if (block.getStart().equals(appendAddress)) {
			return;
		}
		
		int transId = mem.getProgram().startTransaction(String.format("Expand %s block", block.getName()));
		MemoryBlock tmp = mem.createUninitializedBlock(block.getName() + ".exp", appendAddress, 4, false);
		mem.getProgram().endTransaction(transId, true);
		
		if (initialized) {
			tmp = mem.convertToInitialized(tmp, (byte)0x00);
		}
		
		mem.join(block, tmp);
	}

	private static byte[] intToBytes(int x) {
		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.order(ByteOrder.BIG_ENDIAN);
		buffer.putInt(x);
		return buffer.array();
	}
	
	private static byte[] shortToBytes(short x) {
		ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES);
		buffer.order(ByteOrder.BIG_ENDIAN);
		buffer.putShort(x);
		return buffer.array();
	}

	private static void analyzeResident(Memory mem, FlatProgramAPI fpa, FileDataTypeManager fdm, Address startAddr, MessageLog log) {
		Program program = fpa.getCurrentProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		var funcsList = new FdFunctionsInLibs();

		try {
			while (true) {
				Address addr = fpa.find(startAddr, RTC_MATCHWORD);

				if (addr == null) {
					break;
				}

				long rt_MatchTag = mem.getInt(addr.add(2));

				startAddr = addr.add(2);
				if (addr.getOffset() != rt_MatchTag) {
					continue;
				}

				DataUtilities.createData(program, addr, getAmigaDataType(fdm, "Resident"), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				byte rt_Flags = mem.getByte(addr.add(10));

				var NameAddr = addr.getNewAddress(mem.getInt(addr.add(14), true));
				var builder = new StringBuilder();
				for(int i = 0; mem.getByte(NameAddr.add(i)) != 0 && mem.getByte(NameAddr.add(i)) != 0xd && mem.getByte(NameAddr.add(i)) != 0xa; i++)
					builder.append(Character.toChars(mem.getByte(NameAddr.add(i))));
				var rt_Name = builder.toString();

				if ((rt_Flags & RTF_AUTOINIT) == RTF_AUTOINIT) {
					long rt_Init = mem.getInt(addr.add(22));
					Address rt_InitAddr = fpa.toAddr(rt_Init);

					DataUtilities.createData(program, rt_InitAddr, (new InitTable()).toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

					/* long it_DataSize = */mem.getInt(rt_InitAddr.add(0));
					long it_FuncTable = mem.getInt(rt_InitAddr.add(4));
					long it_DataInit = mem.getInt(rt_InitAddr.add(8));
					long it_InitFunc = mem.getInt(rt_InitAddr.add(12));

					Address it_InitFuncAddr = fpa.toAddr(it_InitFunc);
					setFunction(fpa, it_InitFuncAddr, String.format("it_InitFunc_%06X", addr.getOffset()), log);
					Function func = fpa.getFunctionAt(it_InitFuncAddr);
					func.setCustomVariableStorage(true);

					List<ParameterImpl> params = new ArrayList<>();
					
					Structure baseStruct = new StructureDataType("BaseLib", 0);
					baseStruct.add(getAmigaDataType(fdm, "Library"), "base", null);
					baseStruct.add(WordDataType.dataType, "field0", null);

					params.add(new ParameterImpl("libBase", PointerDataType.dataType, program.getRegister("A6"), program));
					params.add(new ParameterImpl("seglist", PointerDataType.dataType, program.getRegister("A0"), program));
					params.add(new ParameterImpl("lib", new PointerDataType(baseStruct), program.getRegister("D0"), program));

					func.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));

					if (it_DataInit != 0) {
						Address it_DataInitAddr = fpa.toAddr(it_DataInit);
						program.getSymbolTable().createLabel(it_DataInitAddr, String.format("it_DataInit_%06X", addr.getOffset()), SourceType.ANALYSIS);

						while (true) {
							InitData_Type tt;
							try {
								tt = new InitData_Type(mem, fpa, it_DataInitAddr.getOffset());
							} catch (Exception e) {
								break;
							}
							DataUtilities.createData(program, it_DataInitAddr, tt.toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
							it_DataInitAddr = it_DataInitAddr.add(tt.toDataType().getLength());
						}
					}
					Address it_FuncTableAddr = fpa.toAddr(it_FuncTable);
					program.getSymbolTable().createLabel(it_FuncTableAddr, String.format("it_FuncTable_%06X", addr.getOffset()), SourceType.ANALYSIS);

					int i = 0;
					boolean askedForFd = false;
					FdLibFunctions funcTable = null;
					
					boolean isRelative = (mem.getShort(it_FuncTableAddr) & 0xFFFF) == 0xFFFF;

					while (true) {
						long funcAddr;
						
						if (isRelative) {
							short relVal = mem.getShort(it_FuncTableAddr.add((i + 1) * 2));
							
							if ((relVal & 0xFFFF) == 0xFFFF) {
								break;
							}
							
							funcAddr = it_FuncTableAddr.add(relVal).getOffset();
						} else {
							funcAddr = mem.getInt(it_FuncTableAddr.add(i * 4));
						}
						
						Address funcAddr_ = fpa.toAddr(funcAddr);
						if (!mem.contains(funcAddr_)) {
							break;
						}

						var libName = rt_Name.replace('.', '_');;
						if(funcsList.findLibIndex(libName) != -1)
							funcTable = funcsList.getFunctionTableByLib(libName);

						if(funcTable == null && !askedForFd && i >= 4) {
							TimeUnit.SECONDS.sleep(1);
							if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null,
									"Question", String.format("Do you have %s.sfd file for this library?", rt_Name))) {
								String fdPath = showSelectFile("Select file...");
								funcTable = FdParser.readSfdFile(fdPath);
							}
							askedForFd = true;
						}

						if (isRelative) {
							DataUtilities.createData(program, it_FuncTableAddr.add((i + 1) * 2), WordDataType.dataType, -1,
									false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
							refMgr.addMemoryReference(it_FuncTableAddr.add((i + 1) * 2), funcAddr_, RefType.DATA, SourceType.ANALYSIS, 0);
						} else {
							DataUtilities.createData(program, it_FuncTableAddr.add(i * 4), PointerDataType.dataType, -1,
									false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
						}

						FdFunction funcDef = null;
						if (funcTable != null) {
							funcDef = funcTable.getFunctionByIndex(i - 4);
						}

						String name;

						switch (i) {
						case 0:
							name = "LIB_OPEN";
							break;
						case 1:
							name = "LIB_CLOSE";
							break;
						case 2:
							name = "LIB_EXPUNGE";
							break;
						case 3:
							name = "LIB_EXTFUNC";
							break;
						default:
							name = funcDef != null ? funcDef.getName(false) : String.format("LibFunc_%03d", i - 4);
						}

						setFunction(fpa, funcAddr_, name, log);
						func = fpa.getFunctionAt(funcAddr_);
						func.setCustomVariableStorage(true);

						params = new ArrayList<>();

						params.add(new ParameterImpl("base", new PointerDataType(baseStruct), program.getRegister("A6"), program));

						if (funcDef != null) {
							for (var arg : funcDef.getArgs()) {
								params.add(new ParameterImpl(arg.name, PointerDataType.dataType, program.getRegister(arg.reg), program));
							}
						}

						func.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true,
								SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));
						i++;
					}
				} // autoinit
			}
		} catch (InvalidInputException | MemoryAccessException | AddressOutOfBoundsException
				| CodeUnitInsertionException | DuplicateNameException | IOException | InterruptedException e) {
			log.appendException(e);
		}
	}

	private static String showSelectFile(String title) {
		JFileChooser jfc = new JFileChooser(new File("."));
		jfc.setDialogTitle(title);

		jfc.setFileFilter(new FileNameExtensionFilter("Functions Definition File", "fd"));
		jfc.setMultiSelectionEnabled(false);

		if (jfc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			return jfc.getSelectedFile().getAbsolutePath();
		}

		return null;
	}

	private static void createBaseSegment(FlatProgramAPI fpa, FileDataTypeManager fdm, MessageLog log) {
		MemoryBlock exec = createSegment(null, fpa, "EXEC", 0x4, 4, false, false, log);
		
		Program program = fpa.getCurrentProgram();

		try {
			DataUtilities.createData(program, exec.getStart(), new PointerDataType(getAmigaDataType(fdm, "ExecBase")), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}

	public static void setFunction(FlatProgramAPI fpa, Address address, String name, MessageLog log) {
		try {
			fpa.disassemble(address);
			fpa.createFunction(address, name);
			fpa.addEntryPoint(address);
			fpa.getCurrentProgram().getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	public static MemoryBlock createSegment(InputStream stream, FlatProgramAPI fpa, String name, long address, long size, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			Program program = fpa.getCurrentProgram();
			
			int transId = program.startTransaction(String.format("Create %s block", name));
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			program.endTransaction(transId, true);
			
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
			return block;
		} catch (Exception e) {
			log.appendException(e);
			return null;
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();

		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		try {
			Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
			imageBase = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(DEF_IMAGE_BASE);
			list.add(new Option(OPTION_NAME, imageBase, Address.class, Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"));
		} catch (LanguageNotFoundException e) {

		}

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		imageBase = null;

		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(OPTION_NAME)) {
					imageBase = (Address) option.getValue();

					long val = imageBase.getOffset();
					if (val >= 0x1000L && val <= 0x700000L) {
						break;
					}
				}
			} catch (Exception e) {
				if (e instanceof OptionException) {
					return e.getMessage();
				}
				return "Invalid value for " + optName + " - " + option.getValue();
			}
		}
		if (imageBase == null || (imageBase.getOffset() < 0x1000L) || (imageBase.getOffset() >= 0x80000000L)) {
			return "Invalid image base";
		}

		return null;
	}
}
