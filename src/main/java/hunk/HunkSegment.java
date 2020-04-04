package hunk;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

class HunkSegment {

	private HunkSegmentBlock segBlock;
	private HunkSymbolBlock symBlock;
	private List<HunkDebugBlock> dbgBlocks;
	private List<DebugInfo> dbgInfos;
	private List<HunkRelocBlock> relocBlocks;
	private HunkExtBlock extBlock;
	
	private String name;
	
	HunkSegment() {
		segBlock = null;
		symBlock = null;
		dbgBlocks = null;
		dbgInfos = null;
		relocBlocks = null;
		extBlock = null;
		
		name = null;
	}
	
	HunkType getHunkType() {
		return (segBlock != null) ? segBlock.getHunkType() : HunkType.HUNK_BAD_TYPE;
	}
	
	void setSizeLongs(int sizeLongs) {
		if (segBlock != null) {
			segBlock.setSizeLongs(sizeLongs);
		}
	}
	
	int getSizeLongs() {
		return (segBlock != null) ? segBlock.getSizeLongs() : 0;
	}
	
	HunkSegmentBlock getSegmentBlock() {
		return segBlock;
	}

	HunkRelocBlock[] getRelocBlocks() {
		return (relocBlocks == null) ? null : relocBlocks.toArray(HunkRelocBlock[]::new);
	}
	
	String getName() {
		return name;
	}
	
	final HashMap<String, Object> getExtLocalDefs() {
		return extBlock.getLocalDefs();
	}
	
	final HashMap<String, Object> getExtGlobalDefs() {
		return extBlock.getGlobalDefs();
	}
	
	final HashMap<String, List<Object>> getExtXrefs() {
		return extBlock.getXrefs();
	}

	public void parse(List<HunkBlock> blocks) throws HunkParseError {
		for (HunkBlock block : blocks) {
			if (block.isValidLoadsegBeginHunk()) {
				segBlock = (HunkSegmentBlock)block;
			} else if (block.getHunkType() == HunkType.HUNK_NAME) {
				name = ((HunkNameBlock)block).getName();
			} else if (block.getHunkType() == HunkType.HUNK_SYMBOL) {
				if (symBlock == null) {
					symBlock = (HunkSymbolBlock)block;
				} else {
					throw new HunkParseError("Duplicate symbols in hunk");
				}
			} else if (block.getHunkType() == HunkType.HUNK_DEBUG) {
				if (dbgBlocks == null) {
					dbgBlocks = new ArrayList<>();
				}
				
				dbgBlocks.add((HunkDebugBlock)block);
				
				ByteProvider provider = new ByteArrayProvider(((HunkDebugBlock)block).getData());
				DebugInfo info = HunkDebug.decode(new BinaryReader(provider, false));
				
				if (info != null) {
					if (dbgInfos == null) {
						dbgInfos = new ArrayList<>();
					}
					
					dbgInfos.add(info);
				}
			} else if (block.getHunkType() == HunkType.HUNK_ABSRELOC32 ||
					   block.getHunkType() == HunkType.HUNK_DREL32 ||
					   block.getHunkType() == HunkType.HUNK_DREL16 ||
					   block.getHunkType() == HunkType.HUNK_DREL8 ||
					   block.getHunkType() == HunkType.HUNK_RELOC32SHORT) {
				if (relocBlocks == null) {
					relocBlocks = new ArrayList<>();
				}
				
				relocBlocks.add((HunkRelocBlock)block);
			} else if (block.getHunkType() == HunkType.HUNK_EXT) {
				if (extBlock == null) {
					extBlock = (HunkExtBlock)block;
				} else {
					throw new HunkParseError("Duplicate EXT block in hunk");
				}
			} else {
				throw new HunkParseError("Invalid hunk block");
			}
		}
	}
}
