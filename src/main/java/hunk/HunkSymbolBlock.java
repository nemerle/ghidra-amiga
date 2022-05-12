package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

import ghidra.util.Msg;

class HunkSymbolBlock extends HunkBlock {
	
	final List<SymbolData> symbols;


	HunkSymbolBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_SYMBOL, reader);

		Msg.info(this, "Symbol Hunk!");

		this.symbols  = new ArrayList<>();

		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		try {
//			int size = 0;
//			long ptrIdx = reader.getPointerIndex();

			List<Symbol> toAdd = new ArrayList<>();

			while (true) {
				String name = HunkBlock.readName(reader);
				
				if (name == null || name.length() == 0) {
					break;
				}

				toAdd.add(new Symbol(reader.readNextInt(), name));
//
//				reader.readNextUnsignedInt();
//				size += name.length() + 4;
			}
			symbols.add(new SymbolData(0, toAdd));
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

	protected SymbolData[] getSymbols() {
		return symbols.toArray(SymbolData[]::new);
	}

}
