package amiga;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;

/**
 * Tests for function pointer parsing logic in AmigaHunkAnalyzer.
 *
 * Note: Full integration tests with Ghidra DataTypes would require a complete
 * Ghidra environment. These tests verify the parsing logic of helper methods.
 */
public class FunctionPointerParserTest {

	@Test
	public void testSplitSimpleParameters() {
		String[] result = splitParameters("APTR, LONG, VOID");
		assertArrayEquals(new String[] {"APTR", "LONG", "VOID"}, result);
	}

	@Test
	public void testSplitParametersWithFunctionPointer() {
		String[] result = splitParameters("APTR, LONG (*)(APTR, APTR), VOID");
		assertArrayEquals(new String[] {"APTR", "LONG (*)(APTR, APTR)", "VOID"}, result);
	}

	@Test
	public void testSplitParametersWithStructs() {
		String[] result = splitParameters("struct Hook *, APTR, struct Message *");
		assertArrayEquals(new String[] {"struct Hook *", "APTR", "struct Message *"}, result);
	}

	@Test
	public void testSplitSingleParameter() {
		String[] result = splitParameters("APTR");
		assertArrayEquals(new String[] {"APTR"}, result);
	}

	@Test
	public void testSplitEmptyParameters() {
		String[] result = splitParameters("");
		assertArrayEquals(new String[] {""}, result);
	}

	@Test
	public void testSplitParametersWithNestedParens() {
		String[] result = splitParameters("LONG, VOID (*)(LONG (*)(APTR)), APTR");
		assertArrayEquals(new String[] {"LONG", "VOID (*)(LONG (*)(APTR))", "APTR"}, result);
	}

	@Test
	public void testFindMatchingParenSimple() {
		String str = "(test)";
		assertEquals(5, findMatchingParen(str, 0));
	}

	@Test
	public void testFindMatchingParenNested() {
		String str = "(outer (inner) test)";
		assertEquals(19, findMatchingParen(str, 0));
	}

	@Test
	public void testFindMatchingParenDeeplyNested() {
		String str = "(a (b (c (d))))";
		assertEquals(14, findMatchingParen(str, 0));
	}

	@Test
	public void testFindMatchingParenInMiddle() {
		String str = "prefix (content) suffix";
		assertEquals(15, findMatchingParen(str, 7));
	}

	@Test
	public void testFindMatchingParenUnmatched() {
		String str = "(unclosed";
		assertEquals(-1, findMatchingParen(str, 0));
	}

	@Test
	public void testFunctionPointerPatternDetection() {
		// These should be detected as function pointers
		String fp1 = "VOID (*)(VOID)";
		String fp2 = "LONG (*)(APTR, APTR)";
		String fp3 = "struct Node * (*)(struct List *)";

		assertEquals(true, fp1.contains("(*"));
		assertEquals(true, fp2.contains("(*"));
		assertEquals(true, fp3.contains("(*"));

		// These should NOT be function pointers
		String notFp1 = "APTR";
		String notFp2 = "struct Hook *";
		String notFp3 = "LONG **";

		assertEquals(false, notFp1.contains("(*"));
		assertEquals(false, notFp2.contains("(*"));
		assertEquals(false, notFp3.contains("(*"));
	}

	@Test
	public void testFunctionPointerReturnTypeExtraction() {
		String type = "VOID (*)(APTR, LONG)";
		int funcPtrStart = type.indexOf("(*");
		String returnType = type.substring(0, funcPtrStart).trim();
		assertEquals("VOID", returnType);
	}

	@Test
	public void testFunctionPointerWithPointerReturn() {
		String type = "struct Node * (*)(APTR)";
		int funcPtrStart = type.indexOf("(*");
		String returnType = type.substring(0, funcPtrStart).trim();
		assertEquals("struct Node *", returnType);
	}

	@Test
	public void testFunctionPointerParameterExtraction() {
		String type = "VOID (*)(struct Hook *, APTR, struct Message *)";
		int funcPtrStart = type.indexOf("(*");
		int paramListStart = type.indexOf('(', funcPtrStart + 2);
		int paramListEnd = findMatchingParen(type, paramListStart);
		String paramList = type.substring(paramListStart + 1, paramListEnd).trim();
		assertEquals("struct Hook *, APTR, struct Message *", paramList);
	}

	// Helper methods copied from AmigaHunkAnalyzer for testing
	// (In a real implementation, these would be made package-private or
	// extracted to a utility class for better testability)

	private static int findMatchingParen(String str, int openPos) {
		int depth = 1;
		for (int i = openPos + 1; i < str.length(); i++) {
			if (str.charAt(i) == '(') {
				depth++;
			} else if (str.charAt(i) == ')') {
				depth--;
				if (depth == 0) {
					return i;
				}
			}
		}
		return -1;
	}

	private static String[] splitParameters(String paramList) {
		java.util.List<String> params = new java.util.ArrayList<>();
		int depth = 0;
		int start = 0;

		for (int i = 0; i < paramList.length(); i++) {
			char c = paramList.charAt(i);
			if (c == '(') {
				depth++;
			} else if (c == ')') {
				depth--;
			} else if (c == ',' && depth == 0) {
				params.add(paramList.substring(start, i).trim());
				start = i + 1;
			}
		}
		params.add(paramList.substring(start).trim());

		return params.toArray(new String[0]);
	}
}
