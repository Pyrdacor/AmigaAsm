package amigaasm.export;

public class AsmReference {
	public String Label;
	public int LineNumber;
	
	public AsmReference(int lineNumber, String label ) {
		Label = label;
		LineNumber = lineNumber;
	}
}
