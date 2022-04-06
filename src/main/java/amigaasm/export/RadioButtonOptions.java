package amigaasm.export;

import java.awt.Choice;
import java.awt.event.ItemEvent;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionListener;

public class RadioButtonOptions extends Option {
	
	private List<String> possibleOptions;
	private int selectedIndex = -1;
	private Choice chooser = new Choice();
	private OptionListener listener = null;
	
	public RadioButtonOptions(String name, List<String> possibleOptions, int initialSelectedIndex) {
		super(name + "_Group", name, possibleOptions.get(initialSelectedIndex));
		
		this.possibleOptions = possibleOptions;
		selectedIndex = initialSelectedIndex;
		
		for (int i = 0; i < possibleOptions.size(); ++i) {
			
			chooser.add(possibleOptions.get(i));
		}
		
		chooser.select(selectedIndex);
		chooser.addItemListener(event -> {
			
			if (event.getStateChange() == ItemEvent.SELECTED) {
				
				String item = (String)event.getItem();
				selectedIndex = possibleOptions.indexOf(item);
				//listener.notify();
			}
		});
	}

	@Override
	public java.awt.Component getCustomEditorComponent() {
		
		return chooser;
	}
	
	@Override
	public Option copy() {
		
		return new RadioButtonOptions(getName(), possibleOptions, selectedIndex);
	}
	
	@Override
	public Object getValue() {
		
		return chooser.getSelectedIndex();
	}
	
	@Override
	public void setValue(Object object) {
		
		if (object instanceof Integer) {
			
			selectedIndex = (Integer)object;
			chooser.select(selectedIndex);
			//listener.notify();
		}
	}
	
	@Override
	public void setOptionListener(OptionListener listener) {
		
		this.listener = listener;
		super.setOptionListener(listener);
	}
}
