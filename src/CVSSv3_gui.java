import java.awt.EventQueue;

import javax.swing.JFrame;

import cvss_utils.*;
import cvss_utils.CvssV3.*;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.ActionEvent;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;

import javax.swing.ButtonGroup;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import java.awt.Color;

/**
 * 
 * @author Lorenzo Grazian
 *
 */
public class CVSSv3_gui {

	
	
	private JFrame frame;
	private static JTextField vectorText;
    private JRadioButton AV_network;
    private JRadioButton AV_adjacent;
    private JRadioButton AV_local;
    private JRadioButton AV_physical;
    private JRadioButton AC_low;
    private JRadioButton AC_high;
    private JRadioButton PR_none;
    private JRadioButton PR_low;
    private JRadioButton UI_none;
    private JRadioButton UI_required;
    private JRadioButton S_unchanged;
    private JRadioButton S_changed;
    private JRadioButton C_none;
    private JRadioButton C_low;
    private JRadioButton C_high;
    private JRadioButton I_none;
    private JRadioButton I_low;
    private JRadioButton I_high;
    private JRadioButton A_none;
    private JRadioButton A_low;
    private JRadioButton A_high;
    private JRadioButton PR_high;
    static ButtonGroup AttackVectorG;
    static ButtonGroup AttackComplexityG;
    static ButtonGroup PrivilegeRequiredG;
    static ButtonGroup UserInteractionG;
    static ButtonGroup ScopeG;
    static ButtonGroup ConfidentialityImpactG;
    static ButtonGroup IntegrityImpactG;
    static ButtonGroup AvailabilityImpactG;
    private static JLabel scoreL;
    private static JTextField scoreT;
    private static JButton calculate_vector;
    private static JButton calculate_radio;
    private static JTextField urlT;
    private JLabel lblNewLabel_2;
    private JButton cpyToClipVector;
    private JButton cpyLinkToClipVector;


	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					CVSSv3_gui window = new CVSSv3_gui();
					window.frame.setVisible(true);
					
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		

	}

	
	
	
	/**
	 * Create the application.
	 */
	public CVSSv3_gui() {
		initialize();
		AttackVectorG = new ButtonGroup();
		AttackVectorG.add(AV_adjacent);
		AttackVectorG.add(AV_network);
		AttackVectorG.add(AV_local);
		AttackVectorG.add(AV_physical);
		
		AttackComplexityG = new ButtonGroup();
		AttackComplexityG.add(AC_low);
		AttackComplexityG.add(AC_high);
		
		PrivilegeRequiredG = new ButtonGroup();
		PrivilegeRequiredG.add(PR_none);
		PrivilegeRequiredG.add(PR_low);
		PrivilegeRequiredG.add(PR_high);
		
		UserInteractionG = new ButtonGroup();
		UserInteractionG.add(UI_none);
		UserInteractionG.add(UI_required);
		
		ScopeG = new ButtonGroup();
		ScopeG.add(S_unchanged);
		ScopeG.add(S_changed);
		
		ConfidentialityImpactG= new ButtonGroup();
		ConfidentialityImpactG.add(C_none);
		ConfidentialityImpactG.add(C_low);
		ConfidentialityImpactG.add(C_high);
		
		IntegrityImpactG= new ButtonGroup();
		IntegrityImpactG.add(I_none);
		IntegrityImpactG.add(I_low);
		IntegrityImpactG.add(I_high);
		
		AvailabilityImpactG= new ButtonGroup();
		AvailabilityImpactG.add(A_none);
		AvailabilityImpactG.add(A_low);
		AvailabilityImpactG.add(A_high);
		
		
		
		setDefaultRadio();
		
		
		calculate_vector.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				calculateFromVector();
				
			}
		});
		
		calculate_radio.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				calculateFromRadio();
			}
		});
		
		
		cpyToClipVector.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String vector = vectorText.getText();
				StringSelection stringSelection = new StringSelection(vector);
				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				clipboard.setContents(stringSelection, null);
				
			}
		});
		
		
		cpyLinkToClipVector.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String vector = urlT.getText();
				StringSelection stringSelection = new StringSelection(vector);
				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				clipboard.setContents(stringSelection, null);
			}
		});
		

		vectorText.addKeyListener(new KeyAdapter(){
      		public void keyPressed(KeyEvent key)
	      	{
	      		if(key.getKeyChar() == KeyEvent.VK_ENTER)

	      			calculateFromVector();
	      	}

	});
		
		
	}
	

	/**
	 * calculate and print score from vector
	 */
	private void calculateFromVector() {
		String vector = vectorText.getText();
		
		Cvss cvss = Cvss.fromVector(vector);
		if (cvss ==null){
			return;
		}
		
		Score score = cvss.calculateScore();				
		scoreT.setText(String.valueOf(score.getBaseScore()));
		setColor(score.getBaseScore());
		
		urlT.setText("https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=" + vector + "&version=3.1");
		
		CvssV3_1 cvssv3_1 =  Cvss.getCvssV3_1FromVector(vector);
		AttackVectorG.clearSelection();
		AttackComplexityG.clearSelection();
		PrivilegeRequiredG.clearSelection();
		UserInteractionG.clearSelection();
		ScopeG.clearSelection();
		ConfidentialityImpactG.clearSelection();
		IntegrityImpactG.clearSelection();
		AvailabilityImpactG.clearSelection();
		
		switch (cvssv3_1.getAttackVector()) {
		case NETWORK:
			AV_network.setSelected(true);
		break;
		case ADJACENT:
			AV_adjacent.setSelected(true);
		break;
		case LOCAL:
			AV_local.setSelected(true);
		break;
		case PHYSICAL:
			AV_physical.setSelected(true);
		break;
		}
		
		switch (cvssv3_1.getAttackComplexity()) {
		case LOW:
			AC_low.setSelected(true);
		break;
		case HIGH:
			AC_high.setSelected(true);
		break;
		}
		
		switch (cvssv3_1.getPrivilegesRequired()) {
		case NONE:
			PR_none.setSelected(true);
		break;
		case LOW:
			PR_low.setSelected(true);
		break;
		case HIGH:
			PR_high.setSelected(true);
		break;
		}
		
		switch (cvssv3_1.getUserInteraction()) {
		case NONE:
		UI_none.setSelected(true);
		break;
		case REQUIRED:
		UI_required.setSelected(true);
		break;			
		}
		
		switch (cvssv3_1.getScope()) {
		case UNCHANGED:
		S_unchanged.setSelected(true);
		break;
		case CHANGED:
		S_changed.setSelected(true);
		break;			
		}
		
		switch (cvssv3_1.getConfidentiality()) {
		case NONE:
			C_none.setSelected(true);
		break;
		case LOW:
			C_low.setSelected(true);
		break;
		case HIGH:
			C_high.setSelected(true);
		break;
		}
		
		switch (cvssv3_1.getIntegrity()) {
		case NONE:
			I_none.setSelected(true);
		break;
		case LOW:
			I_low.setSelected(true);
		break;
		case HIGH:
			I_high.setSelected(true);
		break;
		}
		
		switch (cvssv3_1.getAvailability()) {
		case NONE:
			A_none.setSelected(true);
		break;
		case LOW:
			A_low.setSelected(true);
		break;
		case HIGH:
			A_high.setSelected(true);
		break;
		}
	}
	
	/**
	 * Calculate and print score and vector from radio button
	 */
	private static void calculateFromRadio() {
		CvssV3_1 cvssV3 = new CvssV3_1();

		switch (AttackVectorG.getSelection().getActionCommand()) {
		case "AV_network":
			cvssV3.attackVector(AttackVector.NETWORK);
		break;
		case "AV_adjacent":
			cvssV3.attackVector(AttackVector.ADJACENT);
		break;
		case "AV_local":
			cvssV3.attackVector(AttackVector.LOCAL);
		break;
		case "AV_physical":
			cvssV3.attackVector(AttackVector.PHYSICAL);
		break;
		}
		
		switch (AttackComplexityG.getSelection().getActionCommand()) {
		case "AC_low":
			cvssV3.attackComplexity(AttackComplexity.LOW);
		break;
		case "AC_high":
			cvssV3.attackComplexity(AttackComplexity.HIGH);
		break;
		}
		
		switch (PrivilegeRequiredG.getSelection().getActionCommand()) {
		case "PR_none":
			cvssV3.privilegesRequired(PrivilegesRequired.NONE);
		break;
		case "PR_low":
			cvssV3.privilegesRequired(PrivilegesRequired.LOW);
		break;
		case "PR_high":
			cvssV3.privilegesRequired(PrivilegesRequired.HIGH);
		break;
		}
		
		switch (UserInteractionG.getSelection().getActionCommand()) {
		case "UI_none":
			cvssV3.userInteraction(UserInteraction.NONE);
		break;
		case "UI_required":
			cvssV3.userInteraction(UserInteraction.REQUIRED);
		break;			
		}
		
		switch (ScopeG.getSelection().getActionCommand()) {
		case "S_unchanged":
			cvssV3.scope(Scope.UNCHANGED);
		break;
		case "S_changed":
			cvssV3.scope(Scope.CHANGED);
		break;			
		}
		
		switch (ConfidentialityImpactG.getSelection().getActionCommand()) {
		case "C_none":
			cvssV3.confidentiality(CIA.NONE);
		break;
		case "C_low":
			cvssV3.confidentiality(CIA.LOW);
		break;
		case "C_high":
			cvssV3.confidentiality(CIA.HIGH);
		break;
		}
		
		switch (IntegrityImpactG.getSelection().getActionCommand()) {
		case "I_none":
			cvssV3.integrity(CIA.NONE);
		break;
		case "I_low":
			cvssV3.integrity(CIA.LOW);
		break;
		case "I_high":
			cvssV3.integrity(CIA.HIGH);
		break;
		}
		
		switch (AvailabilityImpactG.getSelection().getActionCommand()) {
		case "A_none":
			cvssV3.availability(CIA.NONE);
		break;
		case "A_low":
			cvssV3.availability(CIA.LOW);
		break;
		case "A_high":
			cvssV3.availability(CIA.HIGH);
		break;
		}
		
		
		
		scoreT.setText(String.valueOf(cvssV3.calculateScore().getBaseScore()));
		setColor(cvssV3.calculateScore().getBaseScore());
		vectorText.setText(cvssV3.getVector());
		urlT.setText("https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=" + cvssV3.getVector() + "&version=3.1");
	}
	
	
	/**
	 * Set color of @scoreL label based on score 
	 * @param score
	 */
	private static void setColor(double score) {
		
		if (score >= 0.1 && score < 4.0) {
			scoreL.setForeground(Color.GREEN);
		}else if (score >= 4.0 && score < 7.0) {
			scoreL.setForeground(Color.ORANGE);
		}else if (score >= 7.0 && score < 9.0) {
			scoreL.setForeground(Color.RED);
		}else if (score >= 9.0 && score <= 10.0) {
			scoreL.setForeground(new Color(204, 0, 255));
		}else {
			scoreL.setForeground(Color.BLACK);
		}
		
	}
	
	
	/**
	 * Set default radio status
	 */
	private void setDefaultRadio() {
		
		AV_network.setSelected(true);
		AC_low.setSelected(true);
		PR_none.setSelected(true);
		UI_none.setSelected(true);
		S_unchanged.setSelected(true);
		C_none.setSelected(true);
		I_none.setSelected(true);
		A_none.setSelected(true);
		
	}
	
	
	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		
		
		frame = new JFrame();
		frame.setBounds(100, 100, 844, 575);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setPreferredSize(frame.getPreferredSize());
		frame.getContentPane().setLayout(null);
		
		calculate_vector = new JButton("Calculate from vector");
		calculate_vector.setBounds(0, 0, 223, 29);
		frame.getContentPane().add(calculate_vector);
		
		vectorText = new JTextField();
		vectorText.setBounds(235, 0, 384, 26);
		frame.getContentPane().add(vectorText);
		vectorText.setColumns(10);
		
		cpyToClipVector = new JButton("Copy Vector To Clipboard");
		cpyToClipVector.setBounds(624, 0, 205, 29);
		frame.getContentPane().add(cpyToClipVector);
		
		scoreL = new JLabel("Score:");
		scoreL.setBounds(9, 39, 38, 16);
		scoreL.setForeground(Color.BLACK);
		frame.getContentPane().add(scoreL);
		
		scoreT = new JTextField();
		scoreT.setBounds(62, 34, 56, 26);
		frame.getContentPane().add(scoreT);
		scoreT.setColumns(10);
		
		lblNewLabel_2 = new JLabel("Url:");
		lblNewLabel_2.setBounds(191, 39, 22, 16);
		frame.getContentPane().add(lblNewLabel_2);
		
		urlT = new JTextField();
		urlT.setBounds(235, 34, 384, 26);
		frame.getContentPane().add(urlT);
		urlT.setColumns(10);
		
		cpyLinkToClipVector = new JButton("Copy Link To Clipboard");
		cpyLinkToClipVector.setBounds(624, 34, 205, 29);
		frame.getContentPane().add(cpyLinkToClipVector);
		
		JLabel lblNewLabel = new JLabel("Attack Vector (AV)");
		lblNewLabel.setBounds(11, 95, 114, 16);
		frame.getContentPane().add(lblNewLabel);
		
		AV_network = new JRadioButton("Network");
		AV_network.setBounds(0, 116, 85, 23);
		AV_network.setActionCommand("AV_network");
		frame.getContentPane().add(AV_network);
		
		AV_adjacent = new JRadioButton("Adjacent Network");
		AV_adjacent.setBounds(92, 116, 144, 23);
		AV_adjacent.setActionCommand("AV_adjacent");
		frame.getContentPane().add(AV_adjacent);
		
		AV_local = new JRadioButton("Local");
		AV_local.setBounds(241, 116, 65, 23);
		AV_local.setActionCommand("AV_local");
		frame.getContentPane().add(AV_local);
		
		AV_physical = new JRadioButton("Physical");
		AV_physical.setBounds(311, 116, 83, 23);
		AV_physical.setActionCommand("AV_physical");
		frame.getContentPane().add(AV_physical);
		
		JLabel lblNewLabel_1 = new JLabel("Attack Complexity (AC)");
		lblNewLabel_1.setBounds(10, 144, 149, 16);
		frame.getContentPane().add(lblNewLabel_1);
		
		JLabel lblNewLabel_1_2 = new JLabel("Scope (S)");
		lblNewLabel_1_2.setBounds(311, 144, 56, 16);
		frame.getContentPane().add(lblNewLabel_1_2);
		
		AC_low = new JRadioButton("Low");
		AC_low.setBounds(0, 165, 57, 23);
		AC_low.setActionCommand("AC_low");
		frame.getContentPane().add(AC_low);
		
		AC_high = new JRadioButton("High");
		AC_high.setBounds(92, 165, 144, 23);
		AC_high.setActionCommand("AC_high");
		frame.getContentPane().add(AC_high);
		
		S_unchanged = new JRadioButton("Unchangeg");
		S_unchanged.setBounds(311, 165, 138, 23);
		S_unchanged.setActionCommand("S_unchanged");
		frame.getContentPane().add(S_unchanged);
		
		S_changed = new JRadioButton("Changed");
		S_changed.setBounds(481, 165, 105, 23);
		S_changed.setActionCommand("S_changed");
		frame.getContentPane().add(S_changed);
		
		JLabel lblNewLabel_1_1 = new JLabel("Privileges Required (PR)");
		lblNewLabel_1_1.setBounds(10, 197, 149, 16);
		frame.getContentPane().add(lblNewLabel_1_1);
		
		JLabel lblNewLabel_1_2_1 = new JLabel("Confidentiality Impact (C)");
		lblNewLabel_1_2_1.setBounds(311, 197, 161, 16);
		frame.getContentPane().add(lblNewLabel_1_2_1);
		
		PR_none = new JRadioButton("None");
		PR_none.setBounds(0, 218, 65, 23);
		PR_none.setActionCommand("PR_none");
		frame.getContentPane().add(PR_none);
		
		PR_low = new JRadioButton("Low");
		PR_low.setBounds(92, 218, 57, 23);
		PR_low.setActionCommand("PR_low");
		frame.getContentPane().add(PR_low);
		
		PR_high = new JRadioButton("High");
		PR_high.setBounds(154, 218, 62, 23);
		PR_high.setActionCommand("PR_high");
		frame.getContentPane().add(PR_high);
		
		C_none = new JRadioButton("None");
		C_none.setBounds(311, 218, 65, 23);
		C_none.setActionCommand("C_none");
		frame.getContentPane().add(C_none);
		
		C_low = new JRadioButton("Low");
		C_low.setBounds(388, 218, 57, 23);
		C_low.setActionCommand("C_low");
		frame.getContentPane().add(C_low);
		
		C_high = new JRadioButton("High");
		C_high.setBounds(449, 218, 62, 23);
		C_high.setActionCommand("C_high");
		frame.getContentPane().add(C_high);
		
		JLabel lblNewLabel_1_1_1 = new JLabel("User Interaction (UI)");
		lblNewLabel_1_1_1.setBounds(9, 250, 125, 16);
		frame.getContentPane().add(lblNewLabel_1_1_1);
		
		JLabel lblNewLabel_1_2_1_1 = new JLabel("Integrity Impact (I)");
		lblNewLabel_1_2_1_1.setBounds(311, 250, 235, 16);
		frame.getContentPane().add(lblNewLabel_1_2_1_1);
		
		UI_none = new JRadioButton("None");
		UI_none.setBounds(0, 271, 65, 23);
		UI_none.setActionCommand("UI_none");
		frame.getContentPane().add(UI_none);
		
		UI_required = new JRadioButton("Required");
		UI_required.setBounds(92, 271, 214, 23);
		UI_required.setActionCommand("UI_required");
		frame.getContentPane().add(UI_required);
		
		I_none = new JRadioButton("None");
		I_none.setBounds(311, 271, 65, 23);
		I_none.setActionCommand("I_none");
		frame.getContentPane().add(I_none);
		
		I_low = new JRadioButton("Low");
		I_low.setBounds(387, 271, 57, 23);
		I_low.setActionCommand("I_low");
		frame.getContentPane().add(I_low);
		
		I_high = new JRadioButton("High");
		I_high.setBounds(449, 271, 62, 23);
		I_high.setActionCommand("I_high");
		frame.getContentPane().add(I_high);
		
		JLabel lblNewLabel_1_2_1_1_1 = new JLabel("Availability Impact (A)");
		lblNewLabel_1_2_1_1_1.setBounds(311, 300, 235, 16);
		frame.getContentPane().add(lblNewLabel_1_2_1_1_1);
		
		A_none = new JRadioButton("None");
		A_none.setBounds(311, 320, 65, 23);
		A_none.setActionCommand("A_none");
		frame.getContentPane().add(A_none);
		
		A_low = new JRadioButton("Low");
		A_low.setBounds(388, 320, 57, 23);
		A_low.setActionCommand("A_low");
		frame.getContentPane().add(A_low);
		
		A_high = new JRadioButton("High");
		A_high.setBounds(449, 320, 62, 23);
		A_high.setActionCommand("A_high");
		frame.getContentPane().add(A_high);
		
		calculate_radio = new JButton("Calculate vector & score");
		calculate_radio.setBounds(0, 348, 619, 29);
		frame.getContentPane().add(calculate_radio);
	}
}
