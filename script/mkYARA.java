// mkYARA - Generate YARA rules from selected bytes in the Listing view.
// Select bytes (click + shift-click), then run this script.
// A dialog lets you pick the wildcarding mode and edit the result.
//
// @author mkYARA-Ghidra (ported from fox-it/mkYARA)
// @category mkYARA
// @keybinding ctrl Y
// @menupath Tools.mkYARA

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.mem.MemoryBlock;

import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

public class mkYARA extends GhidraScript {

    @Override
    public void run() throws Exception {

        // --- Get selection ---
        AddressSetView sel = currentSelection;
        if (sel == null || sel.isEmpty()) {
            sel = currentHighlight;
        }
        if (sel == null || sel.isEmpty()) {
            popup("mkYARA: No bytes selected.\n\n" +
                  "Click on a start address in the Listing,\n" +
                  "then Shift+click on the end address\n" +
                  "(the region turns blue).\n" +
                  "Then run this script again.");
            return;
        }

        AddressRange range = sel.getFirstRange();
        if (range == null || range.getLength() == 0) {
            popup("mkYARA: Selection is empty.");
            return;
        }

        // --- Pick mode ---
        String[] modes = {"Normal", "Loose", "Strict", "Data"};
        String picked = (String) JOptionPane.showInputDialog(null,
            "Select wildcarding mode:", "mkYARA",
            JOptionPane.PLAIN_MESSAGE, null, modes, "Normal");
        if (picked == null) return;
        String mode = picked.toLowerCase();

        // --- Read bytes ---
        Address minAddr = range.getMinAddress();
        Address maxAddr = range.getMaxAddress();
        int size = (int) range.getLength();
        byte[] rawBytes = getBytes(minAddr, size);
        int ptrSize = currentProgram.getLanguage().getDefaultSpace().getPointerSize();

        println("mkYARA [" + mode + "]: " + minAddr + " to " + maxAddr +
                " (" + size + " bytes)");

        // --- Build hex pattern ---
        Listing listing = currentProgram.getListing();
        StringBuilder hex = new StringBuilder();
        StringBuilder comments = new StringBuilder();

        if ("data".equals(mode)) {
            for (byte b : rawBytes) {
                hex.append(String.format("%02X ", b & 0xFF));
            }
        } else {
            int offset = 0;
            Address addr = minAddr;
            while (offset < size) {
                monitor.checkCancelled();
                Instruction instr = listing.getInstructionAt(addr);
                if (instr != null && offset + instr.getLength() <= size) {
                    int len = instr.getLength();
                    byte[] ib = new byte[len];
                    System.arraycopy(rawBytes, offset, ib, 0, len);
                    hex.append(wildcard(instr, ib, mode, ptrSize)).append(' ');
                    comments.append(String.format("// %s  %s\n", addr, instr));
                    addr = addr.add(len);
                    offset += len;
                } else {
                    hex.append(String.format("%02X ", rawBytes[offset] & 0xFF));
                    addr = addr.add(1);
                    offset++;
                }
            }
        }

        // --- Ask rule name ---
        String ruleName = askString("mkYARA", "Enter rule name:", "generated_rule");
        if (ruleName == null || ruleName.isEmpty()) {
            ruleName = "generated_rule";
        }
        ruleName = ruleName.replaceAll("[^a-zA-Z0-9_]", "_");

        // --- Format rule ---
        String rule = formatRule(ruleName, mode, hex.toString().trim(),
                                comments.toString());

        // --- Show result ---
        showDialog(rule, mode);
    }

    // ====================== Wildcarding ======================

    private String wildcard(Instruction instr, byte[] ib, String mode, int ptrSize) {
        int len = ib.length;
        int opc = opcodeLen(ib, ptrSize);
        if (opc >= len) return toHex(ib);

        String mn = instr.getMnemonicString().toLowerCase();
        boolean isBranch = mn.startsWith("call") || mn.startsWith("j");
        boolean hasRef = hasMemRef(instr);

        switch (mode) {
            case "loose":
                return keep(ib, opc);
            case "strict":
                return (isBranch && hasRef) ? keep(ib, opc) : toHex(ib);
            case "normal":
            default:
                if (isBranch && hasRef) return keep(ib, opc);
                if (hasRef || hasDisp(instr)) {
                    int k = modrmEnd(ib, opc);
                    if (len - k >= 1 && len - k <= 8) return keep(ib, k);
                }
                if (hasImm(instr)) {
                    if (len > opc + 1) {
                        int k = modrmEnd(ib, opc);
                        if (len - k == 4 || len - k == ptrSize) return keep(ib, k);
                    }
                    if (len - opc >= 4) return keep(ib, opc);
                }
                return toHex(ib);
        }
    }

    // ====================== x86 Encoding ======================

    private int opcodeLen(byte[] b, int ps) {
        int i = 0, n = b.length;
        while (i < n) {
            int v = b[i] & 0xFF;
            if (v == 0xF0 || v == 0xF2 || v == 0xF3 || v == 0x2E || v == 0x36 ||
                v == 0x3E || v == 0x26 || v == 0x64 || v == 0x65 || v == 0x66 ||
                v == 0x67) { i++; }
            else break;
        }
        if (i >= n) return n;
        int v = b[i] & 0xFF;
        if (v >= 0x40 && v <= 0x4F && ps == 8) {
            if (++i >= n) return n;
            v = b[i] & 0xFF;
        }
        if (v == 0x0F) {
            if (++i >= n) return n;
            int v2 = b[i] & 0xFF;
            i += (v2 == 0x38 || v2 == 0x3A) ? 2 : 1;
        } else {
            i++;
        }
        return Math.min(i, n);
    }

    private int modrmEnd(byte[] b, int oe) {
        if (oe >= b.length) return b.length;
        int modrm = b[oe] & 0xFF;
        int i = oe + 1;
        if ((modrm & 7) == 4 && ((modrm >> 6) & 3) != 3) i++;
        return Math.min(i, b.length);
    }

    private boolean hasMemRef(Instruction ins) {
        for (int i = 0; i < ins.getNumOperands(); i++) {
            int t = ins.getOperandType(i);
            if ((t & OperandType.ADDRESS) != 0 || (t & OperandType.DYNAMIC) != 0) return true;
            if (ins.getOperandReferences(i).length > 0) return true;
        }
        return false;
    }

    private boolean hasDisp(Instruction ins) {
        for (int i = 0; i < ins.getNumOperands(); i++)
            if ((ins.getOperandType(i) & OperandType.DYNAMIC) != 0) return true;
        return false;
    }

    private boolean hasImm(Instruction ins) {
        for (int i = 0; i < ins.getNumOperands(); i++)
            if ((ins.getOperandType(i) & OperandType.SCALAR) != 0) return true;
        return false;
    }

    // ====================== Formatting ======================

    private String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) sb.append(String.format("%02X ", v & 0xFF));
        return sb.toString().trim();
    }

    private String keep(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++)
            sb.append(i < n ? String.format("%02X ", b[i] & 0xFF) : "?? ");
        return sb.toString().trim();
    }

    private String formatRule(String name, String mode, String pattern, String comments) {
        String hash = getFileHash();
        String date = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date());

        StringBuilder r = new StringBuilder();
        r.append("rule ").append(name).append("\n{\n");
        r.append("    meta:\n");
        r.append("        generated_by = \"mkYARA-Ghidra\"\n");
        r.append("        date = \"").append(date).append("\"\n");
        r.append("        mode = \"").append(mode).append("\"\n");
        if (hash != null) r.append("        hash = \"").append(hash).append("\"\n");
        r.append("\n    strings:\n        $code = {\n");

        if (comments != null && !comments.isEmpty()) {
            for (String line : comments.split("\n"))
                if (!line.isEmpty()) r.append("            ").append(line).append("\n");
            r.append("\n");
        }

        String[] tokens = pattern.split("\\s+");
        StringBuilder line = new StringBuilder("            ");
        for (String t : tokens) {
            if (line.length() + t.length() + 1 > 80) {
                r.append(line.toString().stripTrailing()).append("\n");
                line = new StringBuilder("            ");
            }
            line.append(t).append(" ");
        }
        if (!line.toString().isBlank()) r.append(line.toString().stripTrailing()).append("\n");

        r.append("        }\n\n    condition:\n        $code\n}\n");
        return r.toString();
    }

    private String getFileHash() {
        try {
            String sha = currentProgram.getExecutableSHA256();
            if (sha != null && !sha.isEmpty()) return sha;
        } catch (Exception e) { }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {
                if (blk.isInitialized()) {
                    byte[] d = new byte[(int) Math.min(blk.getSize(), 1024 * 1024)];
                    blk.getBytes(blk.getStart(), d);
                    md.update(d);
                }
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append(String.format("%02x", b & 0xFF));
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    // ====================== GUI ======================

    private void showDialog(String rule, String mode) {
        SwingUtilities.invokeLater(() -> {
            JFrame f = new JFrame("mkYARA — " + mode);
            f.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            f.setSize(750, 550);

            JTextArea ta = new JTextArea(rule);
            ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
            ta.setEditable(true);
            ta.setCaretPosition(0);

            JPanel bp = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 5));

            JButton copy = new JButton("Copy to Clipboard");
            copy.addActionListener(e -> {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(ta.getText()), null);
                copy.setText("Copied!");
                javax.swing.Timer t = new javax.swing.Timer(1500,
                    ev -> copy.setText("Copy to Clipboard"));
                t.setRepeats(false);
                t.start();
            });

            JButton save = new JButton("Save to File");
            save.addActionListener(e -> {
                JFileChooser fc = new JFileChooser();
                fc.setSelectedFile(new java.io.File("rule.yar"));
                if (fc.showSaveDialog(f) == JFileChooser.APPROVE_OPTION) {
                    try (java.io.FileWriter fw =
                            new java.io.FileWriter(fc.getSelectedFile())) {
                        fw.write(ta.getText());
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(f, "Error: " + ex.getMessage());
                    }
                }
            });

            JButton close = new JButton("Close");
            close.addActionListener(e -> f.dispose());

            bp.add(copy);
            bp.add(save);
            bp.add(close);

            f.setLayout(new BorderLayout());
            f.add(new JScrollPane(ta), BorderLayout.CENTER);
            f.add(bp, BorderLayout.SOUTH);
            f.setLocationRelativeTo(null);
            f.setVisible(true);
        });
    }
}
