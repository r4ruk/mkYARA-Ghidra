package mkyara;

import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.CODE_VIEWER,
    shortDescription = "mkYARA - Generate YARA rules from selected bytes",
    description = "Select bytes in the Listing, right-click -> mkYARA to generate " +
                  "YARA rules with opcode-aware wildcarding."
)
//@formatter:on
public class mkYARAPlugin extends ProgramPlugin {

    public mkYARAPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        createAction("mkYARA Normal", "Normal YARA Rule", "normal");
        createAction("mkYARA Loose",  "Loose YARA Rule",  "loose");
        createAction("mkYARA Strict", "Strict YARA Rule",  "strict");
        createAction("mkYARA Data",   "Data YARA Rule",    "data");
        Msg.info(this, "mkYARA: plugin loaded, context menu actions registered");
    }

    private void createAction(String name, String label, String mode) {
        new ActionBuilder(name, getName())
            .withContext(ProgramLocationActionContext.class)
            .popupMenuPath("mkYARA", label)
            .popupMenuGroup("mkYARA")
            .enabledWhen(ctx -> {
                ProgramSelection sel = ctx.getSelection();
                return sel != null && !sel.isEmpty();
            })
            .onAction(ctx -> generate(ctx, mode))
            .buildAndInstall(tool);
    }

    private void generate(ProgramLocationActionContext ctx, String mode) {
        ProgramSelection sel = ctx.getSelection();
        if (sel == null || sel.isEmpty()) {
            Msg.showWarn(this, null, "mkYARA",
                "No bytes selected.\n\n" +
                "Click start address, Shift+click end address,\n" +
                "then right-click -> mkYARA.");
            return;
        }

        Program prog = ctx.getProgram();
        AddressRange range = sel.getFirstRange();
        if (range == null || range.getLength() == 0) {
            Msg.showWarn(this, null, "mkYARA", "Selection is empty.");
            return;
        }

        try {
            String rule = buildYaraRule(prog, range, mode);
            showDialog(rule, mode);
        } catch (Exception e) {
            Msg.showError(this, null, "mkYARA", e.getMessage(), e);
        }
    }

    // ====================== Rule Generation ======================

    private String buildYaraRule(Program prog, AddressRange range, String mode)
            throws Exception {
        Address minAddr = range.getMinAddress();
        int size = (int) range.getLength();
        int ptrSize = prog.getLanguage().getDefaultSpace().getPointerSize();

        byte[] raw = new byte[size];
        prog.getMemory().getBytes(minAddr, raw);

        Listing listing = prog.getListing();
        StringBuilder hex = new StringBuilder();
        StringBuilder comments = new StringBuilder();

        if ("data".equals(mode)) {
            for (byte b : raw) hex.append(String.format("%02X ", b & 0xFF));
        } else {
            int off = 0;
            Address addr = minAddr;
            while (off < size) {
                Instruction instr = listing.getInstructionAt(addr);
                if (instr != null && off + instr.getLength() <= size) {
                    int len = instr.getLength();
                    byte[] ib = new byte[len];
                    System.arraycopy(raw, off, ib, 0, len);
                    hex.append(wildcard(instr, ib, mode, ptrSize)).append(' ');
                    comments.append(String.format("// %s  %s\n", addr, instr));
                    addr = addr.add(len);
                    off += len;
                } else {
                    hex.append(String.format("%02X ", raw[off] & 0xFF));
                    addr = addr.add(1);
                    off++;
                }
            }
        }

        String ruleName = JOptionPane.showInputDialog(null,
            "Enter rule name:", "mkYARA", JOptionPane.PLAIN_MESSAGE);
        if (ruleName == null || ruleName.isBlank()) ruleName = "generated_rule";
        ruleName = ruleName.replaceAll("[^a-zA-Z0-9_]", "_");

        return formatRule(ruleName, mode, hex.toString().trim(),
            comments.toString(), prog);
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

    private int opcodeLen(byte[] b, int ps) {
        int i = 0, n = b.length;
        while (i < n) {
            int v = b[i] & 0xFF;
            if (v==0xF0||v==0xF2||v==0xF3||v==0x2E||v==0x36||v==0x3E||
                v==0x26||v==0x64||v==0x65||v==0x66||v==0x67) i++;
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
        } else i++;
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

    private String formatRule(String name, String mode, String pattern,
            String comments, Program prog) {
        String hash = fileHash(prog);
        String date = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date());
        StringBuilder r = new StringBuilder();
        r.append("rule ").append(name).append("\n{\n");
        r.append("    meta:\n");
        r.append("        generated_by = \"mkYARA-Ghidra\"\n");
        r.append("        date = \"").append(date).append("\"\n");
        r.append("        mode = \"").append(mode).append("\"\n");
        if (hash != null)
            r.append("        hash = \"").append(hash).append("\"\n");
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
        if (!line.toString().isBlank())
            r.append(line.toString().stripTrailing()).append("\n");
        r.append("        }\n\n    condition:\n        $code\n}\n");
        return r.toString();
    }

    private String fileHash(Program prog) {
        try {
            String sha = prog.getExecutableSHA256();
            if (sha != null && !sha.isEmpty()) return sha;
        } catch (Exception e) {}
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (MemoryBlock blk : prog.getMemory().getBlocks())
                if (blk.isInitialized()) {
                    byte[] d = new byte[(int) Math.min(blk.getSize(), 1024*1024)];
                    blk.getBytes(blk.getStart(), d);
                    md.update(d);
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
            bp.add(copy); bp.add(save); bp.add(close);
            f.setLayout(new BorderLayout());
            f.add(new JScrollPane(ta), BorderLayout.CENTER);
            f.add(bp, BorderLayout.SOUTH);
            f.setLocationRelativeTo(null);
            f.setVisible(true);
        });
    }
}
