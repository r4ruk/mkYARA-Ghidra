# mkYARA for Ghidra

A Ghidra equivalent of the IDA extension from [fox-it/mkYARA](https://github.com/fox-it/mkYARA) - generate YARA rules directly from selected bytes in the disassembly listing, with automatic opcode-aware wildcarding of variable operands like memory addresses, stack offsets, and call targets.

Originally an IDA Pro plugin by Jelle Vergeer / Fox-IT, this port brings the same functionality natively to Ghidra as both an installable extension (right-click context menu) and a standalone script.

## Installation

### Extension (recommended)

1. Download the latest release zip from the [Releases](../../releases) page
2. In Ghidra's **Project Window**: **File → Install Extensions → green + button**
3. Select the downloaded zip
4. Restart Ghidra
5. In the CodeBrowser: **File → Configure** → find and enable **mkYARAPlugin**

The mkYARA submenu will now appear permanently in the right-click context menu of the Listing view.

### Standalone Script

If you prefer not to install an extension, copy `script/mkYARA.java` into your `~/ghidra_scripts/` directory. Then in Ghidra:

1. **Window → Script Manager**
2. Find **mkYARA** under the **mkYARA** category
3. Optionally check **In Tool** to add it to the Tools menu and bind it to **Ctrl+Y**

The script version works identically but needs to be run manually from the Script Manager or the Tools menu each time.

## Usage

1. Select a range of bytes in the **Listing** or select pseudocode in the **Decompile** view
2. Right-click → **mkYARA** → pick a mode (extension), or (when only added the script) run from **Tools → mkYARA** / **Ctrl+Y** (script)
3. Choose the wildcarding mode and enter a rule name
4. Review, edit, copy to clipboard, or save the generated rule

## Wildcarding Modes

| Mode       | Behavior                                            | Use case                              |
|------------|-----------------------------------------------------|---------------------------------------|
| **Normal** | Wildcards displacement operands and memory addresses | General-purpose code signatures       |
| **Loose**  | Wildcards all operand bytes, keeps only opcodes      | Maximum flexibility, family detection |
| **Strict** | Wildcards only call/jmp target addresses             | Tight matching with specific constants|
| **Data**   | No wildcarding - raw hex bytes                       | Data patterns, strings, magic bytes   |

## Example Output

```yara
rule emotet_payload
{
    meta:
        generated_by = "mkYARA-Ghidra"
        date = "2025-06-15 10:30"
        mode = "normal"
        hash = "a1b2c3d4e5f6..."

    strings:
        $code = {
            // 00401000  PUSH EBP
            // 00401001  MOV EBP,ESP
            // 00401003  SUB ESP,0x20
            // 00401006  MOV EAX,dword ptr [EBP + 0x8]
            // 00401009  CALL 0x00401100

            55 8B EC 83 EC ?? 8B 45 ?? E8 ?? ?? ?? ??
        }

    condition:
        $code
}
```

## Building from Source

Requires Gradle and JDK 21+.

```bash
cd mkYARA-Ghidra
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra_where_ghidraRun_is_located buildExtension
```

The installable zip will be in `dist/`. Install it via **File → Install Extensions** as described above.

## Credits

- Original [mkYARA](https://github.com/fox-it/mkYARA) by Jelle Vergeer / Fox-IT
- Licensed under GPLv3, same as the original
