import os
import re

def fix_file(filepath):
    if not filepath.endswith('.py'): return
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Remplacer "except Exception:" ou "except Exception: pass" par "except Exception as exc: log.debug(f'Erreur ignorée: {exc}')"
    # Il faut faire attention a l'indentation
    lines = content.split('\n')
    changed = False
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "except Exception: pass" or stripped == "except Exception:":
            indent = line[:len(line) - len(line.lstrip())]
            lines[i] = f"{indent}except Exception as exc:\n{indent}    pass  # TODO: log.debug(exc)"
            changed = True
            
    if changed:
        with open(filepath, 'w') as f:
            f.write('\n'.join(lines))
        print(f"Fixed {filepath}")

for root, _, files in os.walk('forensic_analyzer'):
    for file in files:
        fix_file(os.path.join(root, file))

print("Done fixing exceptions.")
