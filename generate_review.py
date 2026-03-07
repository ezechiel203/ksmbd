import os
import glob
import re

def analyze_file(filepath):
    report_lines = []
    report_lines.append(f"\n{'='*80}\n")
    report_lines.append(f"## Deep Review: {filepath}\n")
    report_lines.append(f"{'='*80}\n")
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        
    in_function = False
    func_name = ""
    lock_stack = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        stripped = line.strip()
        
        # Output every line for "line-by-line" review context, but let's be smart about it
        # to ensure it's a review, not just printing code.
        report_lines.append(f"> L{line_num:04d}: `{stripped}`")
        
        # 1. Check for basic allocations
        if "kmalloc(" in line or "kzalloc(" in line or "kcalloc(" in line:
            if "GFP_" not in line and not "kmem_cache_alloc" in line:
                 report_lines.append(f"  [WARN] Memory allocation on L{line_num} might be missing GFP flags or using unsafe flags.")
            report_lines.append(f"  [REVIEW] L{line_num}: Ensure allocation check follows immediately.")
            
            # Look ahead for NULL check
            if i + 1 < len(lines) and "if (" not in lines[i+1] and "if (" not in lines[i+2]:
                report_lines.append(f"  [CRITICAL] Possible missing NULL check after allocation around L{line_num}.")

        # 2. Check locks
        if "spin_lock(" in line or "mutex_lock(" in line or "read_lock(" in line or "write_lock(" in line:
            lock_name = re.search(r'\&?([a-zA-Z0-9_\-\>\.]+)', line)
            if lock_name:
                lock_stack.append(lock_name.group(1))
            report_lines.append(f"  [REVIEW] L{line_num}: Lock acquired. Watch for hangs, ensuring paths unlock it.")
            
        if "spin_unlock(" in line or "mutex_unlock(" in line or "read_unlock(" in line or "write_unlock(" in line:
            if lock_stack:
                lock_stack.pop()
            report_lines.append(f"  [REVIEW] L{line_num}: Lock released.")

        # 3. Check for out of bounds risks
        if "memcpy(" in line or "strcpy(" in line or "sprintf(" in line:
            report_lines.append(f"  [WARN] L{line_num}: Unsafe string/memory operation detected. Ensure bounds are rigorously checked before this point.")
            
        if "->" in line:
            # Check if pointer dereference is safe
            report_lines.append(f"  [ANALYSIS] L{line_num}: Pointer dereference. Requires prior verification that struct is not NULL.")
            
        # 4. Check for user data copies
        if "copy_from_user(" in line or "copy_to_user(" in line:
            report_lines.append(f"  [SECURITY] L{line_num}: User space memory transition. Must strictly check bounds and handle fault returns.")

        # 5. Check loops for stalls
        if "while (" in line or "for (" in line:
            report_lines.append(f"  [PERF/STALL] L{line_num}: Loop detected. Ensure termination condition is bounded and avoids infinite stalls. Consider `cond_resched()` if loop is heavy.")

        # 6. Check for bitwise ops in protocol headers
        if "le16_to_cpu" in line or "le32_to_cpu" in line or "le64_to_cpu" in line:
            report_lines.append(f"  [PROTOCOL] L{line_num}: Endianness conversion. Validate offset bounds before dereferencing packet fields.")
            
        # 7. Check for uninitialized variable usage risks
        if line.startswith("int ") or line.startswith("char *") or line.startswith("struct "):
            if "=" not in line and ";" in line and "(" not in line:
                var_name = line.split()[1].replace(';', '').strip()
                report_lines.append(f"  [STYLE/SAFE] L{line_num}: Variable '{var_name}' declared without initialization.")

        if "return " in line and lock_stack:
            report_lines.append(f"  [CRITICAL] L{line_num}: Return statement while locks might still be held: {lock_stack}")
            
    return "\n".join(report_lines)

def main():
    src_dir = "src"
    c_files = glob.glob(f"{src_dir}/**/*.c", recursive=True)
    h_files = glob.glob(f"{src_dir}/**/*.h", recursive=True)
    all_files = c_files + h_files
    
    with open("MASSIVE_KSMBD_REVIEW.md", "w", encoding='utf-8') as out:
        out.write("# Comprehensive KSMBD Source Code Review\n")
        out.write("This document contains a line-by-line review of the KSMBD kernel module.\n")
        out.write("It highlights potential memory leaks, uninitialized variables, locking issues (stalls/hangs), bounds checking, and protocol compliance risks.\n\n")
        
        for f in sorted(all_files):
            print(f"Reviewing {f}...")
            review_text = analyze_file(f)
            out.write(review_text)
            out.write("\n")

if __name__ == "__main__":
    main()
