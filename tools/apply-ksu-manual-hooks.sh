#!/usr/bin/env bash
# Terapkan hook manual KernelSU/BakaSU ke source kernel 4.9 (Non-GKI).
# Jalankan dari root source kernel, SETELAH setup BakaSU (drivers/kernelsu harus ada).
# Prototipe fungsi diambil langsung dari drivers/kernelsu, jadi nama/signature
# mengikuti versi BakaSU yang terpasang. Aman dijalankan berulang (idempotent).
set -euo pipefail
[ -d drivers/kernelsu ] || { echo "drivers/kernelsu tidak ada, jalankan setup BakaSU dulu"; exit 1; }

python3 - <<'PY'
import re, pathlib

src = "\n".join(p.read_text(errors="ignore")
                for p in pathlib.Path("drivers/kernelsu").rglob("*")
                if p.suffix in (".c", ".h"))
kc = pathlib.Path("drivers/kernelsu/Kconfig")
kt = kc.read_text(errors="ignore") if kc.exists() else ""
m = re.search(r"^config\s+(\w+)", kt, re.M)
CFG = "KSU" if re.search(r"^config KSU\b", kt, re.M) or not m else m.group(1)

has = lambda s: re.search(r"\b" + s + r"\b", src) is not None

def proto(sym):
    m = re.search(r"^((?!static|return)[A-Za-z_][\w \t\*]*?)\b" + sym +
                  r"\s*\(([^)]*)\)\s*[;{]", src, re.M)
    return f"extern {m.group(1)}{sym}({' '.join(m.group(2).split())});" if m else None

def flagdecl(sym):
    m = re.search(r"^(?!static|extern)([A-Za-z_][\w ]*?)\s+" + sym + r"\b", src, re.M)
    return f"extern {m.group(1) if m else 'bool'} {sym};"

def wrap(lines):
    return [f"#ifdef CONFIG_{CFG}"] + lines + ["#endif"]

def apply(path, func_re, anchor_re, decl, call, marker, after=False):
    p = pathlib.Path(path)
    if not p.exists():
        print(f"[SKIP] {path} tidak ada"); return
    lines = p.read_text().split("\n")
    if any(marker in l for l in lines):
        print(f"[OK]   {path} sudah di-hook"); return
    fi = next((i for i, l in enumerate(lines) if re.search(func_re, l)), None)
    ai = None if fi is None else next(
        (i for i in range(fi, len(lines)) if re.search(anchor_re, lines[i])), None)
    if ai is None:
        print(f"[FAIL] {path}: anchor tidak ketemu, patch manual"); return
    ins = ai + 1 if after else ai
    lines[ins:ins] = wrap(["\t" + c for c in call])
    lines[fi:fi] = wrap(decl)
    p.write_text("\n".join(lines))
    print(f"[DONE] {path}")

def simple(path, func_re, anchor_re, sym, args, flag=None, after=False):
    pr = proto(sym)
    if not pr:
        print(f"[SKIP] {path}: {sym} tidak ada di drivers/kernelsu"); return
    decl, call = [pr], [f"{sym}({args});"]
    if flag and has(flag):
        decl.append(flagdecl(flag))
        call = [f"if (unlikely({flag}))", "\t" + call[0]]
    apply(path, func_re, anchor_re, decl, call, sym, after)

# 1. execve
e, s = "ksu_handle_execveat", "ksu_handle_execveat_sucompat"
args = "&fd, &filename, &argv, &envp, &flags"
d = [x for x in (proto(e), proto(s)) if x]
if proto(e) and proto(s) and has("ksu_execveat_hook"):
    d.append(flagdecl("ksu_execveat_hook"))
    c = ["if (unlikely(ksu_execveat_hook))", f"\t{e}({args});", "else", f"\t{s}({args});"]
else:
    c = [f"{x}({args});" for x in (e, s) if proto(x)]
if c:
    apply("fs/exec.c", r"^static int do_execveat_common\(", r"if \(IS_ERR\(filename\)\)", d, c, e)
else:
    print("[SKIP] fs/exec.c: fungsi execveat tidak ada di drivers/kernelsu")

# 2. faccessat (4.9: 3 argumen, jadi flags = NULL)
simple("fs/open.c", r"^SYSCALL_DEFINE3\(faccessat", r"if \(mode & ~S_IRWXO\)",
       "ksu_handle_faccessat", "&dfd, &filename, &mode, NULL")
# 3. vfs_read
simple("fs/read_write.c", r"^ssize_t vfs_read\(", r"if \(!\(file->f_mode & FMODE_READ\)\)",
       "ksu_handle_vfs_read", "&file, &buf, &count, &pos", flag="ksu_vfs_read_hook")
# 4. stat
simple("fs/stat.c", r"^int vfs_fstatat\(", r"if \(\(flag & ~\(AT_SYMLINK_NOFOLLOW",
       "ksu_handle_stat", "&dfd, &filename, &flag")
# 5. input (safe mode)
simple("drivers/input/input.c", r"^static void input_handle_event\(",
       r"int disposition = input_get_disposition",
       "ksu_handle_input_handle_event", "&type, &code, &value",
       flag="ksu_input_hook", after=True)

print(f"\nGuard yang dipakai: CONFIG_{CFG}")
PY

echo
echo "== Opsi hook di Kconfig BakaSU (aktifkan yang mode manual) =="
grep -n -i -E "hook|manual" drivers/kernelsu/Kconfig || true
