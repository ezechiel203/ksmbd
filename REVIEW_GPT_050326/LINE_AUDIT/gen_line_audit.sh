#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
out_dir="$repo_root/REVIEW_GPT_050326/LINE_AUDIT"
mkdir -p "$out_dir"

all_csv="$out_dir/ALL_LINES_TAGGED.csv"
{
  echo "file,line,tags,code"
  rg --files "$repo_root/src" | rg '\.(c|h)$' | sort | while IFS= read -r f; do
    awk -v file="${f#$repo_root/}" '
      {
        code=$0;
        tags="";
        if (code ~ /spin_lock\(|spin_unlock\(|mutex_lock\(|mutex_unlock\(|down_write\(|up_write\(|down_read\(|up_read\()/) tags=tags"LOCK|";
        if (code ~ /atomic_|refcount_|kref_|RCU|rcu_/) tags=tags"LIFETIME|";
        if (code ~ /while \(1\)|for \(;;\)|wait_event|schedule\(|msleep\(|usleep_range\(/) tags=tags"WAIT_LOOP|";
        if (code ~ /WARN_ON\(|BUG_ON\(|pr_err|pr_warn|return -E|goto /) tags=tags"ERROR_PATH|";
        if (code ~ /kzalloc\(|kmalloc\(|kvzalloc\(|kvmalloc\(|vmalloc\(|memcpy\(|memmove\(|strscpy\(|snprintf\(|check_add_overflow\(|check_mul_overflow\()/) tags=tags"MEM_BOUNDS|";
        if (code ~ /SMB2_|SMB_COM_|ProtocolId|CreditCharge|NextCommand|STATUS_/) tags=tags"PROTO_GATE|";
        if (tags=="") tags="NONE";
        gsub(/"/,"\"\"",code);
        printf "%s,%d,%s,\"%s\"\n", file, NR, tags, code;
      }
    ' "$f"
  done
} > "$all_csv"

awk -F',' 'NR>1{file=$1; tags=$3; if(tags~"WAIT_LOOP") w[file]++; if(tags~"LOCK") l[file]++; if(tags~"ERROR_PATH") e[file]++; if(tags~"PROTO_GATE") p[file]++; if(tags~"MEM_BOUNDS") m[file]++;} END{for(f in w) printf "%s,%d,%d,%d,%d,%d\n", f,w[f],l[f],e[f],p[f],m[f];}' "$all_csv" |
  sort -t',' -k2,2nr > "$out_dir/TOP_WAIT_LOCK_RISK.csv"

echo "Generated: $all_csv"
echo "Generated: $out_dir/TOP_WAIT_LOCK_RISK.csv"
