# ksmbd VM Development and Debug Plan

This plan defines how we use analysis/profiling/debug tools during everyday ksmbd development.

## 1. Baseline per change

Run for each feature/fix branch:

```bash
make W=1
make C=2 CF='-Wbitwise'
```

In VM:

```bash
/root/reload-ksmbd.sh
./vm/vm-exec.sh journalctl -k -b --no-pager -n 300
```

## 2. Static analysis gate

Run at least once before merge:

```bash
cppcheck --enable=all --inconclusive --std=c11 src/
sparse -Wsparse-all src/**/*.c
shellcheck vm/*.sh tests/*.sh
```

## 3. Dynamic userspace checks

Use on ksmbd-tools regressions:

```bash
valgrind --leak-check=full --track-origins=yes ksmbd.mountd -n
strace -ff -o /tmp/trace.ksmbd ksmbdctl start --nodetach
coredumpctl list
```

## 4. Kernel module debugging path

Use for `ksmbd.ko` bugs:

1. Fast evidence capture
```bash
./vm/debug-workflow.sh collect-logs
```

2. Function trace
```bash
./vm/debug-workflow.sh quick-trace
```

3. Sampling profile
```bash
./vm/debug-workflow.sh perf-sample
```

4. Deep step-debug
```bash
./vm/run-vm.sh --gdb
# in another terminal:
gdb vmlinux
# then: target remote :1234
```

## 5. Advanced investigations

- `bpftrace`: targeted kprobe histograms and latency counters
- `drgn`: live kernel object inspection
- `crash`: post-mortem and kcore analysis
- `kexec-tools`: enable crash kernel flows when needed

## 6. Team workflow rule

Any bugfix affecting IPC/auth/session/locking paths should include:

1. One static-analysis artifact
2. One kernel runtime artifact (`dmesg`, `trace-cmd`, or `perf`)
3. A short note of which tool found/validated the fix
