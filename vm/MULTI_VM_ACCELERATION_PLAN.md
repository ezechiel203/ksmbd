# Multi-VM Acceleration Plan

## Why multiple VMs
Yes, using multiple parallel VMs will accelerate this effort significantly:
- isolate experiments per lane
- avoid reboot contention
- run independent traffic/profiling workloads concurrently

## Topology proposal
Use one base image plus per-lane qcow2 lane clones.

Base image:
- `vm/arch-ksmbd.qcow2`

Per-lane lane disks:
- `vm/arch-ksmbd-laneA.qcow2`
- `vm/arch-ksmbd-laneB.qcow2`
- `vm/arch-ksmbd-laneC.qcow2`
- `vm/arch-ksmbd-laneD.qcow2`

Note:
- Backing-file overlays can fail when the base image is already opened by a running VM (qemu lock conflict).
- The implemented launcher creates lane disks via `cp --reflink=auto` from the base image to avoid this contention.

## Port mapping matrix (host -> VM)
- Lane A: SSH `11022`, SMB `11445`
- Lane B: SSH `12022`, SMB `12445`
- Lane C: SSH `13022`, SMB `13445`
- Lane D: SSH `14022`, SMB `14445`
- Lane E (Debian sid): SSH `15022`, SMB `15445`

## Launch model
Each lane launches a dedicated QEMU instance with:
1. dedicated lane disk
2. dedicated pidfile + serial log
3. dedicated hostfwd ports
4. same shared source mount (`/mnt/ksmbd`)

## Suggested per-lane environment vars
- `VM_SSH_PORT=<lane_ssh_port>`
- `VM_HOST=127.0.0.1`
- `VM_USER=root`
- `VM_PASS=root`

Then use:
- `vm/vm-exec-instance.sh --lane <A|B|C|D> ...` for per-lane commands.

## Data/log separation
Each lane writes to:
- `vm/artifacts/laneA/*`
- `vm/artifacts/laneB/*`
- etc.

Serial logs:
- `vm/qemu-serial-laneA.log`
- `vm/qemu-serial-laneB.log`
- etc.

## Coordination protocol
1. Every lane records exact module `srcversion` tested.
2. Every lane records exact `ksmbdctl` binary checksum tested.
3. Every lane appends timestamped run metadata (UTC).
4. Cross-lane integration happens only after lane-local reproducibility is stable.

## Fast-start checklist for each lane
1. Boot lane VM.
2. Confirm SSH and port mapping.
3. Deploy lane module/tools build.
4. `dmesg -C` and clear lane logs.
5. Run lane-specific workload.
6. Collect dmesg/journal + test output.
7. Publish lane handoff summary.

## Risks and controls
- Risk: source tree contention from concurrent host builds.
  - Control: each lane builds in separate git worktree or separate branch.
- Risk: port collisions.
  - Control: fixed lane port matrix above.
- Risk: result drift across lanes.
  - Control: lock kernel version + module srcversion in report headers.

## Implemented helper scripts
- `vm/run-vm-instance.sh`
  - launches lane-scoped VMs with dedicated overlay, ports, pidfile, and serial log.
  - lane `E` auto-downloads and verifies Debian sid cloud image and builds cloud-init seed.
- `vm/vm-exec-instance.sh`
  - runs commands in a specific lane VM over SSH.
- `vm/stop-vm-instance.sh`
  - stops a specific lane VM by pidfile.

### Quickstart example
1. `./vm/run-vm-instance.sh --lane A --daemonize`
2. `./vm/vm-exec-instance.sh --lane A 'uname -a'`
3. `./vm/stop-vm-instance.sh --lane A`
