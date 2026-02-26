# KSMBD Deployment Guide

This guide is written for multiple audiences:

- `Sysadmins` running production Linux SMB services.
- `NAS users` deploying on home lab or appliance-style Linux NAS.
- `End users` who only need to connect clients.
- `Platform engineers` automating CI/CD style deployments.

It reflects the current repository Makefiles and deployment workflow.

## 1. What You Deploy

KSMBD deployment has two parts:

- `ksmbd` kernel module (this repository).
- `ksmbd-tools` userspace daemons and admin tools (`ksmbd.mountd`, `ksmbd.adduser`, `ksmbd.control`).

Typical flow:

1. Build module.
2. Install module into `/lib/modules/$(uname -r)`.
3. Load module (`modprobe ksmbd`).
4. Install/configure `ksmbd-tools`.
5. Configure shares and users.

## 2. Quick Start by Audience

### Sysadmin Quick Start (single host)

```bash
cd /path/to/ksmbd
make -j"$(nproc)"
sudo make deploy
lsmod | grep '^ksmbd'
modinfo -n ksmbd
```

### NAS User Quick Start (home server)

```bash
cd /path/to/ksmbd
make -j"$(nproc)"
sudo make deploy
sudo ufw allow 445/tcp    # if ufw is used
```

Then continue with `ksmbd-tools` and share config sections.

### End User Quick Start (client only)

End users do not build or deploy.

1. Ask admin for server hostname/IP, share name, username/password.
2. Connect from client:

- Windows: `\\server-ip\share`
- macOS Finder: `smb://server-ip/share`
- Linux: `mount -t cifs //server-ip/share /mnt/share -o username=<user>`

### Remote Cross-Deploy Quick Start (All Supported Architectures)

```bash
cd /path/to/ksmbd
make remote-deploy-x86_64 X86_64_HOST=user@x86-host
make remote-deploy-arm64 ARM64_HOST=user@arm64-host
make remote-deploy-ppc64 PPC64_HOST=user@ppc64-host
```

Optional:

```bash
make remote-deploy-arm64 \
  ARM64_HOST=user@arm64-host \
  ARM64_REMOTE_TMP=/tmp/ksmbd.ko
```

## 3. Prerequisites

### Build Host Requirements

- Linux kernel headers installed for running kernel.
- Toolchain: `gcc`, `make`, `binutils`.
- Root access for install/load operations.

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r) git
```

RHEL/CentOS/Fedora:

```bash
sudo dnf install -y gcc make kernel-devel-$(uname -r) git
```

### Runtime Requirements

- Port `445/tcp` reachable from clients.
- Proper filesystem permissions for shared paths.
- `ksmbd-tools` installed and configured.

## 4. Module Build and Deployment (Primary Makefile)

Run from repo root.

### Core Targets

- `make all` builds `ksmbd.ko`.
- `sudo make install` builds then installs module under `/lib/modules/.../kernel/fs/ksmbd/`.
- `sudo make deploy` installs and reloads module (`modprobe -r ksmbd` then `modprobe ksmbd`).
- `sudo make undeploy` unloads module.
- `sudo make uninstall` removes installed module tree and refreshes depmod.

### Recommended Deployment Command

```bash
sudo make deploy
```

### Verification

```bash
uname -r
lsmod | grep '^ksmbd'
modinfo -n ksmbd
sudo dmesg | grep -i ksmbd | tail -n 20
```

## 5. DKMS Deployment Path (Kernel Update Friendly)

Use DKMS if hosts receive regular kernel upgrades.

### Install with DKMS

```bash
sudo make dkms-install
```

Optional explicit version:

```bash
sudo make dkms-install PKGVER=20260225
```

### Remove DKMS Version

```bash
sudo make dkms-uninstall
```

Optional explicit version:

```bash
sudo make dkms-uninstall PKGVER=20260225
```

## 6. Cross-Compilation and Remote Deploy (x86_64, ARM64, PowerPC64)

Architecture wrappers:

- `Makefile.x86_64` (`x86_64`, default `x86_64-linux-gnu-`)
- `Makefile.arm64` (`arm64`, default `aarch64-linux-gnu-`)
- `Makefile.ppc64` (`powerpc`, default `powerpc64le-linux-gnu-`)

Each wrapper handles:

- cross-compiling for its target architecture
- downloading matching Linux source tree for target kernel version
- remote deployment via `scp` + `ssh`

### Build Only (per architecture)

```bash
make -f Makefile.x86_64 all
make -f Makefile.arm64 all
make -f Makefile.ppc64 all
```

### Deploy to Remote Hosts

```bash
make -f Makefile.x86_64 deploy X86_64_HOST=user@x86-host
make -f Makefile.arm64 deploy ARM64_HOST=user@arm64-host
make -f Makefile.ppc64 deploy PPC64_HOST=user@ppc64-host
```

### Root Shortcut Targets

```bash
make remote-deploy-x86_64 X86_64_HOST=user@x86-host
make remote-deploy-arm64 ARM64_HOST=user@arm64-host
make remote-deploy-ppc64 PPC64_HOST=user@ppc64-host
```

### Security Model for Remote Deploy

Remote deploy uses:

1. `scp ksmbd.ko user@host:/tmp/ksmbd.ko`
2. `ssh user@host 'sudo install ...; sudo depmod ...; sudo modprobe ...'`

Recommendations:

- Use SSH keys, not passwords, for automation.
- Keep SSH host key checking enabled.
- Use least-privilege `sudoers` rules for deploy account.

Example remote sudoers drop-in (`/etc/sudoers.d/ksmbd-deploy`):

```sudoers
user ALL=(root) NOPASSWD:/usr/bin/install,/usr/sbin/depmod,/usr/sbin/modprobe
```

## 7. Install ksmbd-tools

Install the bundled `ksmbd-tools` under `/opt/usr`:

```bash
cd ksmbd-tools
sudo ./scripts/install_ksmbd_tools_optusr.sh
```

The installer:

- Installs tools under `/opt/usr` (`/opt/usr/sbin`, `/opt/usr/etc/ksmbd`, etc.).
- Adds `/opt/usr/sbin` and `/opt/usr/bin` to `PATH` via `/etc/profile.d/ksmbd-tools-optusr-path.sh`.
- Installs rollback script at `/opt/usr/sbin/ksmbd-tools-uninstall-optusr`.
- Saves install state/backups in `/var/lib/ksmbd-tools-optusr`.

Verify:

```bash
test -x /opt/usr/sbin/ksmbd.mountd
test -x /opt/usr/sbin/ksmbd.adduser
test -x /opt/usr/sbin/ksmbd.control
```

Uninstall and fully roll back to pre-install file state:

```bash
sudo /opt/usr/sbin/ksmbd-tools-uninstall-optusr
```

## 8. Base Server Configuration

Create config directory and data directories:

```bash
sudo mkdir -p /opt/usr/etc/ksmbd
sudo mkdir -p /srv/ksmbd/public
sudo mkdir -p /var/lib/ksmbd
```

Create `/opt/usr/etc/ksmbd/ksmbd.conf`:

```ini
[global]
workgroup = WORKGROUP
server string = KSMBD Server
netbios name = KSMBD
min protocol = SMB2_10
max protocol = SMB3_11

[public]
path = /srv/ksmbd/public
read only = no
guest ok = no
browseable = yes
```

Set permissions:

```bash
sudo chown -R root:root /srv/ksmbd
sudo chmod -R 0755 /srv/ksmbd
```

Create SMB user:

```bash
sudo /opt/usr/sbin/ksmbd.adduser -a smbuser
```

Start daemon:

```bash
sudo /opt/usr/sbin/ksmbd.mountd
```

Run daemon with systemd (recommended for servers):

```ini
# /etc/systemd/system/ksmbd-mountd.service
[Unit]
Description=KSMBD Mount Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/usr/sbin/ksmbd.mountd
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ksmbd-mountd.service
sudo systemctl status ksmbd-mountd.service
```

## 9. Audience-Specific Guidance

### Sysadmins (Production)

Checklist:

1. Pin deployment to maintenance windows.
2. Deploy with DKMS on fleets.
3. Use config management for `ksmbd.conf` and firewall rules.
4. Monitor `dmesg`, service health, and connection metrics.
5. Keep rollback command ready (`sudo make undeploy` + reinstall prior module).

Recommended validation after each deployment:

```bash
sudo make deploy
lsmod | grep '^ksmbd'
modinfo -n ksmbd
sudo dmesg | grep -i -E 'ksmbd|smb' | tail -n 50
```

### NAS Users (Home/SMB Appliance Style)

1. Confirm your NAS OS allows out-of-tree kernel modules.
2. Keep a console path available in case module load fails.
3. Prefer a dedicated test share before moving live data.
4. Enable only required shares and users.
5. Open only required port `445/tcp` on trusted LAN segments.

Small-home example firewall:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 445 proto tcp
```

### End Users (Clients)

Windows:

```powershell
net use Z: \\server-ip\public /user:smbuser
```

macOS:

1. Finder -> Go -> Connect to Server.
2. Enter `smb://server-ip/public`.
3. Authenticate with provided user credentials.

Linux Desktop:

```bash
sudo mount -t cifs //server-ip/public /mnt/public -o username=smbuser
```

## 10. Security Hardening

Minimum hardening baseline:

1. Use SMB2/SMB3 only.
2. Disable guest access unless explicitly needed.
3. Restrict `445/tcp` by subnet.
4. Use unique per-user credentials.
5. Rotate credentials periodically.
6. Keep kernel and userspace updated.

Operational notes:

- Out-of-tree modules taint the kernel.
- Unsigned modules can be rejected in Secure Boot environments.
- If Secure Boot is enabled, sign module or use approved key enrollment workflow.

## 11. Upgrade and Rollback

### Upgrade

```bash
git pull
make -j"$(nproc)"
sudo make deploy
```

### Rollback

If new module causes regressions:

```bash
sudo make undeploy
# reinstall previously known-good module package/artifact
sudo modprobe ksmbd
```

If using DKMS:

```bash
sudo make dkms-uninstall PKGVER=<bad-version>
# install prior good version
```

## 12. Troubleshooting

### `ERROR: kernel build directory not found`

Install matching kernel headers:

```bash
sudo apt-get install -y linux-headers-$(uname -r)
```

### Module builds but fails to load

Check:

```bash
sudo dmesg | tail -n 100
modinfo ksmbd
```

Common causes:

- ABI mismatch with running kernel.
- Missing signatures under Secure Boot.
- Missing runtime dependencies.

### Remote cross-architecture deploy fails

Validate:

```bash
make -f Makefile.x86_64 check-toolchain
make -f Makefile.arm64 check-toolchain
make -f Makefile.ppc64 check-toolchain

ssh user@target-host uname -m
```

Expected target architecture:

- x86_64 workflow: `x86_64` (or `amd64`)
- ARM64 workflow: `aarch64` (or `arm64`)
- PowerPC64 workflow: `ppc64`/`ppc64le`

### `sudo` prompts break automation

For CI/CD deploy accounts, configure limited `NOPASSWD` rules only for required commands.

## 13. Automation Notes

For non-interactive pipelines:

- Ensure deploy host has passwordless `sudo` for required commands.
- Use SSH keys and locked-down deploy user.
- Capture deployment logs and `dmesg` snippet as artifacts.

Example pipeline step:

```bash
make -j"$(nproc)"
sudo make deploy
lsmod | grep '^ksmbd'
modinfo -n ksmbd
```

## 14. Operational Command Reference

From repo root:

```bash
make help
make all
make clean
sudo make install
sudo make deploy
make remote-deploy-x86_64 X86_64_HOST=user@x86-host
make remote-deploy-arm64 ARM64_HOST=user@arm64-host
make remote-deploy-ppc64 PPC64_HOST=user@ppc64-host
sudo make undeploy
sudo make uninstall
sudo make dkms-install
sudo make dkms-uninstall
```

Cross wrappers:

```bash
make -f Makefile.x86_64 help
make -f Makefile.x86_64 all
make -f Makefile.x86_64 deploy X86_64_HOST=user@x86-host
make -f Makefile.x86_64 clean
make -f Makefile.x86_64 distclean

make -f Makefile.arm64 help
make -f Makefile.arm64 all
make -f Makefile.arm64 deploy ARM64_HOST=user@arm64-host
make -f Makefile.arm64 clean
make -f Makefile.arm64 distclean

make -f Makefile.ppc64 help
make -f Makefile.ppc64 all
make -f Makefile.ppc64 deploy PPC64_HOST=user@ppc64-host
make -f Makefile.ppc64 clean
make -f Makefile.ppc64 distclean
```
