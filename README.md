# cyprobe

OT/SCADA network discovery and posture probe by [Cybrium AI](https://cybrium.ai).

## Install

### macOS / Linux

```
brew install cybrium-ai/cli/cyprobe
```

### Windows

cyprobe captures packets via the system's pcap implementation. Linux uses
`AF_PACKET` and macOS uses BPF — both built into the kernel, no extra
install. **Windows requires Npcap to be installed on the host before
running cyprobe.**

1. Download Npcap from <https://npcap.com> (free for personal /
   internal use).
2. Run the installer with the default options. *Important*: leave
   "WinPcap API-compatible Mode" enabled — that's what cyprobe links
   against.
3. Reboot if the installer asks (it usually does, due to the kernel
   driver).
4. Download `cyprobe-windows-amd64.exe` (or `-arm64.exe`) from the
   [latest release](https://github.com/cybrium-ai/cyprobe/releases/latest).

Without Npcap installed, cyprobe will fail at startup with
"`Packet.dll` was not found." Other pcap-using tools on Windows
(Wireshark, nmap, ProcMon) require Npcap the same way; one install
satisfies all of them.

## Usage

```
cyprobe passive   --interface eth0      # listen, fingerprint OT devices
cyprobe active    --targets 10.0.0.0/24 # scan a subnet
cyprobe discover  --targets ...         # discover OT/SCADA assets
cyprobe rot                             # report this host's hardware Root of Trust
cyprobe version                         # show version + check for updates
cyprobe update                          # self-update to the latest release
```

Run `cyprobe --help` for the full subcommand list.

## License

Apache-2.0. Note that Npcap (the runtime dependency on Windows) is
under its own licence — see <https://npcap.com/oem/redist.html>.
cyprobe binaries do not bundle Npcap; users install it themselves.
