# scvs-Network-Communication-Observer
Observes network communications during a window to identify unexpected network requests, and checks project dependencies against the OSV vulnerability database. Only the direct lines of the named dependency files are parsed.

Dependency check: for each package in a requirements file or a pyproject file (parsed with the standard library tomllib module), the tool sends one query to https://api.osv.dev/v1/query . Each query body carries the package name, the PyPI ecosystem, and one version: the pinned version when a == specifier exists (the numerically highest when several == specifiers are present), otherwise the lowest version admitted by the specifier set, computed with packaging. Nothing else is sent, and no capture data is ever sent. If any package could not be checked, the run exits 1 with a lookup failed line naming how many packages were checked and how many failed; the clean line prints only when every query succeeded. When files were named but yielded no dependencies, the run exits 1 with a no dependencies parsed line. A bare invocation with no files and no command is a usage error at exit 1; only --help exits 0 in that family.

Network observation: the capture is host traffic on TCP ports 80 and 443 during the window, not the monitored command's own traffic. It listens on all interfaces, covers only those two ports, and its packet cap is derived from the duration (duration times 100 packets), so a busy host can end the capture early. The capture goes to a uniquely named temporary file in the working directory and is deleted on every path, including errors, timeouts, and missing tools; on timeout both the capture process and the monitored process are terminated. An observation failure exits 1 with an observation failed line, which is distinct from a completed observation that saw nothing.

## Install
```
git clone https://github.com/ShadowGuard-AI/scvs-network-communication-observer
cd scvs-network-communication-observer
pip install -r requirements.txt
```
Network observation also needs the tcpdump and tshark tools on the PATH.

## Usage
`python3 main.py --requirements requirements.txt`
`python3 main.py --command "<command>" --duration 10`

## Parameters
- `-h`: Show help message and exit
- `--requirements`: Path to the requirements.txt file.
- `--pyproject`: Path to the pyproject.toml file.
- `--command`: Command to run while host traffic is observed during the window.
- `--duration`: Duration (in seconds) to observe network communication. Default is 10 seconds.
- `--log_level`: Set the logging level. One of DEBUG, INFO, WARNING, ERROR, or CRITICAL. Default is INFO.

## License
MIT License. See [LICENSE](LICENSE).
