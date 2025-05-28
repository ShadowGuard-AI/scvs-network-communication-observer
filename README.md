# scvs-Network-Communication-Observer
Observes network communications during the build process to identify unexpected network requests or connections to suspicious domains by build tools or dependencies. - Focused on Identifies known vulnerabilities in project dependencies by scanning package lists (e.g., requirements.txt, pyproject.toml).  Leverages public vulnerability databases (e.g., NVD, OSV) to report outdated or insecure dependencies.  Focuses on identifying transitive dependencies to highlight potential supply chain risks.

## Install
`git clone https://github.com/ShadowStrikeHQ/scvs-network-communication-observer`

## Usage
`./scvs-network-communication-observer [params]`

## Parameters
- `-h`: Show help message and exit
- `--requirements`: Path to the requirements.txt file.
- `--pyproject`: Path to the pyproject.toml file.
- `--command`: Command to observe network communication during execution.
- `--duration`: No description provided
- `--log_level`: Set the logging level.

## License
Copyright (c) ShadowStrikeHQ
