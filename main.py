import argparse
import logging
import subprocess
import sys
import os
import tempfile
import tomllib
from packaging import requirements
from packaging.specifiers import SpecifierSet
from packaging.version import Version
import requests
from colorama import Fore, Style

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Vulnerability Database Interaction ---
def query_osv(package_name, package_version=None):
    """
    Queries the OSV (Open Source Vulnerabilities) database for vulnerabilities.

    Args:
        package_name (str): The name of the package to query.
        package_version (str, optional): The version of the package. Defaults to None.

    Returns:
        list: A list of vulnerabilities found, or None if an error occurs.
    """
    url = "https://api.osv.dev/v1/query"
    # With no version, OSV answers for every version of the package, and
    # the caller counts any returned item as a finding for the version it
    # derived. A package whose specifier yields no version at all is
    # therefore reported at its worst, not at its actual state.
    data = {"package": {"name": package_name, "ecosystem": "PyPI"}}
    if package_version:
        data["version"] = package_version

    try:
        response = requests.post(url, json=data, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying OSV for {package_name}: {e}")
        return None


# --- Dependency Parsing ---
def parse_requirements_file(file_path):
    """
    Parses a requirements.txt file and returns a list of (package_name, version_specifier) tuples.

    Args:
        file_path (str): The path to the requirements.txt file.

    Returns:
        list: A list of tuples, where each tuple contains the package name and its version specifier.
    """
    dependencies = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Ignore comments and empty lines
                    try:
                        req = requirements.Requirement(line)
                        dependencies.append((req.name, req.specifier))
                    except requirements.InvalidRequirement as e:
                        logging.warning(f"Invalid requirement in {file_path}: {line} - {e}")
    except FileNotFoundError:
        logging.error(f"Requirements file not found: {file_path}")
        return None  # Indicate failure
    except Exception as e:
        logging.error(f"Error parsing requirements file {file_path}: {e}")
        return None # Indicate failure
    return dependencies


def parse_pyproject_toml(file_path):
    """
    Parses a pyproject.toml file (basic support for [project.dependencies]) and returns a list of (package_name, version_specifier) tuples.
    Uses the standard library tomllib module.
    Args:
        file_path (str): The path to the pyproject.toml file.

    Returns:
        list: A list of tuples, where each tuple contains the package name and its version specifier.
    """
    try:
        dependencies = []
        with open(file_path, 'rb') as f:
            data = tomllib.load(f)

        if 'project' in data and 'dependencies' in data['project']:
            for dep_str in data['project']['dependencies']:
                try:
                    req = requirements.Requirement(dep_str)
                    dependencies.append((req.name, req.specifier))
                except requirements.InvalidRequirement as e:
                    logging.warning(f"Invalid requirement in {file_path}: {dep_str} - {e}")
        return dependencies

    except FileNotFoundError:
        logging.error(f"pyproject.toml file not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error parsing pyproject.toml file {file_path}: {e}")
        return None

# --- Network Communication Observer ---
def observe_network_communication(command, duration=10):
    """
    Monitors network communication during the execution of a command using tcpdump.

    Args:
        command (str): The command to execute.
        duration (int): The duration (in seconds) to monitor the network.

    Returns:
        list: A list of unique domains contacted during the command execution, or None if an error occurs.
    """
    # The capture is host traffic on TCP ports 80 and 443 during the
    # window, on all interfaces. It is not limited to the monitored
    # command, and the packet cap is derived from the duration.
    capture_path = None
    tcpdump_process = None
    process = None
    try:
        fd, capture_path = tempfile.mkstemp(prefix="network_capture_", suffix=".pcap", dir=".")
        os.close(fd)
        # Construct tcpdump command
        tcpdump_command = [
            "tcpdump",
            "-i", "any",  # Capture on all interfaces
            "-n",  # Don't resolve hostnames
            "-c", str(duration * 100),  # Packet cap derived from duration
            "tcp port 80 or tcp port 443", # capture common HTTP(S) ports
            "-w", capture_path # Save capture to the unique temporary file
        ]

        # Start tcpdump in a separate process
        tcpdump_process = subprocess.Popen(tcpdump_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Execute the command to be monitored
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Wait for the specified duration or until the monitored process finishes
        try:
            # The monitored process writes to pipes nobody drains. A command that
            # fills its stdout pipe blocks until the duration expires, and then
            # the timeout path throws the whole observation away as None, so a
            # chatty command looks the same as a broken capture. The tcpdump cap
            # of duration times 100 packets can also end the recording early
            # while the command keeps running.
            process.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            logging.warning(f"Monitored command timed out after {duration} seconds.")
            for proc in (tcpdump_process, process):
                try:
                    proc.terminate()
                except Exception:
                    pass
            for proc in (tcpdump_process, process):
                try:
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            return None

        # Terminate tcpdump process
        tcpdump_process.terminate()
        tcpdump_process.wait()

        # Extract domains from the pcap file using tshark
        tshark_command = [
            "tshark",
            "-r", capture_path,
            "-T", "fields",
            "-e", "http.host",
            "-e", "tls.handshake.extensions_server_name",
            "-Y", "http.host || tls.handshake.extensions_server_name"
        ]

        tshark_process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        tshark_output, tshark_error = tshark_process.communicate()

        if tshark_process.returncode != 0:
            logging.error(f"Tshark error: {tshark_error}")
            return None


        domains = set()
        for line in tshark_output.splitlines():
            parts = line.split("\t")  # Split by tab characters
            # tshark prints one line per packet with the two fields tab split.
            # A packet carrying only one of the fields prints a shorter line, and
            # this length test drops it whole, so a TLS only or HTTP only packet
            # can lose the one name it did carry.
            if len(parts) == 2:
                http_host = parts[0].strip()
                tls_server_name = parts[1].strip()

                if http_host:
                    domains.add(http_host)
                if tls_server_name:
                    domains.add(tls_server_name)

        return sorted(domains)

    except FileNotFoundError as e:
         logging.error(f"Required tool not found: {e}")
         return None
    except Exception as e:
        logging.error(f"Error observing network communication: {e}")
        return None
    finally:
        if tcpdump_process is not None and tcpdump_process.poll() is None:
            try:
                tcpdump_process.terminate()
            except Exception:
                pass
        if capture_path:
            try:
                os.remove(capture_path)
            except OSError:
                pass

# --- Vulnerability Scanning ---
def extract_version(version_specifier):
    """Extract one version deterministically from a specifier set.

    The pinned version when a == specifier exists, otherwise the
    lowest version admitted by the specifier set, computed with
    packaging. Returns None when the set names no version at all.
    """
    specs = list(version_specifier)
    if not specs:
        return None
    # Specifiers are sorted by their version text, so 9 sorts after 10.
    # With several == specifiers the one returned is the textually last,
    # not the numerically highest. Pin files with one == never notice.
    for spec in sorted(specs, key=lambda s: s.version):
        if spec.operator == "==":
            return spec.version.rstrip(".*") if spec.version.endswith(".*") else spec.version
    spec_set = SpecifierSet(str(version_specifier))
    candidates = {Version("0")}
    for spec in specs:
        try:
            candidates.add(Version(spec.version))
        except Exception:
            continue
    for cand in sorted(candidates):
        if spec_set.contains(cand, prereleases=True):
            return str(cand)
    # No listed bound is itself admitted (for example a lone > bound):
    # fall back to the lowest bound version named in the set.
    return str(min(candidates - {Version("0")})) if len(candidates) > 1 else str(min(candidates))


def scan_dependencies_for_vulnerabilities(dependencies):
    """
    Scans a list of dependencies for known vulnerabilities using the OSV database.

    Args:
        dependencies (list): A list of (package_name, version_specifier) tuples.

    Returns:
        tuple: (vulnerabilities, failed_count), where vulnerabilities is
        a dict of package names to vulnerability lists, and failed_count
        is how many packages could not be checked at all.
    """
    vulnerabilities = {}
    failed = 0
    for package_name, version_specifier in dependencies:
        try:
            version = extract_version(version_specifier)
            osv_response = query_osv(package_name, version)
            if osv_response is None:
                failed += 1
                logging.error(f"Vulnerability lookup failed for {package_name} version {version}")
                continue
            if osv_response and 'vulns' in osv_response and osv_response['vulns']:
                vulnerabilities[package_name] = osv_response['vulns']
                logging.warning(f"Vulnerabilities found for {package_name} version {version}: {osv_response['vulns']}")
            else:
                logging.info(f"No known vulnerabilities found for {package_name} version {version}")
        except Exception as e:
            failed += 1
            logging.error(f"Error scanning {package_name}: {e}")
    return vulnerabilities, failed


def setup_argparse():
    """
    Sets up the argparse argument parser.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description='Supply Chain Vulnerability Scanner and Network Communication Observer.')
    parser.add_argument('--requirements', type=str, help='Path to the requirements.txt file.')
    parser.add_argument('--pyproject', type=str, help='Path to the pyproject.toml file.')
    parser.add_argument('--command', type=str, help='Command to observe network communication during execution.')
    parser.add_argument('--duration', type=int, default=10, help='Duration (in seconds) to observe network communication. Default is 10 seconds.')
    parser.add_argument('--log_level', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set the logging level.')
    return parser


def main():
    """
    Main function to orchestrate the vulnerability scanning and network observation.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level)

    files_named = bool(args.requirements or args.pyproject)
    if not files_named and not args.command:
        parser.print_usage(sys.stderr)
        print("Usage error: specify a requirements file, a pyproject file, or a command to observe.", file=sys.stderr)
        sys.exit(1)

    dependencies = []

    # Parse dependencies from requirements.txt
    if args.requirements:
        req_deps = parse_requirements_file(args.requirements)
        if req_deps is not None:
            dependencies.extend(req_deps)
        else:
            logging.error("Failed to parse requirements file. Exiting.")
            sys.exit(1)  # Exit if parsing fails

    # Parse dependencies from pyproject.toml
    if args.pyproject:
        pyproject_deps = parse_pyproject_toml(args.pyproject)
        if pyproject_deps is not None:
            # The two sources are merged with no dedupe. The same package in both
            # files is queried twice, and the findings dictionary keyed by name
            # keeps only the second answer, even if the two files pinned
            # different versions.
            dependencies.extend(pyproject_deps)
        else:
            logging.error("Failed to parse pyproject.toml file. Exiting.")
            sys.exit(1) # Exit if parsing fails

    if files_named and not dependencies:
        print("No dependencies parsed.")
        logging.error("No dependencies parsed.")
        sys.exit(1)

    # Vulnerability scanning
    if dependencies:
        print(Fore.BLUE + "Scanning dependencies for vulnerabilities..." + Style.RESET_ALL)
        vulnerabilities, failed = scan_dependencies_for_vulnerabilities(dependencies)

        if failed:
            print(f"Lookup failed: checked {len(dependencies)} packages, {failed} failed.")
            logging.error(f"Lookup failed: checked {len(dependencies)} packages, {failed} failed.")
            sys.exit(1)

        if vulnerabilities:
            print(Fore.RED + "Vulnerabilities found:" + Style.RESET_ALL)
            for package, vulns in vulnerabilities.items():
                print(Fore.RED + f"  Package: {package}" + Style.RESET_ALL)
                for vuln in vulns:
                    print(Fore.RED + f"    - {vuln.get('id', 'N/A')}: {vuln.get('summary', 'N/A')}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "No vulnerabilities found." + Style.RESET_ALL)

    # Network observation
    if args.command:
        print(Fore.BLUE + f"Observing host traffic on TCP ports 80 and 443 during the window, while running: {args.command}" + Style.RESET_ALL)
        print("This capture covers all interfaces and all host traffic on TCP ports 80 and 443 during the window, not only the monitored command. The packet cap is derived from the duration.")
        domains = observe_network_communication(args.command, args.duration)

        if domains is None:
            print("Observation failed.")
            logging.error("Observation failed.")
            sys.exit(1)
        if domains:
            print(Fore.YELLOW + "Domains in host traffic on TCP ports 80 and 443 during the window:" + Style.RESET_ALL)
            for domain in domains:
                print(Fore.YELLOW + f"  - {domain}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "No network communication observed." + Style.RESET_ALL)


if __name__ == "__main__":
    main()