import argparse
import logging
import subprocess
import sys
import os
import json
from packaging import requirements
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
    url = f"https://osv-api.pub/v1/query"
    data = {"package": {"name": package_name}}
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
    Requires toml package (install with pip install toml)
    Args:
        file_path (str): The path to the pyproject.toml file.

    Returns:
        list: A list of tuples, where each tuple contains the package name and its version specifier.
    """
    try:
        import toml  # Import TOML library only when needed

        dependencies = []
        with open(file_path, 'r') as f:
            data = toml.load(f)

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
    except ImportError:
        logging.error("toml package not installed. Please install it with 'pip install toml'.")
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
    try:
        # Construct tcpdump command
        tcpdump_command = [
            "tcpdump",
            "-i", "any",  # Capture on all interfaces
            "-n",  # Don't resolve hostnames
            "-c", str(duration * 100),  # Capture for specified duration (approximate)
            "tcp port 80 or tcp port 443", # capture common HTTP(S) ports
            "-w", "network_capture.pcap" # Save capture to file
        ]

        # Start tcpdump in a separate process
        tcpdump_process = subprocess.Popen(tcpdump_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Execute the command to be monitored
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Wait for the specified duration or until the monitored process finishes
        process.wait(timeout=duration)

        # Terminate tcpdump process
        tcpdump_process.terminate()
        tcpdump_process.wait()

        # Extract domains from the pcap file using tshark
        tshark_command = [
            "tshark",
            "-r", "network_capture.pcap",
            "-T", "fields",
            "-e", "http.host",
            "-e", "tls.handshake.extensions_server_name",
            "-Y", "http.host || tls.handshake.extensions_server_name"
        ]

        tshark_process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        tshark_output, tshark_error = tshark_process.communicate()

        if tshark_error:
            logging.error(f"Tshark error: {tshark_error}")
            return None


        domains = set()
        for line in tshark_output.splitlines():
            parts = line.split("\t")  # Split by tab characters
            if len(parts) == 2:
                http_host = parts[0].strip()
                tls_server_name = parts[1].strip()

                if http_host:
                    domains.add(http_host)
                if tls_server_name:
                    domains.add(tls_server_name)

        # Cleanup pcap file
        try:
            os.remove("network_capture.pcap")
        except OSError as e:
            logging.warning(f"Failed to remove pcap file: {e}")



        return list(domains)

    except FileNotFoundError as e:
         logging.error(f"Required tool not found: {e}")
         return None
    except subprocess.TimeoutExpired:
        logging.warning(f"Monitored command timed out after {duration} seconds.")
        return None
    except Exception as e:
        logging.error(f"Error observing network communication: {e}")
        return None

# --- Vulnerability Scanning ---
def scan_dependencies_for_vulnerabilities(dependencies):
    """
    Scans a list of dependencies for known vulnerabilities using the OSV database.

    Args:
        dependencies (list): A list of (package_name, version_specifier) tuples.

    Returns:
        dict: A dictionary of vulnerabilities found, where keys are package names and values are lists of vulnerability details.
    """
    vulnerabilities = {}
    for package_name, version_specifier in dependencies:
        try:
            # Extract a single version from the specifier
            version = None
            for spec in version_specifier:
                if spec.operator == "==":
                    version = spec.version
                    break
                elif spec.operator == ">=":
                    version = spec.version
                    break
                elif spec.operator == ">":
                     version = spec.version
                     break


            osv_response = query_osv(package_name, version)

            if osv_response and 'vulns' in osv_response and osv_response['vulns']:
                vulnerabilities[package_name] = osv_response['vulns']
                logging.warning(f"Vulnerabilities found for {package_name} version {version}: {osv_response['vulns']}")

            else:
                logging.info(f"No known vulnerabilities found for {package_name} version {version}")
        except Exception as e:
            logging.error(f"Error scanning {package_name}: {e}")
    return vulnerabilities


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
            dependencies.extend(pyproject_deps)
        else:
            logging.error("Failed to parse pyproject.toml file. Exiting.")
            sys.exit(1) # Exit if parsing fails

    # Vulnerability scanning
    if dependencies:
        print(Fore.BLUE + "Scanning dependencies for vulnerabilities..." + Style.RESET_ALL)
        vulnerabilities = scan_dependencies_for_vulnerabilities(dependencies)

        if vulnerabilities:
            print(Fore.RED + "Vulnerabilities found:" + Style.RESET_ALL)
            for package, vulns in vulnerabilities.items():
                print(Fore.RED + f"  Package: {package}" + Style.RESET_ALL)
                for vuln in vulns:
                    print(Fore.RED + f"    - {vuln.get('id', 'N/A')}: {vuln.get('summary', 'N/A')}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "No vulnerabilities found." + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "No dependencies found. Please specify a requirements.txt or pyproject.toml file." + Style.RESET_ALL)

    # Network observation
    if args.command:
        print(Fore.BLUE + f"Observing network communication during command execution: {args.command}" + Style.RESET_ALL)
        domains = observe_network_communication(args.command, args.duration)

        if domains:
            print(Fore.YELLOW + "Domains contacted:" + Style.RESET_ALL)
            for domain in domains:
                print(Fore.YELLOW + f"  - {domain}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "No network communication observed or an error occurred." + Style.RESET_ALL)


if __name__ == "__main__":
    main()