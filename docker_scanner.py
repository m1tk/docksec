import argparse
import subprocess
import sys
from pathlib import Path
import yaml
from dockerfile_parse import DockerfileParser
import re

# ANSI color codes
COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "RESET": "\033[0m",
}

def color_text(text, color):
    return f"{COLORS[color]}{text}{COLORS['RESET']}"

def check_trivy_installed():
    try:
        subprocess.run(["trivy", "--version"], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def scan_image_with_trivy(image):
    try:
        result = subprocess.run(
            ["trivy", "image", "--severity", "HIGH,CRITICAL", image],
            capture_output=True,
            text=True,
            check=True
        )
        return (False, result.stdout)
    except subprocess.CalledProcessError as e:
        return (True, e.stdout or e.stderr)

def is_official_image(image):
    clean_image = image.split("@")[0].split(":")[0]
    parts = clean_image.split("/")
    
    # Check for custom registry
    if any(c in parts[0] for c in [".", ":"]):
        if parts[0] != "docker.io":
            return False

    return (
        len(parts) == 1 or
        parts[0] == "library" or
        (len(parts) > 1 and parts[1] == "library") or
        (len(parts) == 2 and parts[0] == "docker.io")
    )

def check_dockerfile_security(dockerfile_path):
    findings = []
    dfp = DockerfileParser()
    with open(dockerfile_path, "r") as f:
        dfp.content = f.read()

    # Check base image
    base_image = dfp.baseimage
    if not is_official_image(base_image):
        findings.append(f"Base image '{base_image}' is not an official image")

    # Check for non-root user
    if not any(cmd["instruction"] == "USER" for cmd in dfp.structure):
        findings.append("No non-root user specified - consider adding USER instruction")

    # Check package installations
    package_managers = [
        "apt-get install",
        "apk add",
        "yum install",
        "dnf install",
        "zypper install",
        "pip install",
        "pip3 install",
        "npm install",
        "gem install",
        "bundle install",
        "cargo install",
        "go get",
        "dotnet add",
        "pacman -S",
        "apk add --no-cache",
        "apt-get install -y",
        "python -m pip install",
        "poetry add"
    ]

    run_commands = [cmd["value"] for cmd in dfp.structure if cmd["instruction"] == "RUN"]
    detected_pms = set()
    packages_installed = []
    
    for cmd in run_commands:
        for pm in package_managers:
            if pm in cmd:
                pm_name = pm.split()[0].upper()
                detected_pms.add(pm_name)
                
                # Attempt to extract package names
                packages = re.findall(rf"{pm} (.*?)(?:\\|\n|$)", cmd)
                if packages:
                    packages_installed.extend(packages[0].split())

    if detected_pms:
        pm_list = ", ".join(detected_pms)
        findings.append(
            color_text(f"Package installations detected via: {pm_list}", "YELLOW") + 
            "\n    Installed packages: " + ", ".join(packages_installed)
        )

    # Check security options
    security_options = {
        "no-new-privileges": "--security-opt=no-new-privileges",
        "read-only": "--read-only"
    }
    for opt, flag in security_options.items():
        if not any(flag in cmd["value"] for cmd in dfp.structure if cmd["instruction"] == "RUN"):
            findings.append(f"Missing security option: {opt}")

    return {
        "file": str(dockerfile_path),
        "findings": findings,
        "base_image": base_image
    }

def check_compose_security(compose_path):
    findings = []
    dockerfile_paths = []
    with open(compose_path, "r") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})
    networks = compose.get("networks", {})

    # Analyze network definitions
    network_configs = {}
    for net_name, net_config in networks.items():
        config = {
            'internal': net_config.get('internal', False),
            'driver': net_config.get('driver', 'bridge'),
            'ipam': net_config.get('ipam', {}),
            'labels': net_config.get('labels', [])
        }
        network_configs[net_name] = config

    for service_name, service in services.items():
        service_findings = []
        
        # Network mode checks
        net_mode = service.get("network_mode")
        if net_mode == "host":
            service_findings.append(
                color_text("Host network mode used - breaks container isolation!", "RED")
            )

        # Port exposure analysis
        ports = service.get("ports", [])
        
        for port in ports:
            # Check for 0.0.0.0 exposure
            if isinstance(port, str) and "0.0.0.0" in port:
                service_findings.append(
                    f"Exposing port {port} to all interfaces - "
                    "consider binding to 127.0.0.1 instead"
                )

        # Network membership checks
        service_networks = service.get("networks", [])
        if not service_networks:
            service_findings.append("Using default network - create dedicated networks")

        for net_name in service_networks:
            net_config = network_configs.get(net_name, {})
            if not net_config.get('internal', False):
                service_findings.append(
                    f"Network '{net_name}' not marked as internal - "
                    "external access possible"
                )

        # Inter-service communication analysis
        depends_on = service.get("depends_on", [])
        if len(depends_on) > 0 and not service.get("links"):
            service_findings.append(
                "Service dependencies without explicit links - "
                "consider network segmentation"
            )

        # DNS and network security
        if service.get("dns", None):
            service_findings.append(
                "Custom DNS configured - verify DNSSEC settings"
            )

        # Network policy checks
        if "default" in service_networks and len(service_networks) == 1:
            service_findings.append(
                "Using default network without isolation - "
                "create service-specific networks"
            )
    
    for service_name, service in services.items():
        service_findings = []
        build_config = service.get("build", {})
        image = service.get("image", "")

        # Detect Dockerfiles from build configurations
        if build_config:
            context = build_config.get("context", ".")
            dockerfile = build_config.get("dockerfile", "Dockerfile")

            # Resolve absolute path to Dockerfile
            compose_dir = Path(compose_path).parent
            build_context = (compose_dir / context).resolve()
            df_path = (build_context / dockerfile).resolve()

            if df_path.exists():
                dockerfile_paths.append(str(df_path))
                service_findings.append(f"Using Dockerfile: {df_path}")
            else:
                service_findings.append(f"Missing Dockerfile: {df_path}")
        elif image is not None and image != "":
            if not is_official_image(image):
                findings.append(f"Image '{image}' is not an official image")

        # Image checks
        if not image and not build_config:
            service_findings.append("No image or build configuration specified")

        # Security permission checks
        if service.get("privileged", False):
            service_findings.append(color_text("Privileged mode enabled - extremely dangerous!", "RED"))

        # Capabilities analysis
        cap_add = service.get("cap_add", [])
        dangerous_caps = {
            'SYS_ADMIN', 'NET_ADMIN', 'SYS_MODULE', 'SYS_PTRACE',
            'NET_RAW', 'SYS_CHROOT', 'DAC_OVERRIDE', 'SETUID', 'SETGAC'
        }
        added_dangerous = [cap for cap in cap_add if cap in dangerous_caps]
        if added_dangerous:
            service_findings.append(
                color_text(f"Dangerous capabilities added: {', '.join(added_dangerous)}", "RED")
            )

        cap_drop = service.get("cap_drop", [])
        if 'ALL' not in cap_drop:
            service_findings.append("Not dropping ALL capabilities - consider cap_drop: [ALL]")

        # Security options hardening
        security_opts = service.get("security_opt", [])
        security_checks = {
            'no-new-privileges': "no-new-privileges",
            'seccomp': 'seccomp=',
            'apparmor': 'apparmor='
        }
        
        for opt, pattern in security_checks.items():
            if not any(pattern in val for val in security_opts):
                service_findings.append(f"Missing security_opt: {opt} hardening")

        # Filesystem protections
        if not service.get("read_only", False):
            service_findings.append("Filesystem not read-only - consider read_only: true")

        tmpfs_mounts = service.get("tmpfs", [])
        required_tmp_dirs = {'/tmp', '/run', '/var/tmp'}
        if not required_tmp_dirs.issubset(tmpfs_mounts):
            service_findings.append(
                "Missing tmpfs mounts for temporary directories - consider adding: " +
                ", ".join(required_tmp_dirs)
            )

        # Device restrictions
        if service.get("devices", []):
            service_findings.append("Host devices mounted - verify these are absolutely necessary")

        # Resource limitations
        if not service.get("deploy", {}).get("resources", {}).get("limits"):
            service_findings.append("No resource limits set - add memory/cpu constraints")

        # User namespace
        if not service.get("userns_mode"):
            service_findings.append("Consider using user namespace isolation with userns_mode")

        if service_findings:
            findings.append({
                "service": service_name,
                "findings": service_findings,
                "image": service.get("image", "")
            })

    # Network architecture checks
    if not any(net.get('internal', False) for net in networks.values()):
        findings.append({
            "service": "Global",
            "findings": [color_text("No internal networks defined - "
                                  "critical services might be exposed", "RED")],
            "image": ""
        })

    return {
        "file": str(compose_path),
        "services": findings,
        "dockerfiles": dockerfile_paths
    }

def generate_report(dockerfile_reports, compose_reports, trivy_results):
    report = []
    
    # Dockerfile findings
    report.append(color_text("\n[+] Dockerfile Security Checks", "BLUE"))
    for df in dockerfile_reports:
        report.append(f"\nDockerfile: {df['file']}")
        report.append(f"Base Image: {df['base_image']}")
        for finding in df["findings"]:
            report.append(color_text(f"  [!] {finding}", "YELLOW"))

    # Compose findings
    report.append(color_text("\n[+] Docker Compose Security Checks", "BLUE"))
    for comp in compose_reports:
        report.append(f"\nCompose File: {comp['file']}")
        for service in comp["services"]:
            report.append(f"\nService: {service['service']}")
            if service["image"]:
                report.append(f"Image: {service['image']}")
            for finding in service["findings"]:
                report.append(color_text(f"  [!] {finding}", "YELLOW"))

    # Vulnerability scan results
    report.append(color_text("\n[+] Vulnerability Scanning Results", "BLUE"))
    for image, result in trivy_results.items():
        report.append(f"\nImage: {image}")
        if "HIGH" in result or "CRITICAL" in result:
            report.append(color_text(result, "RED"))
        else:
            report.append(color_text("No high/critical vulnerabilities found", "GREEN"))

    return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Docker Security Scanner")
    parser.add_argument("-c", "--compose-files", nargs="+", help="Path to docker-compose files")
    parser.add_argument("-d", "--dockerfiles", nargs="+", help="Path to Dockerfiles")
    args = parser.parse_args()

    if not check_trivy_installed():
        print(color_text("Error: Trivy not installed or not in PATH", "RED"))
        sys.exit(1)

    # Process files
    dockerfile_reports = []
    compose_reports = []
    images = set()
    all_dockerfiles = set()

    # Collect Dockerfiles from compose files
    if args.compose_files:
        for cf in args.compose_files:
            compose_report = check_compose_security(cf)
            compose_reports.append(compose_report)
            all_dockerfiles.update(compose_report.get("dockerfiles", []))

    # Add explicitly specified Dockerfiles
    if args.dockerfiles:
        all_dockerfiles.update(args.dockerfiles)

    # Process all Dockerfiles
    for df in all_dockerfiles:
        report = check_dockerfile_security(df)
        dockerfile_reports.append(report)
        images.add(report["base_image"])

    # Process compose files for service checks
    if args.compose_files:
        for cf in args.compose_files:
            for service in compose_report["services"]:
                if service["image"]:
                    images.add(service["image"])

    # Run vulnerability scans
    trivy_results = {}
    vulns_found   = False 
    for image in images:
        print(f"Scanning {image} with Trivy...")
        is_vuln, trivy_results[image] = scan_image_with_trivy(image)
        if is_vuln:
            vulns_found = True

    # Generate final report
    print(generate_report(dockerfile_reports, compose_reports, trivy_results))

    if vulns_found or len(dockerfile_reports) > 0 or len(compose_reports) > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
