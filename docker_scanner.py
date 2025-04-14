import argparse
import subprocess
import sys
import re
from pathlib import Path
import yaml
from dockerfile_parse import DockerfileParser

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
        return result.stdout
    except subprocess.CalledProcessError as e:
        return e.stdout or e.stderr

def is_official_image(image):
    return (
        not ("/" in image.split(":")[0]) or 
        image.startswith("library/") or
        image.startswith("docker.io/library/")
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
    run_commands = [cmd["value"] for cmd in dfp.structure if cmd["instruction"] == "RUN"]
    for cmd in run_commands:
        if any(pkg in cmd for pkg in ["apt-get install", "apk add", "yum install"]):
            findings.append("Potential unnecessary packages installed - review installed packages")

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

        # Existing service checks [keep previous checks] ...
        # Image checks
        if not image and not build_config:
            service_findings.append("No image or build configuration specified")

        # Security options
        security_opts = service.get("security_opt", [])
        if "no-new-privileges" not in security_opts:
            service_findings.append("Missing security option: no-new-privileges")

        capabilities = service.get("cap_drop", [])
        if "ALL" not in capabilities:
            service_findings.append("Consider dropping ALL capabilities with cap_drop")

        # User context
        if not service.get("user"):
            service_findings.append("No user specified - running as root")

        # Networking
        networks = service.get("networks", [])
        if "default" in networks and len(networks) == 1:
            service_findings.append("Using default network - consider custom networks")

        ports = service.get("ports", [])
        for port in ports:
            if "0.0.0.0" in str(port):
                service_findings.append(f"Exposing port to all interfaces: {port}")

        if service_findings:
            findings.append({
                "service": service_name,
                "findings": service_findings,
                "image": image
            })

    return {
        "file": str(compose_path),
        "services": findings
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

    # General recommendations
    report.append(color_text("\n[+] General Recommendations", "BLUE"))
    report.append("- Consider implementing rootless Docker mode")
    report.append("- Use secrets management for sensitive data")
    report.append("- Regularly update base images and dependencies")
    report.append("- Implement image signing and verification")
    report.append("- Use healthchecks and resource constraints")

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
    for image in images:
        print(f"Scanning {image} with Trivy...")
        trivy_results[image] = scan_image_with_trivy(image)

    # Generate final report
    print(generate_report(dockerfile_reports, compose_reports, trivy_results))

if __name__ == "__main__":
    main()
