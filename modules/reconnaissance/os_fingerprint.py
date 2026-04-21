import ipaddress
import socket
import nmap


def _is_ip(value: str) -> bool:
	try:
		ipaddress.ip_address(value)
		return True
	except ValueError:
		return False


def _resolve_target_ip(target: str) -> str | None:
	if _is_ip(target):
		return target

	try:
		return socket.gethostbyname(target)
	except socket.gaierror:
		return None


def os_fingerprint_lookup(target: str, arguments: str = "-O --max-os-tries 1 --host-timeout 30s") -> dict:
	target_ip = _resolve_target_ip(target)
	if not target_ip:
		return {
			"domain": None if _is_ip(target) else target,
			"ip": None,
			"source": "nmap_os_fingerprint",
			"os_matches": [],
			"error": "Unable to resolve target IP",
		}

	scanner = nmap.PortScanner()
	try:
		scan_result = scanner.scan(target_ip, arguments=arguments)
	except Exception as exc:
		return {
			"domain": None if _is_ip(target) else target,
			"ip": target_ip,
			"source": "nmap_os_fingerprint",
			"os_matches": [],
			"error": str(exc),
		}

	host_data = scan_result.get("scan", {}).get(target_ip, {})
	matches = host_data.get("osmatch", []) or []

	normalized_matches = []
	for match in matches:
		normalized_matches.append(
			{
				"name": match.get("name"),
				"accuracy": match.get("accuracy"),
				"line": match.get("line"),
				"osclass": match.get("osclass", []),
			}
		)

	return {
		"domain": None if _is_ip(target) else target,
		"ip": target_ip,
		"source": "nmap_os_fingerprint",
		"os_matches": normalized_matches,
	}


if __name__ == "__main__":
	result = os_fingerprint_lookup("192.168.1.1")
	print(result)
	result = os_fingerprint_lookup("uca.ac.ma")
	print(result)