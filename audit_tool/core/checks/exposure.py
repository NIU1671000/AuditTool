import hashlib
import secrets
from urllib.parse import urljoin, urlparse, urlunparse

import requests


HEADERS = {
	"User-Agent": "audit-tool/0.1"
}

MAX_SAMPLE_BYTES = 8192


SENSITIVE_RESOURCES = [
	{
		"path": ".git/HEAD",
		"title": "Repositorio Git expuesto",
		"severity": "high",
		"indicators": ["ref: refs/heads/"],
		"description": "El fichero .git/HEAD es accesible desde HTTP/HTTPS, lo que indica una posible exposición del repositorio Git",
		"recommendation": "Bloquear el acceso al directorio .git desde el servidor web y revisar si el repositorio completo ha quedado expuesto"
	},
	{
		"path": ".git/config",
		"title": "Configuración interna de Git expuesta",
		"severity": "high",
		"indicators": ["repositoryformatversion", "[core]"],
		"description": "Se ha detectado acceso a ficheros internos del repositorio Git",
		"recommendation": "Impedir el acceso público a .git y eliminar cualquier repositorio expuesto del directorio web"
	},
	{
		"path": ".env",
		"title": "Fichero .env potencialmente expuesto",
		"severity": "high",
		"indicators": ["app_key=", "db_password=", "database_url=", "secret_key=", "aws_secret_access_key"],
		"description": "El fichero .env parece accesible públicamente y podría contener credenciales o secretos de configuración",
		"recommendation": "Mover el fichero fuera del directorio público, revocar secretos expuestos y bloquear su acceso desde el servidor web"
	},
	{
		"path": "web.config",
		"title": "Fichero web.config expuesto",
		"severity": "high",
		"indicators": ["<configuration", "<system.webserver", "<system.web>"],
		"description": "Se ha detectado un fichero web.config accesible desde HTTP/HTTPS",
		"recommendation": "Bloquear la descarga de ficheros de configuración y revisar que no contengan credenciales o rutas internas"
	},
	{
		"path": ".ssh/id_rsa",
		"title": "Clave privada SSH expuesta",
		"severity": "high",
		"indicators": ["begin openssh private key", "begin rsa private key", "begin private key"],
		"description": "Se ha detectado una posible clave privada SSH accesible públicamente",
		"recommendation": "Eliminar la clave expuesta, revocarla inmediatamente y generar una nueva"
	},
	{
		"path": ".htpasswd",
		"title": "Fichero .htpasswd expuesto",
		"severity": "high",
		"indicators": ["$apr1$", "{sha}", "$2y$"],
		"description": "Se ha detectado un posible fichero .htpasswd accesible públicamente",
		"recommendation": "Bloquear el acceso a ficheros .ht* y revisar si los hashes expuestos deben ser renovados"
	},
	{
		"path": "backup.zip",
		"title": "Archivo de copia de seguridad expuesto",
		"severity": "high",
		"binary_signatures": [(b"PK\x03\x04", "firma ZIP")],
		"content_type_indicators": ["application/zip", "application/octet-stream"],
		"description": "Se ha detectado un posible archivo de copia de seguridad accesible públicamente",
		"recommendation": "Eliminar backups del directorio público y almacenarlos en ubicaciones protegidas"
	},
	{
		"path": "backup.tar.gz",
		"title": "Archivo comprimido de copia de seguridad expuesto",
		"severity": "high",
		"binary_signatures": [(b"\x1f\x8b", "firma GZIP")],
		"content_type_indicators": ["application/gzip", "application/x-gzip", "application/octet-stream"],
		"description": "Se ha detectado un posible archivo comprimido de copia de seguridad accesible públicamente",
		"recommendation": "Eliminar backups del directorio público y aplicar controles de acceso"
	},
	{
		"path": "database.sql",
		"title": "Dump SQL expuesto",
		"severity": "high",
		"indicators": ["create table", "insert into", "mysql dump", "postgresql database dump"],
		"description": "Se ha detectado un posible volcado de base de datos accesible públicamente",
		"recommendation": "Eliminar dumps SQL del directorio público y rotar credenciales si contienen datos sensibles"
	}
]

DIRECTORY_LISTING_PATHS = [
    ".git/",
    "backup/",
    "backups/",
    "uploads/",
    "files/",
    "logs/",
    "tmp/",
]


def build_url(target: str) -> str:

	if target.startswith(("http://", "https://")):
		return target
	return f"https://{target}"

# Genera las bases de análisis a partir del dominio y, si existe, de la ruta indicada.
def build_scan_bases(target: str) -> list[str]:

	parsed = urlparse(build_url(target))

	if not parsed.netloc:
		raise ValueError("No se pudo extraer un host válido del objetivo")

	root_base = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
	bases = [root_base]

	path = parsed.path or "/"
	if path not in ("", "/"):
		if not path.endswith("/"):
			last_segment = path.rsplit("/", 1)[-1]

			if "." in last_segment:
				path = path.rsplit("/", 1)[0] + "/"
			else:
				path = path + "/"

		path_base = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

		if path_base not in bases:
			bases.append(path_base)

	return bases


def build_resource_url(base_url: str, resource_path: str) -> str:

	return urljoin(base_url, resource_path.lstrip("/"))

# Realiza una petición HTTP y solo descarga una muestra limitada del contenido.
def fetch_limited(url: str, timeout: int = 5):

	response = requests.get(
		url,
		headers=HEADERS,
		timeout=timeout,
		allow_redirects=True,
		stream=True
	)

	try:
		raw_sample = response.raw.read(MAX_SAMPLE_BYTES, decode_content=True) or b""
	finally:
		response.close()

	encoding = response.encoding or "utf-8"
	text_sample = raw_sample.decode(encoding, errors="replace")

	return response, raw_sample, text_sample


def normalize_text(text: str) -> str:

	return " ".join(text.split()).lower()[:2000]


def text_signature(text: str) -> str:
	normalized = normalize_text(text)
	return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

# Obtiene una respuesta inexistente para comparar falsos positivos del servidor.
def build_baseline(base_url: str, timeout: int = 5) -> dict | None:

	random_path = f"__audit_tool_not_found_{secrets.token_hex(8)}__"
	url = build_resource_url(base_url, random_path)

	response, _, text_sample = fetch_limited(url, timeout)

	return {
		"status_code": response.status_code,
		"signature": text_signature(text_sample)
	}

# Comprueba si una respuesta coincide con la página genérica de recurso no encontrado.
def looks_like_baseline(response, text_sample: str, baseline: dict | None) -> bool:
	if not baseline:
		return False

	return (
		response.status_code == baseline["status_code"]
		and text_signature(text_sample) == baseline["signature"]
	)


def is_successful_response(response) -> bool:
	return 200 <= response.status_code < 300

# Busca indicadores textuales asociados a un recurso sensible.
def find_text_indicators(text_sample: str, indicators: list[str]) -> list[str]:
	lower_text = text_sample.lower()
	matches = []

	for indicator in indicators:
		if indicator.lower() in lower_text:
			matches.append(indicator)

	return matches

# Busca firmas binarias al inicio de la muestra descargada.
def find_binary_indicators(raw_sample: bytes, signatures: list[tuple[bytes, str]]) -> list[str]:
	matches = []

	for signature, label in signatures:
		if raw_sample.startswith(signature):
			matches.append(label)

	return matches

# Comprueba si la cabecera Content-Type coincide con tipos esperados.
def find_content_type_indicators(response, indicators: list[str]) -> list[str]:
	content_type = response.headers.get("Content-Type", "").lower()
	matches = []

	for indicator in indicators:
		if indicator.lower() in content_type:
			matches.append(indicator)

	return matches

# Construye el texto de evidencia que se incluirá en el hallazgo.
def build_evidence(response, raw_sample: bytes, matches: list[str]) -> str:
	content_type = response.headers.get("Content-Type", "no indicado")
	content_length = response.headers.get("Content-Length")

	parts = [
		f"URL: {response.url}",
		f"Status code: {response.status_code}",
		f"Content-Type: {content_type}"
	]

	if content_length:
		parts.append(f"Content-Length: {content_length}")
	else:
		parts.append(f"Bytes analizados: {len(raw_sample)}")

	if matches:
		parts.append(f"Indicadores detectados: {', '.join(matches)}")

	return " | ".join(parts)

# Evalúa una respuesta y decide si representa un recurso sensible expuesto.
def evaluate_sensitive_resource(resource: dict, response, raw_sample: bytes, text_sample: str, baseline: dict | None) -> dict | None:
	if not is_successful_response(response):
		return None

	text_matches = find_text_indicators(
		text_sample,
		resource.get("indicators", [])
	)

	binary_matches = find_binary_indicators(
		raw_sample,
		resource.get("binary_signatures", [])
	)

	content_type_matches = find_content_type_indicators(
		response,
		resource.get("content_type_indicators", [])
	)

	all_matches = text_matches + binary_matches + content_type_matches

	if looks_like_baseline(response, text_sample, baseline):
		return None
	
	if content_type_matches and not text_matches and not binary_matches and len(raw_sample) < 512:
		return None

	if not all_matches:
		return None

	return {
		"title": resource["title"],
		"severity": resource["severity"],
		"description": resource["description"],
		"evidence": build_evidence(response, raw_sample, all_matches),
		"recommendation": resource["recommendation"]
	}

# Comprueba rutas comunes donde podría estar habilitado el listado de directorios.
def check_directory_listing(base_url: str, timeout: int = 5, baseline: dict | None = None) -> list[dict]:
	findings = []

	patterns = [
		"index of /",
		"<title>index of",
		"parent directory"
	]

	for path in DIRECTORY_LISTING_PATHS:
		url = build_resource_url(base_url, path)

		try:
			response, raw_sample, text_sample = fetch_limited(url, timeout)
		except requests.RequestException:
			continue

		if not is_successful_response(response):
			continue

		if looks_like_baseline(response, text_sample, baseline):
			continue

		lower_text = text_sample.lower()
		matches = [pattern for pattern in patterns if pattern in lower_text]

		if not matches:
			continue

		severity = "high" if path.startswith(".git") else "medium"

		findings.append({
			"title": "Listado de directorio habilitado",
			"severity": severity,
			"description": "El servidor parece permitir el listado de contenido de un directorio accesible públicamente",
			"evidence": build_evidence(response, raw_sample, matches),
			"recommendation": "Deshabilitar el directory listing y revisar si el directorio contiene información sensible"
		})

	return findings

# Analiza robots.txt para detectar referencias a rutas potencialmente sensibles.
def check_robots_txt(base_url: str, timeout: int = 5, baseline: dict | None = None) -> list[dict]:
	findings = []
	url = build_resource_url(base_url, "robots.txt")

	try:
		response, raw_sample, text_sample = fetch_limited(url, timeout)
	except requests.RequestException:
		return findings

	if not is_successful_response(response):
		return findings

	if looks_like_baseline(response, text_sample, baseline):
		return findings

	lower_text = text_sample.lower()

	if "user-agent:" not in lower_text or "disallow:" not in lower_text:
		return findings

	sensitive_terms = [
		".git",
		".env",
		"admin",
		"backup",
		"config",
		"db",
		"database",
		"private",
		"secret",
		"sql"
	]

	matches = sorted({
		term for term in sensitive_terms
		if term in lower_text
	})

	if matches:
		findings.append({
			"title": "robots.txt revela rutas potencialmente sensibles",
			"severity": "low",
			"description": "El fichero robots.txt contiene referencias a rutas que podrían revelar zonas internas o recursos sensibles",
			"evidence": build_evidence(response, raw_sample, matches),
			"recommendation": "Evitar usar robots.txt como mecanismo de ocultación de rutas sensibles y proteger dichas rutas con controles reales de acceso"
		})

	return findings

# Ejecuta la comprobación completa de exposición de recursos sensibles.
def run_exposure_check(target: str, timeout: int = 5) -> list[dict]:

	findings = []

	try:
		bases = build_scan_bases(target)
	except ValueError as exc:
		return [{
			"title": "Objetivo no válido para comprobación de exposición",
			"severity": "medium",
			"description": "No se pudo construir una URL válida para analizar recursos expuestos",
			"evidence": str(exc),
			"recommendation": "Introducir un dominio o URL válido, por ejemplo https://example.com"
		}]

	for base_url in bases:
		try:
			fetch_limited(base_url, timeout)
		except requests.Timeout:
			findings.append({
				"title": "Timeout en comprobación de exposición",
				"severity": "medium",
				"description": "La petición base excedió el tiempo de espera configurado",
				"evidence": f"URL: {base_url} | Timeout: {timeout}s",
				"recommendation": "Verificar la disponibilidad del servicio y repetir la comprobación"
			})
			continue
		except requests.RequestException as exc:
			findings.append({
				"title": "Error al comprobar exposición de recursos",
				"severity": "medium",
				"description": "No se pudo obtener una respuesta HTTP/HTTPS válida del objetivo",
				"evidence": f"URL: {base_url} | Error: {exc}",
				"recommendation": "Comprobar la URL, la conectividad y si el servicio responde correctamente"
			})
			continue

		try:
			baseline = build_baseline(base_url, timeout)
		except requests.RequestException:
			baseline = None

		for resource in SENSITIVE_RESOURCES:
			url = build_resource_url(base_url, resource["path"])

			try:
				response, raw_sample, text_sample = fetch_limited(url, timeout)
			except requests.RequestException:
				continue

			finding = evaluate_sensitive_resource(
				resource,
				response,
				raw_sample,
				text_sample,
				baseline
			)

			if finding:
				findings.append(finding)

		findings.extend(check_directory_listing(base_url, timeout, baseline))
		findings.extend(check_robots_txt(base_url, timeout, baseline))

	if not any(item.get("severity") in ("high", "medium", "low") for item in findings):
		findings.append({
			"title": "Sin exposición sensible evidente",
			"severity": "info",
			"description": "No se detectaron recursos sensibles expuestos con la lista de comprobaciones aplicada",
			"evidence": "No hubo coincidencias en las rutas candidatas analizadas",
			"recommendation": "Ampliar la lista de rutas según la tecnología usada por la aplicación y repetir la prueba en escenarios representativos"
		})

	return findings