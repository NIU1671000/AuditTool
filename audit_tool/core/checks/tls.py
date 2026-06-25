import os
import socket
import ssl
import tempfile
from datetime import UTC, datetime
from urllib.parse import urlparse

EXPIRY_WARNING_DAYS = 30

def normalize_target(target: str) -> str:

	if not target.startswith(("http://", "https://")):
		target = f"https://{target}"

	parsed = urlparse(target)
	host = parsed.hostname

	if not host:
		raise ValueError("No se pudo extraer un host válido del objetivo")

	return host


def is_port_open(host: str, port: int, timeout: int = 5) -> bool:

	try:
		with socket.create_connection((host, port), timeout=timeout):
			return True
	except Exception:
		return False


def extract_name_parts(name_field: tuple) -> list[str]:

	parts = []

	for item in name_field:
		for key, value in item:
			parts.append(f"{key}={value}")

	return parts

# Evalúa si el cipher negociado contiene indicadores de cifrados débiles.
def check_negotiated_cipher(cipher: tuple | None) -> list[dict]:

	findings = []

	if not cipher:
		return findings

	cipher_name = cipher[0].upper()
	weak_indicators = ["RC4", "3DES", "DES", "MD5", "NULL"]
	weak_found = [item for item in weak_indicators if item in cipher_name]

	if weak_found:
		findings.append({
			"title": "Cipher negociado potencialmente débil",
			"severity": "high",
			"description": "La conexión TLS negoció un cifrado considerado débil o no recomendado",
			"evidence": f"Cipher: {cipher[0]}",
			"recommendation": "Deshabilitar suites criptográficas obsoletas o débiles"
		})
	else:
		findings.append({
			"title": "Cipher negociado sin indicadores débiles evidentes",
			"severity": "info",
			"description": "No se detectaron patrones típicos de debilidad en el cipher negociado",
			"evidence": f"Cipher: {cipher[0]}",
			"recommendation": "Revisar también el conjunto completo de suites soportadas si se desea un análisis más exhaustivo"
		})

	return findings

# Extrae información del sujeto del certificado presentado por el servidor.
def check_certificate_subject(cert: dict, port: int, validated: bool = True) -> list[dict]:

	findings = []

	subject = cert.get("subject", ())
	subject_parts = extract_name_parts(subject)

	if subject_parts:
		findings.append({
			"title": "Información del certificado" if validated else "Información del certificado no validado",
			"severity": "info",
			"description": (
				f"Se obtuvo información básica del certificado presentado por el servidor en el puerto {port}"
				if validated
				else "Se obtuvo información del certificado aunque su validación falló"
			),
			"evidence": f"Subject: {', '.join(subject_parts)}",
			"recommendation": (
				"Comprobar que el certificado corresponde al dominio esperado"
				if validated
				else "Revisar si el certificado es autofirmado o no confiable"
			)
		})

	return findings

# Extrae información del emisor del certificado TLS.
def check_certificate_issuer(cert: dict) -> list[dict]:

	findings = []

	issuer = cert.get("issuer", ())
	issuer_parts = extract_name_parts(issuer)

	if issuer_parts:
		findings.append({
			"title": "Información del emisor del certificado",
			"severity": "info",
			"description": "Se obtuvo información básica del emisor del certificado",
			"evidence": f"Issuer: {', '.join(issuer_parts)}",
			"recommendation": "Comprobar que el certificado fue emitido por una entidad de confianza"
		})

	return findings

# Comprueba si el certificado está expirado o próximo a expirar.
def check_certificate_expiry(cert: dict, port: int, validated: bool = True, validation_error: str | None = None, warning_days: int = EXPIRY_WARNING_DAYS) -> list[dict]:


	findings = []

	not_after = cert.get("notAfter")
	if not not_after:
		return findings

	try:
		expiry_date = datetime.strptime(
			not_after,
			"%b %d %H:%M:%S %Y %Z"
		).replace(tzinfo=UTC)
	except ValueError:
		return findings

	now = datetime.now(UTC)
	days_left = (expiry_date - now).days

	if expiry_date < now:
		findings.append({
			"title": "Certificado expirado",
			"severity": "high",
			"description": (
				f"El certificado TLS del servidor en el puerto {port} está expirado"
				if validated
				else f"No se pudo validar el certificado TLS del servidor en el puerto {port} porque está expirado"
			),
			"evidence": (
				f"Fecha de expiración: {expiry_date.isoformat()}"
				if validated or not validation_error
				else f"{validation_error} | Fecha de expiración: {expiry_date.isoformat()}"
			),
			"recommendation": "Renovar inmediatamente el certificado digital"
		})
		return findings

	if days_left <= warning_days:
		findings.append({
			"title": "Proximidad de expiración del certificado",
			"severity": "medium",
			"description": (
				f"El certificado TLS del servidor en el puerto {port} expirará pronto"
				if validated
				else "El certificado no superó la validación y además expirará pronto"
			),
			"evidence": f"Fecha de expiración: {expiry_date.isoformat()} | Días restantes: {days_left}",
			"recommendation": "Planificar la renovación del certificado antes de su vencimiento"
		})
		return findings

	if validated:
		findings.append({
			"title": "Certificado vigente",
			"severity": "info",
			"description": f"El certificado TLS del servidor en el puerto {port} no está expirado",
			"evidence": f"Fecha de expiración: {expiry_date.isoformat()} | Días restantes: {days_left}",
			"recommendation": "Supervisar la fecha de expiración y renovar antes de su vencimiento"
		})

	return findings

# Intenta obtener el certificado aunque no supere la validación de confianza.
def get_certificate_without_validation(host: str, port: int, timeout: int = 5) -> dict | None:

	try:
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE

		with socket.create_connection((host, port), timeout=timeout) as sock:
			with context.wrap_socket(sock, server_hostname=host) as tls_sock:
				der_cert = tls_sock.getpeercert(binary_form=True)

		if not der_cert:
			return None

		pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)

		with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w", encoding="utf-8") as tmp:
			tmp.write(pem_cert)
			tmp_path = tmp.name

		try:
			return ssl._ssl._test_decode_cert(tmp_path)
		finally:
			try:
				os.unlink(tmp_path)
			except OSError:
				pass

	except Exception:
		return None

# Prueba si el servidor acepta una versión TLS concreta.
def try_tls_version(host: str, port: int, tls_version: ssl.TLSVersion, timeout: int = 5) -> bool:

	try:
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		context.minimum_version = tls_version
		context.maximum_version = tls_version

		with socket.create_connection((host, port), timeout=timeout) as sock:
			with context.wrap_socket(sock, server_hostname=host):
				return True
	except Exception:
		return False

# Comprueba qué versiones de TLS acepta el servidor.
def check_supported_tls_versions(host: str, port: int = 443, timeout: int = 5) -> list[dict]:

	findings = []

	versions_to_test = [
		("TLS 1.0", ssl.TLSVersion.TLSv1),
		("TLS 1.1", ssl.TLSVersion.TLSv1_1),
		("TLS 1.2", ssl.TLSVersion.TLSv1_2),
	]

	if hasattr(ssl.TLSVersion, "TLSv1_3"):
		versions_to_test.append(("TLS 1.3", ssl.TLSVersion.TLSv1_3))

	for version_name, version_value in versions_to_test:
		supported = try_tls_version(host, port, version_value, timeout)

		if supported:
			severity = "high" if version_name in ("TLS 1.0", "TLS 1.1") else "info"
			recommendation = (
				"Deshabilitar versiones antiguas e inseguras"
				if version_name in ("TLS 1.0", "TLS 1.1")
				else "Mantener únicamente versiones modernas si es posible"
			)

			findings.append({
				"title": f"Soporte de {version_name}",
				"severity": severity,
				"description": f"El servidor acepta {version_name}",
				"evidence": f"{host}:{port} acepta {version_name}",
				"recommendation": recommendation
			})

	if not findings:
		findings.append({
			"title": "No se pudo determinar soporte de versiones TLS",
			"severity": "medium",
			"description": "No fue posible confirmar qué versiones TLS acepta el servidor",
			"evidence": f"Host: {host} | Puerto: {port}",
			"recommendation": "Revisar manualmente la configuración TLS del servicio"
		})

	return findings

# Realiza la comprobación TLS principal sobre un puerto concreto.
def check_tls_on_port(host: str, port: int, timeout: int = 5) -> list[dict]:

	findings = []

	try:
		context = ssl.create_default_context()

		with socket.create_connection((host, port), timeout=timeout) as sock:
			with context.wrap_socket(sock, server_hostname=host) as tls_sock:
				cert = tls_sock.getpeercert()
				tls_version = tls_sock.version()
				cipher = tls_sock.cipher()

				findings.append({
					"title": "Conexión TLS establecida",
					"severity": "info",
					"description": f"Se ha podido establecer una conexión TLS con el objetivo en el puerto {port}",
					"evidence": f"Puerto: {port} | Versión TLS negociada: {tls_version} | Cipher: {cipher[0] if cipher else 'desconocido'}",
					"recommendation": "Verificar que la versión y los cifrados negociados cumplen las políticas de seguridad"
				})

				findings.extend(check_negotiated_cipher(cipher))
				findings.extend(check_certificate_subject(cert, port, validated=True))
				findings.extend(check_certificate_issuer(cert))
				findings.extend(check_certificate_expiry(cert, port, validated=True))

	except ssl.SSLCertVerificationError as exc:
		cert = get_certificate_without_validation(host, port, timeout)

		if cert:
			expiry_findings = check_certificate_expiry(
				cert,
				port,
				validated=False,
				validation_error=str(exc)
			)
			findings.extend(expiry_findings)

			if not expiry_findings:
				findings.append({
					"title": "Fallo de validación del certificado",
					"severity": "high",
					"description": f"No se pudo validar el certificado TLS del servidor en el puerto {port}",
					"evidence": str(exc),
					"recommendation": "Revisar la cadena de confianza, el CN/SAN y la validez del certificado"
				})

			findings.extend(check_certificate_subject(cert, port, validated=False))
			findings.extend(check_certificate_issuer(cert))
		else:
			findings.append({
				"title": "Fallo de validación del certificado",
				"severity": "high",
				"description": f"No se pudo validar el certificado TLS del servidor en el puerto {port}",
				"evidence": str(exc),
				"recommendation": "Revisar la cadena de confianza, el CN/SAN y la validez del certificado"
			})

	except ssl.SSLError as exc:
		findings.append({
			"title": "Error TLS",
			"severity": "high",
			"description": f"Se produjo un error durante el handshake TLS en el puerto {port}",
			"evidence": str(exc),
			"recommendation": "Revisar la configuración TLS del servidor y la compatibilidad de protocolos/cifrados"
		})

	except socket.timeout:
		findings.append({
			"title": "Timeout en conexión TLS",
			"severity": "medium",
			"description": f"La conexión TLS al puerto {port} excedió el tiempo de espera",
			"evidence": f"Timeout configurado: {timeout}s",
			"recommendation": "Verificar disponibilidad del servicio y conectividad de red"
		})

	except Exception as exc:
		findings.append({
			"title": "Error general en comprobación TLS",
			"severity": "medium",
			"description": f"Se produjo un error no controlado durante la comprobación TLS en el puerto {port}",
			"evidence": str(exc),
			"recommendation": "Revisar el objetivo introducido y la lógica del módulo TLS"
		})

	return findings

# Ejecuta el análisis TLS completo sobre el objetivo indicado.
def run_tls_check(target: str, timeout: int = 5) -> list[dict]:

	findings = []
	host = normalize_target(target)

	port_80_open = is_port_open(host, 80, timeout)
	port_443_open = is_port_open(host, 443, timeout)


	if port_80_open and port_443_open:
		findings.append({
			"title": "Servicios web HTTP y HTTPS disponibles",
			"severity": "info",
			"description": "El objetivo expone servicios web en los puertos 80 y 443",
			"evidence": f"{host}:80 accesible | {host}:443 accesible",
			"recommendation": "Comprobar si el tráfico HTTP redirige correctamente a HTTPS"
		})
	elif port_80_open and not port_443_open:
		findings.append({
			"title": "Servicio web sin HTTPS disponible",
			"severity": "medium",
			"description": "El objetivo expone HTTP en el puerto 80, pero no ofrece HTTPS en el puerto 443",
			"evidence": f"{host}:80 accesible | {host}:443 no accesible",
			"recommendation": "Habilitar HTTPS en el puerto 443 y redirigir el tráfico HTTP a HTTPS"
		})
	elif not port_80_open and port_443_open:
		findings.append({
			"title": "Servicio HTTPS disponible",
			"severity": "info",
			"description": "El objetivo expone servicio HTTPS en el puerto 443, pero no se detectó servicio HTTP en el puerto 80",
			"evidence": f"{host}:80 no accesible | {host}:443 accesible",
			"recommendation": "Verificar si la exposición únicamente por HTTPS es la configuración esperada"
		})
	else:
		findings.append({
			"title": "Puertos web no accesibles",
			"severity": "info",
			"description": "No se detectó accesibilidad en los puertos 80 ni 443 del objetivo",
			"evidence": f"{host}:80 no accesible | {host}:443 no accesible",
			"recommendation": "Verificar si el servicio debería estar expuesto"
		})

	if port_443_open:
		findings.extend(check_tls_on_port(host, 443, timeout))
		findings.extend(check_supported_tls_versions(host, 443, timeout))

	return findings
