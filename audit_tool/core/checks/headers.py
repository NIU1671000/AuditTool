import requests
from urllib.parse import urlparse, urlunparse

# Construye una URL forzando el esquema http:// a partir del objetivo recibido.
def build_http_url(target: str) -> str:

	parsed = urlparse(build_url(target))
	return urlunparse((
		"http",
		parsed.netloc,
		parsed.path or "",
		parsed.params or "",
		parsed.query or "",
		parsed.fragment or "",
	))


def build_url(target: str) -> str:

	if target.startswith(("http://", "https://")):
		return target
	return f"https://{target}"


def extract_host(target: str) -> str:

	parsed = urlparse(build_url(target))
	host = parsed.hostname

	if not host:
		raise ValueError("No se pudo extraer un host válido del objetivo")

	return host


def normalize_host(host: str | None) -> str:

	if not host:
		return ""
	host = host.lower()
	if host.startswith("www."):
		return host[4:]
	return host

# Comprueba si el servicio HTTP redirige automáticamente hacia HTTPS.
def check_http_to_https_redirect(target: str, timeout: int = 5) -> list[dict]:

	findings = []
	http_url = build_http_url(target)

	try:
		response = requests.get(http_url, timeout=timeout, allow_redirects=False)
		status_code = response.status_code
		location = response.headers.get("Location", "")

		if status_code in (301, 302, 307, 308) and location.lower().startswith("https://"):
			findings.append({
				"title": "Redirección de HTTP a HTTPS detectada",
				"severity": "info",
				"description": "El servicio redirige peticiones HTTP hacia HTTPS",
				"evidence": f"URL inicial: {http_url} | Status code: {status_code} | Location: {location}",
				"recommendation": "Mantener esta configuración para reducir el uso de HTTP sin cifrar"
			})
		else:
			findings.append({
				"title": "Sin redirección de HTTP a HTTPS",
				"severity": "medium",
				"description": "No se observó una redirección automática de HTTP a HTTPS",
				"evidence": f"URL inicial: {http_url} | Status code: {status_code}",
				"recommendation": "Redirigir automáticamente todo el tráfico HTTP hacia HTTPS"
			})

	except requests.Timeout:
		findings.append({
			"title": "Timeout al comprobar redirección HTTP a HTTPS",
			"severity": "medium",
			"description": "La comprobación de redirección excedió el tiempo de espera",
			"evidence": f"URL: {http_url} | Timeout: {timeout}s",
			"recommendation": "Verificar la disponibilidad del servicio HTTP"
		})

	except requests.RequestException as exc:
		findings.append({
			"title": "Error al comprobar redirección HTTP a HTTPS",
			"severity": "medium",
			"description": "No se pudo verificar si el servicio redirige de HTTP a HTTPS",
			"evidence": str(exc),
			"recommendation": "Comprobar la conectividad y la respuesta del servicio en HTTP"
		})

	return findings

# Determina si el dominio observado pertenece al dominio original o a uno de sus subdominios.
def is_same_domain_or_subdomain(original_host: str, observed_host: str) -> bool:

	original = normalize_host(original_host)
	observed = normalize_host(observed_host)

	return observed == original or observed.endswith("." + original)

# Detecta si la cadena de redirecciones termina en un dominio externo.
def check_cross_domain_redirects(responses, target: str) -> list[dict]:

	findings = []
	original_host = extract_host(target)

	for response in responses:
		response_host = urlparse(response.url).hostname

		if response_host and not is_same_domain_or_subdomain(original_host, response_host):
			findings.append({
				"title": "Redirección hacia dominio externo detectada",
				"severity": "medium",
				"description": "La cadena de redirecciones alcanza un dominio distinto al dominio original o a uno de sus subdominios",
				"evidence": f"Dominio original: {original_host} | URL observada: {response.url}",
				"recommendation": "Verificar si la redirección externa es intencionada y forma parte del servicio esperado"
			})
			return findings

	return findings

# Comprueba si alguna respuesta HTTPS incluye la cabecera HSTS.
def check_hsts(responses) -> list[dict]:

	findings = []
	https_responses = []

	for response in responses:
		if response.url.startswith("https://"):
			https_responses.append(response)

	if not https_responses:
		findings.append({
			"title": "HSTS no evaluable sobre HTTP",
			"severity": "info",
			"description": "La cabecera Strict-Transport-Security solo aplica a respuestas servidas por HTTPS",
			"evidence": "No se observaron respuestas HTTPS en la cadena analizada",
			"recommendation": "Comprobar HSTS sobre la versión HTTPS del servicio"
		})
		return findings

	for response in https_responses:
		hsts = response.headers.get("Strict-Transport-Security")

		if hsts:
			findings.append({
				"title": "Cabecera HSTS presente",
				"severity": "info",
				"description": "Se detectó la cabecera Strict-Transport-Security en una respuesta HTTPS",
				"evidence": f"URL: {response.url} | Strict-Transport-Security: {hsts}",
				"recommendation": "Revisar que la política HSTS esté correctamente configurada"
			})
			return findings

	findings.append({
		"title": "Cabecera HSTS no observada",
		"severity": "medium",
		"description": "No se observó Strict-Transport-Security en ninguna de las respuestas HTTPS analizadas",
		"evidence": "Strict-Transport-Security no presente en la cadena HTTPS",
		"recommendation": "Añadir HSTS para forzar el uso de HTTPS en clientes compatibles"
	})

	return findings

# Comprueba la presencia de la cabecera Content-Security-Policy.
def check_csp(responses, response_may_be_blocked: bool = False) -> list[dict]:

	findings = []

	for response in responses:
		csp = response.headers.get("Content-Security-Policy")

		if csp:
			findings.append({
				"title": "Cabecera CSP presente",
				"severity": "info",
				"description": "Se detectó la cabecera Content-Security-Policy en una respuesta",
				"evidence": f"URL: {response.url} | Content-Security-Policy: {csp}",
				"recommendation": "Revisar que la política CSP limite correctamente scripts, estilos y otros recursos"
			})
			return findings

	if response_may_be_blocked:
		findings.append({
			"title": "Cabecera CSP no observada en respuesta bloqueada o de error",
			"severity": "info",
			"description": "No se observó Content-Security-Policy en las respuestas analizadas, pero la respuesta final parece corresponder a una página de bloqueo o error y puede no representar la configuración real del servicio",
			"evidence": "Content-Security-Policy no presente en la cadena de respuestas analizadas",
			"recommendation": "Repetir la prueba en una respuesta no bloqueada antes de concluir que la aplicación no utiliza CSP"
		})
	else:
		findings.append({
			"title": "Cabecera CSP no observada",
			"severity": "medium",
			"description": "No se observó Content-Security-Policy en ninguna de las respuestas analizadas",
			"evidence": "Content-Security-Policy no presente en la cadena",
			"recommendation": "Definir una política CSP para limitar el origen de scripts, estilos y otros recursos"
		})

	return findings

# Comprueba si existe una cabecera X-Frame-Options con un valor restrictivo.
def check_x_frame_options(responses, response_may_be_blocked: bool = False) -> list[dict]:

	findings = []

	for response in responses:
		x_frame_options = response.headers.get("X-Frame-Options")

		if x_frame_options:
			value = x_frame_options.strip().upper()

			if value in ("DENY", "SAMEORIGIN"):
				findings.append({
					"title": "Cabecera X-Frame-Options presente",
					"severity": "info",
					"description": "Se detectó la cabecera X-Frame-Options con un valor restrictivo",
					"evidence": f"URL: {response.url} | X-Frame-Options: {x_frame_options}",
					"recommendation": "Mantener esta configuración mientras siga siendo compatible con la aplicación"
				})
			else:
				findings.append({
					"title": "Cabecera X-Frame-Options con valor no recomendado",
					"severity": "low",
					"description": "Se detectó la cabecera X-Frame-Options, pero su valor no es el habitual para hardening",
					"evidence": f"URL: {response.url} | X-Frame-Options: {x_frame_options}",
					"recommendation": "Usar un valor restrictivo como DENY o SAMEORIGIN según las necesidades de la aplicación"
				})

			return findings

	if response_may_be_blocked:
		findings.append({
			"title": "Cabecera X-Frame-Options no observada en respuesta bloqueada o de error",
			"severity": "info",
			"description": "No se observó X-Frame-Options en las respuestas analizadas, pero la respuesta final parece corresponder a una página de bloqueo o error y puede no representar la configuración real del servicio",
			"evidence": "X-Frame-Options no presente en la cadena de respuestas analizadas",
			"recommendation": "Repetir la prueba en una respuesta no bloqueada antes de concluir que la aplicación no utiliza esta cabecera"
		})
	else:
		findings.append({
			"title": "Cabecera X-Frame-Options no observada",
			"severity": "medium",
			"description": "No se observó X-Frame-Options en ninguna de las respuestas analizadas",
			"evidence": "X-Frame-Options no presente en la cadena",
			"recommendation": "Añadir X-Frame-Options para reducir el riesgo de clickjacking"
		})

	return findings

# Comprueba si la cabecera X-Content-Type-Options usa el valor nosniff.
def check_x_content_type_options(responses, response_may_be_blocked: bool = False) -> list[dict]:

	findings = []

	for response in responses:
		x_content_type_options = response.headers.get("X-Content-Type-Options")

		if x_content_type_options:
			value = x_content_type_options.strip().lower()

			if value == "nosniff":
				findings.append({
					"title": "Cabecera X-Content-Type-Options presente",
					"severity": "info",
					"description": "Se detectó la cabecera X-Content-Type-Options con el valor recomendado",
					"evidence": f"URL: {response.url} | X-Content-Type-Options: {x_content_type_options}",
					"recommendation": "Mantener esta configuración para reducir el riesgo de content sniffing"
				})
			else:
				findings.append({
					"title": "Cabecera X-Content-Type-Options con valor no recomendado",
					"severity": "low",
					"description": "Se detectó la cabecera X-Content-Type-Options, pero su valor no es el esperado",
					"evidence": f"URL: {response.url} | X-Content-Type-Options: {x_content_type_options}",
					"recommendation": "Usar el valor nosniff"
				})

			return findings

	if response_may_be_blocked:
		findings.append({
			"title": "Cabecera X-Content-Type-Options no observada en respuesta bloqueada o de error",
			"severity": "info",
			"description": "No se observó X-Content-Type-Options en las respuestas analizadas, pero la respuesta final puede no representar la configuración real del servicio",
			"evidence": "X-Content-Type-Options no presente en la cadena de respuestas analizadas",
			"recommendation": "Repetir la prueba en una respuesta no bloqueada antes de concluir que la aplicación no utiliza esta cabecera"
		})
	else:
		findings.append({
			"title": "Cabecera X-Content-Type-Options no observada",
			"severity": "medium",
			"description": "No se observó X-Content-Type-Options en ninguna de las respuestas analizadas",
			"evidence": "X-Content-Type-Options no presente en la cadena",
			"recommendation": "Añadir X-Content-Type-Options con el valor nosniff"
		})

	return findings

# Comprueba si el servidor define una política de envío del encabezado Referer.
def check_referrer_policy(responses, response_may_be_blocked: bool = False) -> list[dict]:

	findings = []

	for response in responses:
		referrer_policy = response.headers.get("Referrer-Policy")

		if referrer_policy:
			findings.append({
				"title": "Cabecera Referrer-Policy presente",
				"severity": "info",
				"description": "Se detectó la cabecera Referrer-Policy en una respuesta",
				"evidence": f"URL: {response.url} | Referrer-Policy: {referrer_policy}",
				"recommendation": "Revisar que el valor configurado limite adecuadamente la información enviada en el encabezado Referer"
			})
			return findings

	if response_may_be_blocked:
		findings.append({
			"title": "Cabecera Referrer-Policy no observada en respuesta bloqueada o de error",
			"severity": "info",
			"description": "No se observó Referrer-Policy en las respuestas analizadas, pero la respuesta final puede no representar la configuración real del servicio",
			"evidence": "Referrer-Policy no presente en la cadena de respuestas analizadas",
			"recommendation": "Repetir la prueba en una respuesta no bloqueada antes de concluir que la aplicación no utiliza esta cabecera"
		})
	else:
		findings.append({
			"title": "Cabecera Referrer-Policy no observada",
			"severity": "low",
			"description": "No se observó Referrer-Policy en ninguna de las respuestas analizadas",
			"evidence": "Referrer-Policy no presente en la cadena",
			"recommendation": "Añadir Referrer-Policy para controlar la información enviada en el encabezado Referer"
		})

	return findings

# Comprueba si existe una política para restringir funcionalidades del navegador.
def check_permissions_policy(responses, response_may_be_blocked: bool = False) -> list[dict]:

	findings = []

	for response in responses:
		permissions_policy = response.headers.get("Permissions-Policy")

		if permissions_policy:
			findings.append({
				"title": "Cabecera Permissions-Policy presente",
				"severity": "info",
				"description": "Se detectó la cabecera Permissions-Policy en una respuesta",
				"evidence": f"URL: {response.url} | Permissions-Policy: {permissions_policy}",
				"recommendation": "Revisar que la política limite correctamente el acceso a funcionalidades del navegador"
			})
			return findings

	if response_may_be_blocked:
		findings.append({
			"title": "Cabecera Permissions-Policy no observada en respuesta bloqueada o de error",
			"severity": "info",
			"description": "No se observó Permissions-Policy en las respuestas analizadas, pero la respuesta final puede no representar la configuración real del servicio",
			"evidence": "Permissions-Policy no presente en la cadena de respuestas analizadas",
			"recommendation": "Repetir la prueba en una respuesta no bloqueada antes de concluir que la aplicación no utiliza esta cabecera"
		})
	else:
		findings.append({
			"title": "Cabecera Permissions-Policy no observada",
			"severity": "low",
			"description": "No se observó Permissions-Policy en ninguna de las respuestas analizadas",
			"evidence": "Permissions-Policy no presente en la cadena",
			"recommendation": "Añadir Permissions-Policy para restringir el acceso a capacidades del navegador que no sean necesarias"
		})

	return findings

# Ejecuta el análisis completo de cabeceras HTTP sobre el objetivo indicado.
def run_headers_check(target: str, timeout: int = 5) -> list[dict]:

	findings = []

	url = build_url(target)

	try:
	
		final_response = requests.get(url, timeout=timeout, allow_redirects=True)
		responses = final_response.history + [final_response]

		findings.append({
			"title": "Respuesta HTTP recibida",
			"severity": "info",
			"description": "Se obtuvo una respuesta del objetivo para analizar sus cabeceras",
			"evidence": f"URL: {final_response.url} | Status code: {final_response.status_code}",
			"recommendation": "Usar esta evidencia como contexto para interpretar el resto de hallazgos"
		})


		if target.startswith("http://"):
			findings.extend(check_http_to_https_redirect(target, timeout))


		response_may_be_blocked = final_response.status_code >= 400 or final_response.status_code == 202


		findings.extend(check_hsts(responses))
		findings.extend(check_csp(responses, response_may_be_blocked))
		findings.extend(check_x_frame_options(responses, response_may_be_blocked))
		findings.extend(check_x_content_type_options(responses, response_may_be_blocked))
		findings.extend(check_referrer_policy(responses, response_may_be_blocked))
		findings.extend(check_permissions_policy(responses, response_may_be_blocked))
		findings.extend(check_cross_domain_redirects(responses, target))



	except requests.Timeout:
		findings.append({
			"title": "Timeout en comprobación de cabeceras HTTP",
			"severity": "medium",
			"description": "La petición HTTP excedió el tiempo de espera configurado",
			"evidence": f"Timeout configurado: {timeout}s",
			"recommendation": "Verificar la disponibilidad del servicio y repetir la comprobación"
		})

	except requests.RequestException as exc:
		findings.append({
			"title": "Error al obtener cabeceras HTTP",
			"severity": "medium",
			"description": "No se pudo recuperar una respuesta HTTP/HTTPS válida del objetivo",
			"evidence": str(exc),
			"recommendation": "Comprobar la URL, la conectividad y si el servicio responde correctamente"
		})

	return findings