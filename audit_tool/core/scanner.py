from audit_tool.core.checks import run_headers_check, run_tls_check, run_exposure_check

# Coordina la ejecución de los distintos módulos de análisis.
class Scanner:

  
	def __init__(self, timeout: int = 5):


		self.timeout = timeout

	def scan(self, target: str, module: str = "all") -> dict:
		"""
		Ejecuta uno o varios módulos de análisis sobre el objetivo indicado.

		Args:
			target: URL o dominio objetivo.
			module: Módulo a ejecutar ("headers", "tls", "exposure" o "all").

		Returns:
			Diccionario con el objetivo, módulo ejecutado, hallazgos y errores.
		"""
		findings = []
		errors = []


		checks = {
			"headers": run_headers_check,
			"tls": run_tls_check,
			"exposure": run_exposure_check,
		}
		

		if module == "all":
			modules_to_run = list(checks.keys())
		else:
			modules_to_run = [module]


		for module_name in modules_to_run:
			check_function = checks.get(module_name)


			if check_function is None:
				errors.append(f"Módulo no reconocido: {module_name}")
				continue

			try:

				result = check_function(target, self.timeout)


				if result is None:
					continue


				if isinstance(result, list):
					findings.extend(result)
				else:
					errors.append(
						f"El módulo '{module_name}' no devolvió una lista de hallazgos"
					)
			except Exception as exc:

				errors.append(f"Error en el módulo '{module_name}': {exc}")


		return {
			"target": target,
			"module": module,
			"findings": findings,
			"errors": errors,
		}