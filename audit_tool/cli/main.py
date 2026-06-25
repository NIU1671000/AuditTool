import argparse
from audit_tool.core import Scanner
from pathlib import Path
from audit_tool.report import (
	save_json_report,
	save_html_report,
	build_default_report_filename,
)

# Construye el parser de argumentos de la herramienta CLI.
def build_parser():

	parser = argparse.ArgumentParser(
		prog="audit-tool",
		description="Herramienta de auditoría técnica y hardening para servicios y aplicaciones web"
	)

	parser.add_argument(
		"target",
		help="URL o dominio objetivo, por ejemplo: https://example.com"
	)

	parser.add_argument(
		"--module",
		choices=["headers", "tls", "exposure", "all"],
		default="all",
		help="Módulo a ejecutar"
	)

	parser.add_argument(
		"--timeout",
		type=int,
		default=5,
		help="Timeout de las peticiones en segundos"
	)

	parser.add_argument(
		"--report",
		choices=["json", "html"],
		help="Genera un informe en el formato indicado"
	)

	parser.add_argument(
		"--output",
		help="Carpeta donde se guardará el informe"
	)

	return parser

# Muestra por consola el resumen del escaneo y sus hallazgos.
def print_result(result: dict):

	print("\n=== RESULTADO DEL ESCANEO ===")
	print(f"Objetivo: {result['target']}")
	print(f"Módulo: {result['module']}")
	print(f"Hallazgos: {len(result['findings'])}")
	print(f"Errores: {len(result['errors'])}")

	if result["findings"]:
		print("\n--- Hallazgos ---")
		for i, finding in enumerate(result["findings"], start=1):
			print(f"\n[{i}] {finding.get('title', 'Sin título')}")
			print(f"Severidad: {finding.get('severity', 'info')}")
			if "score" in finding:
				print(f"Score: {finding.get('score', 0)}")
			print(f"Descripción: {finding.get('description', '')}")
			print(f"Evidencia: {finding.get('evidence', '')}")
			print(f"Recomendación: {finding.get('recommendation', '')}")

	if result["errors"]:
		print("\n--- Errores ---")
		for i, error in enumerate(result["errors"], start=1):
			print(f"{i}. {error}")

	print()

# Ejecuta el flujo principal: argumentos, escaneo y generación opcional de informe.
def main():
	parser = build_parser()
	args = parser.parse_args()

	try:
		scanner = Scanner(timeout=args.timeout)

		result = scanner.scan(target=args.target, module=args.module)

		print_result(result)

		if args.report:
			default_filename = build_default_report_filename(args.target, args.report)

			if args.output:
					output_dir = Path(args.output)
					output_dir.mkdir(parents=True, exist_ok=True)
					output_path = output_dir / default_filename
			else:
					output_path = Path(default_filename)

			if args.report == "json":
					save_json_report(result, str(output_path))
			elif args.report == "html":
					save_html_report(result, str(output_path))

			print(f"Informe generado: {output_path}")

	except Exception as exc:
		print(f"Error fatal: {exc}")


if __name__ == "__main__":
	main()