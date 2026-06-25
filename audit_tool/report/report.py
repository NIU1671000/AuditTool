import json
from datetime import datetime
from html import escape
from urllib.parse import urlparse
from pathlib import Path


def extract_domain(target: str) -> str:

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    host = parsed.hostname

    if not host:
        return "report"

    return host.lower()


def sanitize_filename(value: str) -> str:

    safe_chars = []

    for char in value:
        if char.isalnum() or char in ("-", "_", "."):
            safe_chars.append(char)
        else:
            safe_chars.append("_")

    filename = "".join(safe_chars).strip("._")

    if not filename:
        return "report"

    return filename

# Construye un nombre de informe por defecto usando el dominio y el formato.
def build_default_report_filename(target: str, report_format: str) -> str:

    domain = extract_domain(target)
    safe_domain = sanitize_filename(domain)

    return f"{safe_domain}.{report_format}"

# Guarda el resultado del análisis en formato JSON.
def save_json_report(result: dict, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=4)

# Carga la hoja de estilos CSS usada por el informe HTML.
def load_report_css() -> str:
    css_path = Path(__file__).parent / "templates" / "report.css"

    with open(css_path, "r", encoding="utf-8") as file:
        return file.read()

# Genera y guarda el informe final en formato HTML.
def save_html_report(result: dict, output_path: str) -> None:
    css = load_report_css()

    target = escape(str(result.get("target", "")))
    module = escape(str(result.get("module", "")))
    findings = result.get("findings", [])
    errors = result.get("errors", [])

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    domain = escape(extract_domain(str(result.get("target", ""))))

    severity_labels = {
        "high": "ALTO",
        "medium": "MEDIO",
        "low": "BAJO",
        "info": "INFO",
    }

    counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()

        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1

    findings_html = ""

    for index, finding in enumerate(findings, start=1):
        title = escape(str(finding.get("title", "Sin título")))
        severity = str(finding.get("severity", "info")).lower()
        description = escape(str(finding.get("description", "")))
        evidence = escape(str(finding.get("evidence", "")))
        recommendation = escape(str(finding.get("recommendation", "")))

        label = severity_labels.get(severity, severity_labels["info"])

        findings_html += f"""
        <section class="finding">
            <div class="finding-title">
                <span class="badge">{label}</span>
                <h3>{index}. {title}</h3>
            </div>

            <p><strong>Descripción:</strong> {description}</p>
            <p><strong>Evidencia:</strong> {evidence}</p>
            <p><strong>Recomendación:</strong> {recommendation}</p>
        </section>
        """

    if not findings_html:
        findings_html = "<p>No se han detectado hallazgos.</p>"

    errors_html = ""

    for error in errors:
        errors_html += f"<p>{escape(str(error))}</p>"

    if errors_html:
        errors_block = f"""
        <h2>Errores</h2>
        {errors_html}
        """
    else:
        errors_block = ""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Informe de auditoría web</title>

    <style>
        {css}
    </style>
</head>

<body>
    <div class="page">
        <header>
            <h1>Audit Tool</h1>
            <div class="subtitle">Informe de auditoría técnica web</div>

            <div class="meta">
                <div class="meta-row">
                    <div class="meta-label">URL</div>
                    <div class="meta-value">{target}</div>
                </div>

                <div class="meta-row">
                    <div class="meta-label">Módulo</div>
                    <div class="meta-value">{module}</div>
                </div>

                <div class="meta-row">
                    <div class="meta-label">Dominio</div>
                    <div class="meta-value">{domain}</div>
                </div>

                <div class="meta-row">
                    <div class="meta-label">Hallazgos</div>
                    <div class="meta-value">{len(findings)} totales</div>
                </div>

                <div class="meta-row">
                    <div class="meta-label">Fecha</div>
                    <div class="meta-value">{generated_at}</div>
                </div>

                <div class="meta-row">
                    <div class="meta-label">Errores</div>
                    <div class="meta-value">{len(errors)}</div>
                </div>
            </div>
        </header>

        <h2>Resumen de Riesgos</h2>

        <div class="risk-grid">
            <div class="risk-card">
                <span class="risk-number">{counts["high"]}</span>
                <span class="risk-label">Alto</span>
            </div>

            <div class="risk-card">
                <span class="risk-number">{counts["medium"]}</span>
                <span class="risk-label">Medio</span>
            </div>

            <div class="risk-card">
                <span class="risk-number">{counts["low"]}</span>
                <span class="risk-label">Bajo</span>
            </div>

            <div class="risk-card">
                <span class="risk-number">{counts["info"]}</span>
                <span class="risk-label">Info</span>
            </div>
        </div>

        <h2>Hallazgos Detectados</h2>

        {findings_html}

        {errors_block}
    </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(html)