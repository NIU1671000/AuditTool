# Herramienta de auditoría técnica y hardening web

Herramienta CLI para realizar auditorías técnicas básicas y comprobaciones de hardening sobre servicios y aplicaciones web accesibles mediante HTTP/HTTPS.

## Instalación

Antes de ejecutar la herramienta, hay que situarse desde la terminal en la carpeta del proyecto que contiene el paquete `audit_tool`.

```bash
cd ruta/del/proyecto
```

Por ejemplo, si la carpeta del proyecto se llama `TFG`:

```bash
cd TFG
```

En este proyecto, el archivo `requirements.txt` se encuentra dentro de la carpeta `audit_tool`, por lo que las dependencias se instalan con el siguiente comando:

```bash
pip install -r audit_tool/requirements.txt
```

Una vez instaladas las dependencias, la herramienta debe ejecutarse desde la carpeta que contiene `audit_tool`, no desde dentro de `audit_tool`.

## Manual de uso

La herramienta se ejecuta desde la línea de comandos indicando el objetivo que se desea analizar y el módulo correspondiente.

Estructura general:

```bash
python -m audit_tool.cli.main <objetivo> --module <modulo>
```

Los módulos disponibles son:

- `tls`: analiza la configuración TLS/SSL y el certificado del servidor.
- `headers`: revisa cabeceras HTTP de seguridad y redirecciones.
- `exposure`: comprueba la posible exposición de rutas o recursos sensibles.
- `all`: ejecuta todos los módulos disponibles.

## Ejemplos de ejecución

Ejecutar el módulo TLS/SSL:

```bash
python -m audit_tool.cli.main https://example.com --module tls
```

Ejecutar el módulo de cabeceras HTTP:

```bash
python -m audit_tool.cli.main http://sitio.com --module headers
```

Ejecutar el módulo de exposición de recursos:

```bash
python -m audit_tool.cli.main http://localhost:8080 --module exposure
```

Ejecutar todos los módulos:

```bash
python -m audit_tool.cli.main http://localhost:8080 --module all
```

## Generación de informes

Además de mostrar los resultados por consola, la herramienta permite generar informes en formato `json` o `html`.

Generar un informe HTML:

```bash
python -m audit_tool.cli.main http://localhost:8080 --module all --report html
```

Generar un informe JSON:

```bash
python -m audit_tool.cli.main http://localhost:8080 --module all --report json
```

Guardar el informe en una ruta concreta:

```bash
python -m audit_tool.cli.main http://localhost:8080 --module all --report html --output reports
```

La opción `--output` permite indicar una ruta de salida relativa o absoluta. Si no se indica, el informe se guarda en la ubicación actual con un nombre generado automáticamente.

## Opciones disponibles

### `--module`

Permite seleccionar el módulo que se desea ejecutar:

```bash
--module tls
--module headers
--module exposure
--module all
```

### `--report`

Permite generar un informe en formato `json` o `html`.

```bash
--report html
--report json
```

### `--output`

Permite indicar la ruta donde se guardará el informe generado.

```bash
--output reports
```

### `--timeout`

Permite definir el tiempo máximo de espera de las peticiones en segundos.

Ejemplo:

```bash
python -m audit_tool.cli.main http://localhost:8080 --module all --timeout 10
```

## Resultado

El resultado del análisis puede consultarse directamente por consola o guardarse como informe estructurado en formato JSON o HTML.