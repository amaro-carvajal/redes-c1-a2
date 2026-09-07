# Actividad 2 - Resolver DNS

Implementación de un resolver DNS en Python utilizando sockets UDP y la librería `dnslib`.

## Requisitos

- Python 3
- `dnslib`
- `dig`

## Instalación

Se recomienda utilizar un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install dnslib
```

## Configuración

Antes de ejecutar el programa se debe cambiar la variable `IP_VM` en `resolver.py` por la dirección IP de la máquina virtual donde se ejecutará el resolver:

```python
IP_VM = "192.168.X.X"
```

El resolver utiliza:

```text
Puerto local: 8000
DNS externo: puerto 53 UDP
```

## Ejecución

Con el entorno virtual activado:

```bash
python resolver.py
```

El programa quedará escuchando consultas DNS en:

```text
IP_VM:8000
```
