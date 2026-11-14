# CLAUDE.md — zaque

> La configuración GENERAL (directivas, stack, protocolo solo-local, memoria) vive en
> `~/.claude/CLAUDE.md` y se carga siempre. Aquí va **solo lo propio de zaque**.
> Etiqueta de sesión: `[zaque]`.

## Qué es

Detector de integridad por línea base de hashes (SHA-256 propio, cero deps). Capa de
**DETECCIÓN** que no previene, hace evidente. Dos conjuntos:

- **Arranque** (por defecto): sella `/boot` (kernel, initramfs, grub, BLS, ESP). Compensa
  a Secure Boot apagado. Nació el 2026-10-30 de CVE-2026-97631 (UEFI/EDK II), al medir que
  `hope` corre con SB off y sin FDE (`conocimiento/uefi-edk2-pxe-cve-2026-97631.md §7`).
- **Extensiones del editor** (`--editor`, 2026-11-01): el mismo tripwire sobre las carpetas
  de extensiones presentes bajo `$HOME` (VS Code, VS Code Server, VSCodium, Cursor,
  Windsurf), con línea base SEPARADA en `~/.local/state/zaque/extensiones-editor.txt`. Es
  la cadena de suministro del editor: un backdoor inyectado post-install sale como NUEVO.
  Disparador con fecha: el troyano de la extensión de Claude Code en Cursor/VS Code
  (oct-2026). Extensión DELIBERADA del alcance (D21, con motivo, no por inercia); reúsa el
  motor entero (`recolectar`/`comparar`), solo añade descubrimiento de rutas y la 2ª línea
  base. Idea R7 de mindalá (`zaque/FIM` extensiones) → implementada.

## Diseño (lo que no se rompe)

- **Cero dependencias** (D38 llevado al extremo auditable): SHA-256 propio validado
  contra los vectores FIPS 180-4; línea base en texto plano.
- **Falla ruidosamente** (D20): no sella un baseline vacío; no se traga un archivo
  ilegible. Un falso verde aquí sería permanente e invisible (D30).
- **Verifica el MISMO conjunto que selló** (D22): las rutas viajan en la cabecera de la
  línea base; `verificar` las reusa salvo `--ruta` explícito.

## Build y puerta (el único verde: local, sin CI)

```bash
cargo test                                # unit (SHA-256/comparación) + E2E (D28, binario real)
cargo clippy --all-targets -- -D warnings # la PUERTA
```

- Pareja D33: `detecta_cambio_nuevo_y_faltante` es la aguja; el mutante (un `comparar`
  que ignora el hash) la pone roja — verificado al nacer. El SHA-256 se ancla a los
  vectores FIPS (su propio control).

## Operación

- `sudo zaque sellar` tras un arranque sano → `/var/lib/zaque/linea-base.txt`.
- `sudo zaque verificar` → exit 0 íntegro / 2 deriva / 3 error.
- **Re-sellado AUTOMÁTICO en transacciones de kernel** (`kernel-install/99-zaque.install`
  → `/etc/kernel/install.d/`): cada add/remove de kernel re-sella al final. Es SEGURO
  porque `kernel-install` solo lo invoca una transacción de paquetes autenticada como
  root; la manipulación que zaque caza (offline / sin root) no puede llegar ahí, y un root
  ya podía re-sellar a mano. NO debilita el modelo real (razonamiento en
  `conocimiento/uefi-edk2-pxe-cve-2026-97631.md §7`).
- **Cobertura TOTAL vía `libdnf5-plugin-actions`** (`dnf/zaque.actions` →
  `/etc/dnf/libdnf5-plugins/actions.d/`): `post_transaction` con filtro vacío re-sella una
  vez tras CUALQUIER transacción dnf (cubre shim/grub2-efi/fwupd-efi y lo que kernel-install
  no ve). Verificado con positivo de control (mtime de la línea base cambió tras un
  `reinstall`, sin ruido). Envuelto en `sh -c … >/dev/null` (modo plain lee el stdout como
  canal); `raise_error=0` no aborta dnf si falla.
- **El re-sellado manual ya no hace falta en operación normal** — queda como gesto de
  emergencia (`sudo zaque sellar`) si algún día se desactivan los hooks.
- **Extensiones (`--editor`)**: `zaque sellar --editor` tras un estado confiado;
  `zaque verificar --editor` cuando quieras (sin root). NO lo cubren los hooks de dnf
  (las extensiones las actualiza el editor, no una transacción de paquetes), así que el
  re-sellado es manual y consciente tras instalar/actualizar una extensión. Opcional: un
  `--user` timer que verifique al iniciar sesión (pendiente, lo decide Juan).

## Pendiente

- `systemd/zaque-verificar.service` (oneshot al arranque) YA está en el repo; **falta
  habilitarlo** (`sudo systemctl enable`, lo aplica Juan). Deja la unidad en `failed` +
  la salida en el journal si hay deriva.
- Opcional: sellar la línea base en un medio de solo-lectura o firmarla, para que un
  atacante con root no pueda re-sellar su propia manipulación (hoy la línea base vive en
  disco escribible; es el límite honesto de la detección sin un ancla externa/TPM).

## Titularidad

MIT — Copyright (c) 2026 Juan Carlos Isaza. Herramienta de seguridad defensiva.
