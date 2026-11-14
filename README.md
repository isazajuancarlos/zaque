# zaque

**Detector de integridad de la cadena de arranque.** Sella un hash SHA-256 de todo
lo que participa en el arranque (`/boot`: kernel, initramfs, grub, entradas BLS y la
ESP con shim/grub/fallback) y avisa si algo cambió entre reinicios.

Es la capa de **DETECCIÓN** que compensa a Secure Boot cuando está apagado: no *previene*
el manipuleo del arranque —eso es Secure Boot / cifrado de disco / TPM—, lo hace
**evidente**. Un bootkit que reemplaza el cargador de la ESP o el initramfs deja de ser
invisible.

El mismo tripwire sirve **un piso más arriba**, en la cadena de suministro del editor
(`--editor`): las extensiones de VS Code / Cursor / Windsurf son código de terceros que
corre con tus privilegios y se actualiza solo. Un backdoor inyectado **post-install** —el
troyano de la extensión de Claude Code en Cursor/VS Code de octubre de 2026— aparece como
un archivo **NUEVO** frente a la línea base. zaque no firma ni aísla extensiones; hace
evidente que una cambió sin que tú la actualizaras.

## Diseño

- **Cero dependencias.** SHA-256 propio (FIPS 180-4), validado contra los vectores
  conocidos; línea base en **texto plano** auditable y greppable.
- **Falla ruidosamente** (nunca sella un baseline vacío ni se traga un archivo ilegible).
- **Verifica el mismo conjunto que selló** (las rutas van en la cabecera de la línea base).
- Detecta: archivo **cambiado** (hash/tamaño), **nuevo** (intruso) y **faltante** (borrado),
  incluido el redireccionamiento de un **symlink**.

## Uso

```bash
# 1) Tras un arranque que sabes sano, fija la línea base (como root):
sudo zaque sellar                      # -> /var/lib/zaque/linea-base.txt, vigila /boot

# 2) En cada arranque (o cuando quieras), verifica:
sudo zaque verificar
#   exit 0  -> ÍNTEGRO
#   exit 2  -> DERIVA detectada (lista qué cambió/apareció/falta)
#   exit 3  -> error (p. ej. sin línea base: sella primero)

# Acotar o ampliar el conjunto vigilado:
sudo zaque sellar /ruta/base.txt --ruta /boot --ruta /otra/cosa
```

### Extensiones del editor (`--editor`)

Sin root, sobre tu `$HOME`. Descubre las carpetas de extensiones de los editores
instalados (VS Code `~/.vscode/extensions`, VS Code Server, VSCodium, Cursor, Windsurf) y
usa una **línea base separada** de la de arranque (`~/.local/state/zaque/extensiones-editor.txt`):

```bash
# 1) Con las extensiones en un estado que confías:
zaque sellar --editor
#   -> sella las carpetas de editor presentes; falla ruidoso si no hay NINGUNA
#      (no sella un conjunto vacío ni se cae a /boot en silencio)

# 2) Cuando quieras (p. ej. al abrir el editor, por un timer de usuario):
zaque verificar --editor
#   exit 0 ÍNTEGRO · 2 DERIVA (un backdoor inyectado sale como NUEVO) · 3 error
```

**Regla operativa:** actualizar o instalar una extensión **cambia las carpetas a
propósito** → tras hacerlo conscientemente, **re-sella** (`zaque sellar --editor`). A
diferencia de `/boot`, esto no lo cubren los hooks de dnf/kernel-install (las extensiones
se actualizan desde el propio editor), así que el re-sellado es manual y consciente —que
es justo lo que preserva la detección—.

**Regla operativa:** una actualización de kernel o `dracut`/`grub` **cambia `/boot` a
propósito** → tras aplicarla, **re-sella** (`sudo zaque sellar`). Si no, la siguiente
verificación avisará de una deriva legítima. Es la directiva 22 aplicada: el alcance de
lo que se vigila es el que se regenera.

## Cableado a systemd (detección automática)

- Un `zaque-verificar.service` de tipo `oneshot` en el arranque (tras montar `/boot`)
  que corre `zaque verificar`; si sale 2, queda en el journal como fallo visible.
- Re-sellar es manual y consciente, por diseño: sellar automático tras cada cambio
  anularía la detección.

## Build y puerta (el único verde: local, sin CI)

```bash
cargo test                                # 14 unit (SHA-256 vs FIPS, comparación, rutas de editor) + 5 E2E
cargo clippy --all-targets -- -D warnings # la PUERTA
```

El E2E arranca el binario real (D28): sobre un `/boot` simulado sella, verifica íntegro,
manipula el shim y lo caza con exit 2; y en modo `--editor` (con `$HOME`/`XDG_STATE_HOME`
apuntando a temporales) sella las extensiones descubiertas, inyecta un backdoor y confirma
que sale como NUEVO con exit 2, más que sin ningún editor falla ruidoso sin tocar `/boot`.

## Titularidad

MIT — Copyright (c) 2026 Juan Carlos Isaza.
