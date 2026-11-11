<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
-->

# zaque

Boot integrity detection for Linux systems — seals a SHA-256 baseline of everything that participates in startup and reports what changed, appeared, or went missing between boots. MIT. Rust · SHA-256 · systemd · zero dependencies.

**English** · [Español](#español)

---

## What it does

zaque is a **detection** layer, not a prevention one: it makes boot-chain tampering *visible* rather than stopping it. When Secure Boot is disabled or TPM attestation is not in place, there is no other mechanism that alerts you if a bootkit has replaced the bootloader or the initramfs between sessions. zaque fills that gap.

It seals a SHA-256 baseline over every file that participates in boot — kernel images, initramfs, GRUB binaries, BLS boot entries, and the EFI System Partition (shim, fallback) — and compares it on the next verification pass.

The same engine works **one level up** on the editor extension supply chain. VS Code, Cursor, Windsurf, and similar editors update their extensions silently and with broad filesystem access. A backdoor injected post-install appears as a **NEW** file against the sealed baseline; that is exactly how the trojan extension incident of October 2026 would have been caught before it ran.

### What it detects

| Verdict | Meaning |
|---|---|
| **CHANGED** | A file's hash or size no longer matches the baseline. |
| **NEW** | An unexpected file appeared — a potential intruder. |
| **MISSING** | A sealed file is gone. |
| **Symlink redirect** | A path that was a regular file is now a symlink, or points elsewhere. |

### Design decisions

- **Zero dependencies.** The SHA-256 implementation follows FIPS 180-4 and is validated against the official test vectors. The baseline is plain text — auditable and greppable with no special tooling.
- **Fails loudly.** zaque never seals an empty baseline and never silently swallows an unreadable file. A false green here would be permanent and invisible.
- **Verifies the same set it sealed.** The watched paths are stored in the baseline header; a verification run re-reads them from there, so the scope cannot drift silently.

### Integration

A `systemd` oneshot service (`zaque-verificar.service`) runs on boot after `/boot` is mounted. Exit code `2` leaves the unit failed and writes the full diff to the journal. Re-sealing is always manual and deliberate — automatic re-sealing after every change would defeat detection.

For package-manager transactions, a `kernel-install` hook and a `libdnf5-plugin-actions` drop-in re-seal automatically after every authenticated package transaction. That is the only context in which a re-seal is not a security event.

### Test suite

14 unit tests (SHA-256 FIPS vectors, comparison logic, path handling) + 5 end-to-end tests that start the real binary against a simulated `/boot` tree, inject a modified EFI binary, and confirm exit code `2`. The editor-extension path is covered separately with an isolated `$HOME` and a synthetic backdoor confirmed as `NEW`.

---

## The code is not hosted here

Since August 2026 the source of this project **is not hosted on GitHub**, and it is not distributed through crates.io.

This is not abandonment, not an incident, and there was no breach. It is a decision, and it is worth saying what it rests on. Through 2026 the package registries and code-hosting platforms were hit by sustained, chained supply-chain attacks — the Shai-Hulud worm, ChainDrop in August, malicious extensions that exfiltrated thousands of private repositories. For a security tool that monitors the boot chain and editor extension integrity, hosting the source there stopped being a neutral decision.

**The licence has not changed and the code is still available to anyone who asks** — delivered with a signature and a checksum, at no cost, with no NDA, no restriction on what you publish about it, and no expiry.

To request it: **[xiliux.com](https://xiliux.com)**

---

## Español

## Qué hace

zaque es una capa de **detección**, no de prevención: hace *visible* la manipulación de la cadena de arranque en vez de impedirla. Cuando Secure Boot está apagado o no hay atestación por TPM, no existe ningún otro mecanismo que avise si un bootkit ha reemplazado el cargador de arranque o el initramfs entre sesiones. zaque llena ese hueco.

Sella una línea base SHA-256 sobre cada archivo que participa en el arranque —imágenes del kernel, initramfs, binarios de GRUB, entradas BLS y la EFI System Partition (shim, fallback)— y la compara en la siguiente pasada de verificación.

El mismo motor funciona **un piso más arriba** en la cadena de suministro de las extensiones del editor. VS Code, Cursor, Windsurf y editores similares actualizan sus extensiones en silencio y con acceso amplio al sistema de archivos. Un backdoor inyectado después de la instalación aparece como archivo **NUEVO** frente a la línea base sellada; así es exactamente como habría quedado en evidencia el troyano de extensión de octubre de 2026 antes de que corriera.

### Qué detecta

| Veredicto | Significado |
|---|---|
| **CAMBIADO** | El hash o el tamaño de un archivo ya no coincide con la línea base. |
| **NUEVO** | Apareció un archivo inesperado — posible intruso. |
| **FALTANTE** | Un archivo sellado ha desaparecido. |
| **Redirección de symlink** | Una ruta que era un archivo regular ahora es un enlace simbólico, o apunta a otro destino. |

### Decisiones de diseño

- **Cero dependencias.** SHA-256 propio (FIPS 180-4), validado contra los vectores oficiales. La línea base es texto plano, auditable y consultable con `grep` sin herramientas especiales.
- **Falla ruidosamente.** zaque nunca sella una línea base vacía ni se traga en silencio un archivo ilegible. Un falso verde aquí sería permanente e invisible.
- **Verifica el mismo conjunto que selló.** Las rutas vigiladas se guardan en la cabecera de la línea base; la verificación las relee de ahí, de modo que el alcance no pueda derivar en silencio.

### Integración

Un servicio `systemd` `oneshot` (`zaque-verificar.service`) corre al arrancar tras montar `/boot`. El código de salida `2` deja la unidad en fallo y escribe el diff completo en el journal. El re-sellado es siempre manual y consciente: un re-sellado automático tras cada cambio anularía la detección.

Para transacciones del gestor de paquetes, un hook de `kernel-install` y un complemento de `libdnf5-plugin-actions` re-sellan automáticamente tras cada transacción de paquetes autenticada. Ese es el único contexto en el que un re-sellado no es un evento de seguridad.

### Banco de pruebas

14 pruebas unitarias (vectores FIPS SHA-256, lógica de comparación, rutas) + 5 pruebas de extremo a extremo que arrancan el binario real contra un árbol `/boot` simulado, inyectan un binario EFI modificado y confirman el código de salida `2`. El modo de extensiones de editor se cubre por separado con un `$HOME` aislado y un backdoor sintético confirmado como `NUEVO`.

### El código no se publica aquí

Desde agosto de 2026, el código de este proyecto **no se aloja en GitHub**, ni se distribuye por crates.io.

No es abandono ni un incidente: es una decisión, y conviene decir por qué. A lo largo de 2026 los registros de paquetes y las plataformas de código han sufrido ataques encadenados de cadena de suministro —Shai-Hulud, ChainDrop en agosto, extensiones maliciosas que se llevaron miles de repositorios privados—. Alojar aquí el código de una herramienta de seguridad que vigila la cadena de arranque y las extensiones del editor dejó de ser una decisión neutra.

**La licencia no cambia y el código se sigue entregando a quien lo pida**, con su firma y su suma de verificación, sin coste, sin NDA, sin restricción sobre lo que publique y sin caducidad.

Para solicitarlo: **[xiliux.com](https://xiliux.com)**

---

*zaque* — © 2026 Juan Carlos Isaza. Licencia **MIT**.
La licencia no cambia: lo que cambia es por dónde se entrega el código.
