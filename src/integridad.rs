// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Juan Carlos Isaza
//
//! Sellado y verificación de la integridad de un conjunto de archivos (la cadena de
//! arranque, por defecto). Formato de línea base en TEXTO PLANO, auditable y greppable.

use crate::sha256::{a_hex, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Una entrada sellada: el hash (o un marcador de symlink) y el tamaño de un archivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    pub hash: String,
    pub size: u64,
    pub ruta: String,
}

/// Rutas por defecto a vigilar: la cadena de arranque completa. `/boot` contiene el
/// kernel, el initramfs, las entradas BLS (`loader/`), grub (`grub2/`) y —si la ESP
/// está montada ahí— `efi/` con shim/grub/fallback. Vigilar `/boot` entero es la
/// definición honesta de "cadena de arranque" (D19: el caso concreto es prueba, no
/// especificación; se puede acotar con `--ruta`).
pub fn rutas_por_defecto() -> Vec<PathBuf> {
    vec![PathBuf::from("/boot")]
}

/// Carpetas de extensiones de los editores conocidos, RELATIVAS a `$HOME`. Una extensión
/// de editor es código de terceros que corre CON TUS privilegios y se actualiza sola: el
/// mismo modelo de amenaza que la ESP, un piso más arriba (la cadena de suministro del
/// editor). El troyano de la extensión de Claude Code en Cursor/VS Code (oct-2026) es el
/// disparador con fecha. zaque no lo PREVIENE —eso es firma de extensiones / sandbox—, lo
/// hace EVIDENTE: un `backdoor.js` inyectado post-install aparece como NUEVO.
const SUBRUTAS_EDITOR: &[&str] = &[
    ".vscode/extensions",        // VS Code
    ".vscode-server/extensions", // VS Code Remote/WSL server
    ".vscode-oss/extensions",    // VSCodium / OSS
    ".cursor/extensions",        // Cursor
    ".windsurf/extensions",      // Windsurf
];

/// Resuelve las carpetas de extensiones de editor que EXISTEN bajo `home`. Devuelve SOLO
/// las presentes (D20: una carpeta ausente no es un hueco, es un editor no instalado; no
/// se inventa una ruta). Vacío = ningún editor → el llamante falla ruidoso (no sella un
/// conjunto vacío, que sería un falso verde permanente, D30).
pub fn rutas_de_editor_en(home: &Path) -> Vec<PathBuf> {
    SUBRUTAS_EDITOR
        .iter()
        .map(|s| home.join(s))
        .filter(|p| p.exists())
        .collect()
}

/// Como `rutas_de_editor_en` con el `$HOME` real. Falla si no hay `$HOME` (no se adivina
/// una ruta de casa, D20).
pub fn rutas_de_editor() -> io::Result<Vec<PathBuf>> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "$HOME no está definido: no se puede ubicar las extensiones del editor",
        )
    })?;
    Ok(rutas_de_editor_en(Path::new(&home)))
}

/// Línea base por defecto del conjunto de EDITOR, SEPARADA de la de arranque: distinta
/// cadencia de re-sellado (las extensiones se actualizan desde el propio editor, no por
/// una transacción dnf, así que los hooks de `/boot` no la cubren). Vive bajo
/// `XDG_STATE_HOME` (o `~/.local/state`), escribible por el usuario: las extensiones son
/// de `$HOME`, no de root.
pub fn baseline_editor() -> io::Result<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_STATE_HOME").filter(|s| !s.is_empty()) {
        return Ok(Path::new(&x).join("zaque/extensiones-editor.txt"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "$HOME no está definido")
    })?;
    Ok(Path::new(&home).join(".local/state/zaque/extensiones-editor.txt"))
}

/// Codifica una ruta SIN PÉRDIDA. El resultado nunca contiene `\t`, `\n`, `\r` ni un
/// `\\` sin escapar, así que sirve a la vez como:
///   - CLAVE de comparación: es una biyección de los bytes crudos, así que dos nombres
///     distintos JAMÁS colisionan —ni con bytes no-UTF-8— (lo que `Path::display()`
///     sí permitía: colapsar `evil\xfe` y `evil\xff` a `evil�` y enmascarar una deriva);
///   - campo seguro en la línea base (sin inyección de separador `\t`/`\n`);
///   - texto seguro en los avisos (sin inyección de terminal por caracteres de control).
///
/// Es el núcleo del arreglo de las tres observaciones de la revisión de seguridad.
fn ruta_canonica(p: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        escapar_bytes(p.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        // zaque es herramienta de /boot (Linux). En no-Unix se degrada a lossy a propósito.
        escapar_bytes(p.to_string_lossy().as_bytes())
    }
}

fn escapar_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            0x20..=0x7e => s.push(b as char),
            _ => {
                s.push_str("\\x");
                s.push(nibble(b >> 4));
                s.push(nibble(b & 0x0f));
            }
        }
    }
    s
}

fn nibble(n: u8) -> char {
    char::from_digit(u32::from(n), 16).unwrap()
}

/// Inverso de `escapar_bytes`. Falla ruidosamente ante un escape malformado (una línea
/// base manipulada): nunca inventa bytes.
fn desescapar(s: &str) -> io::Result<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let malformado = || io::Error::new(io::ErrorKind::InvalidData, format!("escape inválido en {s:?}"));
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 1;
            match b.get(i) {
                Some(b'\\') => out.push(b'\\'),
                Some(b't') => out.push(b'\t'),
                Some(b'n') => out.push(b'\n'),
                Some(b'r') => out.push(b'\r'),
                Some(b'x') => {
                    let hi = b.get(i + 1).and_then(|c| (*c as char).to_digit(16));
                    let lo = b.get(i + 2).and_then(|c| (*c as char).to_digit(16));
                    match (hi, lo) {
                        (Some(h), Some(l)) => {
                            out.push((h * 16 + l) as u8);
                            i += 2;
                        }
                        _ => return Err(malformado()),
                    }
                }
                _ => return Err(malformado()),
            }
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn desescapar_a_pathbuf(s: &str) -> io::Result<PathBuf> {
    let bytes = desescapar(s)?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)))
    }
    #[cfg(not(unix))]
    {
        Ok(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

/// Recolecta y hashea todos los archivos bajo las rutas dadas, ordenados por ruta.
///
/// FALLA RUIDOSAMENTE (D20): si una ruta configurada no existe se omite con nota en
/// `omitidas` (al sellar es legítimo que falte `/boot/grub2` en un sistema systemd-boot),
/// pero un archivo que SÍ está y no se puede leer/hashear es un error, no un hueco —
/// sellar un baseline incompleto en silencio es el falso verde de la D30.
pub fn recolectar(rutas: &[PathBuf]) -> io::Result<(Vec<Entrada>, Vec<String>)> {
    let mut entradas = Vec::new();
    let mut omitidas = Vec::new();
    for raiz in rutas {
        if !raiz.exists() {
            omitidas.push(raiz.display().to_string());
            continue;
        }
        recorrer(raiz, &mut entradas)?;
    }
    entradas.sort_by(|a, b| a.ruta.cmp(&b.ruta));
    Ok((entradas, omitidas))
}

fn recorrer(ruta: &Path, acc: &mut Vec<Entrada>) -> io::Result<()> {
    let meta = fs::symlink_metadata(ruta)?;
    let tipo = meta.file_type();
    if tipo.is_symlink() {
        // Un symlink que cambia de destino es manipulación (redirigir el arranque).
        // No se sigue: se sella el DESTINO como dato.
        let destino = fs::read_link(ruta)?;
        acc.push(Entrada {
            hash: format!("symlink:{}", ruta_canonica(&destino)),
            size: 0,
            ruta: ruta_canonica(ruta),
        });
    } else if tipo.is_dir() {
        let mut hijos: Vec<PathBuf> = fs::read_dir(ruta)?
            .map(|e| e.map(|e| e.path()))
            .collect::<io::Result<_>>()?;
        hijos.sort();
        for hijo in hijos {
            recorrer(&hijo, acc)?;
        }
    } else if tipo.is_file() {
        let (hash, size) = hashear_archivo(ruta)?;
        acc.push(Entrada { hash, size, ruta: ruta_canonica(ruta) });
    }
    // Otros tipos (socket, fifo, dispositivo) no pertenecen a la cadena de arranque; se
    // ignoran a propósito. Si aparecieran en /boot sería raro, pero no es nuestro objeto.
    Ok(())
}

fn hashear_archivo(ruta: &Path) -> io::Result<(String, u64)> {
    let mut f = fs::File::open(ruta)?;
    let mut h = Sha256::nuevo();
    let mut buf = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.actualizar(&buf[..n]);
        total += n as u64;
    }
    Ok((a_hex(&h.finalizar()), total))
}

/// Escribe la línea base. Cabecera con versión, fecha, y las RUTAS selladas (para que
/// `verificar` vigile EXACTAMENTE el mismo conjunto, D22).
pub fn serializar(entradas: &[Entrada], rutas: &[PathBuf], ahora_epoch: u64) -> String {
    let mut s = String::new();
    s.push_str("# zaque — línea base de integridad de arranque\n");
    s.push_str("# formato: <sha256hex|symlink:destino>\\t<size>\\t<ruta>  (ruta/destino escapados, lossless)\n");
    s.push_str(&format!("# version: 2\n# sellado_epoch: {ahora_epoch}\n"));
    // Una ruta sellada por línea (escapada), para no depender de un separador que un
    // nombre podría contener (la lista con `,` se rompía con una coma en la ruta).
    for r in rutas {
        s.push_str(&format!("# ruta: {}\n", ruta_canonica(r)));
    }
    for e in entradas {
        s.push_str(&format!("{}\t{}\t{}\n", e.hash, e.size, e.ruta));
    }
    s
}

/// Carga una línea base: devuelve las entradas y las rutas que se sellaron.
pub fn parsear(texto: &str) -> io::Result<(Vec<Entrada>, Vec<PathBuf>)> {
    let mut entradas = Vec::new();
    let mut rutas = Vec::new();
    let mut vistas = std::collections::HashSet::new();
    for linea in texto.lines() {
        if let Some(resto) = linea.strip_prefix("# ruta: ") {
            rutas.push(desescapar_a_pathbuf(resto)?);
            continue;
        }
        if linea.starts_with('#') || linea.trim().is_empty() {
            continue;
        }
        let campos: Vec<&str> = linea.splitn(3, '\t').collect();
        if campos.len() != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("línea de baseline malformada: {linea:?}"),
            ));
        }
        let size = campos[1].parse::<u64>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, format!("size inválido en: {linea:?}"))
        })?;
        let ruta = campos[2].to_string();
        // Una ruta duplicada en la línea base es manipulación: con un mapa, "gana la
        // última" y se podría enmascarar la entrada buena. Se rechaza ruidoso (D20/D30).
        if !vistas.insert(ruta.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ruta duplicada en la línea base (¿manipulada?): {ruta}"),
            ));
        }
        entradas.push(Entrada { hash: campos[0].to_string(), size, ruta });
    }
    Ok((entradas, rutas))
}

/// Resultado de comparar la línea base contra el estado actual.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Informe {
    /// (ruta, hash_sellado, hash_actual)
    pub cambiados: Vec<(String, String, String)>,
    /// rutas que aparecieron y no estaban selladas
    pub nuevos: Vec<String>,
    /// rutas selladas que ya no están
    pub faltantes: Vec<String>,
}

impl Informe {
    pub fn limpio(&self) -> bool {
        self.cambiados.is_empty() && self.nuevos.is_empty() && self.faltantes.is_empty()
    }
}

/// Compara baseline vs actual por ruta. Ambos deben venir ordenados por ruta (lo están
/// desde `recolectar`/`parsear` si el fichero no se tocó a mano; por seguridad se usa
/// un mapa, no la posición).
pub fn comparar(base: &[Entrada], actual: &[Entrada]) -> Informe {
    use std::collections::BTreeMap;
    let mapa_base: BTreeMap<&str, &Entrada> = base.iter().map(|e| (e.ruta.as_str(), e)).collect();
    let mapa_act: BTreeMap<&str, &Entrada> = actual.iter().map(|e| (e.ruta.as_str(), e)).collect();

    let mut inf = Informe::default();
    for (ruta, e_base) in &mapa_base {
        match mapa_act.get(ruta) {
            Some(e_act) => {
                if e_act.hash != e_base.hash || e_act.size != e_base.size {
                    inf.cambiados.push((
                        (*ruta).to_string(),
                        e_base.hash.clone(),
                        e_act.hash.clone(),
                    ));
                }
            }
            None => inf.faltantes.push((*ruta).to_string()),
        }
    }
    for ruta in mapa_act.keys() {
        if !mapa_base.contains_key(ruta) {
            inf.nuevos.push((*ruta).to_string());
        }
    }
    inf
}

#[cfg(test)]
mod prueba {
    use super::*;
    use std::fs;

    fn dir_temp(sufijo: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("zaque-prueba-{}-{}", std::process::id(), sufijo));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    // AGUJA (D33): sellar y re-verificar sin tocar nada → LIMPIO. Si el hash o el
    // recorrido no fueran deterministas, esto fallaría.
    #[test]
    fn sellado_sin_cambios_es_limpio() {
        let d = dir_temp("limpio");
        fs::write(d.join("vmlinuz"), b"kernel-bytes").unwrap();
        fs::create_dir(d.join("loader")).unwrap();
        fs::write(d.join("loader/entry.conf"), b"options ...").unwrap();
        let rutas = vec![d];
        let (sellado, _) = recolectar(&rutas).unwrap();
        let (actual, _) = recolectar(&rutas).unwrap();
        assert!(comparar(&sellado, &actual).limpio());
    }

    // CASO ROJO por la vía real (D33): un byte cambiado en el kernel se caza como
    // CAMBIADO; un archivo nuevo, como NUEVO; uno borrado, como FALTANTE. El mutante
    // sería un `comparar` que solo mirara la ruta y no el hash: este rojo lo mata.
    #[test]
    fn detecta_cambio_nuevo_y_faltante() {
        let d = dir_temp("drift");
        fs::write(d.join("vmlinuz"), b"kernel-bytes").unwrap();
        fs::write(d.join("initramfs"), b"initrd").unwrap();
        let rutas = vec![d.clone()];
        let (sellado, _) = recolectar(&rutas).unwrap();

        // manipular: cambiar vmlinuz, borrar initramfs, añadir un .efi intruso
        fs::write(d.join("vmlinuz"), b"kernel-TROYANO").unwrap();
        fs::remove_file(d.join("initramfs")).unwrap();
        fs::write(d.join("intruso.efi"), b"payload").unwrap();

        let (actual, _) = recolectar(&rutas).unwrap();
        let inf = comparar(&sellado, &actual);
        assert!(!inf.limpio());
        assert_eq!(inf.cambiados.len(), 1, "{inf:?}");
        assert!(inf.cambiados[0].0.ends_with("vmlinuz"));
        assert_eq!(inf.faltantes.len(), 1);
        assert!(inf.faltantes[0].ends_with("initramfs"));
        assert_eq!(inf.nuevos.len(), 1);
        assert!(inf.nuevos[0].ends_with("intruso.efi"));
    }

    // Un symlink redirigido se caza (vector de manipulación del arranque).
    #[cfg(unix)]
    #[test]
    fn symlink_redirigido_se_detecta() {
        use std::os::unix::fs::symlink;
        let d = dir_temp("symlink");
        fs::write(d.join("real-a"), b"a").unwrap();
        fs::write(d.join("real-b"), b"b").unwrap();
        symlink("real-a", d.join("vmlinuz")).unwrap();
        let rutas = vec![d.clone()];
        let (sellado, _) = recolectar(&rutas).unwrap();

        fs::remove_file(d.join("vmlinuz")).unwrap();
        symlink("real-b", d.join("vmlinuz")).unwrap();
        let (actual, _) = recolectar(&rutas).unwrap();
        let inf = comparar(&sellado, &actual);
        assert_eq!(inf.cambiados.len(), 1, "el destino del symlink cambió: {inf:?}");
    }

    // Serializar → parsear es ida y vuelta fiel, y conserva las rutas selladas (D22).
    #[test]
    fn serializar_y_parsear_ida_y_vuelta() {
        let d = dir_temp("roundtrip");
        fs::write(d.join("x"), b"contenido").unwrap();
        let rutas = vec![d];
        let (sellado, _) = recolectar(&rutas).unwrap();
        let texto = serializar(&sellado, &rutas, 123);
        let (reload, rutas_leidas) = parsear(&texto).unwrap();
        assert_eq!(sellado, reload);
        assert_eq!(rutas_leidas, rutas);
    }

    // Una ruta configurada que no existe se omite (no revienta el sellado), pero se
    // reporta — no se traga en silencio (D20/D30).
    #[test]
    fn ruta_inexistente_se_reporta_no_revienta() {
        let (entradas, omitidas) = recolectar(&[PathBuf::from("/zaque-no-existe-jamas")]).unwrap();
        assert!(entradas.is_empty());
        assert_eq!(omitidas.len(), 1);
    }

    // Baseline corrupto falla ruidoso al parsear (no se inventa un estado).
    #[test]
    fn baseline_malformado_falla() {
        assert!(parsear("deadbeef\tsin-tercer-campo").is_err());
        assert!(parsear("hash\tno-numero\truta").is_err());
    }

    // HALLAZGO de la revisión de seguridad (D33, las tres observaciones de una vez):
    // nombres patológicos NO colisionan (bytes no-UTF-8 distintos) NI inyectan separador
    // (`\t`/`\n` en el nombre). El mutante es el código anterior con `display()`: `evil\xfe`
    // y `evil\xff` colapsaban a la misma clave → una entrada se perdía.
    #[cfg(unix)]
    #[test]
    fn nombres_patologicos_no_colisionan_ni_inyectan() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let d = dir_temp("patologico");
        fs::write(d.join(OsStr::from_bytes(b"evil\xfe")), b"A").unwrap();
        fs::write(d.join(OsStr::from_bytes(b"evil\xff")), b"B").unwrap();
        // `\t` y `\n` SÍ son válidos en un nombre de archivo Unix (`/` no): el vector de
        // inyección de separador. Simula una línea de baseline falsa dentro del nombre.
        fs::write(d.join(OsStr::from_bytes(b"inject\there\nfakehash\t0\tfake")), b"C").unwrap();
        let rutas = vec![d];
        let (sellado, _) = recolectar(&rutas).unwrap();
        assert_eq!(sellado.len(), 3, "3 archivos → 3 entradas: {sellado:#?}");
        let claves: std::collections::HashSet<_> = sellado.iter().map(|e| e.ruta.clone()).collect();
        assert_eq!(claves.len(), 3, "claves únicas: sin colisión por codificación con pérdida");
        let texto = serializar(&sellado, &[], 1);
        // Ninguna línea de datos tiene campos de más por un \t inyectado en el nombre.
        for linea in texto.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
            assert_eq!(linea.matches('\t').count(), 2, "inyección de separador: {linea:?}");
            assert!(!linea.contains('\n'));
        }
        let (reload, _) = parsear(&texto).unwrap();
        assert_eq!(sellado, reload, "serializar→parsear fiel con nombres patológicos");
    }

    // Una línea base con la MISMA ruta dos veces (manipulada) se rechaza, en vez de
    // "gana la última" que enmascararía la entrada buena.
    #[test]
    fn baseline_con_ruta_duplicada_falla() {
        assert!(parsear("aaa\t1\t/boot/x\nbbb\t2\t/boot/x\n").is_err());
    }

    // --- Modo EDITOR: la resolución de rutas discrimina (D33) ---

    // AGUJA + CONTROL: toma SOLO las carpetas de editor presentes; una ausente no se
    // inventa (D20) y el ruido no-editor se ignora. El mutante sería un `rutas_de_editor_en`
    // que devolviera todas las candidatas sin filtrar por existencia: este rojo lo mata
    // (windsurf, ausente, no debe salir).
    #[test]
    fn rutas_de_editor_toma_solo_las_presentes() {
        let home = dir_temp("editor-home");
        fs::create_dir_all(home.join(".vscode/extensions")).unwrap();
        fs::create_dir_all(home.join(".cursor/extensions")).unwrap();
        // `.windsurf/extensions` NO se crea → no debe aparecer.
        // ruido: una carpeta que no es de editor → no debe aparecer.
        fs::create_dir_all(home.join(".config/otra-cosa")).unwrap();
        let rutas = rutas_de_editor_en(&home);
        assert_eq!(rutas.len(), 2, "solo las dos presentes: {rutas:?}");
        assert!(rutas.iter().any(|p| p.ends_with(".vscode/extensions")));
        assert!(rutas.iter().any(|p| p.ends_with(".cursor/extensions")));
        assert!(
            !rutas.iter().any(|p| p.to_string_lossy().contains("windsurf")),
            "una carpeta ausente no se inventa"
        );
        assert!(
            !rutas.iter().any(|p| p.to_string_lossy().contains("otra-cosa")),
            "ruido no-editor ignorado"
        );
    }

    // Sin ningún editor instalado, la lista es VACÍA — el llamante (cmd_sellar con
    // --editor) debe fallar ruidoso en vez de sellar un conjunto vacío (D30).
    #[test]
    fn sin_editores_rutas_de_editor_es_vacio() {
        let home = dir_temp("editor-vacio");
        assert!(
            rutas_de_editor_en(&home).is_empty(),
            "ningún editor → vacío, no un baseline falso"
        );
    }

    // EL ESCENARIO DE LA IDEA, de extremo a extremo por el motor real (D28): se sella una
    // extensión instalada y luego un atacante INYECTA un `backdoor.js` post-install y
    // altera un archivo legítimo. zaque caza el backdoor como NUEVO y la alteración como
    // CAMBIADO — que es toda la promesa del tripwire aplicado a la extensión del editor.
    #[test]
    fn backdoor_en_extension_se_detecta_como_nuevo_y_cambiado() {
        let home = dir_temp("editor-backdoor");
        let ext = home.join(".vscode/extensions/vendor.ext-1.0.0");
        fs::create_dir_all(&ext).unwrap();
        fs::write(ext.join("extension.js"), b"codigo legitimo").unwrap();
        let rutas = rutas_de_editor_en(&home);
        assert_eq!(rutas.len(), 1, "una carpeta de editor presente");
        let (sellado, _) = recolectar(&rutas).unwrap();

        // Ataque post-install: un payload nuevo y una modificación del código legítimo.
        fs::write(ext.join("backdoor.js"), b"persistencia ssh").unwrap();
        fs::write(ext.join("extension.js"), b"codigo legitimo + evil").unwrap();

        let (actual, _) = recolectar(&rutas).unwrap();
        let inf = comparar(&sellado, &actual);
        assert_eq!(inf.nuevos.len(), 1, "el backdoor es NUEVO: {inf:?}");
        assert!(inf.nuevos[0].ends_with("backdoor.js"));
        assert_eq!(inf.cambiados.len(), 1, "la extensión alterada: {inf:?}");
        assert!(inf.cambiados[0].0.ends_with("extension.js"));
    }
}
