// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Juan Carlos Isaza
//
//! zaque — detector de integridad de la cadena de arranque.
//!
//! Compensa, por DETECCIÓN, lo que Secure Boot haría por PREVENCIÓN cuando está
//! apagado: sella un hash de la cadena de arranque (`/boot`: kernel, initramfs, grub,
//! entradas BLS, ESP) y avisa si algo cambió entre reinicios. No previene el manipuleo
//! —eso es SB/FDE/TPM—; lo hace EVIDENTE.
//!
//! Uso:
//!   zaque sellar    [BASELINE] [--ruta P]...   # fija la línea base (tras un boot sano)
//!   zaque verificar [BASELINE] [--ruta P]...   # compara; exit 0 limpio, 2 si hay deriva
//!
//! BASELINE por defecto: /var/lib/zaque/linea-base.txt
//! Códigos de salida: 0 = limpio · 2 = DERIVA detectada · 3 = error de E/S · 1 = uso.

mod integridad;
mod sha256;

use integridad::{
    baseline_editor, comparar, parsear, recolectar, rutas_de_editor, rutas_por_defecto, serializar,
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const BASELINE_DEFECTO: &str = "/var/lib/zaque/linea-base.txt";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match ejecutar(&args) {
        Ok(codigo) => codigo,
        Err(e) => {
            eprintln!("zaque: error: {e}");
            ExitCode::from(3)
        }
    }
}

fn ejecutar(args: &[String]) -> std::io::Result<ExitCode> {
    let mut posicionales: Vec<&str> = Vec::new();
    let mut rutas_cli: Vec<PathBuf> = Vec::new();
    let mut modo_editor = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ruta" => {
                let p = it.next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "--ruta necesita un argumento")
                })?;
                rutas_cli.push(PathBuf::from(p));
            }
            "--editor" => modo_editor = true,
            "-h" | "--help" | "ayuda" => {
                imprimir_ayuda();
                return Ok(ExitCode::SUCCESS);
            }
            otro => posicionales.push(otro),
        }
    }

    let Some(sub) = posicionales.first() else {
        imprimir_ayuda();
        return Ok(ExitCode::from(1));
    };

    // La línea base: explícita si se dio como posicional; si no, la de EDITOR con --editor,
    // o la de arranque por defecto. Separadas a propósito (otra cadencia de re-sellado).
    let baseline = match posicionales.get(1).copied() {
        Some(p) => PathBuf::from(p),
        None if modo_editor => baseline_editor()?,
        None => PathBuf::from(BASELINE_DEFECTO),
    };

    // En modo editor, SELLAR sin --ruta descubre las carpetas de extensiones presentes
    // (VERIFICAR usa el conjunto que ya viaja en la cabecera de la línea base, D22).
    if modo_editor && *sub == "sellar" && rutas_cli.is_empty() {
        let rutas_editor = rutas_de_editor()?;
        if rutas_editor.is_empty() {
            // Sin editores no se sella un conjunto vacío (falso verde permanente, D30);
            // se dice qué se buscó, no se cae al defecto /boot en silencio.
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no se encontró ninguna carpeta de extensiones de editor bajo $HOME \
                 (.vscode/.cursor/.windsurf/.vscode-server/.vscode-oss) — ¿ningún editor instalado?",
            ));
        }
        rutas_cli = rutas_editor;
    }

    match *sub {
        "sellar" => cmd_sellar(&baseline, &rutas_cli),
        "verificar" => cmd_verificar(&baseline, &rutas_cli),
        otro => {
            eprintln!("zaque: subcomando desconocido: {otro}");
            imprimir_ayuda();
            Ok(ExitCode::from(1))
        }
    }
}

fn cmd_sellar(baseline: &PathBuf, rutas_cli: &[PathBuf]) -> std::io::Result<ExitCode> {
    let rutas = if rutas_cli.is_empty() { rutas_por_defecto() } else { rutas_cli.to_vec() };
    let (entradas, omitidas) = recolectar(&rutas)?;
    if entradas.is_empty() {
        // Sellar un baseline VACÍO sería un falso verde permanente (D30): todo
        // "verificar" futuro saldría limpio sin mirar nada. Se rechaza ruidoso.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "0 archivos bajo {:?} — no se sella un baseline vacío (¿rutas mal? ¿sin permiso de root?)",
                rutas
            ),
        ));
    }
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let texto = serializar(&entradas, &rutas, epoch);
    if let Some(padre) = baseline.parent() {
        if !padre.as_os_str().is_empty() {
            std::fs::create_dir_all(padre)?;
        }
    }
    std::fs::write(baseline, texto)?;
    println!("zaque: sellados {} archivos en {}", entradas.len(), baseline.display());
    for o in &omitidas {
        println!("  (ruta omitida, no existe: {o})");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_verificar(baseline: &PathBuf, rutas_cli: &[PathBuf]) -> std::io::Result<ExitCode> {
    let texto = std::fs::read_to_string(baseline).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("no se pudo leer la línea base {} ({e}) — ¿sellaste primero?", baseline.display()),
        )
    })?;
    let (sellado, rutas_selladas) = parsear(&texto)?;
    // Se verifica el MISMO conjunto que se selló (D22), salvo que el usuario lo acote.
    let rutas = if !rutas_cli.is_empty() {
        rutas_cli.to_vec()
    } else if !rutas_selladas.is_empty() {
        rutas_selladas
    } else {
        rutas_por_defecto()
    };
    let (actual, _omitidas) = recolectar(&rutas)?;
    let inf = comparar(&sellado, &actual);

    if inf.limpio() {
        println!("zaque: INTEGRO — {} archivos coinciden con la línea base", sellado.len());
        return Ok(ExitCode::SUCCESS);
    }

    eprintln!("zaque: ⚠ DERIVA DETECTADA respecto de la línea base");
    for (ruta, viejo, nuevo) in &inf.cambiados {
        eprintln!("  CAMBIADO  {ruta}");
        eprintln!("            sellado: {viejo}");
        eprintln!("            actual : {nuevo}");
    }
    for ruta in &inf.faltantes {
        eprintln!("  FALTANTE  {ruta}");
    }
    for ruta in &inf.nuevos {
        eprintln!("  NUEVO     {ruta}");
    }
    eprintln!(
        "zaque: {} cambiados · {} faltantes · {} nuevos",
        inf.cambiados.len(),
        inf.faltantes.len(),
        inf.nuevos.len()
    );
    Ok(ExitCode::from(2))
}

fn imprimir_ayuda() {
    eprintln!(
        "zaque — detector de integridad por línea base de hashes\n\n\
         uso:\n  \
         zaque sellar    [BASELINE] [--ruta P]... [--editor]   fija la línea base (tras un estado sano)\n  \
         zaque verificar [BASELINE] [--ruta P]... [--editor]   compara; exit 0 limpio, 2 si hay deriva\n\n\
         ARRANQUE (por defecto): vigila /boot entero (kernel, initramfs, grub, BLS, ESP)\n  \
         BASELINE: {BASELINE_DEFECTO}\n\n\
         --editor: vigila las extensiones de los editores instalados (VS Code, Cursor,\n  \
         \x20        Windsurf, VSCodium, VS Code Server) bajo $HOME — el tripwire aplicado a\n  \
         \x20        la cadena de suministro del editor (un backdoor inyectado post-install\n  \
         \x20        aparece como NUEVO). Línea base separada en ~/.local/state/zaque/.\n  \
         \x20        Tras actualizar extensiones (cambio legítimo), re-sella."
    );
}
