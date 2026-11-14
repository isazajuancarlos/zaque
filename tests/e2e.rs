// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Juan Carlos Isaza
//
//! E2E (D28): arranca el BINARIO real y le habla como el mundo —argumentos y códigos
//! de salida—, sobre un `/boot` simulado en un directorio temporal. Mide el producto
//! (el flujo sellar→verificar→código de salida), no las funciones internas.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_zaque")
}

fn temp(sufijo: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("zaque-e2e-{}-{}", std::process::id(), sufijo));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Monta un /boot simulado con kernel, initramfs y una entrada BLS.
fn boot_simulado(d: &Path) {
    fs::write(d.join("vmlinuz-6.1"), b"kernel real").unwrap();
    fs::write(d.join("initramfs-6.1.img"), b"initramfs real").unwrap();
    fs::create_dir_all(d.join("loader/entries")).unwrap();
    fs::write(d.join("loader/entries/fedora.conf"), b"options root=UUID=...").unwrap();
    fs::create_dir_all(d.join("efi/EFI/fedora")).unwrap();
    fs::write(d.join("efi/EFI/fedora/shimx64.efi"), b"shim bytes").unwrap();
}

#[test]
fn flujo_sellar_integro_y_deriva() {
    let d = temp("flujo");
    let boot = d.join("boot");
    fs::create_dir_all(&boot).unwrap();
    boot_simulado(&boot);
    let baseline = d.join("linea-base.txt");

    // sellar → exit 0, baseline escrito
    let s = Command::new(bin())
        .args(["sellar", baseline.to_str().unwrap(), "--ruta", boot.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(s.status.success(), "sellar debió salir 0: {s:?}");
    assert!(baseline.exists(), "la línea base debe existir");

    // verificar sin tocar nada → exit 0 (INTEGRO), usando las rutas selladas
    let v = Command::new(bin()).args(["verificar", baseline.to_str().unwrap()]).output().unwrap();
    assert_eq!(v.status.code(), Some(0), "verificar limpio debe ser 0: {v:?}");
    assert!(String::from_utf8_lossy(&v.stdout).contains("INTEGRO"));

    // MANIPULAR el shim (el vector real: reemplazar el cargador de la ESP)
    fs::write(boot.join("efi/EFI/fedora/shimx64.efi"), b"shim TROYANIZADO").unwrap();

    // verificar → exit 2 (DERIVA), y nombra el archivo cambiado
    let v2 = Command::new(bin()).args(["verificar", baseline.to_str().unwrap()]).output().unwrap();
    assert_eq!(v2.status.code(), Some(2), "deriva debe ser exit 2: {v2:?}");
    let err = String::from_utf8_lossy(&v2.stderr);
    assert!(err.contains("DERIVA"), "{err}");
    assert!(err.contains("shimx64.efi"), "debe nombrar el archivo manipulado: {err}");
}

#[test]
fn verificar_sin_baseline_sale_3() {
    let d = temp("sinbase");
    let baseline = d.join("no-existe.txt");
    let v = Command::new(bin()).args(["verificar", baseline.to_str().unwrap()]).output().unwrap();
    assert_eq!(v.status.code(), Some(3), "baseline ausente debe ser error (exit 3): {v:?}");
}

// --- Modo EDITOR por la frontera del programa (D28): --editor descubre las carpetas
// de extensiones bajo $HOME, usa una línea base SEPARADA, y caza un backdoor inyectado. ---
#[test]
fn editor_flujo_sella_descubre_y_caza_backdoor() {
    let d = temp("editor-flujo");
    let home = d.join("home");
    let ext = home.join(".vscode/extensions/vendor.ext-1.0.0");
    fs::create_dir_all(&ext).unwrap();
    fs::write(ext.join("extension.js"), b"codigo legitimo").unwrap();
    let state = d.join("state"); // XDG_STATE_HOME: donde cae la línea base de editor
    let baseline = state.join("zaque/extensiones-editor.txt");

    // sellar --editor (sin --ruta: descubre) → exit 0, baseline separado escrito
    let s = Command::new(bin())
        .args(["sellar", "--editor"])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state)
        .output()
        .unwrap();
    assert!(s.status.success(), "sellar --editor debió salir 0: {s:?}");
    assert!(baseline.exists(), "la línea base de editor debe caer en XDG_STATE_HOME: {baseline:?}");

    // verificar --editor sin tocar nada → 0
    let v = Command::new(bin())
        .args(["verificar", "--editor"])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state)
        .output()
        .unwrap();
    assert_eq!(v.status.code(), Some(0), "editor íntegro debe ser 0: {v:?}");

    // Ataque post-install: inyectar un backdoor en la extensión
    fs::write(ext.join("backdoor.js"), b"persistencia ssh").unwrap();
    let v2 = Command::new(bin())
        .args(["verificar", "--editor"])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state)
        .output()
        .unwrap();
    assert_eq!(v2.status.code(), Some(2), "backdoor debe dar deriva (exit 2): {v2:?}");
    let err = String::from_utf8_lossy(&v2.stderr);
    assert!(err.contains("backdoor.js"), "debe nombrar el backdoor: {err}");
}

#[test]
fn editor_sin_editores_falla_ruidoso_y_no_sella_boot() {
    let d = temp("editor-sin");
    let home = d.join("home-sin-editores");
    fs::create_dir_all(&home).unwrap(); // $HOME existe pero SIN carpetas de editor
    let state = d.join("state");
    let baseline = state.join("zaque/extensiones-editor.txt");

    let s = Command::new(bin())
        .args(["sellar", "--editor"])
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state)
        .output()
        .unwrap();
    // Sin editores NO se cae al defecto /boot ni se sella vacío: falla ruidoso (exit 3).
    assert_eq!(s.status.code(), Some(3), "sin editores debe fallar ruidoso: {s:?}");
    assert!(!baseline.exists(), "no debe escribir una línea base de editor vacía");
    let err = String::from_utf8_lossy(&s.stderr);
    assert!(err.contains("extensiones de editor"), "el error debe decir qué buscó: {err}");
}

#[test]
fn sellar_ruta_vacia_rechaza() {
    let d = temp("vacio");
    let vacio = d.join("sin-nada");
    fs::create_dir_all(&vacio).unwrap();
    let baseline = d.join("b.txt");
    // Un directorio existente pero SIN archivos → 0 entradas → se rechaza (no falso verde).
    let s = Command::new(bin())
        .args(["sellar", baseline.to_str().unwrap(), "--ruta", vacio.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(s.status.code(), Some(3), "sellar vacío debe fallar ruidoso: {s:?}");
    assert!(!baseline.exists(), "no debe escribir un baseline vacío");
}
