use std::{
    env,
    fs::File,
    io::Write,
    path::{Path, PathBuf}, process::Command,
    // process::Command,
};

// use aya_tool::generate::InputFile;

fn main() {
    // env::set_var("RUSTFLAGS", "-Z unstable-options");
    // println!("cargo:rerun-if-changed=build.rs");

    // // let out_dir = env::var("OUT_DIR").unwrap();
    // // let out_dir = "src";

    // let out_dir = env::var("OUT_DIR").unwrap();
    // println!("{:?}",out_dir);


    // let _ = Command::new("clang")
    //     .arg("-I")
    //     .arg("src/")
    //     .arg("-O2")
    //     .arg("-emit-llvm")
    //     .arg("-target")
    //     .arg("bpf")
    //     .arg("-c")
    //     .arg("-g")
    //     .arg("src/vmlinux_access.c")
    //     .arg("-o")
    //     .arg(format!("{out_dir}/vmlinux_access.o"))
    //     .status()
    //     .expect("Failed to compile the C-shim");

    // println!("cargo:rustc-link-search=native={out_dir}");
    // println!("cargo:rustc-link-lib=link-arg={out_dir}/vmlinux_access.o");
    // println!("cargo:rerun-if-changed=src/vmlinux_access.c");
}
