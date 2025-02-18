fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // 假设 gmp.lib 路径为 C:\\path\\to\\gmp\\lib
    let lib_path = "C:\\Users\\lenovo\\vcpkg\\installed\\x64-windows\\lib";
    let include_path = "C:\\Users\\lenovo\\vcpkg\\installed\\x64-windows\\include";

    // 设置库搜索路径
    println!("cargo:rustc-link-search=native={}", lib_path);
    // 设置头文件路径
    println!("cargo:include-dir={}", include_path);

    // 告诉编译器链接 gmp.lib
    println!("cargo:rustc-link-lib=static=gmp");
}

