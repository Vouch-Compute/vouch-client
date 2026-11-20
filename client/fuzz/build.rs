// The update_sig target includes pool-app's update_policy.rs, which reads the app's build time at compile time.
fn main() {
    println!("cargo:rustc-env=APP_BUILD_UNIX_S=1000");
}
