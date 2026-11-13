// SPDX-License-Identifier: CC0-1.0

fn main() {
    // OnCallWorlds patch: every clock_gettime in the binary goes through ocw_clock's shim,
    // which shifts CLOCK_REALTIME into the seeded incident window.
    println!("cargo:rustc-link-arg-bins=-Wl,--wrap=clock_gettime");
}
