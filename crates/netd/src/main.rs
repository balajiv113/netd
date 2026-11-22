mod switch;

#[cfg(target_os = "linux")]
mod linux;

fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("switch")) {
        if let Err(e) = switch::run(std::env::args().skip(2)) {
            eprintln!("netd: switch: {e}");
            std::process::exit(1);
        }
        return;
    }

    #[cfg(target_os = "linux")]
    linux::main();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("netd: only the experimental switch mode is supported on this platform");
        std::process::exit(2);
    }
}
