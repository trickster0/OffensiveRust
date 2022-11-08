#[cfg(all(feature = "_DIRECT_", feature = "_INDIRECT_"))]
compile_error!("\t [!] RUST_SYSCALLS ERROR: feature \"_DIRECT_\" and feature \"_INDIRECT_\" cannot be enabled at the same time");

#[cfg(not(any(feature = "_DIRECT_", feature = "_INDIRECT_")))]
compile_error!(
    "\t [!] RUST_SYSCALLS ERROR: feature \"_DIRECT_\" or feature \"_INDIRECT_\" must be enabled"
);

pub mod obf;
pub mod syscall;
pub mod syscall_resolve;
