fn main() {
   windows::build! {
        Windows::Win32::System::Rpc::{UuidFromStringA, RPC_STATUS}
    };
}
