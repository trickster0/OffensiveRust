# Ekko in Rust

A small sleep obfuscation technique that uses the `CreateTimerQueueTimer` Win32 API function ported from C https://github.com/Cracked5pider/Ekko/ to Rust.

## Debugging

For debugging uncomment `env_logger::init();` in main and set Powershell environment variable to `$Env:RUST_LOG="info"`.

## Example

```
PS C:\Users\memN0ps\Documents\GitHub\ekko-rs\target\debug\ekko-rs.exe
[*] Ekko Sleep Obfuscation by @memN0ps and @trickster0. Full credits to Cracked5pider (@C5pider), Austin Hudson (@SecIdiot), Peter Winter-Smith (@peterwintrsmith)
[+] Queue timers
[+] Wait for hEvent
[+] Finished waiting for event
[+] Queue timers
[+] Wait for hEvent
[+] Finished waiting for event
[+] Queue timers
[+] Wait for hEvent
[+] Finished waiting for event
[+] Queue timers
[+] Wait for hEvent
[+] Finished waiting for event
[+] Queue timers
[+] Wait for hEvent
[+] Finished waiting for event
[+] Queue timers
[+] Wait for hEvent
[+] Finished waiting for event
[+] Queue timers
[+] Wait for hEvent
[+] Finished waiting for event
[+] Queue timers
[+] Wait for hEvent
[+] Finished waiting for event
```

## Credits / References

- [@C5pider](https://twitter.com/C5pider) https://github.com/Cracked5pider/Ekko/
- [Austin Hudson (@SecIdiot)](https://twitter.com/ilove2pwn_) https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html / https://web.archive.org/web/20220702162943/https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html
- Originally discovered by [Peter Winter-Smith](peterwintrsmith) and used in MDSec’s Nighthawk
- Thanks for contributing [@trickster012](https://twitter.com/trickster012)
- https://learn.microsoft.com/
- Rust Lang Community Discord: https://discord.com/invite/rust-lang-community ([MaulingMonkey](https://github.com/MaulingMonkey/))