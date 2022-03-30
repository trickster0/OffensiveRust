# [Litcrypt](https://github.com/anvie/litcrypt.rs)
This one takes some explanation.

During the OffensiveNotion dev process, Taggart and I found the Litcrypt crate useful in encrypting the literal strings of our agent binary both at rest and in memory. Litcrypt encrypts strings and decrypts them only when they are used. This is useful to conceal strings and retain OPSEC during operations.

## How To
Litcrypt needs an environment variable set in order to encrypt the strings during compilation. You can set this by entering the following in Linux:

```
$ export LITCRYPT_ENCRYPT_KEY="OffensiveRustRules"
```
Then, reopen Visual Studio Code and the Rust Analyzer will recognize that Litcrypt is in use:
```
$ code .
```

Once that env var is set, it's as simple as the usual `cargo build`. You will get a gross error message if the encryption key can't be applied from the env var.

Then, run strings against the binary and look at the ones that show up and the ones that don't.

