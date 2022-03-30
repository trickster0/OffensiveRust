#[macro_use]
extern crate litcrypt;

// Call the litcrypt method first...
use_litcrypt!();

fn main(){
    
    let payload_url: String = "http://fancyladsnacks.local/definitelymalware.exe".to_string();
    let evil_password: String = "OhNoPayUsBitcoin!@#".to_string();

    // If I want to encrypt a literal string, I can use the lc!() macro. This and the use_litcrypt() method will encrypt anything that is passed as the argument.
    let _can_you_see_me: String = lc!("Can you see me?");
    // You will not see the above string in the bin once it is compiled. You WILL see this one, because we aren't using the lc!() macro:
    let _or_can_you_see_me: String = "Or can you see me?".to_string();

    println!("[!] Unencrypted Strings:");

    println!("\t[*] Downloading evil thing from {}", payload_url);
    println!("\t[*] Encrypting all ur filez with password: {}", evil_password);
    println!("\t[-] These strings appear in the binary statically. Run strings and grep for them, they are in there.");

    println!("\n[!] Encrypted Strings using the lc! macro:");

    println!("\t[*] Downloading evil thing from: {}", lc!("http://freetshirts.info.local/superevilthingmuhahahaha.exe"));
    println!("\t[*] Encrypting all ur filez with password: {}", lc!("ThisIsTheEncryptionKeyToYourData123!@#"));
    println!("\t[+] The evil URL and password strings are encrypted and don't appear statically in the binary! They also don't appear in memory until they are used. Run strings and grep for the URL and encryption key to check");


    println!("\n[?] Can I define variables and encrypt them using Litcrypt?\n[A] Nope! You can't use litcrypt to encrypt anything that will not be known at runtime.\n[A] Just like its name suggests, you can only encrypt literal strings. Not variables, raw strings, concatenated strings, or formatted strings.\n[>] Trying to encrypt the same strings but using their defined variables instead of the string literals prints out the value \"unknown\":");

    println!("\t[+] Downloading evil thing from {}", lc!(payload_url));
    println!("\t[+] Encrypting all ur filez with password: {}", lc!(evil_password));

    println!("\n[!] Try using strings to find the two other strings in this program, \"Can you see me?\" and \"Or can you see me?\" (other than in this string, of course). Which one is litcrypted?")

}

// You can imagine a whole bunch of other evil stuff in here:

    // fn download_and_run_evil_thing() { .....

    // fn solemly_swear_up_to_no_good() { ......

    // ... and all of the strings of these functions can use litcrypt to evade static analyzers.
