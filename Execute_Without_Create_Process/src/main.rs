use std::process::Command;

fn main() {
    //executes process via cmd in the same process context with .output
    if let Ok(command) = Command::new("cmd").arg("/c").arg("dir").output() {
        println!("{}",String::from_utf8_lossy(&command.stdout))
    }
    //Spawns a new process with .spawn
    Command::new("notepad").spawn();
}
