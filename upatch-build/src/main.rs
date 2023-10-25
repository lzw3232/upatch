mod cmd;
mod dwarf;
mod elf;
mod log;
mod ffi;
mod tool;
mod upatch;

fn main() {
    let mut upatch = upatch::UpatchBuild::new();
    std::process::exit(match upatch.run() {
        Ok(_) => {
            println!("SUCCESS!");
            0
        }
        Err(e) => {
            match log::Logger::is_inited() {
                true => log::error!("{}", e),
                false => eprintln!("ERROR: {}", e),
            };
            e.code()
        }
    });
}
