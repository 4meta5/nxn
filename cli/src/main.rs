use gen::Generator;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct Opt {
    #[structopt(short, long)]
    pub simple: bool,
    /// Set length
    #[structopt(short, long, default_value = "20")]
    pub len: usize,
}

fn main() {
    let opt = Opt::from_args();
    let pass = if opt.simple {
        Generator::simple(opt.len)
    } else {
        Generator::std(opt.len)
    };
    println!("Password Generated: {}", pass);
}
