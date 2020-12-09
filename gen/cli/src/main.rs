use gen::{
    score,
    Generator,
};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct Opt {
    #[structopt(short, long)]
    pub simple: bool,
    /// Set length
    #[structopt(short, long, default_value = "20")]
    pub len: usize,
    /// Set quantity
    #[structopt(short, long, default_value = "1")]
    pub qty: usize,
}

fn main() {
    let opt = Opt::from_args();
    for _ in 0..opt.qty {
        let pass = if opt.simple {
            Generator::simple(opt.len)
        } else {
            Generator::std(opt.len)
        };
        let score = score(pass.clone());
        println!(
            "Password Generated: {}\n Password Strength: {}",
            pass, score
        );
    }
}
