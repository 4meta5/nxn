use gen::Generator;

fn main() {
    println!("A Few Example Passwords Generated by YOUR OS");
    for _ in 0..20 {
        let x = Generator::std(30usize);
        println!("{}", x);
    }
}