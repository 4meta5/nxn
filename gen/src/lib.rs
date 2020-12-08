//! Password Generation Utilities
use rand::{
    seq::SliceRandom,
    thread_rng,
    Rng,
};

fn shuffle(s: &str) -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = s.to_string().into_bytes();
    bytes.shuffle(&mut rng);
    String::from_utf8(bytes).unwrap()
}

pub struct Generator;

impl Generator {
    pub fn simple(len: usize) -> String {
        let mut rng = thread_rng();
        let mut space_left = len;
        let lower = rng.gen_range(1, len - 3);
        space_left -= lower;
        let upper = rng.gen_range(1, space_left - 2);
        space_left -= upper;
        let number = space_left;
        let mut ret = String::new();
        for _ in 0..lower {
            let u = A::LOWER.as_bytes()[rng.gen_range(1, A::LOWER.len())];
            let v = u as char;
            ret.push(v);
        }
        for _ in 0..upper {
            let w = A::UPPER.as_bytes()[rng.gen_range(1, A::UPPER.len())];
            let x = w as char;
            ret.push(x);
        }
        for _ in 0..number {
            let y = A::NUMBERS.as_bytes()[rng.gen_range(1, A::NUMBERS.len())];
            let z = y as char;
            ret.push(z);
        }
        shuffle(&ret)
    }
    pub fn std(len: usize) -> String {
        let mut rng = thread_rng();
        let mut space_left = len;
        let lower = rng.gen_range(1, len - 3);
        space_left -= lower;
        let upper = rng.gen_range(1, space_left - 2);
        space_left -= upper;
        let number = rng.gen_range(1, space_left - 1);
        space_left -= number;
        let symbol = space_left;
        let mut ret = String::new();
        for _ in 0..lower {
            let u = A::LOWER.as_bytes()[rng.gen_range(1, A::LOWER.len())];
            let v = u as char;
            ret.push(v);
        }
        for _ in 0..upper {
            let w = A::UPPER.as_bytes()[rng.gen_range(1, A::UPPER.len())];
            let x = w as char;
            ret.push(x);
        }
        for _ in 0..number {
            let y = A::NUMBERS.as_bytes()[rng.gen_range(1, A::NUMBERS.len())];
            let z = y as char;
            ret.push(z);
        }
        for _ in 0..symbol {
            let r = A::SYMBOLS.as_bytes()[rng.gen_range(1, A::SYMBOLS.len())];
            let s = r as char;
            ret.push(s);
        }
        shuffle(&ret)
    } // consider writing std_no_space
}

/// Password Strength Score
/// >output ranges from 0-50
/// 0  - matches/contains common passwords
/// 5  - length < 5 characters
/// 10 - length < 9 characters
/// 20 - does not contain lowercase, uppercase or number
/// 30 - does not contain symbol
/// 40 - length < 15 characters
/// 50 - everything else right now
pub fn score(s: String) -> u8 {
    let mut score = 0u8;
    if common_password(&s) {
        return score
    }
    score += 5u8;
    if s.len() <= 4usize {
        return score
    }
    score += 5u8;
    let f: Frequency = s.into();
    let d: Distribution = f.into();
    if d.all.total <= 8usize {
        return score
    }
    score += 10u8;
    if d.upper.total == 0 || d.lower.total == 0 || d.number.total == 0 {
        return score
    }
    score += 10u8;
    if d.symbol.total == 0 {
        return score
    }
    score += 10u8;
    if d.all.total <= 14usize {
        return score
    }
    score += 10u8;
    score
}

pub struct A;
impl A {
    const LOWER: &'static str = "abcdefghijklmnopqrstuvwxyz";
    const UPPER: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const NUMBERS: &'static str = "0123456789";
    // space is a symbol (it may need to be taken out to generate passwords for some forms)
    const SYMBOLS: &'static str = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
}

pub struct Frequency {
    pub lower: (usize, Vec<char>),
    pub upper: (usize, Vec<char>),
    pub number: (usize, Vec<char>),
    pub symbol: (usize, Vec<char>),
}

impl Frequency {
    fn new() -> Frequency {
        Frequency {
            lower: (0usize, Vec::new()),
            upper: (0usize, Vec::new()),
            number: (0usize, Vec::new()),
            symbol: (0usize, Vec::new()),
        }
    }
    pub fn add(&mut self, c: char) {
        if A::LOWER.contains(c) {
            if !self.lower.1.contains(&c) {
                self.lower.0 += 1usize;
            }
            self.lower.1.push(c);
        } else if A::UPPER.contains(c) {
            if !self.upper.1.contains(&c) {
                self.upper.0 += 1usize;
            }
            self.upper.1.push(c);
        } else if A::NUMBERS.contains(c) {
            if !self.number.1.contains(&c) {
                self.number.0 += 1usize;
            }
            self.number.1.push(c);
        } else if A::SYMBOLS.contains(c) {
            if !self.symbol.1.contains(&c) {
                self.symbol.0 += 1usize;
            }
            self.symbol.1.push(c);
        }
    }
}

impl From<String> for Frequency {
    fn from(s: String) -> Frequency {
        let mut ret = Frequency::new();
        for c in s.chars() {
            ret.add(c);
        }
        ret
    }
}

#[derive(Default)]
pub struct Freq {
    pub total: usize,
    pub uneeq: usize,
}

impl Freq {
    pub fn new(total: usize, uneeq: usize) -> Self {
        Freq { total, uneeq }
    }
}

#[derive(Default)]
pub struct Distribution {
    pub all: Freq,
    pub lower: Freq,
    pub upper: Freq,
    pub number: Freq,
    pub symbol: Freq,
}

impl From<Frequency> for Distribution {
    fn from(f: Frequency) -> Distribution {
        let all_t = f.lower.1.len()
            + f.upper.1.len()
            + f.number.1.len()
            + f.symbol.1.len();
        let all_u = f.lower.0 + f.upper.0 + f.number.0 + f.symbol.0;
        Distribution {
            all: Freq::new(all_t, all_u),
            lower: Freq::new(f.lower.1.len(), f.lower.0),
            upper: Freq::new(f.upper.1.len(), f.upper.0),
            number: Freq::new(f.number.1.len(), f.number.0),
            symbol: Freq::new(f.symbol.1.len(), f.symbol.0),
        }
    }
}

/// Matches or contains common passwords
pub fn common_password(s: &str) -> bool {
    s.contains("password")
        || s.contains("123456789")
        || s.contains("qwertyuio")
        || s.contains("asdfghjk")
        || s.contains("zxcvbnm")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passgen_behaves() {
        // 4 fails because not enough entropy
        let cx = Generator::simple(5usize);
        assert!(cx.len() == 5usize);
        assert!(score(cx) == 10);
        let dx = Generator::std(5usize);
        assert!(dx.len() == 5usize);
        assert!(score(dx) == 10);
        let ax = Generator::simple(53usize);
        assert!(ax.len() == 53usize);
        assert!(score(ax) == 30);
        let bx = Generator::std(96usize);
        assert!(bx.len() == 96usize);
        assert!(score(bx) == 50);
    }
    #[test]
    fn lossless_shuffle() {
        let xa = "abcdefghijklmnopqrstuvwxyz";
        let xb = shuffle(xa);
        for xc in xa.chars() {
            assert!(xb.contains(xc));
        }
        assert!(xb.len() == xa.len());
        let xd = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let xe = shuffle(xd);
        for xf in xd.chars() {
            assert!(xe.contains(xf));
        }
        assert!(xd.len() == xe.len());
        let xg = "0123456789";
        let xh = shuffle(xg);
        for xi in xg.chars() {
            assert!(xh.contains(xi));
        }
        assert!(xg.len() == xh.len());
        let xj = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        let xk = shuffle(xj);
        for xl in xj.chars() {
            assert!(xk.contains(xl));
        }
        assert!(xj.len() == xk.len());
    }
    #[test]
    fn contains_literal_password() {
        let a = common_password("chbwsukberi2bv2eivbwwbviobvbwvb2chbuvowecu2u2bf2buekvcbewuvpasswordvwehgkcjgf2ivwijkwhcwvkvwgjkwfw");
        assert!(a);
        let b = common_password("chbwsukberi2bv2eivbwwbviobvbwvb2chbuvowecu2u2bf2buekvcbewuvwehgkcjgf2ivwijkwhcwvkvwgjkwfw");
        assert!(!b);
    }
    #[test]
    fn freq_check() {
        // TODO: convert to prop-tests
        let s = String::from("abcabc");
        let f: Frequency = s.into();
        let d: Distribution = f.into();
        assert!(d.all.total == d.lower.total);
        assert!(d.all.uneeq == d.lower.uneeq);
        assert!(d.all.total == 6usize);
        assert!(d.all.uneeq == 3usize);
        assert!(d.upper.total == 0usize);
        assert!(d.number.total == 0usize);
        assert!(d.symbol.total == 0usize);
        let s2 = String::from("abc123");
        let f2: Frequency = s2.into();
        let d2: Distribution = f2.into();
        let d21 = d2.lower.total + d2.number.total;
        let d22 = d2.lower.uneeq + d2.number.uneeq;
        assert!(d2.all.total == d21);
        assert!(d2.all.uneeq == d22);
        assert!(d2.all.total == 6usize);
        assert!(d2.all.uneeq == 6usize);
        assert!(d2.lower.total == 3usize);
        assert!(d2.number.total == 3usize);
        assert!(d2.upper.total == 0usize);
        assert!(d2.symbol.total == 0usize);
        let s3 = String::from("abc123XYZ");
        let f3: Frequency = s3.into();
        let d3: Distribution = f3.into();
        let d31 = d3.lower.total + d3.number.total + d3.upper.total;
        let d32 = d3.lower.uneeq + d3.number.uneeq + d3.upper.uneeq;
        assert!(d3.all.total == d31);
        assert!(d3.all.uneeq == d32);
        assert!(d3.all.total == 9usize);
        assert!(d3.all.uneeq == 9usize);
        assert!(d3.lower.total == 3usize);
        assert!(d3.upper.total == 3usize);
        assert!(d3.number.total == 3usize);
        assert!(d3.symbol.total == 0usize);
        let s4 = String::from("abc123XYZ $!");
        let f4: Frequency = s4.into();
        let d4: Distribution = f4.into();
        let d41 =
            d4.lower.total + d4.number.total + d4.upper.total + d4.symbol.total;
        let d42 =
            d4.lower.uneeq + d4.number.uneeq + d4.upper.uneeq + d4.symbol.uneeq;
        assert!(d4.all.total == d41);
        assert!(d4.all.uneeq == d42);
        assert!(d4.all.total == 12usize);
        assert!(d4.all.uneeq == 12usize);
        assert!(d4.lower.total == 3usize);
        assert!(d4.upper.total == 3usize);
        assert!(d4.number.total == 3usize);
        assert!(d4.symbol.total == 3usize);
    }
    #[test]
    fn score_check() {
        let a = score("chbwsukberi2bv2eivbwwbviobvbwvb2chbuvowecu2u2bf2buekvcbewuvpasswordvwehgkcjgf2ivwijkwh cwvkvwgjkwfw".to_string());
        assert!(a == 0u8);
        let a0 = score("wxyz".to_string());
        assert!(a0 == 5u8);
        let b = score("chbwsukb".to_string());
        assert!(b == 10u8);
        let c = score("chbwsukberi2bv2eivbwwbviobvbwvb2chbuvowecu2u2bf2buekvcbewuvwehgkcjgf2ivwijkwh cwvkvwgjkwfw".to_string());
        assert!(c == 20u8);
        let d = score("chbwsukber2bV3884shdhhjdshjdbjcjhDGGDGD".to_string());
        assert!(d == 30u8);
        let e = score("chbwsukber2bV$".to_string());
        assert!(e == 40u8);
        let f = score("chbwsukber2bV$s".to_string());
        assert!(f == 50u8);
        // this is an example of a bad password with the highest rating (points to limitations of the score function)
        let g = score("ssssssssss5sS$s".to_string());
        assert!(g == 50u8);
    }
}
