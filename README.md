# nxn

`nxn-cli` is minimal now and only supports password generation.

```bash
% ./nxn-cli -h   
nxn-cli 0.1.0

USAGE:
    nxn-cli [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -s, --simple     
    -V, --version    Prints version information

OPTIONS:
    -l, --len <len>    Set length [default: 20]
```

You can set the length of the generated password and pass the `-s` flag if the password can only be comprised of letters and numbers (no symbols). This is a dumb requirement, but I've seen it enough to add the flag.

Example queries:
```bash
% ./nxn-cli -l=10 -s
Password Generated: c3Lqf2b58n
% ./nxn-cli -l=20 -s
Password Generated: S7L48V56n7R7HZR8EMYk
% ./nxn-cli -l=30 -s
Password Generated: Fn67r2bSjNkuUyBkdVv7FZeCMIRCIT
% ./nxn-cli -l=30   
Password Generated: NV12%Q2N325nOYOqH64qTIrn2c3f;H
% ./nxn-cli -l=30
Password Generated: ,b~Y[Thrx]1pydzVOPpw~vpfn`%9vl
% ./nxn-cli -l=30
Password Generated: P:JyVT}I5@;KTB~G\6R4O[uWFG`o=2
```

`nxn-store` is a password authenticated local store that requires a user set password of strength `>=10` (*strength* as defined in `nxn-gen::score`)