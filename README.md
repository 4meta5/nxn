# nxn

password manager components

- [x] password generator cli (`./gen/cli`)
- [x] password authenticated local storage (`./store`)
- [ ] store (encrypted) credentials
- [ ] store (encrypted) files

## modules

password generation cli (`./gen/cli`)

```
% ./nxn-gen -h        
nxn-gen 0.1.0

USAGE:
    nxn-gen [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -s, --simple     
    -V, --version    Prints version information

OPTIONS:
    -l, --len <len>    Set length [default: 20]
    -q, --qty <qty>    Set quantity [default: 1]
```

You can set the length, quantity, and complexity of the generated password. The default is for the tool to generate one password of length 20 that may include letters, numbers, and symbols.

```
% ./nxn-gen   
Password Generated: j2GVfk.XmHPTpx=gP1U<
 Password Strength: 50
% ./nxn-gen
Password Generated: YDJ)FXTR*ZKRsV3PDTL2
 Password Strength: 50
% ./nxn-gen
Password Generated: (CxU)P)uOM#Sp!gn,3;e
 Password Strength: 50
```

You can pass the `-s` flag if the password can only be comprised of letters and numbers (no symbols). This is a dumb requirement, but I've seen it enough to add the flag. 

```
% ./nxn-gen -s
Password Generated: i6Vw1b37Zbj58u9qzqdf
 Password Strength: 30
% ./nxn-gen -s
Password Generated: N3CqQQYJ72mQ9cKIQmqG
 Password Strength: 30
% ./nxn-gen -s
Password Generated: 129mgrmrltpLyfdsikim
 Password Strength: 30
```

Naturally, password strength suffers when we place restrictions on the alphabet. Setting small length restrictions has the same effect.

```
% ./nxn-gen -s -l=5
Password Generated: 6d16G
 Password Strength: 10
% ./nxn-gen -s -l=5
Password Generated: 976Br
 Password Strength: 10
% ./nxn-gen -s -l=5
Password Generated: 38X1o
 Password Strength: 10
```

Here's how to generate 10 passwords of length 30, which can contain any letter, number, or symbol.

```
./nxn-gen -l=30 -q=10 
Password Generated: nl7sh*vbnlwjgchhrlelrhjdr{Qnrc
 Password Strength: 50
Password Generated: M3w4-|UpsNZ81?5N_B79pG'4QfXS2R
 Password Strength: 50
Password Generated: fMrvpCJ=YF3[ioG7uk5vm4ncoffpgQ
 Password Strength: 50
Password Generated: 6clqhwu1zzeliccjgQUyc,vpx\eekh
 Password Strength: 50
Password Generated: Y6eSuddZIPrz}dQerite{gen?1qMpf
 Password Strength: 50
Password Generated: pxjGuxh\vkq6mVphi)elVNky1vcdol
 Password Strength: 50
Password Generated: <<`s*|_q/or@}jk&qd{v`@@6e@8|iS
 Password Strength: 50
Password Generated: (fm&"lMVVNq2,um(6N/8dVcSwZ@MKZ
 Password Strength: 50
Password Generated: @{CKM63`,I9>_iGZ4GmFYOL!h|6JK?
 Password Strength: 50
Password Generated: wF.R|8G8m36,bcp5Q:ff^c1)D7r%<H
 Password Strength: 50
```

`nxn-store` is a password authenticated local store that requires a user-set password of strength `>=10` (*strength* as defined in `nxn-gen::score`)