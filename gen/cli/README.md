# Password Generation CLI

```
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
    -q, --qty <qty>    Set quantity [default: 1]
```

You can set the length of the generated password and pass the `-s` flag if the password can only be comprised of letters and numbers (no symbols). This is a dumb requirement, but I've seen it enough to add the flag.

```
% ./nxn-cli -s -l=30 -q=5
Password Generated: bhfuyK2U6cydf9XtlbuNx6ynz595d7
 Password Strength: 30
Password Generated: VmotBrdnkUlopigp4pl2CUglpgoFd2
 Password Strength: 30
Password Generated: hhmgxovo8ek8gsE9diomz3rqvpji1t
 Password Strength: 30
Password Generated: 6r8zsqcFgi8hjr7J9hz7Ljy6uKzru1
 Password Strength: 30
Password Generated: S82XRW5XOM4rNhCQTYNFZlOSpGfJRR
 Password Strength: 30
% ./nxn-cli -l=30 -q=5
Password Generated: YwXFSR'BhLJQHRJMEGLLmQH?BPPO9_
 Password Strength: 50
Password Generated: 2e{[XtJNsj{yqEFHNRnb?eSQx{ndsh
 Password Strength: 50
Password Generated: )"ZpGkOWSnZMfN]FFehDbSOT5tFCFZ
 Password Strength: 50
Password Generated: OC"*n8dwh)12CJF5R2c\|Tg[1e471P
 Password Strength: 50
Password Generated: pm5^n#43[-/63314438x3~Hyz^6ww4
 Password Strength: 50
```

`nxn-store` is a password authenticated local store that requires a user-set password of strength `>=10` (*strength* as defined in `nxn-gen::score`)