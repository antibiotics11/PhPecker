# PhPecker

## ⚠️ Disclaimer ⚠️ 
**This is an experimental PHP script, written out of curiosity after reading hacking fiction. <br />
It simulates how a simple worm might behave on a network. <br />
Not for real-world use. Running it on unauthorized systems is strictly prohibited.**

## What it is
A single PHP script (about 700 lines) that simulates how a worm might spread across a network.

## Features
### spread()
- Attempts to propagate via SSH connections to other hosts
- Installs the PHP runtime on vulnerable machines and replicates itself
- Sends a “hi mom” message back to the source host upon successful infection

### listen()
- Listens for “hi” and “hi mom” messages on the network

### destroy()
- Simulates destructive behavior on the host

## Requirements 
- PHP >= 7.3.0
- php-ssh2

## Usage
```bash
sudo php -f phpecker.php output /dev/tty except destroy
```

### CLI Options
- output: specifies the output device for logs
- except: excludes a specific task from being performed on the current host

## Screenshot
![screenshot](https://github.com/antibiotics11/PhPecker/assets/75349747/56b63b95-ef26-4dba-9346-57ec97dcbede)
