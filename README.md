# PhPecker

PhPecker is a PHP-based <a href="https://en.wikipedia.org/wiki/Computer_worm">worm</a> designed to spread through networks and infect Linux servers, potentially causing damage.

## How PhPecker works

PhPecker consists of several functions:

### spread() Function

spread() attempts to spread the worm by SSH-ing into other hosts on the network. <br>
It scans the network for vulnerable hosts and, upon successful password exploitation, installs the PHP runtime and replicates itself. <br>
Infected hosts then greet ("hi mom") the host that infected them before proceeding to infect others. <br>

### listen() Function

listen() responds to greetings ("hi") sent by infected hosts or receives greetings ("hi mom") sent by hosts it has infected. <br>
By receiving these responses, it can determine whether a host is already infected.

### destroy() Function

destroy() is designed to destroy the current host.

## Execution

PhPecker requires PHP >= 7.3.0 and php-ssh2 extension.

```bash
sudo php -f phpecker.php output /dev/tty except destroy
```

### CLI Options

- output: Specifies the device to output the worm's logs.
- except: Excludes a specific task from being performed on the current host.

## Warning

This code is intended for educational purposes only. <br>
It is designed to simulate network security scenarios for learning purposes. <br>
Any unauthorized use of this code for malicious activities is strictly prohibited.

## Screenshot

![screenshot](https://github.com/antibiotics11/PhPecker/assets/75349747/56b63b95-ef26-4dba-9346-57ec97dcbede)
