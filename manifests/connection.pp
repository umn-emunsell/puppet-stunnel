# 
# @summary 
#   Establishes a new stunnel connection.
# 
# @param stunnel_name
#   Name of the stunnel connection.
#
# @param ensure
#   Wheather the connection should be created or deleted.
#
# @param manage_service
#   Wheather or not a service should be created for this connection.
# 
# @param active
#   Weather the service should be running or not. Needs manage_service to be true.
# 
# @param enable
#   Weather the service should be set to run at boot. Needs manage_service to be true.
# 
# @param client
#   Client mode (remote service uses TLS).
# 
# @param accept
#   Accept connections on specified address.
#   If no host specified, defaults to all IPv4 addresses for the local host.
#   To listen on all IPv6 addresses use: :::PORT
# 
# @param protocol
#   Application protocol to negotiate TLS.
#   This option enables initial, protocol-specific negotiation of the TLS encryption. 
#   The protocol option should not be used with TLS encryption on a separate port.
#   See official stunnel documentation for supported protocol.
# 
# @param protocol_host
#   Host address for the protocol negotiations.
#   For the 'connect' protocol negotiations, protocolHost specifies HOST:PORT of the final TLS server to be connected to by the proxy. 
#   The proxy server directly connected by stunnel must be specified with the connect option.
#   For the 'smtp' protocol negotiations, protocolHost controls the client SMTP HELO/EHLO value.
# 
# @param connect
#   Connect to a remote address.
#   If no host is specified, the host defaults to localhost.
#   Multiple connect options are allowed in a single service section. If host resolves to multiple addresses and/or if multiple connect 
#   options are specified, then the remote address is chosen using a round-robin algorithm.
#
# @param failover
#   Failover strategy for multiple "connect" targets.
#   rr    round robin - fair load distribution
#   prio  priority - use the order specified in config file
#   default: prio
# 
# @param ca_file_path
#   Load trusted CA certificates from a file.
#   The loaded CA certificates will be used with the verifyChain and verifyPeer options.
# 
# @param ca_file_content
#   If specified, will populate the CA file @ca_file_path. If this path is not specified, it will populate a default CA file
#   in cert_dir/stunnel_name_CA.pem
#   
# @param ca_dir_path
#   Load trusted CA certificates from a directory.
#   The loaded CA certificates will be used with the verifyChain and verifyPeer options. Note that the certificates in this directory 
#   should be named XXXXXXXX.0 where XXXXXXXX is the hash value of the DER encoded subject of the cert.
#   The hash algorithm has been changed in OpenSSL 1.0.0. It is required to c_rehash the directory on upgrade from OpenSSL 0.x.x to 
#   OpenSSL 1.x.x or later.
#   CApath path is relative to the chroot directory if specified.
# 
# @param cert_file_path
#   Certificate chain file name.
#   The parameter specifies the file containing certificates used by stunnel to authenticate itself against the remote client or server. 
#   The file should contain the whole certificate chain starting from the actual server/client certificate, and ending with the 
#   self-signed root CA certificate. The file must be either in PEM or P12 format.
#   A certificate chain is required in server mode, and optional in client mode.
#   This parameter is also used as the certificate identifier when a hardware engine is enabled.
# 
# @param cert_file_content
#   If specified, will populate the cert file @cert_file_path. If this path is not specified, it will populate a default cert file
#   in cert_dir/stunnel_name_cert.pem
#
# @param key_file_path
#   Private key for the certificate specified with cert option.
#   A private key is needed to authenticate the certificate owner. Since this file should be kept secret it should only be readable by 
#   its owner. On Unix systems you can use the following command:
#   chmod 600 keyfile
#   This parameter is also used as the private key identifier when a hardware engine is enabled.
#   default: the value of the cert option
# 
# @param key_file_content
#   If specified, will populate the key file @key_file_path. If this path is not specified, it will populate a default key file
#   in cert_dir/stunnel_name.key
# 
# @param timeoutidle
#   Time to keep an idle connection.
# 
# @param openssl_options
#   OpenSSL library options.
#   The parameter is the OpenSSL option name as described in the SSL_CTX_set_options(3ssl) manual, but without SSL_OP_ prefix. 
#   stunnel -options lists the options found to be allowed in the current combination of stunnel and the OpenSSL library used to build it.
#   Several option lines can be used to specify multiple options. An option name can be prepended with a dash ("-") to disable the option.
#   Use sslVersionMax or sslVersionMin option instead of disabling specific TLS protocol versions when compiled with OpenSSL 1.1.0 or 
#   later.
#
# @param socket_options
#   Set an option on the accept/local/remote socket.
#   The values for the linger option are l_onof:l_linger. The values for the time are tv_sec:tv_usec.
# 
# @param service_options
#   Any supported service option currently not available in this define.
# 
# @param debug_level
#   Debugging level.
#   Level is a one of the syslog level names or numbers emerg (0), alert (1), crit (2), err (3), warning (4), notice (5), info (6), 
#   or debug (7). All logs for the specified level and all levels numerically less than it will be shown. The default is notice (5).
#   While the debug = debug or debug = 7 level generates the most verbose output, it is only intended to be used by stunnel developers. 
#   Please only use this value if you are a developer, or you intend to send your logs to our technical support. Otherwise, the generated 
#   logs will be confusing.
# 
# @param log_file
#   Append log messages to a file.
#   /dev/stdout device can be used to send log messages to the standard output (for example to log them with daemontools splogger).
# 
# @param global_options
#   Any supported global option currently not available in this define.
#
# @example Basic usage
#   include stunnel
#
#   stunnel::connection {'my_tunnel':
#     active        => true,
#     enable        => true,
#     client        => true,
#     accept        => 32000,
#     protocol      => connect,
#     protocol_host => 'remote_url:564',
#     connect       => 'my_proxy:8080',
#     debug_level   => 5,
#     log_file      => "${stunnel::log_dir}/my_tunnel.log",
#   }
#
# @author 
#   Aaron Russo
#   John Cooper
#   Stephen Hoekstra
#   Max Spicer
#   Philippe Ganz
#
# @see https://www.stunnel.org/static/stunnel.html
#
# @api public
#
# @since 0.0.0
# 
define stunnel::connection (
  String                         $stunnel_name      = $name,
  Enum['present','absent']       $ensure            = 'present',
  Boolean                        $manage_cert_files = false,
  Boolean                        $manage_service    = true,
  Optional[Boolean]              $active            = undef,
  Optional[Variant[
      Boolean,
      Enum['mask']
  ]]                             $enable            = undef,
  Optional[Enum['yes','no']]     $client            = undef,
  Optional[Variant[
      String,
      Integer[0]
  ]]                             $accept            = undef,
  Optional[String]               $protocol          = undef,
  Optional[String]               $protocol_host     = undef,
  Optional[Variant[
      String,
      Array[String]
  ]]                             $connect           = undef,
  Optional[Enum['rr','prio']]    $failover          = undef,
  Optional[String]               $ca_file_content   = undef,
  Optional[Stdlib::Absolutepath] $ca_file_path      = undef,
  Optional[Stdlib::Absolutepath] $ca_dir_path       = undef,
  Optional[String]               $cert_file_content = undef,
  Optional[Stdlib::Absolutepath] $cert_file_path    = undef,
  Optional[String]               $key_file_content  = undef,
  Optional[Stdlib::Absolutepath] $key_file_path     = undef,
  Optional[Array[String]]        $openssl_options   = undef,
  Optional[Array[String]]        $socket_options    = undef,
  Optional[Hash[
      String,
      Data
  ]]                             $service_options   = undef,
  Optional[Integer[0]]           $timeoutidle       = undef,
  Optional[Integer[0,7]]         $debug_level       = undef,
  Optional[Stdlib::Absolutepath] $log_file          = undef,
  Optional[Hash[
      String,
      Data
  ]]                             $global_options    = undef,
) {
  require stunnel

  File {
    owner => $stunnel::user,
    group => $stunnel::group,
  }

  case $facts['kernel'] {
    'Linux' : {
      $path_connector = '/'
    }
    'windows' : {
      $path_connector = "\\"
    }
    default : {
      fail("Unsupported kernel ${facts['kernel']} !")
    }
  }

  if $manage_cert_files {
  if $ca_file_path {
    $ca_file = $ca_file_path
    if $ca_file_content {
      $ca_file_ensure = file
    }
  } elsif $ca_file_content {
    $ca_file = "${stunnel::cert_dir}${path_connector}${stunnel_name}_CA.pem"
    $ca_file_ensure = file
  } else {
    file { "${stunnel::cert_dir}${path_connector}${stunnel_name}_CA.pem":
      ensure => absent,
    }
    $ca_file = undef
    $ca_file_ensure = undef
  }
  if $ca_file_ensure {
    file { $ca_file:
      ensure  => $ca_file_ensure,
      content => $ca_file_content,
      mode    => '0640',
    }
  }

  if $cert_file_path {
    $cert_file = $cert_file_path
    if $cert_file_content {
      $cert_file_ensure = file
    }
  } elsif $cert_file_content {
    $cert_file = "${stunnel::cert_dir}${path_connector}${stunnel_name}_cert.pem"
    $cert_file_ensure = file
  } else {
    file { "${stunnel::cert_dir}${path_connector}${stunnel_name}_cert.pem":
      ensure => absent,
    }
    $cert_file = undef
    $cert_file_ensure = undef
  }
  if $cert_file_ensure {
    file { $cert_file:
      ensure  => $cert_file_ensure,
      content => $cert_file_content,
      mode    => '0640',
    }
  }

  if $key_file_path {
    $key_file = $key_file_path
    if $key_file_content {
      $key_file_ensure = file
    }
  } elsif $key_file_content {
    $key_file = "${stunnel::cert_dir}${path_connector}${stunnel_name}.key"
    $key_file_ensure = file
  } else {
    file { "${stunnel::cert_dir}${path_connector}${stunnel_name}.key":
      ensure => absent,
    }
    $key_file = undef
    $key_file_ensure = undef
  }
  if $key_file_ensure {
    file { $key_file:
      ensure  => $key_file_ensure,
      content => $key_file_content,
      mode    => '0600',
    }
  }
 }
  $config_file = "${stunnel::config_dir}${path_connector}${stunnel_name}.conf"

  file { $config_file:
    ensure  => $ensure,
    mode    => '0664',
    content => epp('stunnel/conf.epp', {
        stunnel_name    => $stunnel_name,
        client          => $client,
        accept          => $accept,
        protocol        => $protocol,
        protocol_host   => $protocol_host,
        connect         => $connect,
        ca_file         => $ca_file,
        ca_dir          => $ca_dir_path,
        cert_file       => $cert_file,
        key_file        => $key_file,
        failover        => $failover,
        openssl_options => $openssl_options,
        socket_options  => $socket_options,
        timeoutidle     => $timeoutidle,
        service_options => $service_options,
        debug_level     => $debug_level,
        log_file        => $log_file,
        global_options  => $global_options,
    }),
  }

  if $manage_service {
    case $facts['kernel'] {
      'Linux' : {
        $service_name = "stunnel-${stunnel_name}.service"

        systemd::manage_unit { $service_name:
          ensure        => $ensure,
          unit_entry    => {
            'Description'   => "Stunnel ${stunnel_name}",
            'Documentation' => 'man:stunnel(8)',
            'After'         => ['syslog.target', 'network.target'],
          },
          service_entry => {
            'Type'      => 'exec',
            'ExecStart' => "${stunnel::bin_path}/${stunnel::bin_name} ${config_file}",
          },
          install_entry => {
            'WantedBy' => 'multi-user.target',
          },
          active        => case $ensure {
            'present' : { $active }
            default   : { false }
          },
          enable        => case $ensure {
            'present' : { $enable }
            default   : { false }
          },
        }
      }
      'windows' : {
        $service_name = "stunnel-${stunnel_name}"
        if $ensure == 'present' {
          exec { "Create service ${service_name}" :
            command   => "New-Service -Name \"${service_name}\" -BinaryPathName '\"${stunnel::bin_path}\\${stunnel::bin_name}\" -install -service \"${config_file}\"'",
            provider  => pwsh,
            logoutput => true,
            unless    => "if ($(Get-Service ${service_name}).name -eq \"${service_name}\") {exit 0} else {exit 1}",
            before    => Service[$service_name],
          }
          service { $service_name:
            ensure => $active,
            enable => $enable,
          }
        } else {
          exec { "Remove service ${service_name}" :
            command   => "Remove-Service -Name \"${service_name}\"",
            provider  => pwsh,
            logoutput => true,
            onlyif    => "if ($(Get-Service ${service_name}).name -eq \"${service_name}\") {exit 0} else {exit 1}",
          }
        }
      }
      default : {
        fail("Unsupported kernel ${facts['kernel']} !")
      }
    }
    if $ensure == 'present' and ($enable != undef or $active != undef) {
      File[$config_file] ~> Service[$service_name]
      if $ca_file {
        File[$ca_file] ~> Service[$service_name]
      }
      if $cert_file {
        File[$cert_file] ~> Service[$service_name]
      }
      if $key_file {
        File[$key_file] ~> Service[$service_name]
      }
    }
  }
}
