define firewalls::rule ( $name, $proto = undef, $action = undef, $sport = undef, $dport = undef,
                         $state = undef, $source = undef, $src_range = undef, $destination = undef, $dst_range = undef, $iniface = undef,
                         $outiface = undef, $icmp = undef, $chain = undef, $provider = undef,
                         $log_level = undef, $log_prefix = undef, $jump = undef, $limit = undef, $table = undef, $toports = undef, $setdscp = undef, $ensure = 'present',
                         $tosource = undef, $algo = undef, $string = undef){

   include firewalls::pre
   include firewalls::post

   firewall { $name:
        proto       => $proto,
        action      => $action,
        sport       => $sport,
        dport       => $dport,
        state       => $state,
        source      => $source,
        src_range   => $src_range,
        destination => $destination,
        dst_range   => $dst_range,
        iniface     => $iniface,
        outiface    => $outiface,
        icmp        => $icmp,
        chain       => $chain,
        provider    => $provider,
        log_level   => $log_level,
        log_prefix  => $log_prefix,
        jump        => $jump,
        limit       => $limit,
        table       => $table,
        toports     => $toports,
        setdscp     => $setdscp,
        ensure      => $ensure,
        tosource    => $tosource,
        string      => $string,
        string_algo => $algo,
  }

  if $provider == 'ip6tables' {

      Firewall {
          notify  => Exec['persist-firewall-v6'],
          before  => Class['firewalls::post'],
          require => Class['firewalls::pre'],
      }
  }
  else {

      Firewall {
          notify  => Exec['persist-firewall-v4'],
          before  => Class['firewalls::post'],
          require => Class['firewalls::pre'],
      }
  }
}
