class firewalls (){

   if $::operatingsystemmajrelease != 6 {
      $packages = [ 'iptables' ]
   } else {
      $packages = [ 'iptables', 'iptables-ipv6' ]
   }

   package{ $packages: ensure => installed }

   $services = [ 'iptables', 'ip6tables', ]

   service { $services :
      ensure  => running,
      enable  => true,
      require => Package[$packages]
   }

   file { '/etc/sysconfig/iptables':
       ensure  => 'present',
       mode    => '0600',
       owner   =>  root,
       require => Package['iptables'],
   }

   file { '/etc/sysconfig/ip6tables':
       ensure  => 'present',
       mode    => '0600',
       owner   =>  root,
   }

   file { '/etc/sysconfig/iptables-config':
       ensure  => 'present',
       mode    => '0600',
       owner   =>  root,
       require => Package['iptables'],
   }

   file { '/etc/sysconfig/ip6tables-config':
       ensure  => 'present',
       mode    => '0600',
       owner   =>  root,
   }

   firewalls::deleteline { 'removeipv4':
       file    => '/etc/sysconfig/iptables-config',
       pattern => 'IPTABLES_MODULES=""'
   }

   firewalls::deleteline { 'removeipv6':
       file    => '/etc/sysconfig/ip6tables-config',
       pattern => 'IP6TABLES_MODULES=""'
   }

   file_line { 'iptables-config':
       path    => '/etc/sysconfig/iptables-config',
       line    => 'IPTABLES_MODULES="ip_conntrack_tftp"',
       notify  => Service['iptables'],
   }

   file_line { 'ip6tables-config':
       path    => '/etc/sysconfig/ip6tables-config',
       line    => 'IP6TABLES_MODULES="ip_conntrack_tftp"',
       notify  => Service['ip6tables'],
  }

   exec { 'persist-firewall-v4':
       command     => '/sbin/service iptables save',
       refreshonly => true,
   }

   exec { 'persist-firewall-v6':
       command     => '/sbin/service ip6tables save',
       refreshonly => true,
   }

   resources { 'firewall':
       purge => true,
   }
}
