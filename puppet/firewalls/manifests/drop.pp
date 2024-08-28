class firewalls::drop (){
    firewalls::rule { '999 drop all':
        name        => '999 drop all',
        proto       => 'all',
        action      => 'drop',
        chain       => 'INPUT',
        provider    => 'iptables',
    }
    firewalls::rule { '1999 drop all':
        name        => '1999 drop all',
        proto       => 'all',
        action      => 'drop',
        chain       => 'OUTPUT',
        provider    => 'iptables',
    }
    firewalls::rule { '999 drop all v6':
        name        => '999 drop all v6',
        proto       => 'all',
        action      => 'drop',
        chain       => 'INPUT',
        provider    => 'ip6tables',
    }
    firewalls::rule { '1999 drop all v6':
        name        => '1999 drop all v6',
        proto       => 'all',
        action      => 'drop',
        chain       => 'OUTPUT',
        provider    => 'ip6tables',
    }
}
