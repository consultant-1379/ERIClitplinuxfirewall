class firewalls::defaultrules (){

  if $puppet_master == 'true' {
    firewalls::rule { '997 cobblerudp':
      name        => '997 cobblerudp',
      proto       => 'udp',
      action      => 'accept',
      chain       => 'INPUT',
      dport       => ['67', '68', '69'],
      state       => 'NEW',
      provider    => 'iptables',
      notify      => Exec['persist-firewall-v4'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '1997 cobblerudp out':
      name        => '1997 cobblerudp out',
      proto       => 'udp',
      action      => 'accept',
      chain       => 'OUTPUT',
      dport       => ['67', '68', '69'],
      state       => 'NEW',
      provider    => 'iptables',
      notify      => Exec['persist-firewall-v4'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '997 cobblerudp v6':
      name        => '997 cobblerudp v6',
      proto       => 'udp',
      action      => 'accept',
      chain       => 'INPUT',
      dport       => ['67', '68', '69'],
      state       => 'NEW',
      provider    => 'ip6tables',
      notify      => Exec['persist-firewall-v6'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '1997 cobblerudp out v6':
      name        => '1997 cobblerudp out v6',
      proto       => 'udp',
      action      => 'accept',
      chain       => 'OUTPUT',
      dport       => ['67', '68', '69'],
      state       => 'NEW',
      provider    => 'ip6tables',
      notify      => Exec['persist-firewall-v6'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '988 https':
      name        => '988 https',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'INPUT',
      dport       => ['443'],
      state       => 'NEW',
      provider    => 'iptables',
      notify      => Exec['persist-firewall-v4'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '1988 https out':
      name        => '1988 https out',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'OUTPUT',
      dport       => ['443'],
      state       => 'NEW',
      provider    => 'iptables',
      notify      => Exec['persist-firewall-v4'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '989 https v6':
      name        => '989 https v6',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'INPUT',
      dport       => ['443'],
      state       => 'NEW',
      provider    => 'ip6tables',
      notify      => Exec['persist-firewall-v6'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '1989 https out v6':
      name        => '1989 https out v6',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'OUTPUT',
      dport       => ['443'],
      state       => 'NEW',
      provider    => 'ip6tables',
      notify      => Exec['persist-firewall-v6'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '994 mco':
      name        => '994 mco',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'INPUT',
      dport       => ['4369', '9100', '9101', '9102', '9103', '9104', '9105', '61613', '61614'],
      state       => 'NEW',
      provider    => 'iptables',
      notify      => Exec['persist-firewall-v4'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '1994 mco out':
      name        => '1994 mco out',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'OUTPUT',
      dport       => ['4369', '9100', '9101', '9102', '9103', '9104', '9105', '61613', '61614'],
      state       => 'NEW',
      provider    => 'iptables',
      notify      => Exec['persist-firewall-v4'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '994 mco v6':
      name        => '994 mco v6',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'INPUT',
      dport       => ['4369', '9100', '9101', '9102', '9103', '9104', '9105', '61613', '61614'],
      state       => 'NEW',
      provider    => 'ip6tables',
      notify      => Exec['persist-firewall-v6'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '1994 mco out v6':
      name        => '1994 mco out v6',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'OUTPUT',
      dport       => ['4369', '9100', '9101', '9102', '9103', '9104', '9105', '61613', '61614'],
      state       => 'NEW',
      provider    => 'ip6tables',
      notify      => Exec['persist-firewall-v6'],
      before      => undef,
      require     => undef,
    }
  }
  else
  {
    firewalls::rule { '994 mco':
      name        => '994 mco',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'INPUT',
      dport       => ['4369', '9100', '9101', '9102', '9103', '9104', '9105', '61614'],
      state       => 'NEW',
      provider    => 'iptables',
      notify      => Exec['persist-firewall-v4'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '1994 mco out':
      name        => '1994 mco out',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'OUTPUT',
      dport       => ['4369', '9100', '9101', '9102', '9103', '9104', '9105', '61614'],
      state       => 'NEW',
      provider    => 'iptables',
      notify      => Exec['persist-firewall-v4'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '994 mco v6':
      name        => '994 mco v6',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'INPUT',
      dport       => ['4369', '9100', '9101', '9102', '9103', '9104', '9105', '61614'],
      state       => 'NEW',
      provider    => 'ip6tables',
      notify      => Exec['persist-firewall-v6'],
      before      => undef,
      require     => undef,
    }

    firewalls::rule { '1994 mco out v6':
      name        => '1994 mco out v6',
      proto       => 'tcp',
      action      => 'accept',
      chain       => 'OUTPUT',
      dport       => ['4369', '9100', '9101', '9102', '9103', '9104', '9105', '61614'],
      state       => 'NEW',
      provider    => 'ip6tables',
      notify      => Exec['persist-firewall-v6'],
      before      => undef,
      require     => undef,
    }
  }

  firewalls::rule { '996 httpd':
    name        => '996 httpd',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'INPUT',
    dport       => ['80'],
    state       => 'NEW',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1996 httpd out':
    name        => '1996 httpd out',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'OUTPUT',
    dport       => ['80'],
    state       => 'NEW',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '996 httpd v6':
    name        => '996 httpd v6',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'INPUT',
    dport       => ['80'],
    state       => 'NEW',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1996 httpd out v6':
    name        => '1996 httpd out v6',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'OUTPUT',
    dport       => ['80'],
    state       => 'NEW',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '993 puppet':
    name        => '993 puppet',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'INPUT',
    dport       => ['8140', '8139', '9999'],
    state       => 'NEW',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1993 puppet out':
    name        => '1993 puppet out',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'OUTPUT',
    dport       => ['8140', '8139', '9999'],
    state       => 'NEW',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '993 puppet v6':
    name        => '993 puppet v6',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'INPUT',
    dport       => ['8140', '8139', '9999'],
    state       => 'NEW',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1993 puppet out v6':
    name        => '1993 puppet out v6',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'OUTPUT',
    dport       => ['8140', '8139', '9999'],
    state       => 'NEW',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '995 ntp':
    name        => '995 ntp',
    proto       => 'udp',
    action      => 'accept',
    chain       => 'INPUT',
    dport       => ['123'],
    state       => 'NEW',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1995 ntp out':
    name        => '1995 ntp out',
    proto       => 'udp',
    action      => 'accept',
    chain       => 'OUTPUT',
    dport       => ['123'],
    state       => 'NEW',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '995 ntp v6':
    name        => '995 ntp v6',
    proto       => 'udp',
    action      => 'accept',
    chain       => 'INPUT',
    dport       => ['123'],
    state       => 'NEW',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1995 ntp out v6':
    name        => '1995 ntp out v6',
    proto       => 'udp',
    action      => 'accept',
    chain       => 'OUTPUT',
    dport       => ['123'],
    state       => 'NEW',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '998 ssh':
    name        => '998 ssh',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'INPUT',
    dport       => ['22'],
    state       => 'NEW',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1998 ssh out':
    name        => '1998 ssh out',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'OUTPUT',
    dport       => ['22'],
    state       => 'NEW',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '998 ssh v6':
    name        => '998 ssh v6',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'INPUT',
    dport       => ['22'],
    state       => 'NEW',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1998 ssh out v6':
    name        => '1998 ssh out v6',
    proto       => 'tcp',
    action      => 'accept',
    chain       => 'OUTPUT',
    dport       => ['22'],
    state       => 'NEW',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '990 related established':
    name        => '990 related established',
    action      => 'accept',
    proto       => 'all',
    state       => ['RELATED', 'ESTABLISHED'],
    chain       => 'INPUT',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1990 related established':
    name        => '1990 related established',
    action      => 'accept',
    proto       => 'all',
    state       => ['RELATED', 'ESTABLISHED'],
    chain       => 'OUTPUT',
    provider    => 'iptables',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '990 related established v6':
    name        => '990 related established v6',
    action      => 'accept',
    proto       => 'all',
    state       => ['RELATED', 'ESTABLISHED'],
    chain       => 'INPUT',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1990 related established v6':
    name        => '1990 related established v6',
    action      => 'accept',
    proto       => 'all',
    state       => ['RELATED', 'ESTABLISHED'],
    chain       => 'OUTPUT',
    provider    => 'ip6tables',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '991 local loop':
    name        => '991 local loop',
    action      => 'accept',
    proto       => 'all',
    chain       => 'INPUT',
    provider    => 'iptables',
    iniface     => 'lo',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1991 local loop':
    name        => '1991 local loop',
    action      => 'accept',
    proto       => 'all',
    chain       => 'OUTPUT',
    provider    => 'iptables',
    outiface    => 'lo',
    notify      => Exec['persist-firewall-v4'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '991 local loop v6':
    name        => '991 local loop v6',
    action      => 'accept',
    proto       => 'all',
    chain       => 'INPUT',
    provider    => 'ip6tables',
    iniface     => 'lo',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }

  firewalls::rule { '1991 local loop v6':
    name        => '1991 local loop v6',
    action      => 'accept',
    proto       => 'all',
    chain       => 'OUTPUT',
    provider    => 'ip6tables',
    outiface    => 'lo',
    notify      => Exec['persist-firewall-v6'],
    before      => undef,
    require     => undef,
  }
}
