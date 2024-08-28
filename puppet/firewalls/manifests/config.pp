define firewalls::config ($drop_all = undef, $action = undef) {

  include firewalls::pre
  include firewalls::post

  if ($action == "create" or $action == "update") {
    # if firewall default rules defined elsewhere, just notify
    if defined(Class['firewalls::defaultrules']) {
      notify{"firewall config already included elsewhere....":}
    }
    else {
      include firewalls::defaultrules
    }
    if $drop_all == "true" {
        include firewalls::drop
    }
    else {
      info('drop config no op')
    }
  }
  elsif ($action == "remove") {
    notify{"$name remove config no op":}
  }
}
