define firewalls::deleteline($file, $pattern) {
    exec { "sed -i -r -e '/$pattern/d' $file":
      path   => '/bin',
      onlyif => "/bin/grep -E '$pattern' '$file'",
    }
}
