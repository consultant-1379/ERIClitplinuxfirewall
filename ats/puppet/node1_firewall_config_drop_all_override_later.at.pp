class task_node1__firewalls_3a_3aconfig____node1__fw(){
    firewalls::config { "_node1_fw":
        action => "create",
        drop_all => "false"
    }
}

class task_node1__firewalls_3a_3aconfig__cluster1__node1__fw(){
    firewalls::config { "cluster1_node1_fw":
        action => "remove",
        drop_all => "true"
    }
}


node "node1" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node1__firewalls_3a_3aconfig____node1__fw':
        require => [Class["task_node1__firewalls_3a_3aconfig__cluster1__node1__fw"]]
    }


    class {'task_node1__firewalls_3a_3aconfig__cluster1__node1__fw':
    }


}