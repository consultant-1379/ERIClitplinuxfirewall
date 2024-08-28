class task_node1__firewalls_3a_3aconfig____node1__fw(){
    firewalls::config { "_node1_fw":
        action => "create",
        drop_all => "true"
    }
}


node "node1" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node1__firewalls_3a_3aconfig____node1__fw':
    }


}