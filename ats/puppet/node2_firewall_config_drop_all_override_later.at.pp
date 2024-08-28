class task_node2__firewalls_3a_3aconfig__cluster1__node2__fw(){
    firewalls::config { "cluster1_node2_fw":
        action => "create",
        drop_all => "true"
    }
}


node "node2" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node2__firewalls_3a_3aconfig__cluster1__node2__fw':
    }


}