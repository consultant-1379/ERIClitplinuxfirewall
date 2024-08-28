##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
from litp.core.plugin import Plugin
from litp.core.validators import ValidationError
from litp.core.task import ConfigTask
from itertools import product

import re

from litp.core.litp_logging import LitpLogger
log = LitpLogger()

from litp.core.translator import Translator
t = Translator('ERIClitplinuxfirewall_CXP9031105')
_ = t._


class LinuxFirewallPlugin(Plugin):
    """
    Provides configuration of iptables and ip6tables.
    Update and remove reconfiguration actions are supported for this plugin.
    """
    DEFAULT_ACTION = 'accept'
    DEFAULT_PROTO = 'tcp'
    DEFAULT_STATE = 'NEW'
    DEFAULT_CHAIN = 'INPUT'
    DEFAULT_PROVIDER = 'iptables'
    OUTPUT_CHAIN = 'OUTPUT'
    FORWARD_CHAIN = 'FORWARD'
    IP6TABLES_PROVIDER = 'ip6tables'
    OUTPUT_PREPEND = '1'
    FORWARD_PREPEND = '2'
    IPV4 = ' ipv4'
    IPV6 = ' ipv6'

    def _add_rule_to_set(self, rule, rules_by_name):
        rule_chains = (self.DEFAULT_CHAIN, self.OUTPUT_CHAIN)
        if rule.chain:
            rule_chains = (rule.chain,)

        rule_chain_no = self._get_chain_number(rule.name)

        for chain in rule_chains:
            rules_by_name.setdefault(
                chain, {}
            ).setdefault(
                int(rule_chain_no), []
            ).append((rule.get_vpath(), rule))

    def _get_chain_number(self, rule_name):
        pattern = r"(?P<chain>\d*)"
        return re.match(pattern, rule_name).group('chain')

    def _validate_firewall_rule_names(self, nodes, clusters):
        errors = []
        paths_with_errors = {}
        rules_by_name = {}
        for cluster in clusters:
            rules_by_name_cluster = {}
            cluster_rules = cluster.configs.query("firewall-rule")
            for rule in cluster_rules:
                if not rule.is_for_removal():
                    self._add_rule_to_set(rule, rules_by_name_cluster)
                self._add_chain_errors(errors, paths_with_errors,
                                rules_by_name_cluster,
                                "cluster '%s'" % cluster.item_id)
            self._add_inout_chain_errors(errors, paths_with_errors,
                rules_by_name_cluster, "cluster '%s'" % cluster.item_id)
        paths_with_errors = {}
        for node in nodes:
            rules = node.query("firewall-rule")
            rules_by_name = {}
            for rule in rules:
                if not rule.is_for_removal():
                    self._add_rule_to_set(rule, rules_by_name)
                    self._add_chain_errors(errors, paths_with_errors,
                        rules_by_name, "node '%s'" % node.hostname)
            self._add_inout_chain_errors(errors, paths_with_errors,
                rules_by_name, "node '%s'" % node.hostname)
            for cluster in clusters:
                if node in cluster.nodes:
                    cluster_rules = cluster.configs.query("firewall-rule")
                    node_rules_by_name = dict(rules_by_name)
                    for rule in cluster_rules:
                        if not rule.is_for_removal():
                            self._add_rule_to_set(rule, node_rules_by_name)
                            self._add_chain_errors(
                                errors,
                                paths_with_errors,
                                node_rules_by_name,
                                "node '%s'" % node.hostname)
                            self._add_inout_chain_errors(
                                errors,
                                paths_with_errors,
                                node_rules_by_name,
                                "node '%s'" % node.hostname)
        return errors

    def list_of_duplicates(self, list1):
        return list(set([x for x in list1 if list1.count(x) >= 2]))

    def _same_name(self, rule1, rule2):
        rule1 = rule1.name.split()[1:]
        rule2 = rule2.name.split()[1:]
        return rule1 == rule2

    def _same_chain(self, rule1, rule2):
        rule1 = rule1.name.split()[0]
        rule2 = rule2.name.split()[0]
        return int(rule1) == int(rule2)

    def same_operation(self, rule1, rule2):
        return rule1.is_for_removal() == rule2.is_for_removal()

    def _validate_firewall_rule_name_conflicts_by_node(
        self, node, cluster_rules=None):
        errors = []
        node_rules = node.query("firewall-rule")
        if cluster_rules is not None:
            node_rules.extend(cluster_rules)
        removal_rules_by_name = {}
        rules_by_name = {}
        error_set = {}
        for rule in node_rules:
            if rule.is_for_removal():
                removal_rules_by_name[rule.get_vpath()] = rule
            else:
                rules_by_name[rule.get_vpath()] = rule
        for removal_name_rule in removal_rules_by_name.values():
            for name_rule in rules_by_name.values():
                if (
                    not self.same_operation(
                        removal_name_rule, name_rule) and
                    self._same_name(removal_name_rule, name_rule) and
                    self._same_chain(removal_name_rule, name_rule)
                ):
                    error_set[removal_name_rule.get_vpath()] = \
                        removal_name_rule
        for name_rule in rules_by_name.values():
            for removal_name_rule in removal_rules_by_name.values():
                if (
                    not self.same_operation(
                        removal_name_rule, name_rule) and
                    self._same_name(removal_name_rule, name_rule) and
                    self._same_chain(removal_name_rule, name_rule)
                ):
                    error_set[name_rule.get_vpath()] = name_rule
        for path, error in error_set.iteritems():
            err_str = error.name
            err_msg = _('RULE_NAME_NOT_UNIQUE_FOR_REUSED_CHAIN_NUM') % err_str
            errors.append(ValidationError(
                item_path=path,
                error_message=err_msg))
        return errors

    def _add_chain_errors(self, errors, paths_with_errors, rules_by_name, msg):
        for chain, rules in rules_by_name.iteritems():
            for rule_name in sorted(rules):
                rule_paths = rules[rule_name]
                if len(rule_paths) > 1:
                    for rule_path in set(rule_paths):
                        appended_list = paths_with_errors.get(chain, [])
                        err_msg = (
                            _("POSITION_S_IN_FW_CHAIN_NOT_UNIQUE_ON_MSG")
                                % (rule_name, chain, msg)
                        )
                        new_error = ValidationError(
                                item_path=rule_path[0],
                                error_message=err_msg)
                        messages_list = [
                            (e.item_path, e.error_message) for e in errors]
                        if ((new_error.item_path, new_error.error_message)
                                not in messages_list):
                            errors.append(new_error)
                        if rule_path[0] not in appended_list:
                            appended_list.append(rule_path[0])
                            paths_with_errors[chain] = appended_list

    def _add_inout_chain_errors(
        self, errors, paths_with_errors, rules_by_name, msg):

        in_chain_rules = rules_by_name.get('INPUT')
        out_chain_rules = rules_by_name.get('OUTPUT')

        if not in_chain_rules or not out_chain_rules:
            return

        for in_rule_chain, in_rules in in_chain_rules.iteritems():
            for out_rule_chain, out_rules in out_chain_rules.iteritems():
                if ('%.3d' % in_rule_chain == '1%.3d' % out_rule_chain and
                    self._same_name(in_rules[0][1], out_rules[0][1])):

                    appended_list = paths_with_errors.get('INPUT', [])

                    err_msg = (
                        _("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                                % (in_rule_chain, 'INPUT',
                                    out_rule_chain, 'OUTPUT', msg)
                        )
                    new_error = ValidationError(
                                    item_path=in_rules[0][1].get_vpath(),
                                    error_message=err_msg)
                    messages_list = [
                            (e.item_path, e.error_message) for e in errors]
                    if ((new_error.item_path, new_error.error_message)
                                not in messages_list):
                        errors.append(new_error)
                    if in_rules[0][1].get_vpath() not in appended_list:
                        appended_list.append(in_rules[0][1].get_vpath())
                        paths_with_errors['INPUT'] = appended_list
                        log.trace.error("For chain identification purposes, "
                            "OUTPUT rule chain positions are prefixed with 1")

                    err_msg = (
                        _("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                            % (out_rule_chain, 'OUTPUT',
                                in_rule_chain, 'INPUT', msg)
                    )
                    out_error = ValidationError(
                                item_path=out_rules[0][1].get_vpath(),
                                error_message=err_msg)
                    if ((out_error.item_path, out_error.error_message)
                                not in messages_list):
                        errors.append(out_error)
                    if out_rules[0][1].get_vpath() not in appended_list:
                        appended_list.append(out_rules[0][1].get_vpath())
                        paths_with_errors['OUTPUT'] = appended_list
                        log.trace.error("For chain identification purposes, "
                            "OUTPUT rule chain positions are prefixed with 1")

    def _validate_firewall_action_conflicts(self, nodes, clusters):
        errors = []
        for cluster in clusters:
            cluster_rules = cluster.configs.query("firewall-rule")
            for rule in cluster_rules:
                conflict = self._validate_action_jump(rule, cluster)
                if conflict:
                    errors.append(conflict)

        for node in nodes:
            rules = node.query("firewall-rule")
            for rule in rules:
                conflict = self._validate_action_jump(rule, node)
                if conflict:
                    errors.append(conflict)

        return errors

    def _validate_action_jump(self, rule, item):
        if rule.action and rule.jump:
            return ValidationError(
                item_path=item.get_vpath(),
                error_message=_("RULE_MAY_NOT_CONTAIN_BOTH_ACTION_AND_JUMP")
            )

    def _validate_single_firewall_cluster_config_only(self, clusters):
        errors = []
        for cluster in clusters:
            configs = cluster.query(
                "firewall-cluster-config", is_for_removal=False)
            if len(configs) > 1:
                err_msg = _(
                    "ONLY_ONE_FW_CLUSTER_CONFIG_CONFIGURED_PER_CLUSTER")
                for config in configs:
                    errors.append(ValidationError(
                        item_path=config.get_vpath(),
                        error_message=err_msg
                        ))
        return errors

    def _validate_single_firewall_node_config_only(self, nodes):
        errors = []
        for node in nodes:
            configs = node.query(
                "firewall-node-config", is_for_removal=False)
            if len(configs) > 1:
                err_msg = _(
                'ONLY_ONE_FW_NODE_CONFIG_CONFIGURED_PER_NODE')
                for config in configs:
                    errors.append(ValidationError(
                        item_path=config.get_vpath(),
                        error_message=err_msg
                        ))
        return errors

    def validate_model(self, plugin_api_context):
        """
        Validation does not check for the misuse of combination of properties.

        This plugin validates the model to ensure that:

        - if jump is 'SNAT':

          - table must be 'nat'.
          - chain must be 'POSTROUTING'.
          - proto must be 'tcp' or 'udp'.
          - tosource property must be supplied.
        - if provider is 'iptables' tosource property must be an IPv4 address.
        - 'firewall-node-config' and 'firewall-cluster-config' model items \
            do not have conflicting 'drop_all' values.
        - 'firewall-rule' model items do not have conflicting chain numbers.

        """
        errors = []

        nodes = plugin_api_context.query("node")
        ms_nodes = plugin_api_context.query("ms")
        all_nodes = nodes + ms_nodes
        clusters = plugin_api_context.query("cluster")

        errors.extend(
              self._validate_single_firewall_cluster_config_only(clusters)
         )
        errors.extend(
              self._validate_single_firewall_node_config_only(all_nodes)
        )

        errors.extend(
                self._validate_firewall_rule_names(all_nodes, clusters))
        for cluster in clusters:
            cluster_rules = cluster.configs.query("firewall-rule")
            for node in nodes:
                errors.extend(
                    self._validate_firewall_rule_name_conflicts_by_node(
                        node, cluster_rules))
        for node in ms_nodes:
            errors.extend(
                self._validate_firewall_rule_name_conflicts_by_node(node))
        errors.extend(
                self._validate_firewall_action_conflicts(nodes, clusters))

        return errors

    def create_configuration(self, plugin_api_context):
        """
        This plugin provides tasks to configure iptables and ip6tables \
based on the specified firewall rules and configuration.

        *Example CLI for configuring a rule on a cluster*

        .. code-block:: bash

            litp create -t firewall-cluster-config \
-p /deployments/dep1/clusters/c1/configs/fw_config
            litp create -t firewall-rule \
-p /deployments/dep1/clusters/c1/configs/fw_config/rules/fw_001 \
-o name="010 basetcp" dport="9999"

        *Example CLI for configuring a rule on a node*

        .. code-block:: bash

            litp create -t firewall-node-config \
-p /deployments/dep1/clusters/c1/nodes/node1/configs/fw_node_config \
-o drop_all=true
            litp create -t firewall-rule \
-p /deployments/dep1/clusters/c1/nodes/node1/\
configs/fw_node_config/rules/fw_001 -o name="110 basetcp" \
dport="9999,1234"

        *Example CLI for removing a property from a rule*

        .. code-block:: bash

            litp update -p /deployments/dep1/clusters/c1/nodes/node1/\
configs/fw_node_config/fw_001 -d dport

        *Example CLI for removing a rule*

        .. code-block:: bash

            litp remove -p /deployments/dep1/clusters/c1/nodes/node1/\
configs/fw_node_config/fw_001



        *Example CLI for configuring a SNAT rule on a node*

        .. code-block:: bash

            litp create -t firewall-rule \
-p /deployments/site1/clusters/cluster1/nodes/node1/configs/fw2/rules/\
fw_validSNATNodeLevel2 -o provider=iptables name="904 SNAT" jump="SNAT" \
chain="POSTROUTING" source="10.247.244.0/22" destination="10.140.1.0/24" \
proto=udp tosource="10.140.1.56" table=nat

        *Example XML for configuring a rule on a node*

        .. code-block:: bash

            <?xml version='1.0' encoding='utf-8'?>
            <litp:firewall-node-config \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xmlns:litp="http://www.ericsson.com/litp" \
xsi:schemaLocation="http://www.ericsson.com/litp\
litp-xml-schema/litp.xsd" id="firewall_config">
                <drop_all>true</drop_all>
                <litp:firewall-node-config-rules-collection id="rules">
                    <litp:firewall-rule id="fw_basetcp">
                        <action>accept</action>
                        <dport>2222,4444,5555</dport>
                        <name>020 tcprule</name>
                        <proto>tcp</proto>
                        <state>NEW</state>
                    </litp:firewall-rule>
                </litp:firewall-node-config-rules-collection>
            </litp:firewall-node-config>

        For more information, see "Introduction to Firewall Security" \
from :ref:`LITP References <litp-references>`.

        """
        tasks = []
        cluster_config_exists = False
        for node in plugin_api_context.query("node") + \
            plugin_api_context.query("ms"):
            fw_node_configs = node.query("firewall-node-config")
            for fw_n_config in fw_node_configs:
                for rule in fw_n_config.rules:
                    if not rule.is_applied():
                        tasks.extend(self.create_firewall_tasks(
                                     node, rule,
                                     model_items=(fw_n_config,))
                        )

        for cluster in plugin_api_context.query("cluster"):
            for fw_c_config in cluster.query("firewall-cluster-config"):
                cluster_config_exists = True
                for node in cluster.nodes:
                    for rule in fw_c_config.rules:
                        if (not node.is_for_removal() and
                            not node.is_initial() and
                            not rule.is_applied()):
                            tasks.extend(
                                self.create_firewall_tasks(
                                    node, rule, cluster.item_id,
                                    model_items=(fw_c_config,))
                            )

                        elif node.is_initial() and not rule.is_for_removal():
                            tasks.extend(
                                self.create_firewall_tasks(
                                    node, rule, cluster.item_id,
                                    model_items=(fw_c_config,))
                            )

        if cluster_config_exists:
            for cluster in plugin_api_context.query("cluster"):
                for fw_c_config in cluster.query("firewall-cluster-config"):
                    for node in cluster.nodes:
                        node_config = node.query("firewall-node-config")
                        if ((not node_config and
                                not fw_c_config.is_applied() and
                                not (node.is_initial() and
                                    fw_c_config.is_for_removal())) or
                            (not node_config and fw_c_config.is_applied() and
                                node.is_initial())):
                            task = self.create_firewall_config_task(
                                    node,
                                    fw_c_config,
                                    fw_c_config.drop_all,
                                    cluster.item_id,
                                    model_items=(node, fw_c_config))
                            if task:
                                tasks.append(task)
                        elif (node_config and
                              (node_config[0].is_initial() or
                              node_config[0].is_updated())):
                            create_task = self.create_firewall_config_task(
                                    node,
                                    node_config[0],
                                    node_config[0].drop_all,
                                    model_items=(node, fw_c_config))
                            tasks.append(create_task)
                            if node_config[0].is_initial() and\
                                not fw_c_config.is_initial() and\
                                not fw_c_config.is_for_removal() and\
                                not node.is_initial():
                                removal_task =\
                                    self.create_firewall_config_task(
                                        node,
                                        fw_c_config,
                                        fw_c_config.drop_all,
                                        cluster.item_id,
                                        force_removal=True,
                                        model_items=(fw_c_config,))
                                tasks.append(removal_task)
                                for task in tasks:
                                    if task.item_vpath == \
                                        node_config[0].get_vpath():
                                        task.requires = set([removal_task])
                        elif (node_config and
                             node_config[0].is_for_removal() and
                              (fw_c_config.is_updated() or
                                fw_c_config.is_applied())):
                            remove_task = self.create_firewall_config_task(
                                    node,
                                    node_config[0],
                                    node_config[0].drop_all,
                                    force_removal=True,
                                    model_items=(fw_c_config,))
                            tasks.append(remove_task)
                            create_task = self.create_firewall_config_task(
                                    node,
                                    fw_c_config,
                                    fw_c_config.drop_all,
                                    cluster.item_id,
                                    model_items=(fw_c_config,))
                            tasks.append(create_task)
                        elif (node_config and
                              node_config[0].is_for_removal() and
                              fw_c_config.is_for_removal()):
                            remove_task = self.create_firewall_config_task(
                                    node,
                                    node_config[0],
                                    node_config[0].drop_all,
                                    model_items=(fw_c_config,))
                                    # no extra model_items to set to Applied
                            if remove_task:
                                tasks.append(remove_task)
        else:
            for node in plugin_api_context.query("node"):
                fw_node_configs = node.query("firewall-node-config")
                for fw_n_config in fw_node_configs:
                    if not fw_n_config.is_applied():
                        create_task = self.create_firewall_config_task(
                            node,
                            fw_n_config,
                            fw_n_config.drop_all,
                            model_items=(fw_n_config,))
                        if create_task:
                            tasks.append(create_task)

        for node in plugin_api_context.query("ms"):
            fw_node_configs = node.query("firewall-node-config")
            for fw_n_config in fw_node_configs:
                if not fw_n_config.is_applied():
                    create_task = self.create_firewall_config_task(
                        node,
                        fw_n_config,
                        fw_n_config.drop_all)
                        # no extra model_items to set to Applied
                    if create_task:
                        tasks.append(create_task)
        return tasks

    def _drop_all_precedence(self, fw_c_config, node):
        node_configs = node.query("firewall-node-config", is_for_removal=False)
        if node_configs:
            return node_configs[0].drop_all
        return fw_c_config.drop_all

    def create_firewall_tasks(self, node, rule, cluster_id='', model_items=()):
        tasks = []
        task_props = {}
        providers = [self.DEFAULT_PROVIDER, self.IP6TABLES_PROVIDER]
        chains = [self.DEFAULT_CHAIN, self.OUTPUT_CHAIN]
        if rule.chain:
            chains = [rule.chain]

        for idx, provider_chain in enumerate(product(providers, chains)):
            provider, chain = provider_chain
            task_props['rule%d' % (idx + 1)] = self._create_one_rule(
                    rule,
                    provider,
                    chain
                    )

        rule_id = "%s_%s_%s" % (cluster_id, node.item_id, rule.item_id)
        firewall_rule_task = self.create_firewall_rule_task(
                node, rule, rule_id, task_props, model_items)
        tasks.append(firewall_rule_task)
        return tasks

    def pad(self, rule_name):
        rule_chain_no = self._get_chain_number(rule_name)
        chain_value = rule_name.split(rule_chain_no)[1]
        rule_chain_no = '%.3d' % int(rule_chain_no)
        return rule_chain_no + chain_value

    def _create_one_rule(self, rule, provider, chain):
        values = {"name": self.pad(rule.name)}
        values["chain"] = chain
        values["ensure"] = 'present'
        values["provider"] = provider
        if rule.proto:
            values["proto"] = rule.proto
        if rule.action:
            values["action"] = rule.action
        else:
            if not rule.jump:
                values["action"] = self.DEFAULT_ACTION
                try:
                    rule.action = self.DEFAULT_ACTION
                except AttributeError:
                    log.trace.error("Unable to update action with default")

        if rule.sport:
            sportlist = rule.sport.split(',')
            values["sport"] = sportlist
            # if state or proto not set, set to defaults
            if not rule.state:
                values["state"] = self.DEFAULT_STATE
                try:
                    rule.state = self.DEFAULT_STATE
                except AttributeError:
                    log.trace.error("Unable to update state with default")
            if not rule.proto:
                values["proto"] = self.DEFAULT_PROTO
                try:
                    rule.proto = self.DEFAULT_PROTO
                except AttributeError:
                    log.trace.error("Unable to update proto with default")
        if rule.dport:
            dportlist = rule.dport.split(',')
            values["dport"] = dportlist
            # if state or proto not set, set to defaults
            if not rule.state:
                values["state"] = self.DEFAULT_STATE
                try:
                    rule.state = self.DEFAULT_STATE
                except AttributeError:
                    log.trace.error("Unable to update state with default")
            if not rule.proto:
                values["proto"] = self.DEFAULT_PROTO
                try:
                    rule.proto = self.DEFAULT_PROTO
                except AttributeError:
                    log.trace.error("Unable to update proto with default")

        if (rule.sport or rule.dport) and rule.state == 'none':
            pass
        elif rule.state:
            statelist = rule.state.split(',')
            values["state"] = statelist
        if rule.source and self._propogate_addresses(rule, provider):
            if '-' in rule.source:
                values["src_range"] = rule.source
            else:
                values["source"] = rule.source
        if rule.destination and self._propogate_addresses(rule, provider):
            if '-' in rule.destination:
                values["dst_range"] = rule.destination
            else:
                values["destination"] = rule.destination
        if rule.iniface and chain == self.DEFAULT_CHAIN:
            values["iniface"] = rule.iniface
        if rule.outiface and chain == self.OUTPUT_CHAIN:
            values["outiface"] = rule.outiface
        if rule.icmp:
            values["icmp"] = rule.icmp
        if rule.log_level:
            values["log_level"] = rule.log_level
        if rule.log_prefix:
            values["log_prefix"] = rule.log_prefix
        if rule.jump:
            values["jump"] = rule.jump
        if rule.table:
            values["table"] = rule.table
            if rule.chain:
                values['chain'] = rule.chain
        if rule.toports:
            values["toports"] = rule.toports
        if rule.limit:
            values["limit"] = rule.limit
        if rule.setdscp:
            values["setdscp"] = rule.setdscp
        if chain == self.OUTPUT_CHAIN:
            values['name'] = (self.OUTPUT_PREPEND + str(values["name"]))
        if chain == self.FORWARD_CHAIN:
            values['name'] = (self.FORWARD_PREPEND + str(values["name"]))
        if provider == self.DEFAULT_PROVIDER:
            values['name'] = (str(values["name"]) + self.IPV4)
        elif provider == self.IP6TABLES_PROVIDER:
            values['name'] = (str(values["name"]) + self.IPV6)
        values['title'] = values['name'].replace(" ", "_")
        if (rule.chain and rule.chain != chain) or (
            rule.provider and rule.provider != provider):
            values["ensure"] = 'absent'
        if (rule.table and rule.chain and not rule.is_for_removal() and
            rule.provider and rule.provider == provider):
            values["ensure"] = 'present'
        if rule.is_for_removal():
            values["ensure"] = 'absent'
        if rule.tosource:
            values["tosource"] = rule.tosource
        if rule.algo:
            values["algo"] = rule.algo
        if rule.string:
            values["string"] = rule.string
        return values

    def create_firewall_rule_task(self, node, rule, rule_id,
                                      properties, model_items):
        action = "Add"
        if rule.is_updated():
            action = "Update"
        elif rule.is_for_removal():
            action = "Remove"
        desc = '%s firewall rule "%s" on node "%s"' % (
            action, rule.name, node.hostname)
        task = ConfigTask(
            node=node,
            model_item=rule,
            description=desc,
            call_type="firewalls::rules",
            call_id=rule_id,
            **properties
        )
        task.model_items.update(model_items)

        return task

    def create_firewall_config_task(self, node, config, drop_all,
                                    cluster_id='', force_removal=False,
                                    model_items=()):
        action = "Add"
        drop_all_snippet = ""
        call_type = "firewalls::config"
        props = {"drop_all": drop_all,
                 "action": "create"}
        if drop_all == "true":
            drop_all_snippet = "and drop all traffic not explicitly defined "
        desc = '%s default LITP firewall rules %son node "%s"' % (
                                  action, drop_all_snippet, node.hostname)
        if config.is_updated():
            action = "Update"
            props['action'] = "update"
            if drop_all == "false":
                desc = 'Allow all traffic not explicitly defined on node "%s"'\
                    % (node.hostname)
            elif drop_all == "true":
                desc = 'Drop all traffic not explicitly defined on node "%s"'\
                    % (node.hostname)
        if config.is_for_removal() or force_removal:
            action = "Remove"
            props['action'] = "remove"
            desc = 'Remove all LITP firewall rules on node "%s"' % (
               node.hostname)

        config_id = "%s_%s_%s" % (cluster_id, node.item_id, config.item_id)

        task = ConfigTask(
                          node=node,
                          model_item=config,
                          description=desc,
                          call_type=call_type,
                          call_id=config_id,
                          **props
        )
        task.model_items.update(model_items)

        return task

    def _decode_provider(self, provider):
        if provider:
            if provider == self.DEFAULT_PROVIDER:
                return self.IPV4
            else:
                return self.IPV6
        else:
            return self.IPV4

    def _propogate_addresses(self, rule, provider):
        should_it = True
        if provider == self.DEFAULT_PROVIDER:
            should_it = False
        ipv4addrs = False
        # should not clone an ipv4 rule which includes ipv4 addr
        if rule.source:
            if not ":" in rule.source:
                ipv4addrs = True
        if rule.destination:
            if not ":" in rule.destination:
                ipv4addrs = True

        return ipv4addrs != should_it
