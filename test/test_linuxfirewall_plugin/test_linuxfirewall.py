##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
import unittest

from linuxfirewall_plugin.linuxfirewallplugin import LinuxFirewallPlugin
from linuxfirewall_extension.linuxfirewallextension \
    import LinuxFirewallExtension
from litp.extensions.core_extension import CoreExtension
from litp.core.model_manager import ModelManager
from litp.core.model_manager import ModelItem
from litp.core.plugin_manager import PluginManager
from litp.core.plugin_context_api import PluginApiContext
from litp.core.validators import ValidationError
from litp.core import constants
from litp.core.translator import Translator
t = Translator('ERIClitplinuxfirewall_CXP9031105')
_  = t._


class TestLinuxFirewallPlugin(unittest.TestCase):

    def setUp(self):
        """
        Construct a model, sufficient for test cases
        that you wish to implement in this suite.
        """
        self.model = ModelManager()
        self.plugin_manager = PluginManager(self.model)
        self.context = PluginApiContext(self.model)
        # Use add_property_types to add property types defined in
        # model extenstions
        # For example, from CoreExtensions (recommended)
        self.plugin_manager.add_property_types(
            CoreExtension().define_property_types())

        # Use add_item_types to add item types defined in
        # model extensions
        # For example, from CoreExtensions
        self.plugin_manager.add_item_types(
            CoreExtension().define_item_types())

        # Add default minimal model (which creates '/' root item)
        self.plugin_manager.add_default_model()

        # Instantiate your plugin and register with PluginManager
        self.plugin = LinuxFirewallPlugin()
        self.plugin_manager.add_property_types(
            LinuxFirewallExtension().define_property_types())
        self.plugin_manager.add_item_types(
            LinuxFirewallExtension().define_item_types())
        self.plugin_manager.add_plugin('TestPlugin', 'some.test.plugin',
                                       '1.0.0', self.plugin)

    def setup_model(self):
        self.cluster_url = "/deployments/local_vm/clusters/cluster1"
        self.node1_url = "/deployments/local_vm/clusters/cluster1/nodes/node1"
        created_items = [
            self.model.create_root_item("root", "/"),
            self.model.create_item('deployment', '/deployments/local_vm'),
            self.model.create_item('cluster', self.cluster_url),
            self.model.create_item("node", self.node1_url, hostname="node1")
        ]

        [self.assertEquals(ModelItem, type(i)) for i in created_items]
        return created_items

    def setup_model2(self):
        self.cluster_url = "/deployments/local_vm/clusters/cluster1"
        self.node1_url = "/deployments/local_vm/clusters/cluster1/nodes/node1"
        self.cluster2_url = "/deployments/local_vm/clusters/cluster2"
        self.node12_url = "/deployments/local_vm/clusters/cluster2/nodes/node1"
        self.assertEquals(ModelItem,
                          type(self.model.create_root_item("root", "/")))
        self.assertEquals(
            ModelItem, type(
                self.model.create_item('deployment', '/deployments/local_vm')))
        self.assertEquals(
            ModelItem, type(
                self.model.create_item('cluster', self.cluster_url)))
        self.assertEquals(
            ModelItem, type(
                self.model.create_item(
                    "node", self.node1_url, hostname="node1")))
        self.assertEquals(
            ModelItem, type(
                self.model.create_item('cluster', self.cluster2_url)))
        self.assertEquals(
            ModelItem, type(
                self.model.create_item(
                    "node", self.node12_url, hostname="node1c2")))

    def query(self, item_type=None, **kwargs):
        # Use PluginApiContext.query to find items in the model
        # properties to match desired item are passed as kwargs.
        # The use of this method is not required, but helps
        # plugin developer mimic the run-time environment
        # where plugin sees QueryItem-s.
        return self.context.query(item_type, **kwargs)

    def test_validate_basic_cluster_config(self):
        self.setup_model()
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_single_firewall_cluster_config(self):
        self.setup_model()
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf1")
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf2")
        errors = self.plugin.validate_model(self)
        self.assertEqual(2, len(errors))
        ref_errors = [ValidationError(
                                      item_path = ("/deployments/local_vm/"
                                                   "clusters/cluster1/"
                                                   "configs/fw_conf2"),
                                      error_message = _('ONLY_ONE_FW_CLUSTER_CONFIG_CONFIGURED_PER_CLUSTER'),
                                      error_type=constants.VALIDATION_ERROR),
                      ValidationError(item_path = ("/deployments/local_vm/"
                                                   "clusters/cluster1/"
                                                   "configs/fw_conf1"),
                                      error_message = _('ONLY_ONE_FW_CLUSTER_CONFIG_CONFIGURED_PER_CLUSTER'),
                                      error_type=constants.VALIDATION_ERROR)
                      ]
        self.assertTrue(all(x in ref_errors for x in errors))

    def test_validate_single_firewall_node_config(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf1")
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf2")
        errors = self.plugin.validate_model(self)
        self.assertEqual(2, len(errors))
        err_str =  _('ONLY_ONE_FW_NODE_CONFIG_CONFIGURED_PER_NODE')
        ref_errors = [ValidationError(
                    item_path = ("/deployments/local_vm/clusters/cluster1"
                    "/nodes/node1/configs/fw_conf2"),
                    error_message =err_str,
                     error_type=constants.VALIDATION_ERROR),
                     ValidationError(
                     item_path = ("/deployments/local_vm/clusters/cluster1/"
                     "nodes/node1/configs/fw_conf1"),
                      error_message =
                      _('ONLY_ONE_FW_NODE_CONFIG_CONFIGURED_PER_NODE'),
                      error_type=constants.VALIDATION_ERROR)
                      ]
        self.assertEquals(set(ref_errors), set(errors))

    def test_validate_basic_node_config(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not '
            'explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_rule_mandatory_properties(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        result = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1")
        self.assertEquals(ValidationError(
            property_name="name",
            error_message='ItemType "firewall-rule" is required to have a '
                'property with name "name"',
            error_type=constants.MISSING_REQ_PROP_ERROR), result[0])

    def test_validate_action_and_jump(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            action="drop",
            log_level="debug",
            jump="log")
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="111 rule",
            action="drop",
            log_level="debug",
            jump="log")
        errors = self.plugin.validate_model(self)
        self.assertEquals(ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1",
            error_message=_('RULE_MAY_NOT_CONTAIN_BOTH_ACTION_AND_JUMP'),
            error_type=constants.VALIDATION_ERROR), errors[0])
        self.assertEquals(ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes/node1",
            error_message=_('RULE_MAY_NOT_CONTAIN_BOTH_ACTION_AND_JUMP'),
            error_type=constants.VALIDATION_ERROR), errors[1])

    def test_validate_rule_invalid_properties(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        result = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            unit_test="test_fail")
        self.assertEquals(ValidationError(
            property_name="unit_test",
            error_message='"unit_test" is not an allowed property of'\
                ' firewall-rule',
            error_type=constants.PROP_NOT_ALLOWED_ERROR), result[0])

    def test_validate_double_cluster_name(self):
        self.setup_model2()
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf")
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster2"
            "/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster2"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        result = self.plugin.validate_model(self.context)
        self.assertEqual(0, len(result))

    def test_validate_double_rule_name(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="001 rule")
        result = self.plugin.validate_model(self.context)
        self.assertEqual(4, len(result))
        self.assertEqual(ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
                "/node1/configs/fw_conf/rules/rule1",
            error_message=str(_("POSITION_S_IN_FW_CHAIN_NOT_UNIQUE_ON_MSG") % ("1", "INPUT", "node 'node1'")),
            error_type=constants.VALIDATION_ERROR), result[0])
        self.assertEqual(ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
                "/node1/configs/fw_conf/rules/rule2",
            error_message=str(_("POSITION_S_IN_FW_CHAIN_NOT_UNIQUE_ON_MSG") % ("1", "INPUT", "node 'node1'")),
            error_type=constants.VALIDATION_ERROR), result[1])
        self.assertEqual(ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
                "/node1/configs/fw_conf/rules/rule1",
            error_message=str(_("POSITION_S_IN_FW_CHAIN_NOT_UNIQUE_ON_MSG") % ("1", "OUTPUT", "node 'node1'")),
            error_type=constants.VALIDATION_ERROR), result[2])
        self.assertEqual(ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
                "/node1/configs/fw_conf/rules/rule2",
            error_message=str(_("POSITION_S_IN_FW_CHAIN_NOT_UNIQUE_ON_MSG") % ("1", "OUTPUT", "node 'node1'")),
            error_type=constants.VALIDATION_ERROR), result[3])

    def test_validate_single_rule_name(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule")
        result = self.plugin.validate_model(self.context)
        self.assertEqual(0, len(result))

    def test_validate_split_chain(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 input",
            chain="INPUT")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="001 output",
            chain="OUTPUT")
        result = self.plugin.validate_model(self.context)
        self.assertEqual(0, len(result))

    def test_validate_split_chain_same_name(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/ms/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/ms/configs/fw_conf/rules/rule1",
            name="001 rule name",
            chain="INPUT")
        self.model.create_item("firewall-rule",
            "/ms/configs/fw_conf/rules/rule2",
            name="001 rule name",
            chain="OUTPUT")
        result = self.plugin.validate_model(self.context)
        self.assertEqual(0, len(result))

    def test_validate_double_rule_name_removed_rule(self):
        self.setup_model()
        i1 = self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule", action="accept", provider="ip6tables")
        i1.set_applied()
        i2.set_applied()
        self.model.set_all_applied()
        self.model.remove_item("/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="001 rule", action="accept", provider="ip6tables")
        result = self.plugin.validate_model(self.context)
        self.assertEqual(2, len(result))
        err_msg=str(_("RULE_NAME_NOT_UNIQUE_FOR_REUSED_CHAIN_NUM") % "001 rule" )
        self.assertEqual(ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes/node1/configs/fw_conf/rules/rule1",
            error_message=(err_msg),
        error_type=constants.VALIDATION_ERROR), result[0])
        self.assertEqual(ValidationError(
        error_message = err_msg,
        item_path="/deployments/local_vm/clusters/cluster1/nodes/node1/configs/fw_conf/rules/rule2",
        error_type=constants.VALIDATION_ERROR), result[1])

    def test_validate_double_rule_name_removed_rule_renamed(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule", action="accept", provider="ip6tables")
        self.model.set_all_applied()
        self.model.remove_item("/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="001 rule2", action="accept", provider="ip6tables")
        result = self.plugin.validate_model(self.context)
        self.assertEqual(0, len(result))

    def test_validate_double_rule_name_removed_rule_renumbered(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule", action="accept", provider="ip6tables")
        self.model.set_all_applied()
        self.model.remove_item("/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="002 rule", action="accept", provider="ip6tables")
        result = self.plugin.validate_model(self.context)
        self.assertEqual(0, len(result))

    def test_validate_cluster_config_only(self):
        self.setup_model()
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual('Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
                         config_tasks[0].description)
        self.assertEqual(1, len(config_tasks))

    def test_validate_drop_all_cluster_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf",
            drop_all='false')
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual('Add default LITP firewall rules on node "node1"',
                         config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_drop_all_node_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='false')
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual('Add default LITP firewall rules on node "node1"',
                         config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_inout_rule_nodes(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='false')
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="111179")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="11179")
        errors = self.plugin.validate_model(self)
        self.assertEqual(2, len(errors))
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("111179", "INPUT", "11179", "OUTPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("11179", "OUTPUT", "111179", "INPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)

    def test_validate_inout_rule_nodes_reverse(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='false')
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="1001 rule")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="1 rule")
        errors = self.plugin.validate_model(self)
        self.assertEqual(2, len(errors))
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1001", "INPUT", "1", "OUTPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1", "OUTPUT", "1001", "INPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)

    def test_validate_inout_rule_nodes_in_only(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='false')
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="1001 rule",
            chain="INPUT")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="1 rule",
            chain="OUTPUT")
        errors = self.plugin.validate_model(self)
        self.assertEqual(2, len(errors))
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1001", "INPUT", "1", "OUTPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1", "OUTPUT", "1001", "INPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)

    def test_validate_inout_rule_cluster(self):
        self.setup_model()
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf",
            drop_all='false')
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="1 rule")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule2",
            name="1001 rule")
        errors = self.plugin.validate_model(self)
        self.assertEqual(4, len(errors))
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1", "OUTPUT", "1001", "INPUT", "cluster 'cluster1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule2",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1001", "INPUT", "1", "OUTPUT", "cluster 'cluster1'"),
            error_type=constants.VALIDATION_ERROR)
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1", "OUTPUT", "1001", "INPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule2",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1001", "INPUT", "1", "OUTPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)

    def test_validate_inout_rule_cluster_node(self):
        self.setup_model()
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf",
            drop_all='false')
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='false')
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="1 rule")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="1001 rule")
        errors = self.plugin.validate_model(self)
        self.assertEqual(2, len(errors))
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1", "OUTPUT", "1001", "INPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)
        expected_error = ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            error_message=_("DEPRECATED_POSITION_S_IN_FW_CHAIN_MSG")
                % ("1001", "INPUT", "1", "OUTPUT", "node 'node1'"),
            error_type=constants.VALIDATION_ERROR)
        self.assertTrue(expected_error in errors)

    def test_validate_drop_all_config_rules_different_levels(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[0].description)
        self.assertEqual(
            '/deployments/local_vm/clusters/cluster1/nodes/node1',
            config_tasks[0].node.get_vpath())
        self.assertEqual(1, len(config_tasks))

    def test_validate_drop_all_config_rules_different_levels_set(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf",
            drop_all="false")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[0].description)
        self.assertEqual(
            '/deployments/local_vm/clusters/cluster1/nodes/node1',
            config_tasks[0].node.get_vpath())
        self.assertEqual(1, len(config_tasks))

    def test_validate_drop_all_config_rules_different_levels_set_2(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all="false")
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual('Add default LITP firewall rules on node "node1"',
                         config_tasks[0].description)
        self.assertEqual(
            '/deployments/local_vm/clusters/cluster1/nodes/node1',
            config_tasks[0].node.get_vpath())
        self.assertEqual(1, len(config_tasks))

    def test_validate_drop_all_config_rules_different_levels_set_3(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all="true")
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf",
            drop_all="false")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[0].description)
        self.assertEqual(
            '/deployments/local_vm/clusters/cluster1/nodes/node1',
            config_tasks[0].node.get_vpath())
        self.assertEqual(1, len(config_tasks))

    def test_validate_drop_all_config_rules_conflict_node(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf1",
            drop_all="false")
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf2")
        errors = self.plugin.validate_model(self)
        self.assertEqual(2, len(errors))
        self.assertTrue(ValidationError(
            item_path="/deployments/local_vm/clusters/cluster1"
                "/nodes/node1/configs/fw_conf2",
            error_message=_('ONLY_ONE_FW_NODE_CONFIG_CONFIGURED_PER_NODE'),
            error_type=constants.VALIDATION_ERROR) in errors)

    def test_validate_proto_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            proto="ospf")
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_action_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            action="drop")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_sport_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            sport="123")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_dport_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            dport="123")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_state_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            state="ESTABLISHED")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_source_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            provider="iptables",
            source="123.123.123.123")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="002 rule",
            provider="iptables",
            source="123.123.123.123-123.123.123.153")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "002 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::rules', config_tasks[1].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[1].description)
        self.assertEqual('firewalls::config', config_tasks[2].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[2].description)
        self.assertEqual(3, len(config_tasks))

    def test_validate_destination_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            provider="iptables",
            destination="123.123.123.123",
            limit="2/min")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="002 rule",
            provider="iptables",
            destination="123.123.123.123-123.123.123.153")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "002 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::rules', config_tasks[1].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[1].description)
        self.assertEqual('firewalls::config', config_tasks[2].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[2].description)
        self.assertEqual(3, len(config_tasks))

    def test_validate_iniface_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            iniface="eth1")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_outiface_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            outiface="eth0")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_icmp_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            icmp="echo-reply")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_chain_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 forward",
            chain="FORWARD")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="002 pre",
            chain="PREROUTING",
            proto="udp",
            dport="162",
            jump="REDIRECT",
            toports="30162",
            provider='iptables',
            table="nat")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule3",
            name="003 post",
            chain="POSTROUTING",
            proto="udp",
            dport="162",
            jump="REDIRECT",
            toports="30162",
            provider='ip6tables',
            table="nat")

        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)

        self.assertEqual(4, len(config_tasks))
        self.assertEqual('firewalls::config', config_tasks[3].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[3].description)
        self.assertEqual('firewalls::rules', config_tasks[2].call_type)
        self.assertEqual('Add firewall rule "001 forward" on node "node1"', config_tasks[2].description)
        self.assertEqual('FORWARD', config_tasks[2].kwargs.get('rule1').get('chain'))
        self.assertEqual('FORWARD', config_tasks[2].kwargs.get('rule2').get('chain'))
        self.assertEqual('2001 forward ipv4', config_tasks[2].kwargs.get('rule1').get('name'))
        self.assertEqual('2001 forward ipv6', config_tasks[2].kwargs.get('rule2').get('name'))
        self.assertEqual('present', config_tasks[2].kwargs.get('rule1').get('ensure'))
        self.assertEqual('present', config_tasks[2].kwargs.get('rule2').get('ensure'))
        self.assertEqual(None, config_tasks[2].kwargs.get('rule3'))
        self.assertEqual(None, config_tasks[2].kwargs.get('rule4'))

        self.assertEqual('firewalls::rules', config_tasks[1].call_type)
        self.assertEqual('Add firewall rule "002 pre" on node "node1"', config_tasks[1].description)
        self.assertEqual('PREROUTING', config_tasks[1].kwargs.get('rule1').get('chain'))
        self.assertEqual('PREROUTING', config_tasks[1].kwargs.get('rule1').get('chain'))
        self.assertEqual('002 pre ipv4', config_tasks[1].kwargs.get('rule1').get('name'))
        self.assertEqual('002 pre ipv6', config_tasks[1].kwargs.get('rule2').get('name'))
        self.assertEqual('present', config_tasks[1].kwargs.get('rule1').get('ensure'))
        self.assertEqual('absent', config_tasks[1].kwargs.get('rule2').get('ensure'))
        self.assertEqual(None, config_tasks[1].kwargs.get('rule3'))
        self.assertEqual(None, config_tasks[1].kwargs.get('rule4'))

        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "003 post" on node "node1"', config_tasks[0].description)
        self.assertEqual('POSTROUTING', config_tasks[0].kwargs.get('rule1').get('chain'))
        self.assertEqual('POSTROUTING', config_tasks[0].kwargs.get('rule2').get('chain'))
        self.assertEqual('003 post ipv4', config_tasks[0].kwargs.get('rule1').get('name'))
        self.assertEqual('003 post ipv6', config_tasks[0].kwargs.get('rule2').get('name'))
        self.assertEqual('absent', config_tasks[0].kwargs.get('rule1').get('ensure'))
        self.assertEqual('present', config_tasks[0].kwargs.get('rule2').get('ensure'))
        self.assertEqual(None, config_tasks[0].kwargs.get('rule3'))
        self.assertEqual(None, config_tasks[0].kwargs.get('rule4'))

    def test_validate_chain_default_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            chain="INPUT")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_provider_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            provider="ip6tables")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
             config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_provider_default_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            provider="iptables")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
             config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_log_level_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            log_level="notice")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
             config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_log_prefix_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            log_prefix="some_string")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
             config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_jump_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
                               "/deployments/local_vm/clusters/cluster1"
                               "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
                               "/deployments/local_vm/clusters/cluster1/nodes"
                               "/node1/configs/fw_conf/rules/rule1",
                               name="001 rule",
                               jump="some_string")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual('Add default LITP firewall rules and drop all traffic'
                         ' not explicitly defined on node "node1"',
                         config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_table_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
                               "/deployments/local_vm/clusters/cluster1"
                               "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
                               "/deployments/local_vm/clusters/cluster1/nodes"
                               "/node1/configs/fw_conf/rules/rule1",
                               name="1 rule")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))

        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "1 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
             config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_same_name_and_same_chain_fucntions(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        rule1 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule 123")
        rule2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule2",
            name="002 rule 123")

        rule3 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule3",
            name="002 rule is cool")

        rule4 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule4",
            name="002 rule123")
        self.assertEqual(True, self.plugin._same_name(rule1, rule2))
        self.assertEqual(True, self.plugin._same_chain(rule3, rule4))

    def test_validate_toports_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            toports="123")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
             config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_validate_setdscp_config_rule(self):
        self.setup_model()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule",
            setdscp="0xbeef")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Add firewall rule "001 rule" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
             config_tasks[1].description)
        self.assertEqual(2, len(config_tasks))

    def test_update_drop_all_from_false_to_true_node_config_rule(self):
        setup_items = self.setup_model()
        i1 = self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='false')
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule")
        [i.set_applied() for i in [i1, i2] + setup_items]
        self.model.set_all_applied()
        self.model.update_item("/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='true')
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Drop all traffic not explicitly defined on node "node1"',
            config_tasks[0].description)
        self.assertEqual(1, len(config_tasks))

    def test_update_drop_all_from_true_to_false_node_config_rule(self):
        self.setup_model()
        i1 = self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='true')
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/nodes"
            "/node1/configs/fw_conf/rules/rule1",
            name="001 rule")
        [i.set_applied() for i in (i1, i2)]
        self.model.set_all_applied()
        self.model.update_item("/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all='false')
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Allow all traffic not explicitly defined on node "node1"',
            config_tasks[0].description)
        self.assertEqual(1, len(config_tasks))

    def test_update_basic_cluster_config_rule(self):
        setup_items = self.setup_model()
        i1 = self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        [i.set_applied() for i in [i1, i2] + setup_items]
        self.model.set_all_applied()
        self.model.update_item("/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rules")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual('firewalls::rules', config_tasks[0].call_type)
        self.assertEqual('Update firewall rule "001 rules" on node "node1"',
                         config_tasks[0].description)
        self.assertEqual(1, len(config_tasks))

    def test_remove_basic_cluster_config_rule(self):
        self.setup_model()
        i1 = self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        [i.set_applied() for i in (i1, i2)]
        self.model.set_all_applied()
        result = self.model.remove_item("/deployments/local_vm/clusters"
            "/cluster1/configs/fw_conf/rules/rule1")
        self.assertEqual(ModelItem, type(result))
        self.assertEqual("ForRemoval", self.model.get_item(
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1").get_state())

    def test_remove_basic_node_config_rule(self):
        setup_items = self.setup_model()
        i1 = self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf/rules/rule1",
            name="001 rule")
        [i.set_applied() for i in [i1, i2] + setup_items]
        self.model.set_all_applied()
        result = self.model.remove_item(
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf/rules/rule1")
        self.assertEqual(ModelItem, type(result))
        self.assertEqual("ForRemoval", self.model.get_item(
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf/rules/rule1").get_state())

    def test_remove_basic_cluster_config(self):
        self.setup_model()
        i1 = self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        i1.set_applied()
        i2.set_applied()
        self.model.set_all_applied()
        result = self.model.remove_item("/deployments/local_vm/clusters"
            "/cluster1/configs/fw_conf")
        self.assertEqual(ModelItem, type(result))
        self.assertEqual("ForRemoval", self.model.get_item(
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf").get_state())
        self.assertEqual("ForRemoval", self.model.get_item(
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1").get_state())
        self.plugin.create_configuration(self.context)

    def test_remove_basic_node_config(self):
        self.setup_model()
        i1 = self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf/rules/rule1",
            name="001 rule")
        [i.set_applied() for i in (i1, i2)]
        self.model.set_all_applied()
        result = self.model.remove_item(
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        self.assertEqual(ModelItem, type(result))
        self.assertEqual("ForRemoval", self.model.get_item(
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf").get_state())
        self.assertEqual("ForRemoval", self.model.get_item(
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf/rules/rule1").get_state())
        self.plugin.create_configuration(self.context)

    def test_create_drop_all_node_config_rule_later(self):
        setup_items = self.setup_model()
        i1 = self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        [i.set_applied() for i in [i1, i2] + setup_items]
        self.model.set_all_applied()
        self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all="false")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual(2, len(config_tasks))
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Add default LITP firewall rules on node "node1"',
            config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Remove all LITP firewall rules on node "node1"',
            config_tasks[1].description)
        self.assertEqual(1, len(config_tasks[0].requires))
        requires_task = config_tasks[0].requires.pop()
        self.assertEqual('cluster1_node1_fw_conf', requires_task.call_id)

    def test_create_drop_all_node_config_rule_later_removed(self):
        setup_items = self.setup_model()
        i1 = self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        [i.set_applied() for i in [i1, i2] + setup_items]
        self.model.set_all_applied()
        i3 = self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all="false")
        [i.set_applied() for i in (i1, i2, i3)]
        self.model.set_all_applied()
        self.model.remove_item("/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual(2, len(config_tasks))
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Remove all LITP firewall rules on node "node1"',
            config_tasks[0].description)
        self.assertEqual('firewalls::config', config_tasks[1].call_type)
        self.assertEqual(
            'Add default LITP firewall rules and drop all traffic not explicitly defined on node "node1"',
            config_tasks[1].description)
        self.assertEqual(0, len(config_tasks[0].requires))

    def test_update_drop_all_to_false_node_config(self):
        items_setup = self.setup_model()
        i1 = self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf",
            drop_all="false")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        i3 = self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all="true")
        [i.set_applied() for i in [i1, i2, i3] + items_setup]
        self.model.set_all_applied()
        self.model.update_item("/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf", drop_all="false")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual(1, len(config_tasks))
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Allow all traffic not explicitly defined on node "node1"',
            config_tasks[0].description)

    def test_update_drop_all_node_and_cluster_config(self):
        setup_items = self.setup_model()
        i1 = self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf",
            drop_all="false")
        i2 = self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf/rules/rule1",
            name="001 rule")
        i3 = self.model.create_item("firewall-node-config",
            "/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf",
            drop_all="true")
        [i.set_applied() for i in [i1, i2, i3] + setup_items]
        self.model.set_all_applied()
        self.model.update_item("/deployments/local_vm/clusters/cluster1"
            "/nodes/node1/configs/fw_conf", drop_all="false")
        self.model.update_item("/deployments/local_vm/clusters/cluster1"
            "/configs/fw_conf", drop_all="true")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
        config_tasks = self.plugin.create_configuration(self.context)
        self.assertEqual(1, len(config_tasks))
        self.assertEqual('firewalls::config', config_tasks[0].call_type)
        self.assertEqual(
            'Allow all traffic not explicitly defined on node "node1"',
            config_tasks[0].description)

    def test_remove_ms_rule_with_same_name(self):
        self.setup_model()
        self.model.create_item("firewall-cluster-config",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/deployments/local_vm/clusters/cluster1/configs/fw_conf/rules/rule1",
            name="001 rule")
        self.model.create_item("firewall-node-config",
            "/ms/configs/fw_conf")
        self.model.create_item("firewall-rule",
            "/ms/configs/fw_conf/rules/rule1",
            name="001 rule")
        self.model.set_all_applied()
        self.model.remove_item("/ms/configs/fw_conf/rules/rule1")
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))
