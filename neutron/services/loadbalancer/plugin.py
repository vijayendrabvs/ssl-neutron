#
# Copyright 2013 Radware LTD.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Avishay Balderman, Radware

from neutron.api.v2 import attributes as attrs
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import api as qdbapi
from neutron.db.loadbalancer import lbaas_ssl_db as ssldb
from neutron.db.loadbalancer import loadbalancer_db as ldb
from neutron.db import servicetype_db as st_db
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer import agent_scheduler
from neutron.services.loadbalancer.drivers import (
    abstract_ssl_extension_driver as abs_ssl_driver)
from neutron.services import provider_configuration as pconf
from neutron.services import service_base
from neutron.extensions import lbaas_ssl
from oslo.config import cfg
from keystoneclient.v2_0.client import Client
from keystoneclient.middleware import auth_token
import json

# List of subnets per VPC
# The lbaas_vpc_vip_subnets is a dictionary of this form:
# {
#   'vpc_name1': ['subnet_uuid1', 'subnet_uuid2', ...],
#   'vpc_name2': ['subnet_uuid1', 'subnet_uuid2', ...]
#   ...
# }
lbaas_vpc_vip_subnets = [
    cfg.StrOpt('lbaas_vpc_vip_subnets',
                default='',
                help='Subnets that VIPs can belong to, for a VPC.'),
]

cfg.CONF.register_opts(lbaas_vpc_vip_subnets)

LOG = logging.getLogger(__name__)


class LoadBalancerPlugin(ldb.LoadBalancerPluginDb,
                         agent_scheduler.LbaasAgentSchedulerDbMixin,
                         ssldb.LBaasSSLDbMixin):

    """Implementation of the Neutron Loadbalancer Service Plugin.

    This class manages the workflow of LBaaS request/response.
    Most DB related works are implemented in class
    loadbalancer_db.LoadBalancerPluginDb.
    """
    supported_extension_aliases = ["lbaas",
                                   "lbaas_agent_scheduler",
                                   "service-type",
                                   "lbaas-ssl"]

    # lbaas agent notifiers to handle agent update operations;
    # can be updated by plugin drivers while loading;
    # will be extracted by neutron manager when loading service plugins;
    agent_notifiers = {}

    def __init__(self):
        """Initialization for the loadbalancer service plugin."""

        qdbapi.register_models()
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        self._load_drivers()

        self.authhost = cfg.CONF.keystone_authtoken['auth_host']
        self.keystone_admin_username = cfg.CONF.keystone_authtoken['admin_user']
        self.keystone_pwd = cfg.CONF.keystone_authtoken['admin_password']
        self.keystone_tenant_name = cfg.CONF.keystone_authtoken['admin_tenant_name']
        self.auth_uri = "http://" + self.authhost + ":5000/v2.0"

        self.keystone_client = Client(username=self.keystone_admin_username,
                                    password=self.keystone_pwd,
                                    tenant_name=self.keystone_tenant_name,
                                    auth_url=self.auth_uri)

    def _load_drivers(self):
        """Loads plugin-drivers specified in configuration."""
        self.drivers, self.default_provider = service_base.load_drivers(
            constants.LOADBALANCER, self)

        # we're at the point when extensions are not loaded yet
        # so prevent policy from being loaded
        ctx = context.get_admin_context(load_admin_roles=False)
        # stop service in case provider was removed, but resources were not
        self._check_orphan_pool_associations(ctx, self.drivers.keys())

    def _check_orphan_pool_associations(self, context, provider_names):
        """Checks remaining associations between pools and providers.

        If admin has not undeployed resources with provider that was deleted
        from configuration, neutron service is stopped. Admin must delete
        resources prior to removing providers from configuration.
        """
        pools = self.get_pools(context)
        lost_providers = set([pool['provider'] for pool in pools
                              if pool['provider'] not in provider_names])
        # resources are left without provider - stop the service
        if lost_providers:
            msg = _("Delete associated loadbalancer pools before "
                    "removing providers %s") % list(lost_providers)
            LOG.exception(msg)
            raise SystemExit(msg)

    def _get_driver_for_provider(self, provider):
        if provider in self.drivers:
            return self.drivers[provider]
        # raise if not associated (should never be reached)
        raise n_exc.Invalid(_("Error retrieving driver for provider %s") %
                            provider)

    def _get_driver_for_pool(self, context, pool_id):
        pool = self.get_pool(context, pool_id)
        try:
            return self.drivers[pool['provider']]
        except KeyError:
            raise n_exc.Invalid(_("Error retrieving provider for pool %s") %
                                pool_id)

    def _get_driver_for_vip_ssl(self, context, vip_id):
        vip = self.get_vip(context, vip_id)
        pool = self.get_pool(context, vip['pool_id'])
        if pool['provider']:
            try:
                driver = self.drivers[pool['provider']]
                if not issubclass(
                    driver.__class__,
                    abs_ssl_driver.LBaaSAbstractSSLDriver
                ):
                    raise n_exc.ExtensionNotSupportedByProvider(
                        extension_name='lbaas-ssl',
                        provider_name=pool['provider'])
                return driver
            except KeyError:
                raise n_exc.Invalid(_("Error retrieving provider for "
                                      "vip's %s SSL configuration"), vip_id)
        else:
            raise n_exc.Invalid(_("Error retrieving provider for vip %s"),
                                vip_id)

    def get_plugin_type(self):
        return constants.LOADBALANCER

    def get_plugin_description(self):
        return "Neutron LoadBalancer Service Plugin"

    def create_vip(self, context, vip):
        requested_subnet = vip['vip']['subnet_id']
        tenant_info = self.keystone_client.tenants.get(tenant_id=vip['vip']['tenant_id'])
        tenant_info_dict = tenant_info.__dict__['_info']
        if 'cos' not in tenant_info_dict:
            raise n_exc.Invalid('Tenant not configured with a COS value!')

        tenant_cos = tenant_info_dict['cos']
        if not tenant_cos:
            raise n_exc.Invalid('Tenant not configured with a COS value!')

        all_cos_subnets_dict = json.loads(cfg.CONF.lbaas_vpc_vip_subnets)
        if tenant_cos in all_cos_subnets_dict:
            cos_subnet_list = all_cos_subnets_dict[tenant_cos]
            if requested_subnet not in cos_subnet_list:
                raise n_exc.Invalid('This VIP is not authorized to use the specified subnet')
        else:
            raise n_exc.Invalid('The tenant COS is not configured with a VIP network list')

        v = super(LoadBalancerPlugin, self).create_vip(context, vip)
        driver = self._get_driver_for_pool(context, v['pool_id'])
        driver.create_vip(context, v)
        return v

    def update_vip(self, context, id, vip):
        if 'status' not in vip['vip']:
            vip['vip']['status'] = constants.PENDING_UPDATE
        old_vip = self.get_vip(context, id)
        v = super(LoadBalancerPlugin, self).update_vip(context, id, vip)
        driver = self._get_driver_for_pool(context, v['pool_id'])
        driver.update_vip(context, old_vip, v)
        return v

    def _delete_db_vip(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        super(LoadBalancerPlugin, self).delete_vip(context, id)

    def delete_vip(self, context, id):
        self.update_status(context, ldb.Vip,
                           id, constants.PENDING_DELETE)
        v = self.get_vip(context, id)
        driver = self._get_driver_for_pool(context, v['pool_id'])
        driver.delete_vip(context, v)

    def create_ssl_certificate(self, context, ssl_certificate):
        ssl_cert = ssl_certificate['ssl_certificate']
        new_cert = super(
            LoadBalancerPlugin,
            self).create_ssl_certificate(
            context,
            ssl_cert)
        return new_cert

    def create_ssl_certificate_chain(self, context, ssl_certificate_chain):
        ssl_cert_chain = ssl_certificate_chain['ssl_certificate_chain']
        new_cert_chain = super(
            LoadBalancerPlugin,
            self).create_ssl_certificate_chain(
            context, ssl_cert_chain)
        return new_cert_chain

    def create_ssl_certificate_key(self, context, ssl_certificate_key):
        ssl_cert_key = ssl_certificate_key['ssl_certificate_key']
        new_cert_key = super(
            LoadBalancerPlugin,
            self).create_ssl_certificate_key(
            context, ssl_cert_key)
        return new_cert_key

    def update_ssl_certificate_chain(self, context, id, ssl_certificate_chain):
        # Don't support update for now.
        pass

    def update_vip_ssl_certificate_association(self, context, id, vip_ssl_certificate_association):
        # Don't support update for now.
        pass

    def delete_ssl_certificate(self, context, id):
        super(LoadBalancerPlugin, self).delete_ssl_certificate(context, id)

    def delete_ssl_certificate_chain(self, context, id):
        super(LoadBalancerPlugin, self).delete_ssl_certificate_chain(context, id)

    def delete_ssl_certificate_key(self, context, id):
        super(LoadBalancerPlugin, self).delete_ssl_certificate_key(context, id)

    def update_ssl_certificate_key(self, context, id, ssl_certificate_key):
        # Don't support update for now.
        pass

    def get_ssl_certificate(self, context, cert_id, fields=None):
        res = super(
            LoadBalancerPlugin,
            self).get_ssl_certificate(
            context,
            cert_id,
            fields)
        return res

    def get_ssl_certificates(self, context, filters=None, fields=None):
        res = super(
            LoadBalancerPlugin,
            self).get_ssl_certificates(
            context,
            filters,
            fields)
        return res

    def update_ssl_certificate(self, context, id, ssl_certificate):
        # Don't support update for now.
        pass

    def create_vip_ssl_certificate_association(self, context,
                                               vip_ssl_certificate_association):
        assoc = vip_ssl_certificate_association[
            'vip_ssl_certificate_association']
        cert_id = assoc['cert_id']
        vip_id = assoc['vip_id']
        key_id = assoc['key_id']
        cert_chain_id = assoc['cert_chain_id']
        tenant_id = assoc['tenant_id']
        # First check if this association already exists for this tenant.
        exists = super(LoadBalancerPlugin, self).find_vip_ssl_cert_assoc(context,
                                                                         cert_id,
                                                                         vip_id,
                                                                         key_id,
                                                                         cert_chain_id)
        if exists:
            raise lbaas_ssl.VipSSLCertificateAssociationExists()
        # Else go ahead and create it.
        # At this stage, assoc will not have device_ip to begin with. So set it
        # to none explicitly.
        assoc['device_ip'] = None
        assoc_db = super(
            LoadBalancerPlugin,
            self).create_vip_ssl_certificate_association(
            context,
            assoc)
        vip_db = self.get_vip(context, vip_id)
        cert_db = self.get_ssl_certificate(context, cert_id)
        if cert_chain_id:
            cert_chain_db = self.get_ssl_certificate_chain(
                context,
                cert_chain_id)
        else:
            cert_chain_db = None
        key_db = self.get_ssl_certificate_key(context, key_id)
        driver = self._get_driver_for_vip_ssl(context, vip_id)
        driver.create_vip_ssl_certificate_association(
            context,
            assoc_db,
            cert_db,
            key_db,
            vip_db,
            cert_chain_db)
        return assoc_db

    def delete_vip_ssl_certificate_association(
            self, context, vip_ssl_certificate_association):
        assoc_id = vip_ssl_certificate_association
        # First, get the vip_id of this association.
        assoc_db = super(
            LoadBalancerPlugin,
            self)._get_vip_ssl_cert_assoc_by_id(
            context,
            assoc_id)
        vip_id = assoc_db['vip_id']
        cert_id = assoc_db['cert_id']
        cert_chain_id = assoc_db['cert_chain_id']
        key_id = assoc_db['key_id']
        res = super(LoadBalancerPlugin, self).delete_vip_ssl_certificate_association(
            context, assoc_db)
        # The above call to delete marks the record as PENDING_DELETE
        vip_db = self.get_vip(context, vip_id)
        cert_db = self.get_ssl_certificate(context, cert_id)
        if cert_chain_id:
            cert_chain_db = self.get_ssl_certificate_chain(
                context,
                cert_chain_id)
        else:
            cert_chain_db = None
        key_db = self.get_ssl_certificate_key(context, key_id)
        driver = self._get_driver_for_vip_ssl(context, vip_id)
        # Check if key is used in any other association. If not,
        # mark it for deletion on the LB device.
        status_set = ['ACTIVE', 'PENDING_UPDATE', 'PENDING_CREATE']
        assoc_sets = self._get_vip_ssl_cert_assocs_by_key_id(context, key_id, status_set)
        if not assoc_sets:
            key_delete_flag = True
        else:
            key_delete_flag = False

        assoc_sets = self._get_vip_ssl_cert_assocs_by_cert_id(context, cert_id, status_set)
        if not assoc_sets:
            cert_delete_flag = True
        else:
            cert_delete_flag = False

        assoc_sets = self._get_vip_ssl_cert_assocs_by_cert_chain_id(context, cert_chain_id, status_set)
        if not assoc_sets:
            cert_chain_delete_flag = True
        else:
            cert_chain_delete_flag = False

        driver.delete_vip_ssl_certificate_association(
            context,
            assoc_db,
            cert_db,
            key_db,
            vip_db,
            cert_chain_db,
            cert_delete_flag,
            cert_chain_delete_flag,
            key_delete_flag)
        return res

    def get_vip_ssl_certificate_association(
            self, context, assoc_id, fields=None):
        res = super(
            LoadBalancerPlugin,
            self).get_vip_ssl_certificate_association(
            context,
            assoc_id,
            fields)
        return res

    def get_vip_ssl_certificate_associations(
            self, context, filters=None, fields=None):
        res = super(
            LoadBalancerPlugin,
            self).get_vip_ssl_certificate_associations(
            context,
            filters,
            fields)
        return res

    def _get_provider_name(self, context, pool):
        if ('provider' in pool and
                pool['provider'] != attrs.ATTR_NOT_SPECIFIED):
            provider_name = pconf.normalize_provider_name(pool['provider'])
            self.validate_provider(provider_name)
            return provider_name
        else:
            if not self.default_provider:
                raise pconf.DefaultServiceProviderNotFound(
                    service_type=constants.LOADBALANCER)
            return self.default_provider

    def create_pool(self, context, pool):
        provider_name = self._get_provider_name(context, pool['pool'])
        p = super(LoadBalancerPlugin, self).create_pool(context, pool)

        self.service_type_manager.add_resource_association(
            context,
            constants.LOADBALANCER,
            provider_name, p['id'])
        # need to add provider name to pool dict,
        # because provider was not known to db plugin at pool creation
        p['provider'] = provider_name
        driver = self.drivers[provider_name]
        driver.create_pool(context, p)
        return p

    def update_pool(self, context, id, pool):
        if 'status' not in pool['pool']:
            pool['pool']['status'] = constants.PENDING_UPDATE
        old_pool = self.get_pool(context, id)
        p = super(LoadBalancerPlugin, self).update_pool(context, id, pool)
        driver = self._get_driver_for_provider(p['provider'])
        driver.update_pool(context, old_pool, p)
        return p

    def _delete_db_pool(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        # rely on uuid uniqueness:
        with context.session.begin(subtransactions=True):
            self.service_type_manager.del_resource_associations(context, [id])
            super(LoadBalancerPlugin, self).delete_pool(context, id)

    def delete_pool(self, context, id):
        self.update_status(context, ldb.Pool,
                           id, constants.PENDING_DELETE)
        p = self.get_pool(context, id)
        driver = self._get_driver_for_provider(p['provider'])
        driver.delete_pool(context, p)

    def create_member(self, context, member):
        m = super(LoadBalancerPlugin, self).create_member(context, member)
        driver = self._get_driver_for_pool(context, m['pool_id'])
        driver.create_member(context, m)
        return m

    def update_member(self, context, id, member):
        if 'status' not in member['member']:
            member['member']['status'] = constants.PENDING_UPDATE
        old_member = self.get_member(context, id)
        m = super(LoadBalancerPlugin, self).update_member(context, id, member)
        driver = self._get_driver_for_pool(context, m['pool_id'])
        driver.update_member(context, old_member, m)
        return m

    def _delete_db_member(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        super(LoadBalancerPlugin, self).delete_member(context, id)

    def delete_member(self, context, id):
        self.update_status(context, ldb.Member,
                           id, constants.PENDING_DELETE)
        m = self.get_member(context, id)
        driver = self._get_driver_for_pool(context, m['pool_id'])
        driver.delete_member(context, m)

    def create_health_monitor(self, context, health_monitor):
        hm = super(LoadBalancerPlugin, self).create_health_monitor(
            context,
            health_monitor
        )
        return hm

    def update_health_monitor(self, context, id, health_monitor):
        old_hm = self.get_health_monitor(context, id)
        hm = super(LoadBalancerPlugin, self).update_health_monitor(
            context,
            id,
            health_monitor
        )

        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                ldb.PoolMonitorAssociation
            ).filter_by(monitor_id=hm['id']).join(ldb.Pool)
            for assoc in qry:
                driver = self._get_driver_for_pool(context, assoc['pool_id'])
                driver.update_health_monitor(context, old_hm,
                                             hm, assoc['pool_id'])
        return hm

    def _delete_db_pool_health_monitor(self, context, hm_id, pool_id):
        super(LoadBalancerPlugin, self).delete_pool_health_monitor(context,
                                                                   hm_id,
                                                                   pool_id)

    def _delete_db_health_monitor(self, context, id):
        super(LoadBalancerPlugin, self).delete_health_monitor(context, id)

    def delete_health_monitor(self, context, id):
        with context.session.begin(subtransactions=True):
            hm = self.get_health_monitor(context, id)
            qry = context.session.query(
                ldb.PoolMonitorAssociation
            ).filter_by(monitor_id=id).join(ldb.Pool)
            for assoc in qry:
                driver = self._get_driver_for_pool(context, assoc['pool_id'])
                driver.delete_pool_health_monitor(context,
                                                  hm,
                                                  assoc['pool_id'])
        super(LoadBalancerPlugin, self).delete_health_monitor(context, id)

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        retval = super(LoadBalancerPlugin, self).create_pool_health_monitor(
            context,
            health_monitor,
            pool_id
        )
        monitor_id = health_monitor['health_monitor']['id']
        hm = self.get_health_monitor(context, monitor_id)
        driver = self._get_driver_for_pool(context, pool_id)
        driver.create_pool_health_monitor(context, hm, pool_id)
        return retval

    def delete_pool_health_monitor(self, context, id, pool_id):
        self.update_pool_health_monitor(context, id, pool_id,
                                        constants.PENDING_DELETE)
        hm = self.get_health_monitor(context, id)
        driver = self._get_driver_for_pool(context, pool_id)
        driver.delete_pool_health_monitor(context, hm, pool_id)

    def stats(self, context, pool_id):
        driver = self._get_driver_for_pool(context, pool_id)
        stats_data = driver.stats(context, pool_id)
        # if we get something from the driver -
        # update the db and return the value from db
        # else - return what we have in db
        if stats_data:
            super(LoadBalancerPlugin, self).update_pool_stats(
                context,
                pool_id,
                stats_data
            )
        return super(LoadBalancerPlugin, self).stats(context,
                                                     pool_id)

    def populate_vip_graph(self, context, vip):
        """Populate the vip with: pool, members, healthmonitors."""

        pool = self.get_pool(context, vip['pool_id'])
        vip['pool'] = pool
        vip['members'] = [self.get_member(context, member_id)
                          for member_id in pool['members']]
        vip['health_monitors'] = [self.get_health_monitor(context, hm_id)
                                  for hm_id in pool['health_monitors']]
        return vip

    def validate_provider(self, provider):
        if provider not in self.drivers:
            raise pconf.ServiceProviderNotFound(
                provider=provider, service_type=constants.LOADBALANCER)
