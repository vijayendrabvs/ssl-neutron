# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 OpenStack Foundation.
# All Rights Reserved.
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
# @author: Vijayendra Bhamidipati, Ebay Inc.

import abc

from oslo.config import cfg
import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as qexception
from neutron.extensions import loadbalancer
from neutron import manager
from neutron.plugins.common import constants
from neutron.services.service_base import ServicePluginBase


# SSL Exceptions

class SSLCertificateException(qexception.Conflict):
    message = _("An internal error occurred")


class SSLCertificateNotFound(qexception.NotFound):
    message = _("SSL Certificate %(certificate_id)s could not be found")


class SSLCertificateInUse(qexception.InUse):
    message = _("SSL Certificate %(certificate_id)s is still associated "
                "with vips")


class SSLCertificateChainNotFound(qexception.NotFound):
    message = _("SSL Certificate chain %(ssl_cert_id)s does not exist")


class SSLCertificateKeyNotFound(qexception.NotFound):
    message = _("SSL Certificate key %(ssl_key_id)s does not exist")


class SSLCertificateKeyInUse(qexception.InUse):
    message = _("SSL Certificate %(cert_key_id)s is still associated "
                "with vips")


class SSLCertificateChainInUse(qexception.InUse):
    message = _("SSL Certificate %(cert_chain_id)s is still associated "
                "with vips")


class SSLCertificateChainException(Exception):
    message = _("A generic exception occurred with an operation on "
                "cert chain %(cert_chain_id)s with vips")


class SSLCertificateKeyException(Exception):
    message = _("A generic exception occurred with an operation on "
                "cert key %(cert_key_id)s with vips")


class VipSSLCertificateAssociationNotFound(qexception.NotFound):
    message = _("Vip %(vip_id)s is not associated "
                "with SSL Certificate %(certificate_id)s")


class VipSSLCertificateAssociationExists(qexception.Conflict):
    message = _("Association of specified entities already exists")


class VipSSLCertificateException(Exception):
    message = _("An internal error occurred in DDL of "
                "association %(assoc_id)s")


class VipSSLCertificateAssociationDeleteException(Exception):
    message = _("Deletion of vip ssl cert association %(assoc_id)s failed")


RESOURCE_ATTRIBUTE_MAP = {
    'ssl_certificates': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'default': '',
                        'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'certificate': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'passphrase': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:string': None},
                       'is_visible': True, 'default': ''}
    },
    'ssl_certificate_keys': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'key': {'allow_post': True, 'allow_put': True,
                'validate': {'type:string': None},
                'is_visible': True, 'default': ''}
    },
    'ssl_certificate_chains': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'cert_chain': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:string': None},
                       'is_visible': True, 'default': ''}
    },
    'vip_ssl_certificate_associations': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'cert_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:string': None},
                    'default': '',
                    'is_visible': True},
        'key_id': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '',
                   'is_visible': True},
        'cert_chain_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'default': '',
                          'is_visible': True},
        'vip_id': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '',
                   'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:string': None},
                   'default': '',
                   'is_visible': True},
        'status_description': {'allow_post': False, 'allow_put': False,
                               'validate': {'type:string': None},
                               'default': '',
                               'is_visible': True}
    }
}


class Lbaas_ssl(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Loadbalancing service SSL extension"

    @classmethod
    def get_alias(cls):
        return "lbaas-ssl"

    @classmethod
    def get_description(cls):
        return ("Extension for Loadbalancing service SSL")

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/LBaaS/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2014-07-27T10:00:00-00:00"

    @classmethod
    def get_resources(cls, ext_plugin=None):
        ssl_plurals = {
            'ssl_certificates': 'ssl_certificate',
            'vip_ssl_certificate_associations': 'vip_ssl_certificate_association',
            'ssl_certificate_keys': 'ssl_certificate_key',
            'ssl_certificate_chains': 'ssl_certificate_chain'
        }
        attr.PLURALS.update(ssl_plurals)
        resources = []
        plugin = ext_plugin or manager.NeutronManager.get_service_plugins()[
            constants.LOADBALANCER]

        for collection_name in RESOURCE_ATTRIBUTE_MAP:
            resource_name = ssl_plurals[collection_name]
            params = RESOURCE_ATTRIBUTE_MAP[collection_name]

            member_actions = {}
            controller = base.create_resource(
                collection_name, resource_name, plugin, params,
                member_actions=member_actions,
                allow_pagination=cfg.CONF.allow_pagination,
                allow_sorting=cfg.CONF.allow_sorting)

            resource = extensions.ResourceExtension(
                collection_name,
                controller,
                path_prefix=constants.COMMON_PREFIXES[constants.LOADBALANCER],
                member_actions=member_actions,
                attr_map=params)
            resources.append(resource)

        return resources

    @classmethod
    def get_plugin_interface(cls):
        return loadbalancer.LoadBalancerPluginBase

    def update_attributes_map(self, attributes):
        super(Lbaas_ssl, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)


@six.add_metaclass(abc.ABCMeta)
class LbaasSSLPluginBase(ServicePluginBase):

    def get_plugin_name(self):
        return constants.LOADBALANCER

    def get_plugin_type(self):
        return constants.LOADBALANCER

    def get_plugin_description(self):
        return 'LoadBalancer ssl extension service v1 plugin'

    @abc.abstractmethod
    def create_ssl_certificate(self, context, ssl_certificate):
        pass

    @abc.abstractmethod
    def update_ssl_certificate(self, context, id, ssl_certificate):
        pass

    @abc.abstractmethod
    def delete_ssl_certificate(self, context, id):
        pass

    @abc.abstractmethod
    def get_ssl_certificate(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_ssl_certificates(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_ssl_certificate_key(self, context, ssl_certificate_key):
        pass

    @abc.abstractmethod
    def update_ssl_certificate_key(self, context, id, ssl_certificate_key):
        pass

    @abc.abstractmethod
    def delete_ssl_certificate_key(self, context, id):
        pass

    @abc.abstractmethod
    def get_ssl_certificate_key(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_ssl_certificate_keys(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_ssl_certificate_chain(self, context, ssl_certificate_chain):
        pass

    @abc.abstractmethod
    def update_ssl_certificate_chain(self, context, id, ssl_certificate_chain):
        pass

    @abc.abstractmethod
    def delete_ssl_certificate_chain(self, context, id):
        pass

    @abc.abstractmethod
    def get_ssl_certificate_chain(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_ssl_certificate_chains(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_vip_ssl_certificate_association(self, context,
                                               vip_ssl_certificate_association):
        # Note that in this function signature, keep the parameter
        # names exactly as what gets passed in the HTTP request body.
        # The boilerplate code that invokes this function passes it
        # in as a keyword argument. So in this case, our param name
        # can only be vip_ssl_certificate_association and not something
        # like vip_ssl_certificate_dict.
        pass

    @abc.abstractmethod
    def delete_vip_ssl_certificate_association(
            self, context, vip_ssl_certificate_association):
        # The association must contain the tenant_id and the association id
        # that we would like to delete.
        pass

    @abc.abstractmethod
    def update_vip_ssl_certificate_association(self, context, vip_ssl_certificate_association):
        pass

    @abc.abstractmethod
    def get_vip_ssl_certificate_association(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_vip_ssl_certificate_associations(
            self, context, filters=None, fields=None):
        pass
