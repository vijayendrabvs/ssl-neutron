# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

import six


@six.add_metaclass(abc.ABCMeta)
class LBaaSAbstractSSLDriver(object):

    @abc.abstractmethod
    def update_ssl_certificate(self, context, ssl_certificate, vip):
        pass

    @abc.abstractmethod
    def delete_vip_ssl_certificate_association(
            self, context, assoc_db, cert_db, key_db, vip_db, cert_chain_db=None):
        pass

    @abc.abstractmethod
    def create_vip_ssl_certificate_association(self, context, assoc_db_record, cert_db_record,
                                               key_db_record, vip_db_record, cert_chain_db_record=None):
        pass
