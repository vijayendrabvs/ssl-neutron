# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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


import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.db import db_base_plugin_v2 as base_db
from neutron.db.loadbalancer import loadbalancer_db as lbaas_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import lbaas_ssl
from neutron.extensions import loadbalancer
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants


class SSLCertificate(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):

    """Represents a v2 neutron SSL Certificate.

    SSL Certificate may be associated to 0..N vips
    Vip can be associated with 0..M certificates.
    """
    __tablename__ = 'ssl_certificates'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    certificate = sa.Column(sa.Text(20480))
    passphrase = sa.Column(sa.String(128))


class SSLCertificateKey(
        model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):

    """Represents a v2 neutron SSL certificate Key.

    The key is associated with a vip along with a cert and/or cert chain.
    It can be used in multiple vip/cert/cert-chain combinations and hence
    the relation between all these entities is 0..n and n..0.
    """
    __tablename__ = 'ssl_cert_keys'
    name = sa.Column(sa.String(255))
    key = sa.Column(sa.String(20480))


class SSLCertificateChain(
        model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):

    """ Represents an SSL cert chain.
    """
    __tablename__ = 'ssl_cert_chains'
    name = sa.Column(sa.String(255))
    cert_chain = sa.Column(sa.String(20480))


class VipSSLCertificateAssociation(model_base.BASEV2, models_v2.HasId,
                                   models_v2.HasStatusDescription,
                                   models_v2.HasTenant):

    __tablename__ = 'vip_ssl_cert_associations'
    name = sa.Column(sa.String(255))
    vip_id = sa.Column(sa.String(36),
                       sa.ForeignKey('vips.id'),
                       nullable=False)
    cert_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ssl_certificates.id'),
                        nullable=False)
    cert_chain_id = sa.Column(sa.String(36),
                              sa.ForeignKey('ssl_cert_chains.id'),
                              nullable=True)
    key_id = sa.Column(sa.String(36),
                       sa.ForeignKey('ssl_cert_keys.id'),
                       nullable=False)
    device_ip = sa.Column(sa.String(255))


class LBaasSSLDbMixin(lbaas_ssl.LbaasSSLPluginBase, base_db.CommonDbMixin):

    def _get_vip_ssl_cert_assoc_by_id(self, context, assoc_id):
        model = VipSSLCertificateAssociation
        query = self._model_query(context, model)
        return query.filter(model.id == assoc_id).one()

    def _get_vip_ssl_cert_assoc_by_vip_id(self, context, model, vip_id):
        query = self._model_query(context, model)
        return query.filter(model.vip_id == vip_id).one()

    def _get_vip_ssl_cert_assoc_by_cert_id(self, context, cert_id, status):
        model = VipSSLCertificateAssociation
        query = self._model_query(context, model)
        try:
            if status:
                assoc = query.filter(model.cert_id == cert_id, model.status == status).first()
            else:
                assoc = query.filter(model.cert_id == cert_id).first()
            return assoc
        except exc.NoResultFound:
            return None

    def _get_vip_ssl_cert_assocs_by_cert_id(self, context, cert_id, status_set=None):
        model = VipSSLCertificateAssociation
        query = self._model_query(context, model)
        try:
            if status_set:
                assocs = query.filter(model.cert_id == cert_id, model.status.in_(status_set)).all()
            else:
                assocs = query.filter(model.cert_id == cert_id).all()
            return assocs
        except exc.NoResultFound:
            return None

    def find_model_record_with_generic_filters(self, context, **kwargs):
        model = VipSSLCertificateAssociation
        cond = []
        for key in kwargs:
            cond.append(getattr(model, key))

        query = self._model_query(context, model)
        try:
            assoc = query.filter(*cond)
            return assoc
        except exc.NoResultFound:
            return None

    def find_vip_ssl_cert_assoc(self, context, cert_id, vip_id, key_id,
                                cert_chain_id):
        model = VipSSLCertificateAssociation
        query = self._model_query(context, model)
        try:
            assoc = query.filter(model.cert_id == cert_id, model.vip_id == vip_id,
                                 model.key_id == key_id, model.cert_chain_id == cert_chain_id)
            return assoc.one()
        except exc.NoResultFound:
            return None

    def _get_pool_id_by_vip_id(self, context, vip_id):
        vip_db_record = self._get_ssl_resource(context, lbaas_db.Vip, vip_id)
        return vip_db_record['pool_id']

    def _get_vip_ssl_cert_assocs_by_cert_chain_id(
            self, context, cert_chain_id, status_set=None):
        model = VipSSLCertificateAssociation
        query = self._model_query(context, model)
        try:
            if status_set:
                assocs = query.filter(model.cert_chain_id == cert_chain_id, model.status.in_(status_set)).all()
            else:
                assocs = query.filter(model.cert_chain_id == cert_chain_id).all()
            return assocs
        except exc.NoResultFound:
            return None

    def _get_vip_ssl_cert_assoc_by_cert_chain_id(
            self, context, cert_chain_id, status=None):
        model = VipSSLCertificateAssociation
        query = self._model_query(context, model)
        try:
            if status:
                assoc = query.filter(model.cert_chain_id == cert_chain_id, model.status == status).one()
            else:
                assoc = query.filter(model.cert_chain_id == cert_chain_id).first()
            return assoc
        except exc.NoResultFound:
            return None

    def _get_vip_ssl_cert_assocs_by_key_id(self, context, key_id, status_set=None):
        model = VipSSLCertificateAssociation
        query = self._model_query(context, model)
        try:
            if status_set:
                assocs = query.filter(model.key_id == key_id, model.status.in_(status_set)).all()
            else:
                assocs = query.filter(model.key_id == key_id).all()
            return assocs
        except exc.NoResultFound:
            return None

    def _get_vip_ssl_cert_assoc_by_key_id(self, context, key_id, status=None):
        model = VipSSLCertificateAssociation
        query = self._model_query(context, model)
        try:
            if status:
                assoc = query.filter(model.key_id == key_id, model.status == status).first()
            else:
                assoc = query.filter(model.key_id == key_id).first()
            return assoc
        except exc.NoResultFound:
            return None

    def _get_ssl_cert_by_id(self, context, cert_id):
        model = SSLCertificate
        query = self._model_query(context, model)
        try:
            cert = query.filter(model.id == cert_id).first()
            return cert
        except exc.NoResultFound:
            return None

    def _get_ssl_cert_chain_by_id(self, context, cert_chain_id):
        model = SSLCertificateChain
        query = self._model_query(context, model)
        try:
            cert_chain = query.filter(model.id == cert_chain_id).first()
            return cert_chain
        except exc.NoResultFound:
            return None

    def _get_ssl_cert_key_by_id(self, context, key_id):
        model = SSLCertificateKey
        query = self._model_query(context, model)
        try:
            cert_key = query.filter(model.id == key_id).first()
            return cert_key
        except exc.NoResultFound:
            return None

    def _get_vip_by_id(self, context, vip_id):
        model = lbaas_db.Vip
        query = self._model_query(context, model)
        try:
            vip = query.filter(model.id == vip_id).first()
            return vip
        except exc.NoResultFound:
            return None

    def _get_ssl_resource(self, context, model, id):
        try:
            r = self._get_by_id(context, model, id)
        except exc.NoResultFound:
            if issubclass(model, lbaas_db.Vip):
                raise loadbalancer.VipNotFound(vip_id=id)
            if issubclass(model, lbaas_db.Pool):
                raise loadbalancer.PoolNotFound(pool_id=id)
            elif issubclass(model, SSLCertificate):
                raise lbaas_ssl.SSLCertificateNotFound(certificate_id=id)
            elif issubclass(model, VipSSLCertificateAssociation):
                raise lbaas_ssl.VipSSLCertificateAssociationNotFound(vip_id=id)
            elif issubclass(model, SSLCertificateChain):
                raise lbaas_ssl.SSLCertificateChainNotFound(ssl_cert_id=id)
            elif issubclass(model, SSLCertificateKey):
                raise lbaas_ssl.SSLCertificateKeyNotFound(ssl_key_id=id)
            else:
                raise
        return r

    def _make_ssl_certificate_key_dict(self, ssl_cert_key, fields=None):
        res = {'id': ssl_cert_key['id'],
               'name': ssl_cert_key['name'],
               'tenant_id': ssl_cert_key['tenant_id'],
               'key': ssl_cert_key['key']
               }
        return self._fields(res, fields)

    def _make_ssl_certificate_chain_dict(self, ssl_cert_chain, fields=None):
        res = {'id': ssl_cert_chain['id'],
               'name': ssl_cert_chain['name'],
               'tenant_id': ssl_cert_chain['tenant_id'],
               'cert_chain': ssl_cert_chain['cert_chain']
               }
        return self._fields(res, fields)

    def _make_ssl_certificate_dict(self, ssl_certificate, fields=None):
        res = {'id': ssl_certificate['id'],
               'name': ssl_certificate['name'],
               'description': ssl_certificate['description'],
               'tenant_id': ssl_certificate['tenant_id'],
               'certificate': ssl_certificate['certificate'],
               'passphrase': ssl_certificate['passphrase']
               }
        return self._fields(res, fields)

    def _make_vip_ssl_assoc_dict(self, vip_ssl_association, fields=None):
        res = {'id': vip_ssl_association['id'],
               'name': vip_ssl_association['name'],
               'tenant_id': vip_ssl_association['tenant_id'],
               'vip_id': vip_ssl_association['vip_id'],
               'cert_id': vip_ssl_association['cert_id'],
               'cert_chain_id': vip_ssl_association['cert_chain_id'],
               'key_id': vip_ssl_association['key_id'],
               'device_ip': vip_ssl_association['device_ip'],
               'status': vip_ssl_association['status'],
               'status_description': vip_ssl_association['status_description']
               }
        return self._fields(res, fields)

    def create_ssl_certificate(self, context, ssl_certificate):
        tenant_id = self._get_tenant_id_for_create(context, ssl_certificate)
        with context.session.begin(subtransactions=True):
            certificate_db = SSLCertificate(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=ssl_certificate['name'],
                certificate=ssl_certificate['certificate'],
                description=ssl_certificate['description'],
                passphrase=ssl_certificate['passphrase']
            )
            context.session.add(certificate_db)
        return self._make_ssl_certificate_dict(certificate_db)

    """
    def update_ssl_certificate(self, context, id, ssl_certificate):
        # Updation of an ssl cert only updates the db.
        # Associating a vip with this ssl cert will reconfigure
        # the cert on the device.
        with context.session.begin(subtransactions=True):
            certificate_db = self._get_ssl_resource(context,
                                                    SSLCertificate, id)
            if certificate_db:
                certificate_db.update(ssl_certificate)
            return self._make_ssl_certificate_dict(certificate_db)
    """

    def delete_ssl_certificate(self, context, id):
        with context.session.begin(subtransactions=True):
            certificate = self._get_ssl_resource(context, SSLCertificate, id)
            # If there are any vip ssl associations that are not in
            # PENDING_DELETE or ERROR status (i.e., in ACTIVE/PENDING_CREATE/
            # PENDING_UPDATE statuses), disallow deletion.
            status_set = ['PENDING_CREATE', 'ACTIVE', 'PENDING_UPDATE']
            vip_ssl_assocs = self._get_vip_ssl_cert_assocs_by_cert_id(
                context, id, status_set)
            if vip_ssl_assocs:
                raise lbaas_ssl.SSLCertificateInUse(certificate_id=id)
            try:
                context.session.delete(certificate)
                context.session.flush()
            except Exception as e:
                raise lbaas_ssl.SSLCertificateException(certificate_id=id)

    def get_ssl_certificate(self, context, id, fields=None):
        cert = self._get_ssl_resource(context, SSLCertificate, id)
        return self._make_ssl_certificate_dict(cert, fields)

    def get_ssl_certificates(self, context, filters=None, fields=None):
        return self._get_collection(context, SSLCertificate,
                                    self._make_ssl_certificate_dict,
                                    filters=filters, fields=fields)

    def create_ssl_certificate_key(self, context, cert_key):
        tenant_id = self._get_tenant_id_for_create(context, cert_key)
        with context.session.begin(subtransactions=True):
            certificate_key_db = SSLCertificateKey(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=cert_key['name'],
                key=cert_key['key']
            )
            context.session.add(certificate_key_db)
        return self._make_ssl_certificate_key_dict(certificate_key_db)

    """
    def update_ssl_certificate_key(self, context, id, ssl_certificate_key):
        # Updation of an ssl cert only updates the db.
        # Associating a vip with this ssl cert will reconfigure
        # the cert on the device.
        cert_key = ssl_certificate_key['ssl_certificate_key']
        with context.session.begin(subtransactions=True):
            certificate_key_db = self._get_ssl_resource(context,
                                                        SSLCertificateKey, id)
            if certificate_key_db:
                certificate_key_db.update(cert_key)
            return self._make_ssl_certificate_key_dict(certificate_key_db)
        # TODO: Need to cascade these changes to the device in plugin.py that
        # calls this function.
    """

    def delete_ssl_certificate_key(self, context, id):
        with context.session.begin(subtransactions=True):
            certificate_key = self._get_ssl_resource(
                context,
                SSLCertificateKey,
                id)
            status_set = ['PENDING_CREATE', 'ACTIVE', 'PENDING_UPDATE']
            vip_ssl_assocs = self._get_vip_ssl_cert_assocs_by_key_id(
                context, id, status_set)
            if vip_ssl_assocs:
                raise lbaas_ssl.SSLCertificateKeyInUse(cert_key_id=id)
            try:
                context.session.delete(certificate_key)
                context.session.flush()
            except Exception as e:
                raise lbaas_ssl.SSLCertificateKeyException(cert_key_id=id)

    def get_ssl_certificate_key(self, context, id, fields=None):
        cert_key = self._get_ssl_resource(context, SSLCertificateKey, id)
        return self._make_ssl_certificate_key_dict(cert_key, fields)

    def get_ssl_certificate_keys(self, context, filters=None, fields=None):
        return self._get_collection(context, SSLCertificateKey,
                                    self._make_ssl_certificate_key_dict,
                                    filters=filters, fields=fields)

    def create_ssl_certificate_chain(self, context, cert_chain):
        tenant_id = self._get_tenant_id_for_create(context, cert_chain)
        with context.session.begin(subtransactions=True):
            certificate_chain_db = SSLCertificateChain(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=cert_chain['name'],
                cert_chain=cert_chain['cert_chain']
            )
            context.session.add(certificate_chain_db)
        return self._make_ssl_certificate_chain_dict(certificate_chain_db)

    """
    def update_vip_ssl_cert_association(self, context, assoc_record):
        # We simply set the record to pending_update in this.
        # The driver must set the status to either ACTIVE or
        # error accordingly after duly updating the association
        # on the LB device.
        assoc_record['status'] = "PENDING_UPDATE"
        if assoc_record['cert_chain_id']:
            cert_chain_id = assoc_record['cert_chain_id']
        else:
            cert_chain_id = None
        try:
            with context.session.begin(subtransactions=True):
                assoc_db = VipSSLCertificateAssociation(
                    id=assoc_record['id'],
                    tenant_id=assoc_record['tenant_id'],
                    vip_id=assoc_record['vip_id'],
                    cert_id=assoc_record['cert_id'],
                    cert_chain_id=cert_chain_id,
                    key_id=assoc_record['key_id'],
                    device_ip=assoc_record['device_ip'],
                    status=assoc_record['status'],
                    status_description=''
                )
                context.session.merge(assoc_db)
        except Exception as e:
            raise lbaas_ssl.VipSSLCertificateException(assoc_id=id)
        # Remember, this is the db layer, so the invoker of this function
        # in the plugin layer will invoke the driver.

    def update_ssl_certificate_chain(self, context, id, ssl_certificate_chain):
        # Updation of an ssl cert only updates the db.
        # Associating a vip with this ssl cert will reconfigure
        # the cert on the device.
        with context.session.begin(subtransactions=True):
            certificate_chain_db = self._get_ssl_resource(context,
                                                          SSLCertificateChain, id)
            if certificate_chain_db:
                certificate_chain_db.update(ssl_certificate_chain)
            return self._make_ssl_certificate_chain_dict(certificate_chain_db)
    """

    def delete_ssl_certificate_chain(self, context, id):
        with context.session.begin(subtransactions=True):
            certificate_chain = self._get_ssl_resource(
                context, SSLCertificateChain, id)
            status_set = ['PENDING_CREATE', 'ACTIVE', 'PENDING_UPDATE']
            vip_ssl_assocs = self._get_vip_ssl_cert_assocs_by_cert_chain_id(
                context, id, status_set)
            if vip_ssl_assocs:
                raise lbaas_ssl.SSLCertificateChainInUse(cert_chain_id=id)
            try:
                context.session.delete(certificate_chain)
                context.session.flush()
            except Exception as e:
                raise lbaas_ssl.SSLCertificateChainException(cert_chain_id=id)

    def get_ssl_certificate_chain(self, context, id, fields=None):
        cert_chain = self._get_ssl_resource(context, SSLCertificateChain, id)
        return self._make_ssl_certificate_chain_dict(cert_chain, fields)

    def get_ssl_certificate_chains(self, context, filters=None, fields=None):
        return self._get_collection(context, SSLCertificateChain,
                                    self._make_ssl_certificate_chain_dict,
                                    filters=filters, fields=fields)

    def create_vip_ssl_certificate_association(self, context,
                                               vip_ssl_certificate_association):
        # ssl_association_dict will contain the cert_id, vip_id, key, tenant_id.
        #tenant_id = self._get_tenant_id_for_create(context, assoc)
        tenant_id = vip_ssl_certificate_association['tenant_id']
        with context.session.begin(subtransactions=True):
            assoc_db = VipSSLCertificateAssociation(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=vip_ssl_certificate_association['name'],
                vip_id=vip_ssl_certificate_association['vip_id'],
                cert_id=vip_ssl_certificate_association['cert_id'],
                cert_chain_id=vip_ssl_certificate_association['cert_chain_id'],
                key_id=vip_ssl_certificate_association['key_id'],
                device_ip=vip_ssl_certificate_association['device_ip'],
                status='PENDING_CREATE',
                status_description=''
            )
            context.session.add(assoc_db)
        return self._make_vip_ssl_assoc_dict(assoc_db)

    def delete_vip_ssl_cert_assoc(self, context, assoc_id):
        assoc_db = self._get_ssl_resource(
            context,
            VipSSLCertificateAssociation,
            assoc_id)
        try:
            context.session.delete(assoc_db)
            context.session.flush()
        except Exception as e:
            raise lbaas_ssl.VipSSLCertificateAssociationDeleteException(
                assoc_id=assoc_id)

    def delete_vip_ssl_certificate_association(self, context,
                                               vip_ssl_certificate_association):
        # We don't delete this record here. We just set it to PENDING_DELETE.
        # The invoker in plugin.py will call into the driver, which will do the actual record deletion
        # once it successfully removes the cert association with the vip on the
        # device.
        vip_ssl_certificate_association['status'] = "PENDING_DELETE"
        if vip_ssl_certificate_association['cert_chain_id']:
            cert_chain_id = vip_ssl_certificate_association['cert_chain_id']
        else:
            cert_chain_id = None
        try:
            with context.session.begin(subtransactions=True):
                assoc_db = VipSSLCertificateAssociation(
                    id=vip_ssl_certificate_association['id'],
                    tenant_id=vip_ssl_certificate_association['tenant_id'],
                    vip_id=vip_ssl_certificate_association['vip_id'],
                    cert_id=vip_ssl_certificate_association['cert_id'],
                    cert_chain_id=cert_chain_id,
                    key_id=vip_ssl_certificate_association['key_id'],
                    device_ip=vip_ssl_certificate_association['device_ip'],
                    status=vip_ssl_certificate_association['status'],
                    status_description=''
                )
                context.session.merge(assoc_db)
        except Exception as e:
            raise lbaas_ssl.VipSSLCertificateException(assoc_id=id)

    def update_vip_ssl_cert_assoc_status(self, context, assoc_id,
                                         status, status_description=None,
                                         device_ip=None):
        try:
            with context.session.begin(subtransactions=True):
                assoc_db = self.get_vip_ssl_certificate_association(
                    context, assoc_id)
                if assoc_db:
                    if assoc_db['status'] != status:
                        assoc_db['status'] = status
                    if status_description or assoc_db['status_description']:
                        assoc_db['status_description'] = status_description

                if device_ip:
                    dev_ip = device_ip
                else:
                    dev_ip = assoc_db['device_ip']
                assoc_db_new = VipSSLCertificateAssociation(
                    id=assoc_db['id'],
                    tenant_id=assoc_db['tenant_id'],
                    name=assoc_db['name'],
                    vip_id=assoc_db['vip_id'],
                    cert_id=assoc_db['cert_id'],
                    cert_chain_id=assoc_db['cert_chain_id'],
                    key_id=assoc_db['key_id'],
                    device_ip=dev_ip,
                    status=assoc_db['status'],
                    status_description=assoc_db['status_description'])
                context.session.merge(assoc_db_new)
                context.session.flush()
                return self._make_vip_ssl_assoc_dict(assoc_db_new)
                # TODO: Cascade the changes to device.
        except Exception as e:
            raise lbaas_ssl.VipSSLCertificateException(assoc_id=assoc_id)

    def get_vip_ssl_certificate_association(self, context, id, fields=None):
        vip_ssl_association = self._get_ssl_resource(context,
                                                     VipSSLCertificateAssociation,
                                                     id)
        return self._make_vip_ssl_assoc_dict(vip_ssl_association, fields)

    def get_vip_ssl_certificate_associations(
            self, context, filters=None, fields=None):
        return self._get_collection(context, VipSSLCertificateAssociation,
                                    self._make_vip_ssl_assoc_dict,
                                    filters=filters, fields=fields)

    def _get_vip_id_by_assoc_id(self, context, assoc_id):
        vip_ssl_assoc = self._get_ssl_resource(context,
                                               VipSSLCertificateAssociation,
                                               assoc_id)
        return vip_ssl_assoc['vip_id']

    # def _get_vip_ssl_assocs(self, context, assoc_type, vip_id):
    #    assoc_qry = context.session.query(assoc_type)
    #    return assoc_qry.filter_by(vip_id=vip_id).all()

    # def _get_vip_ssl_assocs_for_deletion(self, context, assoc_type, vip_id):
    #    assoc_qry = context.session.query(assoc_type)
    #    return assoc_qry.filter_by(vip_id=vip_id,
    #                               status=constants.PENDING_DELETE).all()
