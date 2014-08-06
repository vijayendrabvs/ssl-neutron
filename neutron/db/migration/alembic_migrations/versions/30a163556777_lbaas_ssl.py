# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 OpenStack Foundation
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

"""lbaas_ssl

Revision ID: 30a163556777
Revises: havana
Create Date: 2014-08-04 12:29:45.848581

"""

# revision identifiers, used by Alembic.
revision = '30a163556777'
down_revision = 'havana'

# Change to ['*'] if this migration applies to all plugins

# migration_for_plugins = ['*']
migration_for_plugins = [
    'neutron.plugins.nicira.nicira_nvp_plugin.NeutronPlugin.NvpPluginV2'
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'ssl_certificates',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('certificate', sa.String(length=20480), nullable=False),
        sa.Column('passphrase', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'ssl_cert_chains',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('cert_chain', sa.String(length=20480), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'ssl_cert_keys',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('key', sa.String(length=20480), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'vip_ssl_cert_associations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('vip_id', sa.String(length=36), nullable=False),
        sa.Column('cert_id', sa.String(length=36), nullable=False),
        sa.Column('cert_chain_id', sa.String(length=36), nullable=True),
        sa.Column('key_id', sa.String(length=36), nullable=False),
        sa.Column('device_ip', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['vip_id'], ['vips.id']),
        sa.ForeignKeyConstraint(['cert_id'], ['ssl_certificates.id']),
        sa.ForeignKeyConstraint(['cert_chain_id'], ['ssl_cert_chains.id']),
        sa.ForeignKeyConstraint(['key_id'], ['ssl_cert_keys.id']),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('vip_ssl_cert_associations')
    op.drop_table('ssl_certificates')
    op.drop_table('ssl_cert_chains')
    op.drop_table('ssl_cert_keys')
