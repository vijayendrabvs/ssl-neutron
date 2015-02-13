# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2015 OpenStack Foundation
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

"""ssl_profile

Revision ID: 509c8ec06c5b
Revises: 137af00bf1d3
Create Date: 2015-02-03 21:50:44.560893

"""

# revision identifiers, used by Alembic.
revision = '509c8ec06c5b'
down_revision = '137af00bf1d3'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['*']

from alembic import op
import sqlalchemy as sa


from neutron.db import migration

#### #### #### #### #### #### #### #### #### #### ####
#### WARNING!! THIS IS A DESTRUCTIVE UPGRADE!! #####
#### #### #### #### #### #### #### #### #### #### ####

def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    # Create a new table 'ssl_profiles'.
    op.create_table(
        'ssl_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('cert_id', sa.String(length=36), nullable=False),
        sa.Column('cert_chain_id', sa.String(length=36), nullable=True),
        sa.Column('key_id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('shared', sa.Boolean, nullable=False, default=False),
        sa.ForeignKeyConstraint(['cert_id'], ['ssl_certificates.id']),
        sa.ForeignKeyConstraint(['cert_chain_id'], ['ssl_cert_chains.id']),
        sa.ForeignKeyConstraint(['key_id'], ['ssl_cert_keys.id']),
        sa.PrimaryKeyConstraint('id')
    )

    # Refactor existing vip-ssl associations to remove the
    # vip_ssl_cert_associations table as it currently is
    # and recreate it differently.
    op.drop_table('vip_ssl_cert_associations')
    op.create_table(
        'vip_ssl_cert_associations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('vip_id', sa.String(length=36), nullable=False),
        sa.Column('ssl_profile_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('device_ip', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['vip_id'], ['vips.id']),
        sa.ForeignKeyConstraint(['ssl_profile_id'], ['ssl_profiles.id']),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('vip_ssl_cert_associations')
    op.drop_table('ssl_profiles')

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
