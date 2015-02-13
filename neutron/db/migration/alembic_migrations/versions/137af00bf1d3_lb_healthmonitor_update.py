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

"""lb_healthmonitor_update

Revision ID: 137af00bf1d3
Revises: 30a163556777
Create Date: 2015-01-29 02:03:59.653152

"""

# revision identifiers, used by Alembic.
revision = '137af00bf1d3'
down_revision = '30a163556777'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['*']

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.add_column('healthmonitors', sa.Column('name',
                                                       sa.String(255),
                                                       nullable=False))
    op.add_column('healthmonitors', sa.Column('response_string',
                                                       sa.String(8192),
                                                       nullable=True))
    op.add_column('healthmonitors', sa.Column('shared', sa.Boolean(), nullable=False, default=True))

    # Set name to os-<id> for existing healthmonitors
    op.execute("UPDATE healthmonitors SET name=CONCAT('uuid_',id)")

    #op.create_unique_constraint(
    #    name='unique_name_constraint',
    #    source='healthmonitors',
    #    local_cols=['name']
    #)

def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_column('healthmonitors', 'name')
    op.drop_column('healthmonitors', 'shared')
    op.drop_column('healthmonitors', 'response_string')
