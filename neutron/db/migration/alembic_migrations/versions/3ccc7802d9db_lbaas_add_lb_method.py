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
__author__ = 'vivekjain'

"""lbaas_add_lb_method

Revision ID: 3ccc7802d9db
Revises: 509c8ec06c5b
Create Date: 2015-04-06 20:57:12.161337

"""

# revision identifiers, used by Alembic.
revision = '3ccc7802d9db'
down_revision = '509c8ec06c5b'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['*']

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.alter_column('pools', 'lb_method',
                    type_=sa.Enum("ROUND_ROBIN",
                                  "LEAST_CONNECTIONS",
                                  "LEAST_SESSIONS",
                                  "SOURCE_IP"),
                    existing_nullable=False)


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.alter_column('pools', 'lb_method',
                    type_=sa.Enum("ROUND_ROBIN",
                                  "LEAST_CONNECTIONS",
                                  "SOURCE_IP"),
                    existing_nullable=False)
