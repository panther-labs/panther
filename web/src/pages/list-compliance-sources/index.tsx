/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from 'react';
import { Box, Button, Flex, Icon } from 'pouncejs';
import RoleRestrictedAccess from 'Components/role-restricted-access';
import { READONLY_ROLES_ARRAY } from 'Source/constants';
import { Link } from 'react-router-dom';
import urls from 'Source/urls';
import ErrorBoundary from 'Components/error-boundary';
import Panel from 'Components/panel';
import ComplianceSourceTable from './subcomponents/compliance-source-table';

const ListComplianceSources = () => {
  return (
    <Box mb={6}>
      <Panel
        title="AWS Account Sources"
        size="large"
        actions={
          <RoleRestrictedAccess deniedRoles={READONLY_ROLES_ARRAY}>
            <Button size="large" variant="primary" is={Link} to={urls.compliance.sources.create()}>
              <Flex alignItems="center">
                <Icon type="add" size="small" mr={1} />
                Add Account
              </Flex>
            </Button>
          </RoleRestrictedAccess>
        }
      >
        <ErrorBoundary>
          <ComplianceSourceTable />
        </ErrorBoundary>
      </Panel>
    </Box>
  );
};

export default ListComplianceSources;
