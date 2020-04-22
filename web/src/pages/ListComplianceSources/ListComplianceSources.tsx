/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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
import { ComplianceIntegration } from 'Generated/schema';
import TablePlaceholder from 'Components/TablePlaceholder';
import { Alert, Box, Button, Card, Flex, Icon, Table } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import Panel from 'Components/Panel';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import ErrorBoundary from 'Components/ErrorBoundary';
import columns from './columns';
import { useListComplianceSources } from './graphql/listComplianceSources.generated';
import EmptyDataFallback from './EmptyDataFallback';

const ListComplianceSources = () => {
  const { loading, error, data } = useListComplianceSources();

  if (loading) {
    return (
      <Card p={9}>
        <TablePlaceholder />
      </Card>
    );
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your sources"
        description={
          extractErrorMessage(error) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  if (!data.listComplianceIntegrations.length) {
    return <EmptyDataFallback />;
  }

  return (
    <Box mb={6}>
      <Panel
        title="Connected Accounts"
        size="large"
        actions={
          <Button size="large" variant="primary" as={RRLink} to={urls.compliance.sources.create()}>
            <Flex align="center">
              <Icon type="add" size="small" mr={1} />
              Add Account
            </Flex>
          </Button>
        }
      >
        <ErrorBoundary>
          <Table<ComplianceIntegration>
            items={data.listComplianceIntegrations}
            getItemKey={item => item.integrationId}
            columns={columns}
          />
        </ErrorBoundary>
      </Panel>
    </Box>
  );
};

export default ListComplianceSources;
