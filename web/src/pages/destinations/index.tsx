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
import { Alert, Box, Card, Flex, Table } from 'pouncejs';
import { READONLY_ROLES_ARRAY } from 'Source/constants';
import RoleRestrictedAccess from 'Components/role-restricted-access';
import ErrorBoundary from 'Components/error-boundary';
import { gql, useQuery } from '@apollo/client';
import { Destination } from 'Generated/schema';
import { extractErrorMessage } from 'Helpers/utils';
import columns from './columns';
import DestinationsPageSkeleton from './skeleton';
import DestinationsPageEmptyDataFallback from './empty-data-fallback';
import DestinationCreateButton from './subcomponents/create-button';

export const LIST_DESTINATIONS = gql`
  query ListDestinationsAndDefaults {
    destinations {
      createdBy
      creationTime
      displayName
      lastModifiedBy
      lastModifiedTime
      outputId
      outputType
      outputConfig {
        slack {
          webhookURL
        }
        sns {
          topicArn
        }
        pagerDuty {
          integrationKey
        }
        github {
          repoName
          token
        }
        jira {
          orgDomain
          projectKey
          userName
          apiKey
          assigneeId
          issueType
        }
        opsgenie {
          apiKey
        }
        msTeams {
          webhookURL
        }
        sqs {
          queueUrl
        }
      }
      verificationStatus
      defaultForSeverity
    }
  }
`;

export interface ListDestinationsQueryData {
  destinations: Destination[];
}

const ListDestinations = () => {
  const { loading, error, data } = useQuery<ListDestinationsQueryData>(LIST_DESTINATIONS, {
    fetchPolicy: 'cache-and-network',
  });

  if (loading && !data) {
    return <DestinationsPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your available destinations"
        description={
          extractErrorMessage(error) ||
          'There was an error while attempting to list your destinations'
        }
      />
    );
  }

  if (!data.destinations.length) {
    return <DestinationsPageEmptyDataFallback />;
  }

  return (
    <Box mb={6}>
      <RoleRestrictedAccess deniedRoles={READONLY_ROLES_ARRAY}>
        <Flex justifyContent="flex-end">
          <DestinationCreateButton />
        </Flex>
      </RoleRestrictedAccess>
      <Card>
        <ErrorBoundary>
          <Table<Destination>
            items={data.destinations}
            getItemKey={item => item.outputId}
            columns={columns}
          />
        </ErrorBoundary>
      </Card>
    </Box>
  );
};

export default ListDestinations;
