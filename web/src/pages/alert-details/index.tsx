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

import useRouter from 'Hooks/useRouter';
import { useQuery, gql } from '@apollo/client';
import { GetAlertInput, AlertDetails } from 'Generated/schema';
import { Alert, Box } from 'pouncejs';
import AlertDetailsInfo from 'Pages/alert-details/subcomponent/alert-details-info';
import AlertEvents from 'Pages/alert-details/subcomponent/alert-events';
import ErrorBoundary from 'Components/error-boundary';
import { extractErrorMessage } from 'Helpers/utils';
import AlertDetailsPageSkeleton from 'Pages/alert-details/skeleton';

export const ALERT_DETAILS = gql`
  query AlertDetails($alertDetailsInput: GetAlertInput!) {
    alert(input: $alertDetailsInput) {
      alertId
      rule {
        description
        displayName
        id
        logTypes
        runbook
        severity
        tags
      }
      creationTime
      lastEventMatched
      events
    }
  }
`;

interface ApolloQueryData {
  alert: AlertDetails;
}

interface ApolloQueryInput {
  alertDetailsInput: GetAlertInput;
}

// The front end needs to know if the newly queried page is the last page but backend does
// not yet provide this value. A temporary workaround is to add a large page size as we internally
// assuming they won't page through this much event.
// TODO: Update the query to handle pagination correctly
const PAGE_SIZE = 250;

const AlertDetailsPage = () => {
  const { match } = useRouter<{ id: string }>();
  const { error, data, loading } = useQuery<ApolloQueryData, ApolloQueryInput>(ALERT_DETAILS, {
    fetchPolicy: 'cache-and-network',
    variables: {
      alertDetailsInput: {
        alertId: match.params.id,
        eventPage: 0,
        eventPageSize: PAGE_SIZE,
      },
    },
  });

  if (loading && !data) {
    return <AlertDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load alert"
        description={
          extractErrorMessage(error) ||
          "An unknown error occured and we couldn't load the alert details from the server"
        }
        mb={6}
      />
    );
  }

  return (
    <article>
      <Box mb={6}>
        <Box mb={4}>
          <ErrorBoundary>
            <AlertDetailsInfo alert={data.alert} />
          </ErrorBoundary>
        </Box>
        <ErrorBoundary>
          <AlertEvents events={data.alert.events} />
        </ErrorBoundary>
      </Box>
    </article>
  );
};

export default AlertDetailsPage;
