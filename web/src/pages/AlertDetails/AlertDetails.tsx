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
import useRouter from 'Hooks/useRouter';
import { Alert, Box, FadeIn } from 'pouncejs';
import Page404 from 'Pages/404';
import withSEO from 'Hoc/withSEO';
import { extractErrorMessage, shortenId } from 'Helpers/utils';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { useListDestinations } from 'Source/graphql/queries';
import { AlertTypesEnum } from 'Generated/schema';
import Skeleton from './Skeleton';
import RuleAlertDetails from './RuleAlertDetails';
import PolicyAlertDetails from './PolicyAlertDetails';
import { useAlertDetails } from './graphql/alertDetails.generated';

const AlertDetailsPage = () => {
  const { match } = useRouter<{ id: string }>();

  const { data: alertData, loading: alertLoading, error: alertError, fetchMore } = useAlertDetails({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        alertId: match.params.id,
        eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  // FIXME: The destination information should come directly from GraphQL, by executing another
  //  query in the Front-end and using the results of both to calculate it.
  const { data: destinationData, loading: destinationLoading } = useListDestinations();

  if ((alertLoading && !alertData) || (destinationLoading && !destinationData)) {
    return (
      <FadeIn from="bottom">
        <Skeleton />
      </FadeIn>
    );
  }

  if (alertError) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load alert"
          description={
            extractErrorMessage(alertError) ||
            "An unknown error occurred and we couldn't load the alert details from the server"
          }
        />
      </Box>
    );
  }

  const { alert } = alertData;
  if (!alert) {
    return <Page404 />;
  }

  switch (alert.type) {
    case AlertTypesEnum.Policy:
      return <PolicyAlertDetails alert={alert} />;

    case AlertTypesEnum.Rule:
    case AlertTypesEnum.RuleError:
    default:
      return <RuleAlertDetails alert={alert} fetchMore={fetchMore} />;
  }
};

export default withSEO({ title: ({ match }) => `Alert #${shortenId(match.params.id)}` })(
  AlertDetailsPage
);
