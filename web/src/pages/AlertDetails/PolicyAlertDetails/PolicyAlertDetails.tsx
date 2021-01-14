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
import { Box, Card, Flex } from 'pouncejs';
import Skeleton from 'Pages/AlertDetails/Skeleton';
import ErrorBoundary from 'Components/ErrorBoundary';
import { AlertDetailsFull } from 'Source/graphql/fragments/AlertDetailsFull.generated';
import { AlertSummaryPolicyInfo } from 'Generated/schema';
import { useGetPolicySummary } from './graphql/getPolicySummary.generated';
import AlertDetailsBanner from './AlertDetailsBanner';
import AlertDetailsInfo from './AlertDetailsInfo';

interface PolicyAlertDetailsProps {
  alert: AlertDetailsFull;
}

const PolicyAlertDetails: React.FC<PolicyAlertDetailsProps> = ({ alert }) => {
  const alertDetectionInfo = alert.detection as AlertSummaryPolicyInfo;
  const { data, loading } = useGetPolicySummary({
    variables: { input: { id: alertDetectionInfo.policyId } },
  });

  if (loading && !data) {
    return <Skeleton />;
  }

  return (
    <Box as="article" mb={6}>
      <Flex direction="column" spacing={6}>
        <AlertDetailsBanner alert={alert} />
        <Card position="relative" p={6}>
          <ErrorBoundary>
            <AlertDetailsInfo alert={alert} policy={data?.policy} />
          </ErrorBoundary>
        </Card>
      </Flex>
    </Box>
  );
};

export default PolicyAlertDetails;
