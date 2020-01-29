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
import {
  ComplianceStatusEnum,
  GetPolicyInput,
  Integration,
  PolicyDetails,
  ResourcesForPolicyInput,
  ListComplianceItemsResponse,
} from 'Generated/schema';
import { Alert, Box } from 'pouncejs';
import Panel from 'Components/panel';
import PaginationControls from 'Components/utils/offset-pagination-controls';
import TableComplianceFilterControl from 'Components/utils/table-compliance-filter-control';
import {
  extendResourceWithIntegrationLabel,
  getComplianceItemsTotalCount,
  convertObjArrayValuesToCsv,
  extractErrorMessage,
} from 'Helpers/utils';
import pick from 'lodash-es/pick';
import { DEFAULT_SMALL_PAGE_SIZE, INTEGRATION_TYPES } from 'Source/constants';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import ErrorBoundary from 'Components/error-boundary';
import PolicyDetailsTable from './subcomponents/policy-details-table';
import PolicyDetailsInfo from './subcomponents/policy-details-info';
import columns from './columns';
import PolicyDetailsPageSkeleton from './skeleton';

export const POLICY_DETAILS = gql`
  query PolicyDetails(
    $policyDetailsInput: GetPolicyInput!
    $resourcesForPolicyInput: ResourcesForPolicyInput!
  ) {
    policy(input: $policyDetailsInput) {
      autoRemediationId
      autoRemediationParameters
      complianceStatus
      createdAt
      description
      displayName
      enabled
      suppressions
      id
      lastModified
      reference
      resourceTypes
      runbook
      severity
      tags
    }
    resourcesForPolicy(input: $resourcesForPolicyInput) {
      items {
        errorMessage
        integrationId
        lastUpdated
        policyId
        resourceId
        status
        suppressed
      }
      paging {
        totalItems
        totalPages
        thisPage
      }
      totals {
        active {
          fail
          pass
          error
        }
        suppressed {
          fail
          pass
          error
        }
      }
    }
    integrations(input: { integrationType: "${INTEGRATION_TYPES.AWS_INFRA}" }) {
        integrationId
        integrationLabel
    }
  }
`;

interface ApolloQueryData {
  policy: PolicyDetails;
  resourcesForPolicy: ListComplianceItemsResponse;
  integrations: Integration[];
}

interface ApolloQueryInput {
  policyDetailsInput: GetPolicyInput;
  resourcesForPolicyInput: ResourcesForPolicyInput;
}

const acceptedRequestParams = ['page', 'status', 'pageSize', 'suppressed'] as const;

const PolicyDetailsPage = () => {
  const { match } = useRouter<{ id: string }>();
  const {
    requestParams,
    updatePagingParams,
    setRequestParamsAndResetPaging,
  } = useRequestParamsWithPagination<
    Pick<ResourcesForPolicyInput, typeof acceptedRequestParams[number]>
  >();

  const { error, data, loading } = useQuery<ApolloQueryData, ApolloQueryInput>(POLICY_DETAILS, {
    fetchPolicy: 'cache-and-network',
    variables: {
      policyDetailsInput: {
        policyId: match.params.id,
      },
      resourcesForPolicyInput: convertObjArrayValuesToCsv({
        ...pick(requestParams, acceptedRequestParams),
        policyId: match.params.id,
        pageSize: DEFAULT_SMALL_PAGE_SIZE,
      }),
    },
  });

  if (loading && !data) {
    return <PolicyDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load policy"
        description={
          extractErrorMessage(error) ||
          "An unknown error occured and we couldn't load the policy details from the server"
        }
        mb={6}
      />
    );
  }

  const resources = data.resourcesForPolicy.items;
  const totalCounts = data.resourcesForPolicy.totals;
  const pagingData = data.resourcesForPolicy.paging;

  // add an `integrationLabel` field to each resource based on its matching integrationId
  const enhancedResources = resources.map(r =>
    extendResourceWithIntegrationLabel(r, data.integrations)
  );

  return (
    <article>
      <ErrorBoundary>
        <PolicyDetailsInfo policy={data.policy} />
      </ErrorBoundary>
      <Box mt={2} mb={6}>
        <Panel
          size="large"
          title="Resources"
          actions={
            <Box ml={6} mr="auto">
              <TableComplianceFilterControl<'status'>
                mr={1}
                filterKey="status"
                filterValue={undefined}
                activeFilterValue={requestParams.status}
                updateFilter={setRequestParamsAndResetPaging}
                count={getComplianceItemsTotalCount(totalCounts)}
                text="All"
              />
              <TableComplianceFilterControl<'status'>
                mr={1}
                filterKey="status"
                filterValue={ComplianceStatusEnum.Fail}
                activeFilterValue={requestParams.status}
                updateFilter={setRequestParamsAndResetPaging}
                count={totalCounts.active.fail}
                countColor="red300"
                text="Failing"
              />
              <TableComplianceFilterControl<'status'>
                mr={1}
                filterKey="status"
                filterValue={ComplianceStatusEnum.Pass}
                activeFilterValue={requestParams.status}
                updateFilter={setRequestParamsAndResetPaging}
                countColor="green300"
                count={totalCounts.active.pass}
                text="Passing"
              />
              <TableComplianceFilterControl<'suppressed'>
                mr={1}
                filterKey="suppressed"
                filterValue={true}
                activeFilterValue={requestParams.suppressed}
                updateFilter={setRequestParamsAndResetPaging}
                countColor="orange300"
                count={
                  totalCounts.suppressed.fail +
                  totalCounts.suppressed.pass +
                  totalCounts.suppressed.error
                }
                text="Ignored"
              />
            </Box>
          }
        >
          <ErrorBoundary>
            <PolicyDetailsTable
              items={enhancedResources}
              columns={columns}
              enumerationStartIndex={(pagingData.thisPage - 1) * DEFAULT_SMALL_PAGE_SIZE}
            />
          </ErrorBoundary>
          <Box my={6}>
            <PaginationControls
              page={pagingData.thisPage}
              totalPages={pagingData.totalPages}
              onPageChange={updatePagingParams}
            />
          </Box>
        </Panel>
      </Box>
    </article>
  );
};

export default PolicyDetailsPage;
