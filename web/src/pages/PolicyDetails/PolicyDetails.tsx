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
import { ComplianceStatusEnum, ResourcesForPolicyInput } from 'Generated/schema';
import { Alert, Box } from 'pouncejs';
import Panel from 'Components/Panel';
import {
  TableControlsPagination,
  TableControlsComplianceFilter,
} from 'Components/utils/TableControls';
import {
  extendResourceWithIntegrationLabel,
  getComplianceItemsTotalCount,
  convertObjArrayValuesToCsv,
  extractErrorMessage,
} from 'Helpers/utils';
import pick from 'lodash-es/pick';
import { DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import ErrorBoundary from 'Components/ErrorBoundary';
import PolicyDetailsTable from './PolicyDetailsTable';
import PolicyDetailsInfo from './PolicyDetailsInfo';
import columns from './columns';
import PolicyDetailsPageSkeleton from './Skeleton';
import { usePolicyDetails } from './graphql/policyDetails.generated';

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

  const { error, data, loading } = usePolicyDetails({
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
              <TableControlsComplianceFilter
                mr={1}
                count={getComplianceItemsTotalCount(totalCounts)}
                text="All"
                isActive={!requestParams.status && !requestParams.suppressed}
                onClick={() =>
                  setRequestParamsAndResetPaging({ status: undefined, suppressed: undefined })
                }
              />
              <TableControlsComplianceFilter
                mr={1}
                count={totalCounts.active.fail}
                countColor="red300"
                text="Failing"
                isActive={requestParams.status === ComplianceStatusEnum.Fail}
                onClick={() =>
                  setRequestParamsAndResetPaging({
                    status: ComplianceStatusEnum.Fail,
                    suppressed: undefined,
                  })
                }
              />
              <TableControlsComplianceFilter
                mr={1}
                countColor="green300"
                count={totalCounts.active.pass}
                text="Passing"
                isActive={requestParams.status === ComplianceStatusEnum.Pass}
                onClick={() =>
                  setRequestParamsAndResetPaging({
                    status: ComplianceStatusEnum.Pass,
                    suppressed: undefined,
                  })
                }
              />
              <TableControlsComplianceFilter
                mr={1}
                countColor="orange300"
                count={
                  totalCounts.suppressed.fail +
                  totalCounts.suppressed.pass +
                  totalCounts.suppressed.error
                }
                text="Ignored"
                isActive={!requestParams.status && requestParams.suppressed}
                onClick={() =>
                  setRequestParamsAndResetPaging({
                    status: undefined,
                    suppressed: true,
                  })
                }
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
            <TableControlsPagination
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
