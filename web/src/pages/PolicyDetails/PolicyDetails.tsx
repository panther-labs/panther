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
import { ComplianceStatusEnum, ResourcesForPolicyInput } from 'Generated/schema';
import { Alert, Box, Flex, Heading } from 'pouncejs';
import Panel from 'Components/Panel';
import NoResultsFound from 'Components/NoResultsFound';
import {
  TableControlsPagination,
  TableControlsComplianceFilter,
} from 'Components/utils/TableControls';
import {
  extendResourceWithIntegrationLabel,
  getComplianceItemsTotalCount,
  extractErrorMessage,
} from 'Helpers/utils';
import EmptyBoxImg from 'Assets/illustrations/empty-box.svg';
import pick from 'lodash/pick';
import { DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import withSEO from 'Hoc/withSEO';
import ErrorBoundary from 'Components/ErrorBoundary';
import PolicyDetailsTable from './PolicyDetailsTable';
import PolicyDetailsInfo from './PolicyDetailsInfo';
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
        id: match.params.id,
      },
      resourcesForPolicyInput: {
        ...pick(requestParams, acceptedRequestParams),
        policyId: match.params.id,
        pageSize: DEFAULT_SMALL_PAGE_SIZE,
      },
    },
  });

  if (loading && !data) {
    return <PolicyDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load policy"
          description={
            extractErrorMessage(error) ||
            "An unknown error occured and we couldn't load the policy details from the server"
          }
        />
      </Box>
    );
  }

  const resources = data.resourcesForPolicy.items;
  const totalCounts = data.resourcesForPolicy.totals;
  const pagingData = data.resourcesForPolicy.paging;

  // add an `integrationLabel` field to each resource based on its matching integrationId
  const enhancedResources = resources.map(r =>
    extendResourceWithIntegrationLabel(r, data.listComplianceIntegrations)
  );

  const resourceResultsExist = enhancedResources.length > 0;
  const areResourcesFiltered = !!requestParams.status || !!requestParams.suppressed;
  const policyHasResources = getComplianceItemsTotalCount(totalCounts) > 0;
  return (
    <article>
      <ErrorBoundary>
        <PolicyDetailsInfo policy={data.policy} />
      </ErrorBoundary>
      <Box mt={5} mb={6}>
        <Panel
          title="Resources"
          actions={
            policyHasResources && (
              <Flex spacing={1}>
                <TableControlsComplianceFilter
                  count={getComplianceItemsTotalCount(totalCounts)}
                  text="All"
                  isActive={!areResourcesFiltered}
                  onClick={() => setRequestParamsAndResetPaging({})}
                />
                <TableControlsComplianceFilter
                  count={totalCounts.active.fail}
                  countColor="red-300"
                  text="Failing"
                  isActive={requestParams.status === ComplianceStatusEnum.Fail}
                  onClick={() =>
                    setRequestParamsAndResetPaging({
                      status: ComplianceStatusEnum.Fail,
                      suppressed: false,
                    })
                  }
                />
                <TableControlsComplianceFilter
                  countColor="green-400"
                  count={totalCounts.active.pass}
                  text="Passing"
                  isActive={requestParams.status === ComplianceStatusEnum.Pass}
                  onClick={() =>
                    setRequestParamsAndResetPaging({
                      status: ComplianceStatusEnum.Pass,
                      suppressed: false,
                    })
                  }
                />
                <TableControlsComplianceFilter
                  countColor="yellow-500"
                  count={
                    totalCounts.suppressed.fail +
                    totalCounts.suppressed.pass +
                    totalCounts.suppressed.error
                  }
                  text="Ignored"
                  isActive={!requestParams.status && requestParams.suppressed}
                  onClick={() =>
                    setRequestParamsAndResetPaging({
                      suppressed: true,
                    })
                  }
                />
              </Flex>
            )
          }
        >
          <ErrorBoundary>
            {!resourceResultsExist && !areResourcesFiltered && (
              <Flex justify="center" align="center" direction="column" my={8} spacing={8}>
                <img alt="Empty Box Illustration" src={EmptyBoxImg} width="auto" height={200} />
                <Heading size="small" color="navyblue-100">
                  This policy isn{"'"}t applied to any resources
                </Heading>
              </Flex>
            )}
            {!resourceResultsExist && areResourcesFiltered && (
              <Box my={6}>
                <NoResultsFound />
              </Box>
            )}
            {resourceResultsExist && (
              <Flex direction="column" spacing={6}>
                <PolicyDetailsTable items={enhancedResources} />
                <TableControlsPagination
                  page={pagingData.thisPage}
                  totalPages={pagingData.totalPages}
                  onPageChange={updatePagingParams}
                />
              </Flex>
            )}
          </ErrorBoundary>
        </Panel>
      </Box>
    </article>
  );
};

export default withSEO({ title: ({ match }) => match.params.id })(PolicyDetailsPage);
