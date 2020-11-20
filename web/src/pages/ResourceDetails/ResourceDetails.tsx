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
import { ComplianceStatusEnum, PoliciesForResourceInput } from 'Generated/schema';
import EmptyBoxImg from 'Assets/illustrations/empty-box.svg';
import NoResultsFound from 'Components/NoResultsFound';
import Panel from 'Components/Panel';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import {
  extendResourceWithIntegrationLabel,
  getComplianceItemsTotalCount,
  extractErrorMessage,
} from 'Helpers/utils';
import { Alert, Box, Flex, Heading } from 'pouncejs';
import {
  TableControlsPagination,
  TableControlsComplianceFilter,
} from 'Components/utils/TableControls';
import pick from 'lodash/pick';
import ErrorBoundary from 'Components/ErrorBoundary';
import withSEO from 'Hoc/withSEO';
import { DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import ResourceDetailsAttributes from 'Pages/ResourceDetails/ResourceDetailsAttributes';
import ResourceDetailsTable from './ResourceDetailsTable';
import ResourceDetailsInfo from './ResourceDetailsInfo';
import ResourceDetailsPageSkeleton from './Skeleton';
import { useResourceDetails } from './graphql/resourceDetails.generated';

const acceptedRequestParams = ['page', 'status', 'pageSize', 'suppressed'] as const;

const ResourceDetailsPage = () => {
  const { match } = useRouter<{ id: string }>();
  const {
    requestParams,
    updatePagingParams,
    setRequestParamsAndResetPaging,
  } = useRequestParamsWithPagination<
    Pick<PoliciesForResourceInput, typeof acceptedRequestParams[number]>
  >();

  const { error, data, loading } = useResourceDetails({
    fetchPolicy: 'cache-and-network',
    variables: {
      resourceDetailsInput: {
        resourceId: match.params.id,
      },
      policiesForResourceInput: {
        ...pick(requestParams, acceptedRequestParams),
        resourceId: match.params.id,
        pageSize: DEFAULT_SMALL_PAGE_SIZE,
      },
    },
  });

  if (loading && !data) {
    return <ResourceDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load resource"
          description={
            extractErrorMessage(error) ||
            "An unknown error occured and we couldn't load the resource details from the server"
          }
        />
      </Box>
    );
  }

  const policies = data.policiesForResource.items;
  const totalCounts = data.policiesForResource.totals;
  const pagingData = data.policiesForResource.paging;

  // Extend the resource by adding its integrationLabel fetched from another internal API
  const enhancedResource = extendResourceWithIntegrationLabel(
    data.resource,
    data.listComplianceIntegrations
  );

  const policyResultsExist = policies.length > 0;
  const arePoliciesFiltered = !!requestParams.status || !!requestParams.suppressed;
  const resourceHasPolicies = getComplianceItemsTotalCount(totalCounts) > 0;
  return (
    <article>
      <ErrorBoundary>
        <Box mb={5}>
          <ResourceDetailsInfo resource={enhancedResource} />
        </Box>
      </ErrorBoundary>
      <Box mb={5}>
        <ResourceDetailsAttributes resource={enhancedResource} />
      </Box>
      <Box mb={6}>
        <Panel
          title="Policies"
          actions={
            resourceHasPolicies && (
              <Flex spacing={1}>
                <TableControlsComplianceFilter
                  mr={1}
                  count={getComplianceItemsTotalCount(totalCounts)}
                  text="All"
                  isActive={!arePoliciesFiltered}
                  onClick={() => setRequestParamsAndResetPaging({})}
                />
                <TableControlsComplianceFilter
                  mr={1}
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
                  mr={1}
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
                  mr={1}
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
            {!policyResultsExist && !arePoliciesFiltered && (
              <Flex justify="center" align="center" direction="column" my={8} spacing={8}>
                <img alt="Empty Box Illustration" src={EmptyBoxImg} width="auto" height={200} />
                <Heading size="small" color="navyblue-100">
                  This resource doesn{"'"}t have any policies applied to it
                </Heading>
              </Flex>
            )}
            {!policyResultsExist && arePoliciesFiltered && (
              <Box my={6}>
                <NoResultsFound />
              </Box>
            )}
            {policyResultsExist && (
              <Flex direction="column" spacing={6}>
                <ResourceDetailsTable policies={policies} />
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

export default withSEO({ title: ({ match }) => match.params.id })(ResourceDetailsPage);
