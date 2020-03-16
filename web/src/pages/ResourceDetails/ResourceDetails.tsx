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
import { ComplianceStatusEnum, PoliciesForResourceInput } from 'Generated/schema';
import Panel from 'Components/Panel';
import JsonViewer from 'Components/JsonViewer';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import {
  convertObjArrayValuesToCsv,
  extendResourceWithIntegrationLabel,
  getComplianceItemsTotalCount,
  extractErrorMessage,
} from 'Helpers/utils';
import { Alert, Box } from 'pouncejs';
import {
  TableControlsPagination,
  TableControlsComplianceFilter,
} from 'Components/utils/TableControls';
import pick from 'lodash-es/pick';
import ErrorBoundary from 'Components/ErrorBoundary';
import { DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import ResourceDetailsTable from './ResourceDetailsTable';
import ResourceDetailsInfo from './ResourceDetailsInfo';
import columns from './columns';
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
      policiesForResourceInput: convertObjArrayValuesToCsv({
        ...pick(requestParams, acceptedRequestParams),
        resourceId: match.params.id,
        pageSize: DEFAULT_SMALL_PAGE_SIZE,
      }),
    },
  });

  if (loading && !data) {
    return <ResourceDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load resource"
        description={
          extractErrorMessage(error) ||
          "An unknown error occured and we couldn't load the resource details from the server"
        }
        mb={6}
      />
    );
  }

  const policies = data.policiesForResource.items;
  const totalCounts = data.policiesForResource.totals;
  const pagingData = data.policiesForResource.paging;

  // Extend the resource by adding its integrationLabel fetched from another internal API
  const enhancedResource = extendResourceWithIntegrationLabel(data.resource, data.integrations);

  return (
    <article>
      <ErrorBoundary>
        <Box mb={2}>
          <ResourceDetailsInfo resource={enhancedResource} />
        </Box>
      </ErrorBoundary>
      <Box mb={2}>
        <Panel size="large" title="Attributes">
          <JsonViewer data={JSON.parse(enhancedResource.attributes)} />
        </Panel>
      </Box>
      <Box mb={6}>
        <Panel
          size="large"
          title="Policies"
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
            <ResourceDetailsTable
              items={policies}
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

export default ResourceDetailsPage;
