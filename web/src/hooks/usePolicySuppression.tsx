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
import { PolicyDetails, ResourceDetails } from 'Generated/schema';
import { useSnackbar } from 'pouncejs';
import { ResourceDetailsDocument } from 'Pages/ResourceDetails';
import { PolicyDetailsDocument } from 'Pages/PolicyDetails';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { extractErrorMessage } from 'Helpers/utils';
import { useSuppressPolicy } from './graphql/suppressPolicy.generated';

interface UsePolicySuppressionProps {
  /** A list of IDs whose corresponding policies should receive the suppression */
  policyIds: PolicyDetails['id'][];

  /** A list of resource patterns (globs) whose matching resources should neglect the above policies
   * during their checks. In other words the resource patterns that should be suppressed for the
   * above policies
   */
  resourcePatterns: ResourceDetails['id'][];
}
const usePolicySuppression = ({ policyIds, resourcePatterns }: UsePolicySuppressionProps) => {
  const [suppressPolicies, { data, loading, error }] = useSuppressPolicy({
    awaitRefetchQueries: true,
    refetchQueries: [
      getOperationName(ResourceDetailsDocument),
      getOperationName(PolicyDetailsDocument),
    ],
    variables: {
      input: { policyIds, resourcePatterns },
    },
  });

  const { pushSnackbar } = useSnackbar();
  React.useEffect(() => {
    if (error) {
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(error) ||
          'Failed to apply suppression due to an unknown and unpredicted error',
      });
    }
  }, [error]);

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: 'Suppression applied successfully' });
    }
  }, [data]);

  return React.useMemo(() => ({ suppressPolicies, data, loading, error }), [
    suppressPolicies,
    data,
    loading,
    error,
  ]);
};

export default usePolicySuppression;
