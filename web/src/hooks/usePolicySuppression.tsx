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
import { Policy, ResourceDetails } from 'Generated/schema';
import { useSnackbar } from 'pouncejs';
import { ResourceDetailsDocument } from 'Pages/ResourceDetails';
import { GetPolicyDetailsDocument } from 'Pages/PolicyDetails';
import { getOperationName } from 'apollo-utilities';
import { extractErrorMessage } from 'Helpers/utils';
import { useSuppressPolicy } from './graphql/suppressPolicy.generated';

interface UsePolicySuppressionProps {
  /** A list of IDs whose corresponding policies should receive the suppression */
  policyIds: Policy['id'][];

  /** A list of resource patterns (globs) whose matching resources should neglect the above policies
   * during their checks. In other words the resource patterns that should be suppressed for the
   * above policies
   */
  resourcePatterns: ResourceDetails['id'][];
}
const usePolicySuppression = ({ policyIds, resourcePatterns }: UsePolicySuppressionProps) => {
  const { pushSnackbar } = useSnackbar();

  const [suppressPolicies, { loading }] = useSuppressPolicy({
    awaitRefetchQueries: true,
    refetchQueries: [
      getOperationName(ResourceDetailsDocument),
      getOperationName(GetPolicyDetailsDocument),
    ],
    variables: {
      input: { policyIds, resourcePatterns },
    },
    onCompleted: () => {
      pushSnackbar({ variant: 'success', title: 'Suppression applied successfully' });
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(error) ||
          'Failed to apply suppression due to an unknown and unpredicted error',
      });
    },
  });

  return React.useMemo(() => ({ suppressPolicies, loading }), [suppressPolicies, loading]);
};

export default usePolicySuppression;
