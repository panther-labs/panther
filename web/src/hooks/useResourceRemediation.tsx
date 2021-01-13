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
import { useSnackbar } from 'pouncejs';
import { getOperationName } from 'apollo-utilities';
import { ResourceDetailsDocument } from 'Pages/ResourceDetails';
import { GetPolicyDetailsDocument } from 'Pages/PolicyDetails';
import { extractErrorMessage } from 'Helpers/utils';
import { Policy, ResourceDetails } from 'Generated/schema';
import {
  RemediateResourceDocument,
  useRemediateResource,
} from './graphql/remediateResource.generated';

interface UseResourceRemediationProps {
  policyId: Policy['id'];
  resourceId: ResourceDetails['id'];
}

const useResourceRemediation = ({ policyId, resourceId }: UseResourceRemediationProps) => {
  const { pushSnackbar } = useSnackbar();

  // Prepare the remediation mutation.
  const [remediateResource, { loading }] = useRemediateResource({
    mutation: RemediateResourceDocument,
    awaitRefetchQueries: true,
    refetchQueries: [
      getOperationName(ResourceDetailsDocument),
      getOperationName(GetPolicyDetailsDocument),
    ],
    variables: {
      input: {
        resourceId,
        policyId,
      },
    },
    onCompleted: () => {
      pushSnackbar({ variant: 'success', title: 'Remediation has been applied successfully' });
    },
    onError: remediationError => {
      pushSnackbar({
        variant: 'error',
        title: extractErrorMessage(remediationError) || 'Failed to apply remediation',
      });
    },
  });

  return React.useMemo(() => ({ remediateResource, loading }), [remediateResource, loading]);
};

export default useResourceRemediation;
