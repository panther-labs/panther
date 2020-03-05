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
import { Button, ButtonProps, useSnackbar } from 'pouncejs';
import { useMutation, gql } from '@apollo/client';

import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { RESOURCE_DETAILS } from 'Pages/ResourceDetails';
import { POLICY_DETAILS } from 'Pages/PolicyDetails';
import { ResourceDetails, RemediateResourceInput, PolicyDetails } from 'Generated/schema';
import { extractErrorMessage } from 'Helpers/utils';

interface RemediationButtonProps {
  buttonVariant: ButtonProps['variant'];
  resourceId: ResourceDetails['id'];
  policyId: PolicyDetails['id'];
}

const REMEDIATE_RESOURCE = gql`
  mutation RemediateResource($input: RemediateResourceInput!) {
    remediateResource(input: $input)
  }
`;

interface ApolloMutationInput {
  input: RemediateResourceInput;
}

const RemediationButton: React.FC<RemediationButtonProps> = ({
  buttonVariant,
  resourceId,
  policyId,
}) => {
  const { pushSnackbar } = useSnackbar();

  // Prepare the remediation mutation.
  const [
    remediateResource,
    { data: remediationSuccess, error: remediationError, loading: remediationInProgress },
  ] = useMutation<boolean, ApolloMutationInput>(REMEDIATE_RESOURCE, {
    mutation: REMEDIATE_RESOURCE,
    awaitRefetchQueries: true,
    refetchQueries: [getOperationName(RESOURCE_DETAILS), getOperationName(POLICY_DETAILS)],
    variables: {
      input: {
        resourceId,
        policyId,
      },
    },
  });

  React.useEffect(() => {
    if (remediationError) {
      pushSnackbar({
        variant: 'error',
        title: extractErrorMessage(remediationError) || 'Failed to apply remediation',
      });
    }
  }, [remediationError]);

  React.useEffect(() => {
    if (remediationSuccess) {
      pushSnackbar({ variant: 'success', title: 'Remediation has been applied successfully' });
    }
  }, [remediationSuccess]);

  return (
    <Button
      size="small"
      variant={buttonVariant}
      onClick={e => {
        // Table row is clickable, we don't want to navigate away
        e.stopPropagation();
        remediateResource();
      }}
      disabled={remediationInProgress}
    >
      Remediate
    </Button>
  );
};

export default React.memo(RemediationButton);
