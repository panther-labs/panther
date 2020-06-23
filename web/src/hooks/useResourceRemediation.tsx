import React from 'react';
import { useSnackbar } from 'pouncejs';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { ResourceDetailsDocument } from 'Pages/ResourceDetails';
import { PolicyDetailsDocument } from 'Pages/PolicyDetails';
import { extractErrorMessage } from 'Helpers/utils';
import { PolicyDetails, ResourceDetails } from 'Generated/schema';
import {
  RemediateResourceDocument,
  useRemediateResource,
} from './graphql/remediateResource.generated';

interface UseResourceRemediationProps {
  policyId: PolicyDetails['id'];
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
      getOperationName(PolicyDetailsDocument),
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
