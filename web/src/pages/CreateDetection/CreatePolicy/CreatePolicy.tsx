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
import { Alert, Box } from 'pouncejs';
import urls from 'Source/urls';
import PolicyForm from 'Components/forms/PolicyForm';
import { AddPolicyInput } from 'Generated/schema';
import { DEFAULT_POLICY_FUNCTION } from 'Source/constants';
import { extractErrorMessage } from 'Helpers/utils';
import useRouter from 'Hooks/useRouter';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { useCreatePolicy } from './graphql/createPolicy.generated';

export const initialValues: Required<AddPolicyInput> = {
  body: DEFAULT_POLICY_FUNCTION,
  autoRemediationId: '',
  autoRemediationParameters: '{}',
  description: '',
  displayName: '',
  enabled: true,
  id: '',
  outputIds: [],
  reference: '',
  resourceTypes: [],
  runbook: '',
  severity: null,
  suppressions: [],
  tags: [],
  tests: [],
};

const CreatePolicy: React.FC = () => {
  const { history } = useRouter();
  const [createPolicy, { error }] = useCreatePolicy({
    onCompleted: data => {
      trackEvent({ event: EventEnum.AddedPolicy, src: SrcEnum.Policies });
      history.push(urls.compliance.policies.details(data.addPolicy.id));
    },
    onError: () => trackError({ event: TrackErrorEnum.FailedToAddPolicy, src: SrcEnum.Policies }),
  });

  const handleSubmit = React.useCallback(
    values => createPolicy({ variables: { input: values } }),
    []
  );

  return (
    <Box mb={6}>
      <PolicyForm initialValues={initialValues} onSubmit={handleSubmit} />
      {error && (
        <Box mt={2} mb={6}>
          <Alert
            variant="error"
            title="Couldn't create your policy"
            discardable
            description={
              extractErrorMessage(error) ||
              'An unknown error occured as we were trying to create your policy'
            }
          />
        </Box>
      )}
    </Box>
  );
};

export default CreatePolicy;
