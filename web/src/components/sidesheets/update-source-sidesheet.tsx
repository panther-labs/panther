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

import { Heading, SideSheet, useSnackbar } from 'pouncejs';
import React from 'react';
import { useMutation, gql } from '@apollo/client';
import { LIST_INFRA_SOURCES } from 'Pages/list-compliance-sources/subcomponents/compliance-source-table';
import { LIST_LOG_SOURCES } from 'Pages/list-log-sources/subcomponents/log-source-table';
import useSidesheet from 'Hooks/useSidesheet';
import { Integration, UpdateIntegrationInput } from 'Generated/schema';
import { extractErrorMessage } from 'Helpers/utils';
import { INTEGRATION_TYPES } from 'Source/constants';
import UpdateSourceForm, { UpdateSourceFormValues } from 'Components/forms/update-source-form';

const UPDATE_SOURCE = gql`
  mutation UpdateSource($input: UpdateIntegrationInput!) {
    updateIntegration(input: $input)
  }
`;

export interface UpdateSourceSidesheetProps {
  source: Integration;
}

interface ApolloMutationInput {
  input: UpdateIntegrationInput;
}

export const UpdateAwsSourcesSidesheet: React.FC<UpdateSourceSidesheetProps> = ({ source }) => {
  const isInfraSource = source.integrationType === INTEGRATION_TYPES.AWS_INFRA;
  const [updateSource, { data, error }] = useMutation<Integration, ApolloMutationInput>(
    UPDATE_SOURCE
  );
  const { pushSnackbar } = useSnackbar();
  const { hideSidesheet } = useSidesheet();

  React.useEffect(() => {
    if (error) {
      pushSnackbar({
        variant: 'error',
        title: extractErrorMessage(error) || 'Failed to update your source due to an unknown error',
      });
    }
  }, [error]);

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: `Successfully updated sources` });
      hideSidesheet();
    }
  }, [data]);

  const handleSubmit = (values: UpdateSourceFormValues) =>
    updateSource({
      awaitRefetchQueries: true,
      variables: {
        input: {
          ...values,
          integrationId: source.integrationId,
        },
      },
      refetchQueries: [{ query: isInfraSource ? LIST_INFRA_SOURCES : LIST_LOG_SOURCES }],
    });

  return (
    <SideSheet open onClose={hideSidesheet}>
      <Heading size="medium" mb={8}>
        Update Account
      </Heading>
      <UpdateSourceForm
        initialValues={{ integrationLabel: source.integrationLabel }}
        onSubmit={handleSubmit}
      />
    </SideSheet>
  );
};

export default UpdateAwsSourcesSidesheet;
