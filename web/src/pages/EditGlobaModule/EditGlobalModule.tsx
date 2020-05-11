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
import Panel from 'Components/Panel';
import { Alert, Card, Box, useSnackbar } from 'pouncejs';
import GlobalModuleForm from 'Components/forms/GlobalModuleForm';
import withSEO from 'Hoc/withSEO';
import { GlobalModuleDetails } from 'Generated/schema';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage } from 'Helpers/utils';
import { useGlobalModuleDetails } from './graphql/globalModuleDetails.generated';
import { useUpdateGlobalModule } from './graphql/updateGlobalModule.generated';

export const defaultInitialValues: Pick<GlobalModuleDetails, 'id' | 'description' | 'body'> = {
  description: '',
  id: '',
  body: '',
};
const EditGlobalModulePage: React.FC = () => {
  const { pushSnackbar } = useSnackbar();

  const {
    error: fetchPolicyError,
    data: queryData,
    loading: isFetchingPolicy,
  } = useGlobalModuleDetails({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        globalId: 'panther',
      },
    },
  });

  const [updateGlobalModule, { error: updateError }] = useUpdateGlobalModule({
    onCompleted: () =>
      pushSnackbar({
        variant: 'success',
        title: 'Successfully updated global module!',
      }),
  });

  const handleSubmit = React.useCallback(
    values => updateGlobalModule({ variables: { input: values } }),
    []
  );

  const initialValues = React.useMemo(() => {
    if (queryData) {
      const { id, body, description } = queryData.getGlobalPythonModule;
      return { id, body, description };
    }

    return defaultInitialValues;
  }, [queryData]);

  if (isFetchingPolicy) {
    return (
      <Card p={9}>
        <TablePlaceholder rowCount={5} rowHeight={15} />
        <TablePlaceholder rowCount={1} rowHeight={100} />
      </Card>
    );
  }

  if (fetchPolicyError) {
    return (
      <Alert
        mb={6}
        variant="error"
        title="Couldn't load the policy details"
        description={
          extractErrorMessage(fetchPolicyError) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  return (
    <Box mb={6}>
      <Panel size="large" title="Global Module">
        <GlobalModuleForm initialValues={initialValues} onSubmit={handleSubmit} />
      </Panel>
      {updateError && (
        <Alert
          mt={2}
          mb={6}
          variant="error"
          title={
            extractErrorMessage(updateError) ||
            'Unknown error occurred during update. Please contact support@runpanther.io'
          }
        />
      )}
    </Box>
  );
};

export default withSEO({ title: 'Global Module' })(EditGlobalModulePage);
