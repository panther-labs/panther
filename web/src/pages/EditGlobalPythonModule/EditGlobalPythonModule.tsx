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
import useRouter from 'Hooks/useRouter';
import GlobalModuleForm from 'Components/forms/GlobalModuleForm';
import withSEO from 'Hoc/withSEO';
import { GlobalPythonModule } from 'Generated/schema';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage } from 'Helpers/utils';
import { useGlobalPythonModuleDetails } from './graphql/globalPythonModuleDetails.generated';
import { useUpdateGlobalPythonModule } from './graphql/updateGlobalPythonModule.generated';

export const defaultInitialValues: Pick<GlobalPythonModule, 'id' | 'description' | 'body'> = {
  description: '',
  id: '',
  body: '',
};
const EditGlobalModulePage: React.FC = () => {
  const { match } = useRouter<{ id: string }>();
  const { pushSnackbar } = useSnackbar();

  const {
    error: fetchPolicyError,
    data: queryData,
    loading: isFetchingPolicy,
  } = useGlobalPythonModuleDetails({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        globalId: match.params.id,
      },
    },
  });

  const [updateGlobalPythonModule, { error: updateError }] = useUpdateGlobalPythonModule({
    onCompleted: () =>
      pushSnackbar({
        variant: 'success',
        title: 'Successfully updated global module!',
      }),
  });

  const handleSubmit = React.useCallback(
    values => updateGlobalPythonModule({ variables: { input: values } }),
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
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load the policy details"
          description={
            extractErrorMessage(fetchPolicyError) ||
            'There was an error when performing your request, please contact support@runpanther.io'
          }
        />
      </Box>
    );
  }

  return (
    <Box mb={6}>
      <Panel size="large" title="Global Module">
        <GlobalModuleForm initialValues={initialValues} onSubmit={handleSubmit} />
      </Panel>
      {updateError && (
        <Box mt={2} mb={6}>
          <Alert
            variant="error"
            title={
              extractErrorMessage(updateError) ||
              'Unknown error occurred during update. Please contact support@runpanther.io'
            }
          />
        </Box>
      )}
    </Box>
  );
};

export default withSEO({ title: 'Global Module' })(EditGlobalModulePage);
