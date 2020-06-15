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
import { Alert, Box } from 'pouncejs';
import urls from 'Source/urls';
import { AddGlobalPythonModuleInput } from 'Generated/schema';
import withSEO from 'Hoc/withSEO';
import { extractErrorMessage } from 'Helpers/utils';
import useRouter from 'Hooks/useRouter';
import GlobalModuleForm from 'Components/forms/GlobalModuleForm';
import { useCreateGlobalPythonModule } from './graphql/createGlobalPythonModule.generated';

const initialValues: Required<AddGlobalPythonModuleInput> = {
  id: '',
  description: '',
  body: '',
};

const CreateGlobalPythonModulePage: React.FC = () => {
  const { history } = useRouter();
  const [createRule, { error }] = useCreateGlobalPythonModule({
    onCompleted: data =>
      history.push(urls.settings.globalModule.edit(data.addGlobalPythonModule.id)),
  });

  const handleSubmit = React.useCallback(
    values => createRule({ variables: { input: values } }),
    []
  );

  return (
    <Box mb={10}>
      <Panel size="large" title="Global Python Module">
        <GlobalModuleForm initialValues={initialValues} onSubmit={handleSubmit} />
      </Panel>
      {error && (
        <Box mt={2} mb={6}>
          <Alert
            variant="error"
            title={
              extractErrorMessage(error) ||
              'An unknown error occurred as we were trying to create your rule'
            }
          />
        </Box>
      )}
    </Box>
  );
};

export default withSEO({ title: 'New Global Module' })(CreateGlobalPythonModulePage);
