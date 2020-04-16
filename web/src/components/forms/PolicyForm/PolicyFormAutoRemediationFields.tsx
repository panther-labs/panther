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
import { Alert, Box, Combobox, InputElementLabel, SimpleGrid, Spinner } from 'pouncejs';
import { Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import { formatJSON, extractErrorMessage } from 'Helpers/utils';
import FormikEditor from 'Components/fields/Editor';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';
import { PolicyFormValues } from './PolicyForm';
import { useListRemediations } from './graphql/listRemediations.generated';

const PolicyFormAutoRemediationFields: React.FC = () => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const { values, setFieldValue } = useFormikContext<PolicyFormValues>();

  // This state is used to track/store the value of the auto-remediation combobox. This combobox
  // doesn't belong to the form and we wouldn't wanna pollute our form with undesired information.
  // Instead what this checkbox does, is to control the value of the actual fields in the form which
  // are the ID and Params of the auto remediation.
  // Here we are parsing & reformatting for display purposes only (since the JSON that arrives as a
  // string doesn't have any formatting)
  const [autoRemediationSelection, setAutoRemediationSelection] = React.useState<[string, string]>([
    values.autoRemediationId,
    values.autoRemediationParameters,
  ]);

  const { data, loading, error } = useListRemediations();

  if (loading) {
    return <Spinner size="medium" />;
  }

  if (error) {
    return (
      <Alert
        variant="warning"
        title="Couldn't load your available remediations"
        description={[
          extractErrorMessage(error),
          '. For more info, please consult the ',
          <a
            key="docs"
            href={`${PANTHER_SCHEMA_DOCS_LINK}/amazon-web-services/aws-setup/automatic-remediation`}
            target="_blank"
            rel="noopener noreferrer"
          >
            related docs
          </a>,
        ]}
      />
    );
  }

  const remediationTuples = Object.entries(
    JSON.parse(data.remediations)
  ).map(([id, params]: [string, { [key: string]: string }]) => [id, formatJSON(params)]) as [
    string,
    string
  ][];

  return (
    <section>
      <SimpleGrid columns={2} spacingX={9} spacingY={2}>
        <Combobox<[string, string]>
          searchable
          label="Remediation"
          items={[['', '{}'], ...remediationTuples]}
          itemToString={remediationTuple => remediationTuple[0] || '(No remediation)'}
          value={autoRemediationSelection}
          onChange={remediationTuple => {
            setFieldValue('autoRemediationId', remediationTuple[0]);
            setFieldValue('autoRemediationParameters', remediationTuple[1]);
            setAutoRemediationSelection(remediationTuple);
          }}
        />
      </SimpleGrid>
      <Box hidden>
        <Field as={FormikTextInput} name="autoRemediationId" />
      </Box>
      <Box mt={10} hidden={!values.autoRemediationId}>
        <InputElementLabel htmlFor="enabled">Remediation Parameters</InputElementLabel>
        <Field
          as={FormikEditor}
          placeholder="# Enter a JSON object describing the parameters of the remediation"
          name="autoRemediationParameters"
          width="100%"
          minLines={9}
          mode="json"
        />
      </Box>
    </section>
  );
};

export default React.memo(PolicyFormAutoRemediationFields);
