/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
import { Box, Combobox } from 'pouncejs';
import { FastField } from 'formik';
import Panel from 'Components/Panel';
import FormikTextInput from 'Components/fields/TextInput';
import { formatJSON } from 'Helpers/utils';
import FormikEditor from 'Components/fields/Editor';
import { PolicyFormValues } from '../PolicyForm';

export interface PolicyFormAutoRemediationFieldsProps {
  remediations: string;
  initialValues: PolicyFormValues;
  onChange: (
    values: Pick<PolicyFormValues, 'autoRemediationId' | 'autoRemediationParameters'>
  ) => void;
}

type RemediationTuple = [string, string];

const PolicyFormAutoRemediationFields: React.FC<PolicyFormAutoRemediationFieldsProps> = ({
  remediations,
  initialValues,

  onChange,
}) => {
  // This state is used to track/store the value of the auto-remediation combobox. This combobox
  // doesn't belong to the form and we wouldn't wanna pollute our form with undesired information.
  // Instead what this checkbox does, is to control the value of the actual fields in the form which
  // are the ID and Params of the auto remediation.
  const [autoRemediationSelection, setAutoRemediationSelection] = React.useState<RemediationTuple>([
    initialValues.autoRemediationId,
    initialValues.autoRemediationParameters,
  ]);

  // Here we are parsing & reformatting for display purposes only (since the JSON that arrives as a
  // string doesn't have any formatting)
  const remediationTuples = React.useMemo(
    () =>
      Object.entries(
        JSON.parse(remediations)
      ).map(([id, params]: [string, { [key: string]: string }]) => [id, formatJSON(params)]),
    [remediations]
  );

  const comboboxOptions = React.useMemo(() => [['', '{}'], ...remediationTuples], [
    remediationTuples,
  ]) as RemediationTuple[];

  const handleComboboxChange = React.useCallback(
    (remediationTuple: RemediationTuple) => {
      setAutoRemediationSelection(remediationTuple);
      onChange({
        autoRemediationId: remediationTuple[0],
        autoRemediationParameters: remediationTuple[1],
      });
    },
    [onChange, setAutoRemediationSelection]
  );

  const autoRemediationSelected = !!autoRemediationSelection[0];
  return (
    <Panel
      title="Auto Remediation Settings"
      actions={
        <Box minWidth={300}>
          <Combobox<RemediationTuple>
            searchable
            label="Remediation"
            items={comboboxOptions}
            itemToString={remediationTuple => remediationTuple[0] || '(No remediation)'}
            value={autoRemediationSelection}
            onChange={handleComboboxChange}
            placeholder="Remediation"
          />
        </Box>
      }
    >
      {autoRemediationSelected && (
        <React.Fragment>
          <FastField as={FormikTextInput} name="autoRemediationId" hidden />
          <FastField
            as={FormikEditor}
            placeholder="# Enter a JSON object describing the parameters of the remediation"
            name="autoRemediationParameters"
            width="100%"
            minLines={9}
            mode="json"
          />
        </React.Fragment>
      )}
    </Panel>
  );
};

export default React.memo(PolicyFormAutoRemediationFields);
