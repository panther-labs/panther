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
import { Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import { InputElementLabel, Flex, Box, InputElementErrorLabel, Text, SimpleGrid } from 'pouncejs';
import { SeverityEnum } from 'Generated/schema';
import { capitalize, minutesToString } from 'Helpers/utils';
import FormikTextArea from 'Components/fields/TextArea';
import FormikSwitch from 'Components/fields/Switch';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import FormikEditor from 'Components/fields/Editor';
import { LOG_TYPES, RESOURCE_TYPES } from 'Source/constants';
import { RuleFormValues } from 'Components/forms/RuleForm';
import { PolicyFormValues } from 'Components/forms/PolicyForm';

export const ruleCoreEditableFields = [
  'body',
  'description',
  'displayName',
  'enabled',
  'id',
  'reference',
  'runbook',
  'severity',
  'tags',
] as const;

interface BaseRuleCoreFieldsProps {
  type: 'rule' | 'policy';
}

type FormValues = Required<Pick<RuleFormValues, typeof ruleCoreEditableFields[number]>> &
  Pick<RuleFormValues, 'logTypes'> &
  Pick<PolicyFormValues, 'resourceTypes' | 'suppressions'>;

const severityOptions = Object.values(SeverityEnum);
const severityItemToString = severity => capitalize(severity.toLowerCase());
const dedupPeriodMinutesOptions = [15, 30, 60, 180, 720, 1440];
const suppressionInputProps = {
  placeholder: 'i.e. aws::s3::* (separate with <Enter>)',
};
const resourceTypesInputProps = {
  placeholder: 'Filter affected resource types',
};
const tagsInputProps = {
  placeholder: 'i.e. Bucket Security (separate with <Enter>)',
};
const logTypesInputProps = {
  placeholder: 'Filter affected log types',
};

const BaseRuleFormCoreFields: React.FC<BaseRuleCoreFieldsProps> = ({ type }) => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const { values, errors, touched, initialValues } = useFormikContext<FormValues>();

  const tagAdditionValidation = React.useMemo(() => tag => !values.tags.includes(tag), [
    values.tags,
  ]);

  return (
    <section>
      <SimpleGrid columns={2} spacingX={9} spacingY={2}>
        <Box>
          <Flex justify="space-between">
            <Flex align="center">
              <InputElementLabel htmlFor="enabled" mr={6}>
                Enabled
              </InputElementLabel>
              <Field as={FormikSwitch} name="enabled" />
            </Flex>
            <Flex align="center">
              <InputElementLabel htmlFor="severity" mr={6}>
                * Severity
              </InputElementLabel>
              <Field
                as={FormikCombobox}
                name="severity"
                items={severityOptions}
                itemToString={severityItemToString}
              />
            </Flex>
          </Flex>
        </Box>
        <div />
        <Field
          as={FormikTextInput}
          label="* ID"
          placeholder={`The unique ID of this ${type}`}
          name="id"
          disabled={initialValues.id}
          aria-required
        />
        <Field
          as={FormikTextInput}
          label="Display Name"
          placeholder={`A human-friendly name for this ${type}`}
          name="displayName"
        />
        <Field
          as={FormikTextInput}
          label="Runbook"
          placeholder={`Procedures and operations related to this ${type}`}
          name="runbook"
        />
        <Field
          as={FormikTextInput}
          label="Reference"
          placeholder={`An external link to why this ${type} exists`}
          name="reference"
        />
        <Field
          as={FormikTextArea}
          label="Description"
          placeholder={`Additional context about this ${type}`}
          name="description"
        />
        {type === 'policy' && (
          <React.Fragment>
            <Field
              as={FormikMultiCombobox}
              searchable
              name="suppressions"
              label="Resource Ignore Patterns"
              items={values.suppressions}
              allowAdditions
              inputProps={suppressionInputProps}
            />
            <Box>
              <Field
                as={FormikMultiCombobox}
                searchable
                label="Resource Types"
                name="resourceTypes"
                items={RESOURCE_TYPES}
                inputProps={resourceTypesInputProps}
              />
              <Text size="small" color="grey300" mt={2}>
                Leave empty to apply to all resources
              </Text>
            </Box>
          </React.Fragment>
        )}
        <Field
          as={FormikMultiCombobox}
          searchable
          name="tags"
          label="Custom Tags"
          items={values.tags}
          allowAdditions
          validateAddition={tagAdditionValidation}
          inputProps={tagsInputProps}
        />
        {type === 'rule' && (
          <React.Fragment>
            <Field
              as={FormikMultiCombobox}
              searchable
              label="* Log Types"
              name="logTypes"
              items={LOG_TYPES}
              inputProps={logTypesInputProps}
            />
            <Field
              as={FormikCombobox}
              label="* Deduplication Period"
              name="dedupPeriodMinutes"
              items={dedupPeriodMinutesOptions}
              itemToString={minutesToString}
            />
          </React.Fragment>
        )}
      </SimpleGrid>
      <Box my={6}>
        <InputElementLabel htmlFor="enabled">{`* ${capitalize(type)} Function`}</InputElementLabel>
        <Field
          as={FormikEditor}
          placeholder={`# Enter the body of the ${type} here...`}
          name="body"
          width="100%"
          minLines={16}
          mode="python"
          aria-required
        />
        {errors.body && touched.body && (
          <InputElementErrorLabel mt={6}>{errors.body}</InputElementErrorLabel>
        )}
      </Box>
    </section>
  );
};

export default BaseRuleFormCoreFields;
