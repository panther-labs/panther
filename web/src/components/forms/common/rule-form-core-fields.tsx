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
import { Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/Fields/text-input';
import { InputElementLabel, Grid, Flex, Box, InputElementErrorLabel, Text } from 'pouncejs';
import { SeverityEnum } from 'Generated/schema';
import { capitalize } from 'Helpers/utils';
import FormikTextArea from 'Components/Fields/textarea';
import FormikSwitch from 'Components/Fields/switch';
import FormikCombobox from 'Components/Fields/combobox';
import FormikMultiCombobox from 'Components/Fields/multi-combobox';
import FormikEditor from 'Components/Fields/editor';
import { LOG_TYPES, RESOURCE_TYPES } from 'Source/constants';
import { RuleFormValues } from 'Components/forms/rule-form';
import { PolicyFormValues } from 'Components/forms/policy-form';

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

const BaseRuleCoreFields: React.FC<BaseRuleCoreFieldsProps> = ({ type }) => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const { values, errors, touched, initialValues } = useFormikContext<FormValues>();

  const tagAdditionValidation = React.useMemo(() => tag => !values.tags.includes(tag), [
    values.tags,
  ]);

  return (
    <section>
      <Grid gridTemplateColumns="1fr 1fr" gridRowGap={2} gridColumnGap={9}>
        <Box>
          <Flex justifyContent="space-between">
            <Flex alignItems="center">
              <InputElementLabel htmlFor="enabled" mr={6}>
                Enabled
              </InputElementLabel>
              <Field as={FormikSwitch} name="enabled" />
            </Flex>
            <Flex alignItems="center">
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
          <Field
            as={FormikMultiCombobox}
            searchable
            label="* Log Types"
            name="logTypes"
            items={LOG_TYPES}
            inputProps={logTypesInputProps}
          />
        )}
      </Grid>
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

export default BaseRuleCoreFields;
