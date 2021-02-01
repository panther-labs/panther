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
import { FastField, useFormikContext, Field } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import {
  Text,
  Flex,
  Box,
  Grid,
  FormHelperText,
  Link,
  FormError,
  useSnackbar,
  SimpleGrid,
} from 'pouncejs';
import { SeverityEnum } from 'Generated/schema';
import { capitalize, minutesToString } from 'Helpers/utils';
import FormikTextArea from 'Components/fields/TextArea';
import FormikSwitch from 'Components/fields/Switch';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikNumberInput from 'Components/fields/NumberInput';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { RuleFormValues } from 'Components/forms/RuleForm';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import { useListAvailableLogTypes } from 'Source/graphql/queries';
import useListAvailableDestinations from 'Hooks/useListAvailableDestinations';

const severityOptions = Object.values(SeverityEnum);
const severityItemToString = (severity: string) => capitalize(severity.toLowerCase());
const dedupPeriodMinutesOptions = [15, 30, 60, 180, 720, 1440];

const RuleFormCoreSection: React.FC = () => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const { values, initialValues } = useFormikContext<RuleFormValues>();
  const { pushSnackbar } = useSnackbar();
  const { data } = useListAvailableLogTypes({
    onError: () => pushSnackbar({ title: "Couldn't fetch your available log types" }),
  });

  const tagAdditionValidation = React.useMemo(() => (tag: string) => !values.tags.includes(tag), [
    values.tags,
  ]);

  const {
    loading: destinationsLoading,
    destinationOutputIds: availableOutputIds,
    destinationIdToDisplayName: destIdToDisplayName,
    validOutputIds: listValidOutputIds,
    disabled: disableDestinationField,
    error: destinationsError,
  } = useListAvailableDestinations({
    outputIds: values.outputIds,
  });

  const generateDestinationHelperText = React.useCallback(() => {
    if (destinationsError) {
      return (
        <FormError id="outputIds-description" mt={2}>
          There was a problem loading your destinations!
        </FormError>
      );
    }
    if (!availableOutputIds.length && !destinationsLoading) {
      return (
        <FormHelperText id="outputIds-description" mt={2} mr={1}>
          You have not configured any destinations, create one
          <Link ml={1} as={RRLink} to={urls.settings.destinations.create()}>
            here
          </Link>
        </FormHelperText>
      );
    }
    if (destinationsLoading) {
      return (
        <FormHelperText id="outputIds-description" mt={2}>
          Loading your destinations...
        </FormHelperText>
      );
    }
    return (
      <FormHelperText id="outputIds-description" mt={2}>
        Send alerts to these destinations regardless of their severity level settings
      </FormHelperText>
    );
  }, [destinationsError, destinationsLoading, availableOutputIds]);

  const destinationHelperText = React.useMemo(() => generateDestinationHelperText(), [
    destinationsError,
    destinationsLoading,
    availableOutputIds,
  ]);

  return (
    <React.Fragment>
      <Flex as="section" direction="column" spacing={4} mb={8}>
        <Text as="h2" fontWeight="normal" color="navyblue-100">
          Required
        </Text>
        <Flex width="50%" spacing={5}>
          <Box mt={3}>
            <FastField as={FormikSwitch} name="enabled" label="Enabled" />
          </Box>
          <FastField
            as={FormikCombobox}
            name="severity"
            items={severityOptions}
            itemToString={severityItemToString}
            label="Severity"
          />
          <Box flexGrow={1}>
            <FastField
              as={FormikTextInput}
              label="Rule ID"
              placeholder={`The unique ID of this Rule`}
              name="id"
              disabled={!!initialValues.id}
              required
            />
          </Box>
        </Flex>
        <Field
          as={FormikMultiCombobox}
          searchable
          label="Log Types"
          name="logTypes"
          items={data?.listAvailableLogTypes.logTypes ?? []}
          placeholder="Which log types should this rule apply to?"
        />
      </Flex>
      <Flex as="section" direction="column" spacing={5}>
        <Text as="h2" fontWeight="normal" color="navyblue-100">
          Optional
        </Text>

        <FastField
          as={FormikTextInput}
          label="Display Name"
          placeholder="A human-friendly name for this Rule"
          name="displayName"
        />
        <FastField
          as={FormikTextArea}
          label="Description"
          placeholder="Additional context about this Rule"
          name="description"
        />
        <FastField
          as={FormikTextArea}
          label="Runbook"
          placeholder={`Procedures and operations related to this Rule`}
          name="runbook"
        />
        <Grid templateColumns="3fr 1fr" columnGap={5}>
          <FastField
            as={FormikTextArea}
            label="Reference"
            placeholder={`An external link to why this Rule exists`}
            name="reference"
          />
          <Field
            as={FormikNumberInput}
            label="Events Threshold"
            min={1}
            name="threshold"
            placeholder="Send an alert only after # events"
          />
        </Grid>
        <Grid templateColumns="3fr 1fr" columnGap={5}>
          <SimpleGrid columns={2} spacing={5}>
            <FastField
              as={FormikMultiCombobox}
              searchable
              name="tags"
              label="Custom Tags"
              items={values.tags}
              allowAdditions
              validateAddition={tagAdditionValidation}
              placeholder="i.e. HIPAA (separate with <Enter>)"
            />

            <Box as="fieldset">
              {/* FIXME: We have an issue with FastField here. We shouldn't be setting props like that on FastField or Field elements */}
              <Field
                as={FormikMultiCombobox}
                disabled={disableDestinationField}
                searchable
                label="Destination Overrides"
                name="outputIds"
                value={listValidOutputIds}
                items={availableOutputIds}
                itemToString={destIdToDisplayName}
                placeholder="Select destinations"
                aria-describedby="outputIds-description"
              />
              {destinationHelperText}
            </Box>
          </SimpleGrid>
          <FastField
            as={FormikCombobox}
            label="Deduplication Period"
            name="dedupPeriodMinutes"
            items={dedupPeriodMinutesOptions}
            itemToString={minutesToString}
          />
        </Grid>
      </Flex>
    </React.Fragment>
  );
};

export default React.memo(RuleFormCoreSection);
