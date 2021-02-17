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
import * as Yup from 'yup';
import { SeverityEnum, DestinationConfigInput, AlertTypesEnum } from 'Generated/schema';
import { Box, SimpleGrid, Flex, Text } from 'pouncejs';
import { FastField, Form, Formik } from 'formik';
import urls from 'Source/urls';
import Breadcrumbs from 'Components/Breadcrumbs';
import SaveButton from 'Components/buttons/SaveButton';
import LinkButton from 'Components/buttons/LinkButton';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { alertTypeToString, getEnumKeyByValue } from 'Helpers/utils';

export interface BaseDestinationFormValues<
  AdditionalValues extends Partial<DestinationConfigInput>
> {
  outputId?: string;
  displayName: string;
  outputConfig: AdditionalValues;
  defaultForSeverity: SeverityEnum[];
  alertTypes: AlertTypesEnum[];
}

interface BaseDestinationFormProps<AdditionalValues extends Partial<DestinationConfigInput>> {
  /**
   * The initial values of the form. `DefaultForSeverity` is given as a list of severity values,
   * while internally the form will treat them as an object with the keys being the severities and
   * the values being true/false. This is a limitation on using a checkbox to control each severity
   * */
  initialValues: BaseDestinationFormValues<AdditionalValues>;

  /**
   * The validation schema for the form
   */
  validationSchema?: Yup.ObjectSchema<
    Yup.Shape<Record<string, unknown>, Partial<BaseDestinationFormValues<AdditionalValues>>>
  >;

  /** callback for the submission of the form */
  onSubmit: (values: BaseDestinationFormValues<AdditionalValues>) => void;
}

const AlertTypeValues = Object.values(AlertTypesEnum);
const SeverityValues = Object.values(SeverityEnum);
const severityToString = value => getEnumKeyByValue(SeverityEnum, value);

// The validation checks that Formik will run
export const defaultValidationSchema = Yup.object().shape({
  displayName: Yup.string().required(),
  defaultForSeverity: Yup.array().of(Yup.mixed().oneOf(Object.values(SeverityEnum)).required()),
  alertTypes: Yup.array()
    .min(1)
    .of(Yup.mixed().oneOf(Object.values(AlertTypesEnum)).required()),
});

function BaseDestinationForm<AdditionalValues extends Partial<DestinationConfigInput>>({
  initialValues,
  validationSchema,
  onSubmit,
  children,
}: React.PropsWithChildren<BaseDestinationFormProps<AdditionalValues>>): React.ReactElement {
  return (
    <Formik<BaseDestinationFormValues<AdditionalValues>>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Form autoComplete="off">
        {children}
        <SimpleGrid columns={2} gap={5} my={4} textAlign="left">
          <Box width={1}>
            Severity Levels
            <Text
              color="gray-300"
              fontSize="small-medium"
              id="severity-disclaimer"
              mt={1}
              fontWeight="medium"
            >
              We will only notify you on issues related to these severity types
            </Text>
          </Box>
          <FastField
            name="defaultForSeverity"
            as={FormikMultiCombobox}
            items={SeverityValues}
            itemToString={severityToString}
            label="Severity"
            placeholder="Select severities"
            aria-describedby="severity-disclaimer"
          />

          <Box>
            Default Alert Types
            <Text
              color="gray-300"
              fontSize="small-medium"
              id="alert-type-disclaimer"
              mt={1}
              fontWeight="medium"
            >
              The selected alert types will be default for this destination
            </Text>
          </Box>
          <FastField
            name="alertTypes"
            as={FormikMultiCombobox}
            items={AlertTypeValues}
            itemToString={alertTypeToString}
            label="Alert Types"
            placeholder="Select Alert Types"
            required
            aria-describedby="alert-type-disclaimer"
          />
        </SimpleGrid>
        {initialValues.outputId ? (
          <Breadcrumbs.Actions>
            <Flex spacing={4} justify="flex-end">
              <SaveButton aria-label="Update Destination">Update Destination</SaveButton>
              <LinkButton
                variantColor="darkgray"
                icon="close-outline"
                aria-label="Cancel destination editing"
                to={urls.integrations.destinations.list()}
              >
                Cancel
              </LinkButton>
            </Flex>
          </Breadcrumbs.Actions>
        ) : (
          <Flex justify="center" my={6}>
            <SubmitButton aria-label="Add destination">Add Destination</SubmitButton>
          </Flex>
        )}
      </Form>
    </Formik>
  );
}

export default BaseDestinationForm;
