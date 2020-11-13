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

import * as Yup from 'yup';
import { SeverityEnum, DestinationConfigInput } from 'Generated/schema';
import { Box, Flex, Text } from 'pouncejs';
import { Field, Form, Formik } from 'formik';
import urls from 'Source/urls';
import React from 'react';
import FormikCheckbox from 'Components/fields/Checkbox';
import SeverityBadge from 'Components/badges/SeverityBadge';
import Breadcrumbs from 'Components/Breadcrumbs';
import SaveButton from 'Components/buttons/SaveButton';
import CancelButton from 'Components/buttons/CancelButton';
import SubmitButton from 'Components/buttons/SubmitButton';

export interface BaseDestinationFormValues<
  AdditionalValues extends Partial<DestinationConfigInput>
> {
  outputId?: string;
  displayName: string;
  outputConfig: AdditionalValues;
  defaultForSeverity: SeverityEnum[];
}

// Converts the `defaultForSeverity` from an array to an object in order to handle it properly
// internally within the form. Essentially converts ['CRITICAL', 'LOW'] to
// { CRITICAL: true, LOW: true }
interface PrivateBaseDestinationFormValues<
  AdditionalValues extends Partial<DestinationConfigInput>
> extends Omit<BaseDestinationFormValues<AdditionalValues>, 'defaultForSeverity'> {
  defaultForSeverity: { [key in SeverityEnum]: boolean };
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
    Yup.Shape<Record<string, unknown>, Partial<PrivateBaseDestinationFormValues<AdditionalValues>>>
  >;

  /** callback for the submission of the form */
  onSubmit: (values: BaseDestinationFormValues<AdditionalValues>) => void;
}

// The validation checks that Formik will run
export const defaultValidationSchema = Yup.object().shape({
  displayName: Yup.string().required(),
  defaultForSeverity: Yup.object<{ [key in SeverityEnum]: boolean }>(),
});

function BaseDestinationForm<AdditionalValues extends Partial<DestinationConfigInput>>({
  initialValues,
  validationSchema,
  onSubmit,
  children,
}: React.PropsWithChildren<BaseDestinationFormProps<AdditionalValues>>): React.ReactElement {
  // Converts the `defaultForSeverity` from an array to an object in order to handle it properly
  // internally within the form. Essentially converts ['CRITICAL', 'LOW'] to
  // { CRITICAL: true, LOW: true }
  const convertedInitialValues = React.useMemo(() => {
    const { defaultForSeverity, ...otherInitialValues } = initialValues;
    return {
      ...otherInitialValues,
      defaultForSeverity: Object.values(SeverityEnum).reduce(
        (acc, severity) => ({ ...acc, [severity]: defaultForSeverity.includes(severity) }),
        {}
      ) as PrivateBaseDestinationFormValues<AdditionalValues>['defaultForSeverity'],
    };
  }, [initialValues]);

  // makes sure that the internal representation of `defaultForSeverity` doesn't leak outside to
  // the components. For this reason, we revert the value of it back to an array of Severities, the
  // same way it was passed in as a prop.
  const onSubmitWithConvertedValues = React.useCallback(
    ({ defaultForSeverity, ...rest }: PrivateBaseDestinationFormValues<AdditionalValues>) =>
      onSubmit({
        ...rest,
        defaultForSeverity: Object.values(SeverityEnum).filter(
          (severity: SeverityEnum) => defaultForSeverity[severity]
        ),
      }),
    [onSubmit]
  );

  return (
    <Formik<PrivateBaseDestinationFormValues<AdditionalValues>>
      initialValues={convertedInitialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmitWithConvertedValues}
    >
      <Form autoComplete="off">
        {children}
        <Box my={8} aria-describedby="severity-disclaimer" textAlign="center">
          Severity Levels
          <Text
            color="gray-300"
            fontSize="small-medium"
            id="severity-disclaimer"
            mt={1}
            mb={4}
            fontWeight="medium"
          >
            We will only notify you on issues related to the severity types chosen above
          </Text>
          <Flex spacing={5} cursor="pointer">
            {Object.values(SeverityEnum)
              .reverse()
              .map(severity => (
                <Field name="defaultForSeverity" key={severity}>
                  {() => (
                    <Field
                      as={FormikCheckbox}
                      name={`defaultForSeverity.${severity}`}
                      id={severity}
                      label={<SeverityBadge severity={severity} />}
                    />
                  )}
                </Field>
              ))}
          </Flex>
        </Box>

        {initialValues.outputId ? (
          <Breadcrumbs.Actions>
            <Flex spacing={4} justify="flex-end">
              <SaveButton aria-label="Update Destination">Update Destination</SaveButton>
              <CancelButton
                aria-label="Cancel destination editing"
                to={urls.settings.destinations.list()}
              >
                Cancel
              </CancelButton>
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
