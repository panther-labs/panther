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
import { Badge, Box, Flex, InputElementLabel, Text } from 'pouncejs';
import { Field, Formik } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import SubmitButton from 'Components/buttons/SubmitButton';
import React from 'react';
import FormikCheckbox from 'Components/fields/Checkbox';

export interface BaseDestinationFormValues<
  AdditionalValues extends Partial<DestinationConfigInput>
> {
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
    Yup.Shape<object, Partial<BaseDestinationFormValues<AdditionalValues>>>
  >;

  /** callback for the submission of the form */
  onSubmit: (values: BaseDestinationFormValues<AdditionalValues>) => void;
}

// The validation checks that Formik will run
export const defaultValidationSchema = Yup.object().shape({
  displayName: Yup.string().required(),
  defaultForSeverity: Yup.object().test(
    'atLeastOneSeverity',
    'You need to select at least one severity type',
    val => Object.values(val).some(checked => checked)
  ),
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
      defaultForSeverity: defaultForSeverity.reduce(
        (acc, severity) => ({ ...acc, [severity]: true }),
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
      {({ handleSubmit, isValid, isSubmitting, dirty }) => (
        <form onSubmit={handleSubmit} autoComplete="off">
          <Box mb={6} pb={6} borderBottom="1px solid" borderColor="grey100">
            <Field
              name="displayName"
              as={FormikTextInput}
              label="Display Name"
              placeholder="A nickname to recognise this destination"
              mb={6}
              aria-required
            />
            {children}
            <InputElementLabel>Severity Types</InputElementLabel>
            {Object.values(SeverityEnum)
              .reverse()
              .map(severity => (
                <Field name="defaultForSeverity" key={severity}>
                  {() => (
                    <Flex align="center">
                      <Field
                        as={FormikCheckbox}
                        name={`defaultForSeverity.${severity}`}
                        id={severity}
                      />
                      <InputElementLabel
                        htmlFor={severity}
                        ml={2}
                        style={{ display: 'inline-block' }} // needed since we have non-text content
                      >
                        <Badge color={SEVERITY_COLOR_MAP[severity]}>{severity}</Badge>
                      </InputElementLabel>
                    </Flex>
                  )}
                </Field>
              ))}
            <Text size="small" color="grey300" mt={2}>
              We will only notify you on issues related to the severity types chosen above
            </Text>
          </Box>
          <SubmitButton
            width={1}
            disabled={isSubmitting || !isValid || !dirty}
            submitting={isSubmitting}
          >
            {initialValues.displayName ? 'Update' : 'Add'} Destination
          </SubmitButton>
        </form>
      )}
    </Formik>
  );
}

export default BaseDestinationForm;
