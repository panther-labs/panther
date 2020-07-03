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
import { Box, Flex, FormHelperText } from 'pouncejs';
import { Field, Form, Formik } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import SubmitButton from 'Components/buttons/SubmitButton';
import React from 'react';
import FormikCheckbox from 'Components/fields/Checkbox';
import SeverityBadge from 'Components/SeverityBadge';

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
  defaultForSeverity: Yup.object<{ [key in SeverityEnum]: boolean }>().test(
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
        <Flex direction="column" spacing={4}>
          <Field
            name="displayName"
            as={FormikTextInput}
            label="Display Name"
            placeholder="A nickname to recognise this destination"
            required
          />
          {children}
        </Flex>

        <Box my={6} aria-describedby="severity-disclaimer">
          Associated Severities
          <FormHelperText id="severity-disclaimer" mt={1} mb={4}>
            We will only notify you on issues related to the severity types chosen above
          </FormHelperText>
          {Object.values(SeverityEnum)
            .reverse()
            .map(severity => (
              <Field name="defaultForSeverity" key={severity}>
                {() => (
                  <Field
                    as={FormikCheckbox}
                    name={`defaultForSeverity.${severity}`}
                    id={severity}
                    label={
                      <Box ml={2}>
                        <SeverityBadge severity={severity} />
                      </Box>
                    }
                  />
                )}
              </Field>
            ))}
        </Box>
        <SubmitButton fullWidth>
          {initialValues.outputId ? 'Update' : 'Add'} Destination
        </SubmitButton>
      </Form>
    </Formik>
  );
}

export default BaseDestinationForm;
