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

import { Field, Formik } from 'formik';
import React from 'react';
import * as Yup from 'yup';
import { Box } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import useAuth from 'Hooks/useAuth';

interface MfaFormValues {
  mfaCode: string;
}

const initialValues = {
  mfaCode: '',
};

const validationSchema = Yup.object().shape({
  mfaCode: Yup.string()
    .matches(/\b\d{6}\b/, 'Code should contain exactly six digits.')
    .required(),
});

const MfaForm: React.FC = () => {
  const { confirmSignIn } = useAuth();

  return (
    <Formik<MfaFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={async ({ mfaCode }, { setErrors }) =>
        confirmSignIn({
          mfaCode,
          onError: ({ message }) =>
            setErrors({
              mfaCode: message,
            }),
        })
      }
    >
      {({ handleSubmit, isValid, isSubmitting, dirty }) => (
        <Box as="form" width={1} onSubmit={handleSubmit}>
          <Field
            autoFocus
            as={FormikTextInput}
            placeholder="The 6-digit MFA code"
            name="mfaCode"
            autoComplete="off"
            aria-required
            mb={6}
          />
          <SubmitButton
            width={1}
            submitting={isSubmitting}
            disabled={isSubmitting || !isValid || !dirty}
          >
            Sign in
          </SubmitButton>
        </Box>
      )}
    </Formik>
  );
};

export default MfaForm;
