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

import { Box, Flex, Link, FormHelperText, useTheme, AbstractButton, Text } from 'pouncejs';
import { Field, Form, Formik } from 'formik';
import QRCode from 'qrcode.react';
import * as React from 'react';
import * as Yup from 'yup';
import { formatSecretCode } from 'Helpers/utils';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import useAuth from 'Hooks/useAuth';

interface TotpFormValues {
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

export const TotpForm: React.FC = () => {
  const theme = useTheme();
  const [code, setCode] = React.useState('');
  const [showCode, setShowCode] = React.useState(false);

  const { userInfo, verifyTotpSetup, requestTotpSecretCode } = useAuth();

  React.useEffect(() => {
    (async () => {
      setCode(await requestTotpSecretCode());
    })();
  }, []);

  return (
    <Formik<TotpFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={async ({ mfaCode }, { setFieldError }) =>
        verifyTotpSetup({
          mfaCode,
          onError: ({ message }) => setFieldError('mfaCode', message),
        })
      }
    >
      <Form>
        <Flex justify="center" mb={6} width={1} aria-describedby="totp-helper-text">
          <QRCode
            value={formatSecretCode(code, userInfo.email)}
            includeMargin
            size={150}
            fgColor={theme.colors['navyblue-600']}
            bgColor={theme.colors['gray-50']}
          />
        </Flex>
        <Text color="gray-300" textAlign="center" my={2}>
          Or enter the code manually:
        </Text>
        <Box justify="center" textAlign="center" mb={6}>
          {showCode ? (
            <Text color="gray-300" wordBreak="break-word" my={2}>
              {code}
            </Text>
          ) : (
            <AbstractButton onClick={() => setShowCode(true)}>Show Code</AbstractButton>
          )}
        </Box>
        <Box mb={4}>
          <Field
            as={FormikTextInput}
            maxLength="6"
            placeholder="The 6-digit MFA code"
            name="mfaCode"
            autoComplete="off"
            required
            label="MFA Code"
          />
        </Box>
        <SubmitButton fullWidth>Verify</SubmitButton>
        <FormHelperText id="totp-helper-text" mt={10} textAlign="center">
          Open any two-factor authentication app, scan the barcode and then enter the MFA code to
          complete the sign-in. Popular software options include{' '}
          <Link
            external
            href="https://duo.com/product/trusted-users/two-factor-authentication/duo-mobile"
          >
            Duo
          </Link>
          ,{' '}
          <Link
            external
            href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en"
          >
            Google authenticator
          </Link>
          ,{' '}
          <Link external href="https://lastpass.com/misc_download2.php">
            LastPass
          </Link>{' '}
          and{' '}
          <Link external href="https://1password.com/downloads/mac/">
            1Password
          </Link>
          .
        </FormHelperText>
      </Form>
    </Formik>
  );
};

export default TotpForm;
