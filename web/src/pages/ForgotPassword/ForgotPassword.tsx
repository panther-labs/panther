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
import withSEO from 'Hoc/withSEO';
import Banner from 'Assets/sign-up-banner.jpg';
import AuthPageContainer from 'Components/AuthPageContainer';
import ForgotPasswordForm from 'Components/forms/ForgotPasswordForm';
import { Flex, Link, Text } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';

const ForgotPasswordPage: React.FC = () => {
  return (
    <AuthPageContainer banner={Banner}>
      <AuthPageContainer.Caption
        title="Forgot your password?"
        subtitle="We'll help you reset your password and get back on track."
      />
      <ForgotPasswordForm />
      <Text size="small" color="gray-300" mt={4} as="p" textAlign="center">
        By submitting a request, you will receive an email with instructions on how to reset your
        password
      </Text>
      <AuthPageContainer.AltOptions>
        <Flex align="center">
          <Text size="medium" as="span" mr={3}>
            Remembered it all of a sudden?
          </Text>
          <Link as={RRLink} to={urls.account.auth.signIn()}>
            Sign in
          </Link>
        </Flex>
      </AuthPageContainer.AltOptions>
    </AuthPageContainer>
  );
};

export default withSEO({ title: 'Forgot Password' })(ForgotPasswordPage);
