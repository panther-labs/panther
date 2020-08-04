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
import AuthPageContainer from 'Components/AuthPageContainer';
import ForgotPasswordForm from 'Components/forms/ForgotPasswordForm';
import { FadeIn, Link } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';

const ForgotPasswordPage: React.FC = () => {
  return (
    <AuthPageContainer>
      <AuthPageContainer.Content>
        <FadeIn delay={100}>
          <AuthPageContainer.Caption
            title="Forgot your password?"
            subtitle="We'll help you reset your password and get back on track."
          />
          <ForgotPasswordForm />
        </FadeIn>
      </AuthPageContainer.Content>

      <AuthPageContainer.AltOptions>
        Remembered it all of a sudden?
        <Link as={RRLink} to={urls.account.auth.signIn()} ml={2}>
          Sign in
        </Link>
      </AuthPageContainer.AltOptions>
    </AuthPageContainer>
  );
};

export default withSEO({ title: 'Forgot Password' })(ForgotPasswordPage);
