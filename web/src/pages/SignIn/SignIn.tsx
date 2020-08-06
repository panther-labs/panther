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
import { Link, FadeIn } from 'pouncejs';
import AuthPageContainer from 'Components/AuthPageContainer';
import SetPasswordForm from 'Components/forms/SetPasswordForm';
import MfaForm from 'Components/forms/MfaForm';
import TotpForm from 'Components/forms/TotpForm';
import SignInForm from 'Components/forms/SigninForm';
import useAuth from 'Hooks/useAuth';
import { CHALLENGE_NAMES } from 'Components/utils/AuthContext';
import withSEO from 'Hoc/withSEO';

/**
 * This page is only visitable by non-auth Users (since it's sitting behind a guarded route). Thus,
 * no authenticated user will ever be in this page so we don't have to handle the redirect here
 * (meaning the redirect to the referrer page when the user became authenticated). This happens in
 * the `guarded-route` component which handles auth-related accesses and redirects.
 */

const SignInPage: React.FC = () => {
  const { currentAuthChallengeName, userInfo } = useAuth();

  // if there is an user object, then we check to see if he should go through any challenges. If he
  // should then we render the appropriate screen
  switch (currentAuthChallengeName) {
    case CHALLENGE_NAMES.SOFTWARE_TOKEN_MFA:
      return (
        <AuthPageContainer>
          <AuthPageContainer.Content>
            <AuthPageContainer.Caption
              title="One last thing..."
              subtitle="Enter your MFA code to complete the sign-in"
            />
            <MfaForm />
          </AuthPageContainer.Content>
          <AuthPageContainer.AltOptions>
            Can{"'"}t seem to get it right?
            <Link
              ml={2}
              external
              href={`mailto:support@runpanther.io?subject=MFA issues for ${userInfo?.email}`}
            >
              Email us
            </Link>
          </AuthPageContainer.AltOptions>
        </AuthPageContainer>
      );
    case CHALLENGE_NAMES.MFA_SETUP:
      return (
        <AuthPageContainer>
          <AuthPageContainer.Content>
            <AuthPageContainer.Caption
              title="Great!"
              subtitle="Now let's set up two-factor authentication for your account."
            />
            <TotpForm />
          </AuthPageContainer.Content>
        </AuthPageContainer>
      );
    case CHALLENGE_NAMES.NEW_PASSWORD_REQUIRED:
      return (
        <AuthPageContainer>
          <AuthPageContainer.Content>
            <AuthPageContainer.Caption
              title="First things first"
              subtitle="We need to set you up with a new password."
            />
            <SetPasswordForm />
          </AuthPageContainer.Content>
        </AuthPageContainer>
      );
    default:
      return (
        <FadeIn delay={100}>
          <AuthPageContainer>
            <AuthPageContainer.Content>
              <AuthPageContainer.Caption title="Sign in" subtitle="to continue to Panther" />
              <SignInForm />
            </AuthPageContainer.Content>
            <AuthPageContainer.AltOptions>
              Don{"'"}t have an account? Talk to your admin
            </AuthPageContainer.AltOptions>
          </AuthPageContainer>
        </FadeIn>
      );
  }
};

export default withSEO({ title: 'Sign In' })(SignInPage);
