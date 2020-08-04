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
import AuthPageContainer from 'Components/AuthPageContainer';
import queryString from 'query-string';
import ForgotPasswordConfirmForm from 'Components/forms/ForgotPasswordConfirmForm';
import useRouter from 'Hooks/useRouter';
import withSEO from 'Hoc/withSEO';
import { FadeIn } from 'pouncejs';

const ForgotPasswordConfirmPage: React.FC = () => {
  const { location } = useRouter();

  // protect against not having the proper parameters in place
  const { email, token } = queryString.parse(location.search) as { email: string; token: string };
  if (!token || !email) {
    return (
      <AuthPageContainer>
        <AuthPageContainer.Content>
          <AuthPageContainer.Caption
            title="Something seems off..."
            subtitle="Are you sure that the URL you followed is valid?"
          />
        </AuthPageContainer.Content>
      </AuthPageContainer>
    );
  }

  return (
    <AuthPageContainer>
      <FadeIn delay={100}>
        <AuthPageContainer.Content>
          <AuthPageContainer.Caption
            title="Alrighty then.."
            subtitle="Let's set you up with a new password."
          />
          <ForgotPasswordConfirmForm email={email} token={token} />
        </AuthPageContainer.Content>
      </FadeIn>
    </AuthPageContainer>
  );
};

export default withSEO({ title: 'Reset Password' })(ForgotPasswordConfirmPage);
