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

import Auth from '@aws-amplify/auth';
import { ApolloLink } from '@apollo/client';
import { pantherConfig } from 'Source/config';
import { createAuthLink, AUTH_TYPE } from 'aws-appsync-auth-link';

/**
 * This link is here to add the necessary headers present for AMAZON_COGNITO_USER_POOLS
 * authentication. It essentially signs the Authorization header with a JWT token
 */
const authLink = (createAuthLink({
  region: pantherConfig.AWS_REGION,
  url: pantherConfig.WEB_APPLICATION_GRAPHQL_API_ENDPOINT,
  auth: {
    jwtToken: () =>
      Auth.currentSession()
        .then(session => session.getIdToken().getJwtToken())
        .catch(() => null),
    type: AUTH_TYPE.AMAZON_COGNITO_USER_POOLS,
  },
}) as unknown) as ApolloLink;

export default authLink;
