/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import { ApolloClient, ApolloLink, createHttpLink, InMemoryCache } from '@apollo/client';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { History } from 'history';
import { createAuthLink, AUTH_TYPE } from 'aws-appsync-auth-link';
import { ErrorResponse, onError } from 'apollo-link-error';
import Auth from '@aws-amplify/auth';
import { LocationErrorState } from 'Components/utils/api-error-fallback';
import { LIST_REMEDIATIONS } from 'Components/forms/policy-form/policy-form-auto-remediation-fields';
import { logError } from 'Helpers/loggers';
import { RULE_TEASER } from 'Pages/alert-details';

/**
 * A link to react to GraphQL and/or network errors
 */
const createErrorLink = (history: History<LocationErrorState>) => {
  // Define the operations that won't trigger any handler actions or be logged anywhere (those can
  // still be handled by the component independently)
  const silentFailingOperations = [
    getOperationName(LIST_REMEDIATIONS),
    getOperationName(RULE_TEASER),
  ];

  return (onError(({ graphQLErrors, networkError, operation }: ErrorResponse) => {
    // If the error is not considered a fail, then don't log it to sentry
    if (silentFailingOperations.includes(operation.operationName)) {
      return;
    }

    if (graphQLErrors) {
      graphQLErrors.forEach(error => {
        logError(error, { operation });
        history.replace(history.location.pathname, { errorType: error.errorType });
      });
    }

    if (networkError) {
      logError(networkError, { operation });
    }
  }) as unknown) as ApolloLink;
};

/**
 * Typical HTTP link to add the GraphQL URL to query
 */
const httpLink = createHttpLink({ uri: process.env.WEB_APPLICATION_GRAPHQL_API_ENDPOINT });

/**
 * This link is here to add the necessary headers present for AMAZON_COGNITO_USER_POOLS
 * authentication. It essentially signs the Authorization header with a JWT token
 */
const authLink = (createAuthLink({
  region: process.env.AWS_REGION,
  url: process.env.WEB_APPLICATION_GRAPHQL_API_ENDPOINT,
  auth: {
    jwtToken: () => Auth.currentSession().then(session => session.getIdToken().getJwtToken()),
    type: AUTH_TYPE.AMAZON_COGNITO_USER_POOLS,
  },
}) as unknown) as ApolloLink;

/**
 * A function that will create an ApolloClient given a specific instance of a history
 */
const createApolloClient = (history: History<LocationErrorState>) =>
  new ApolloClient({
    link: ApolloLink.from([createErrorLink(history), authLink, httpLink]),
    cache: new InMemoryCache({
      typePolicies: {
        Destination: {
          keyFields: ['outputId'],
        },
        AlertDetails: {
          keyFields: ['alertId'],
        },
        AlertSummary: {
          keyFields: ['alertId'],
        },
      },
    }),
  });

export default createApolloClient;
