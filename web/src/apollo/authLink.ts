import Auth from '@aws-amplify/auth';
import { ApolloLink } from '@apollo/client';
import { createAuthLink, AUTH_TYPE } from 'aws-appsync-auth-link';

/**
 * This link is here to add the necessary headers present for AMAZON_COGNITO_USER_POOLS
 * authentication. It essentially signs the Authorization header with a JWT token
 */
const authLink = (createAuthLink({
  region: process.env.AWS_REGION,
  url: process.env.WEB_APPLICATION_GRAPHQL_API_ENDPOINT,
  auth: {
    jwtToken: () =>
      Auth.currentSession()
        .then(session => session.getIdToken().getJwtToken())
        .catch(() => null),
    type: AUTH_TYPE.AMAZON_COGNITO_USER_POOLS,
  },
}) as unknown) as ApolloLink;

export default authLink;
