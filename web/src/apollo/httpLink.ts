import { createHttpLink } from '@apollo/client';

/**
 * Typical HTTP link to add the GraphQL URL to query
 */
const httpLink = createHttpLink({ uri: process.env.WEB_APPLICATION_GRAPHQL_API_ENDPOINT });

export default httpLink;
