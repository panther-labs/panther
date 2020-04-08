import { ApolloLink } from '@apollo/client';
import { getMainDefinition } from '@apollo/client/utilities/graphql/getFromAST';
import { OperationDefinitionNode } from 'graphql';

/**
 * A link to strip `__typename` from mutations params. Useful when you extend the same values you
 * received from a query, and submit them as variables to a mutation
 * https://github.com/apollographql/apollo-client/issues/1913#issuecomment-425281027
 */
const cleanParamsLink = new ApolloLink((operation, forward) => {
  const def = getMainDefinition(operation.query) as OperationDefinitionNode;
  if (def && def.operation === 'mutation') {
    const omitTypename = (key, value) => (key === '__typename' ? undefined : value);
    // eslint-disable-next-line no-param-reassign
    operation.variables = JSON.parse(JSON.stringify(operation.variables), omitTypename);
  }
  return forward(operation);
});

export default cleanParamsLink;
