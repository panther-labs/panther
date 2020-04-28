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
