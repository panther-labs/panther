'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
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
const graphql_1 = require('graphql');
const visitor_plugin_common_1 = require('@graphql-codegen/visitor-plugin-common');
/**
 * This visitor runs for all GraphQL operations found in the graphql documents that it received
 * as input. It just returns a type-safe way of creating mock API requests. The "stringified" return
 * value is typical in those codegen-plugins and not a "hack" from our side
 */
class MockGraphqlOperationsVisitor extends visitor_plugin_common_1.ClientSideBaseVisitor {
  // eslint-disable-next-line class-methods-use-this
  buildOperation(
    node,
    documentVariableName,
    operationType,
    operationResultType,
    operationVariablesTypes
  ) {
    return `export function mock${node.name.value}({ data, variables, errors }: { 
      data: ${operationResultType}, 
      variables?: ${operationVariablesTypes || 'never'}, 
      errors?: GraphQLError[] 
    }) {
      return {
        request: { query: ${documentVariableName}, variables },
        result: { data, errors },
      }
    }`;
  }
}
module.exports = {
  plugin: (schema, documents, config) => {
    const allAst = graphql_1.concatAST(documents.map(v => v.document));
    const allFragments = allAst.definitions
      .filter(d => d.kind === graphql_1.Kind.FRAGMENT_DEFINITION)
      .map(fragmentDef => ({
        node: fragmentDef,
        name: fragmentDef.name.value,
        onType: fragmentDef.typeCondition.name.value,
        isExternal: false,
      }));
    const visitor = new MockGraphqlOperationsVisitor(schema, allFragments, config, documents);
    const visitorResult = graphql_1.visit(allAst, { leave: visitor });
    return {
      prepend: ["import { GraphQLError } from 'graphql'"],
      content: visitorResult.definitions
        // Only get the stringified definitions
        .filter(t => typeof t === 'string')
        // filter our  the part that we care about, since, by default, `@graphql-codegen/visitor-plugin-common`
        // prepends additional stuff
        .map(t => t.slice(t.indexOf('export function mock'), t.length))
        .join('\n'),
    };
  },
};
