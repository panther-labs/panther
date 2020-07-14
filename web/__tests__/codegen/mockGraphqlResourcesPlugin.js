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

'use strict';
// Based on work from @ardeois and @3nvi on MIT licensed  `graphql-codegen-typescript-mock-data`
// https://github.com/ardeois/graphql-codegen-typescript-mock-data
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.plugin = void 0;
const graphql_1 = require('graphql');
const pascal_case_1 = require('pascal-case');
const faker_1 = __importDefault(require('faker'));
const toMockName = str => `build${str}`;
const getNamedType = (typeName, fieldName, types, namedType) => {
  if (!namedType) {
    return '';
  }
  const name = namedType.name.value;
  switch (name) {
    case 'String':
      return `faker.random.word()`;
    case 'Float':
      return `faker.random.number({ min: 0, max: 10, precision: 2 ** -2 })`;
    case 'ID':
      return `faker.random.uuid()`;
    case 'Boolean':
      return `faker.random.boolean()`;
    case 'Int':
      return `faker.random.number({ min: 0, max: 1000 })`;
    case 'Date':
      return `faker.date.past().toISOString()`;
    default: {
      const foundType = types.find(enumType => enumType.name === name);
      if (foundType) {
        switch (foundType.type) {
          case 'enum':
            // Return a random enum
            return `faker.random.arrayElement([${foundType.values.map(
              v => `${foundType.name}.${pascal_case_1.pascalCase(v)}`
            )}])`;
          case 'union':
            // Return a random union type node.
            return getNamedType(
              typeName,
              fieldName,
              types,
              foundType.types && faker_1.default.random.arrayElement(foundType.types)
            );
          case 'scalar':
            switch (foundType.name) {
              case 'AWSTimestamp':
                return `faker.date.past().getTime()`;
              case 'AWSEmail':
                return `faker.internet.email()`;
              case 'AWSPhone':
                return `faker.phone.phoneNumber()`;
              case 'AWSDateTime':
                return `faker.date.past().toISOString()`;
              case 'AWSJSON':
                return `JSON.stringify(faker.random.objectElement())`;
              default:
                throw new Error(`Found unknown Scalar: ${foundType.name}`);
            }
          default:
            throw new Error(`foundType is unknown: ${foundType.name}: ${foundType.type}`);
        }
      }
      return `${toMockName(name)}()`;
    }
  }
};
const generateMockValue = (typeName, fieldName, types, currentType) => {
  switch (currentType.kind) {
    case 'NamedType':
      return getNamedType(typeName, fieldName, types, currentType);
    case 'NonNullType':
      return generateMockValue(typeName, fieldName, types, currentType.type);
    case 'ListType': {
      const valueGenerator = generateMockValue(typeName, fieldName, types, currentType.type);
      return `generateRandomArray(() => ${valueGenerator})`;
    }
    default:
      return 'FAIL';
  }
};
const createGraphQLResourceFunction = (typeName, fields, addTypename = true) => {
  return `
		export const ${toMockName(typeName)} = (overrides?: Partial<${typeName}>): ${typeName} => {
    return {
			${fields}
			...overrides,
			${addTypename ? `__typename: '${typeName}',` : ''}
    };
};`;
};
// This plugin was generated with the help of ast explorer.
// https://astexplorer.net
// Paste your graphql schema in it, and you'll be able to see what the `astNode` will look like
exports.plugin = (schema, documents, config) => {
  const printedSchema = graphql_1.printSchema(schema); // Returns a string representation of the schema
  const astNode = graphql_1.parse(printedSchema); // Transforms the string into ASTNode
  // List of types that are enums
  const types = [];
  const visitor = {
    EnumTypeDefinition: node => {
      const name = node.name.value;
      if (!types.find(enumType => enumType.name === name)) {
        types.push({
          name,
          type: 'enum',
          values: node.values.map(valueNode => valueNode.name.value),
        });
      }
    },
    UnionTypeDefinition: node => {
      const name = node.name.value;
      if (!types.find(enumType => enumType.name === name)) {
        types.push({
          name,
          type: 'union',
          types: node.types,
        });
      }
    },
    FieldDefinition: node => {
      const fieldName = node.name.value;
      return {
        name: fieldName,
        mockFn: typeName => {
          const value = generateMockValue(typeName, fieldName, types, node.type);
          return `${fieldName}: ${value},`;
        },
      };
    },
    InputObjectTypeDefinition: node => {
      const fieldName = node.name.value;
      return {
        typeName: fieldName,
        mockFn: () => {
          const mockFields = node.fields
            ? node.fields
                .map(field => {
                  const value = generateMockValue(fieldName, field.name.value, types, field.type);
                  return `${field.name.value}: ${value},`;
                })
                .join('\n')
            : '';
          return createGraphQLResourceFunction(fieldName, mockFields, false);
        },
      };
    },
    ObjectTypeDefinition: node => {
      // This function triggered per each type
      const typeName = node.name.value;
      if (typeName === 'Query' || typeName === 'Mutation') {
        return null;
      }
      const { fields } = node;
      return {
        typeName,
        mockFn: () => {
          const mockFields = fields ? fields.map(({ mockFn }) => mockFn(typeName)).join('\n') : '';
          return createGraphQLResourceFunction(typeName, mockFields);
        },
      };
    },
    ScalarTypeDefinition: node => {
      const name = node.name.value;
      if (!types.find(enumType => enumType.name === name)) {
        types.push({
          name,
          type: 'scalar',
        });
      }
    },
  };
  const result = graphql_1.visit(astNode, { leave: visitor });
  const definitions = result.definitions.filter(definition => !!definition);
  const typeImports = definitions.map(({ typeName }) => typeName).filter(typeName => !!typeName);
  typeImports.push(...types.filter(({ type }) => type !== 'scalar').map(({ name }) => name));
  // List of function that will generate the mock.
  // We generate it after having visited because we need to distinct types from enums
  const mockFns = definitions.map(({ mockFn }) => mockFn).filter(mockFn => !!mockFn);
  const typesFileImport = `
    import { ${typeImports.join(', ')} } from '${config.typesFile.replace(/\.[\w]+$/, '')}';
    import { generateRandomArray, faker } from 'test-utils';
    `;
  return `${typesFileImport}${mockFns.map(mockFn => mockFn()).join('\n')}`;
};
