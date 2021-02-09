'use strict';
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
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.plugin = void 0;
// Based on work from @ardeois and @3nvi on MIT licensed  `graphql-codegen-typescript-mock-data`
// https://github.com/ardeois/graphql-codegen-typescript-mock-data
/* eslint-disable no-bitwise */
const graphql_1 = require('graphql');
const pascal_case_1 = require('pascal-case');
const faker_1 = __importDefault(require('faker'));
// import { generateRandomArray } from 'test-utils';
// monkeypatching the date func since seeding is broken without it
// https://github.com/Marak/faker.js/issues/608#issuecomment-491345249
const oldPast = faker_1.default.date.past;
faker_1.default.date.past = (years = 1, refDate = '2021-01-01T00:00:00.000Z') =>
  oldPast.call(faker_1.default.date, years, refDate);
const toMockName = str => `build${str}`;
const wrapWithQuotes = str => `'${str}'`;
const hashStringToNumber = value => {
  let hash = 0;
  if (value.length === 0) {
    return hash;
  }
  for (let i = 0; i < value.length; i += 1) {
    const char = value.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash &= hash; // Convert to 32bit integer
  }
  return hash;
};
const getNamedType = (typeName, fieldName, types, namedType) => {
  if (!namedType) {
    return '';
  }
  faker_1.default.seed(hashStringToNumber(typeName + fieldName));
  const name = namedType.name.value;
  switch (name) {
    case 'String':
      return wrapWithQuotes(faker_1.default.random.word());
    case 'Float':
      return faker_1.default.random.number({ min: 0, max: 10, precision: Math.pow(2, -2) });
    case 'ID':
      return wrapWithQuotes(faker_1.default.random.uuid());
    case 'Boolean':
      return faker_1.default.random.boolean();
    case 'Int':
      return faker_1.default.random.number({ min: 0, max: 1000 });
    case 'Date':
      return wrapWithQuotes(faker_1.default.date.past().toISOString());
    default: {
      const foundType = types.find(enumType => enumType.name === name);
      if (foundType) {
        switch (foundType.type) {
          case 'enum':
            // Return a random enum
            return faker_1.default.random.arrayElement(
              foundType.values.map(v => `${foundType.name}.${pascal_case_1.pascalCase(v)}`)
            );
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
                return faker_1.default.date.past().getTime();
              case 'AWSEmail':
                return wrapWithQuotes(faker_1.default.internet.email());
              case 'AWSPhone':
                return wrapWithQuotes(faker_1.default.phone.phoneNumber());
              case 'AWSDateTime':
                return wrapWithQuotes(faker_1.default.date.past().toISOString());
              case 'AWSJSON':
                return wrapWithQuotes(JSON.stringify(faker_1.default.random.objectElement()));
              case 'Long':
                return faker_1.default.random.number();
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
      return `[${valueGenerator}]`;
    }
    default:
      return 'FAIL';
  }
};
const createGraphQLResourceFunction = (typeName, fields, addTypename = true) => {
  return `
		export const ${toMockName(typeName)} = (overrides: Partial<${typeName}> = {}): ${typeName} => {
    return {
			${addTypename ? `__typename: '${typeName}',` : ''}
			${fields}
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
    InterfaceTypeDefinition: node => {
      const typeName = node.name.value;
      const { fields } = node;
      return {
        typeName,
        mockFn: () => {
          const mockFields = fields ? fields.map(({ mockFn }) => mockFn(typeName)).join('\n') : '';
          return createGraphQLResourceFunction(typeName, mockFields, false);
        },
      };
    },
    FieldDefinition: node => {
      const fieldName = node.name.value;
      return {
        name: fieldName,
        mockFn: typeName => {
          const value = generateMockValue(typeName, fieldName, types, node.type);
          return `${fieldName}: '${fieldName}' in overrides ? overrides.${fieldName} : ${value},`;
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
                  return `${field.name.value}: '${field.name.value}' in overrides ? overrides.${field.name.value} : ${value},`;
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
