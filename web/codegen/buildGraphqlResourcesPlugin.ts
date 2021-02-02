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

// Based on work from @ardeois and @3nvi on MIT licensed  `graphql-codegen-typescript-mock-data`
// https://github.com/ardeois/graphql-codegen-typescript-mock-data

/* eslint-disable no-bitwise */
import {
  printSchema,
  parse,
  visit,
  ASTKindToNode,
  NamedTypeNode,
  TypeNode,
  VisitFn,
} from 'graphql';
import { PluginFunction } from '@graphql-codegen/plugin-helpers';
import { pascalCase } from 'pascal-case';
import faker from 'faker';
// import { generateRandomArray } from 'test-utils';

// monkeypatching the date func since seeding is broken without it
// https://github.com/Marak/faker.js/issues/608#issuecomment-491345249
const oldPast = faker.date.past;
faker.date.past = (years = 1, refDate = '2021-01-01T00:00:00.000Z') =>
  oldPast.call(faker.date, years, refDate);

const toMockName = (str: string) => `build${str}`;
const wrapWithQuotes = (str: string) => `'${str}'`;

const hashStringToNumber = (value: string) => {
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

const getNamedType = (
  typeName: string,
  fieldName: string,
  types: TypeItem[],
  namedType?: NamedTypeNode
): string | number | boolean => {
  if (!namedType) {
    return '';
  }

  faker.seed(hashStringToNumber(typeName + fieldName));
  const name = namedType.name.value;
  switch (name) {
    case 'String':
      return wrapWithQuotes(faker.random.word());
    case 'Float':
      return faker.random.number({ min: 0, max: 10, precision: 2 ** -2 });
    case 'ID':
      return wrapWithQuotes(faker.random.uuid());
    case 'Boolean':
      return faker.random.boolean();
    case 'Int':
      return faker.random.number({ min: 0, max: 1000 });
    case 'Date':
      return wrapWithQuotes(faker.date.past().toISOString());
    default: {
      const foundType = types.find((enumType: TypeItem) => enumType.name === name);
      if (foundType) {
        switch (foundType.type) {
          case 'enum':
            // Return a random enum
            return faker.random.arrayElement(
              foundType.values.map(v => `${foundType.name}.${pascalCase(v)}`)
            );
          case 'union':
            // Return a random union type node.
            return getNamedType(
              typeName,
              fieldName,
              types,
              foundType.types && faker.random.arrayElement(foundType.types)
            );
          case 'scalar':
            switch (foundType.name) {
              case 'AWSTimestamp':
                return faker.date.past().getTime();
              case 'AWSEmail':
                return wrapWithQuotes(faker.internet.email());
              case 'AWSPhone':
                return wrapWithQuotes(faker.phone.phoneNumber());
              case 'AWSDateTime':
                return wrapWithQuotes(faker.date.past().toISOString());
              case 'AWSJSON':
                return wrapWithQuotes(JSON.stringify(faker.random.objectElement()));
              case 'Long':
                return faker.random.number();
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

const generateMockValue = (
  typeName: string,
  fieldName: string,
  types: TypeItem[],
  currentType: TypeNode
): string | number | boolean => {
  switch (currentType.kind) {
    case 'NamedType':
      return getNamedType(typeName, fieldName, types, currentType as NamedTypeNode);
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

const createGraphQLResourceFunction = (typeName: string, fields: string, addTypename = true) => {
  return `
		export const ${toMockName(typeName)} = (overrides: Partial<${typeName}> = {}): ${typeName} => {
    return {
			${addTypename ? `__typename: '${typeName}',` : ''}
			${fields}
    };
};`;
};

interface TypeItem {
  name: string;
  type: 'enum' | 'scalar' | 'union';
  values?: string[];
  types?: readonly NamedTypeNode[];
}

type VisitorType = {
  [K in keyof ASTKindToNode]?: VisitFn<ASTKindToNode[keyof ASTKindToNode], ASTKindToNode[K]>;
};

type MockGraphqlResourcesPluginConfig = { typesFile: string };

// This plugin was generated with the help of ast explorer.
// https://astexplorer.net
// Paste your graphql schema in it, and you'll be able to see what the `astNode` will look like
export const plugin: PluginFunction<MockGraphqlResourcesPluginConfig> = (
  schema,
  documents,
  config
) => {
  const printedSchema = printSchema(schema); // Returns a string representation of the schema
  const astNode = parse(printedSchema); // Transforms the string into ASTNode

  // List of types that are enums
  const types: TypeItem[] = [];
  const visitor: VisitorType = {
    EnumTypeDefinition: node => {
      const name = node.name.value;
      if (!types.find((enumType: TypeItem) => enumType.name === name)) {
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
          const mockFields = fields
            ? fields.map(({ mockFn }: any) => mockFn(typeName)).join('\n')
            : '';

          return createGraphQLResourceFunction(typeName, mockFields, false);
        },
      };
    },
    FieldDefinition: node => {
      const fieldName = node.name.value;

      return {
        name: fieldName,
        mockFn: (typeName: string) => {
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
          const mockFields = fields
            ? fields.map(({ mockFn }: any) => mockFn(typeName)).join('\n')
            : '';

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

  const result = visit(astNode, { leave: visitor });
  const definitions = result.definitions.filter(definition => !!definition);
  const typeImports = definitions
    .map(({ typeName }: { typeName: string }) => typeName)
    .filter((typeName: string) => !!typeName);
  typeImports.push(...types.filter(({ type }) => type !== 'scalar').map(({ name }) => name));
  // List of function that will generate the mock.
  // We generate it after having visited because we need to distinct types from enums
  const mockFns = definitions.map(({ mockFn }: any) => mockFn).filter(mockFn => !!mockFn);
  const typesFileImport = `
    import { ${typeImports.join(', ')} } from '${config.typesFile.replace(/\.[\w]+$/, '')}';
    import { generateRandomArray, faker } from 'test-utils';
    `;

  return `${typesFileImport}${mockFns.map(mockFn => mockFn()).join('\n')}`;
};
