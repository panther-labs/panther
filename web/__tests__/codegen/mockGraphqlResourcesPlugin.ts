// Based on work from @ardeois and @3nvi on MIT licensed  `graphql-codegen-typescript-mock-data`
// https://github.com/ardeois/graphql-codegen-typescript-mock-data

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

const toMockName = (str: string) => `build${str}`;

const getNamedType = (
  typeName: string,
  fieldName: string,
  types: TypeItem[],
  namedType?: NamedTypeNode
): string | number | boolean => {
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
      const foundType = types.find((enumType: TypeItem) => enumType.name === name);
      if (foundType) {
        switch (foundType.type) {
          case 'enum':
            // Return a random enum
            return `faker.random.arrayElement([${foundType.values.map(
              v => `${foundType.name}.${pascalCase(v)}`
            )}])`;
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
      return `generateRandomArray(() => ${valueGenerator})`;
    }
    default:
      return 'FAIL';
  }
};

const createGraphQLResourceFunction = (typeName: string, fields: string, addTypename = true) => {
  return `
		export const ${toMockName(typeName)} = (overrides?: Partial<${typeName}>): ${typeName} => {
    return {
			${fields}
			...overrides,
			${addTypename ? `__typename: '${typeName}',` : ''}
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
    FieldDefinition: node => {
      const fieldName = node.name.value;

      return {
        name: fieldName,
        mockFn: (typeName: string) => {
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
