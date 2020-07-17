import { GraphQLSchema } from 'graphql';
import { PluginFunction, Types } from '@graphql-codegen/plugin-helpers';
import fs from 'fs';
import path from 'path';

export type ContentType = string | string[] | { [index: string]: string };

export interface AddLicenseHeaderPluginParams {
  /** The path to the license file */
  licenseFilePath: string;
}

const getLicenseTextFromFile = (licenseFilePath: string) => {
  const licenseText = fs.readFileSync(path.resolve(__dirname, licenseFilePath), {
    encoding: 'utf-8',
  });

  const licenseLines = licenseText.trim().split(/\r?\n/);
  return `/**\n${licenseLines.map(licenseLine => `* ${licenseLine}`).join('\n')}\n*/\n`; // prettier-ignore
};

export const plugin: PluginFunction<AddLicenseHeaderPluginParams> = async (
  schema: GraphQLSchema,
  documents: Types.DocumentFile[],
  { licenseFilePath }: AddLicenseHeaderPluginParams
): Promise<Types.PluginOutput> => {
  if (!licenseFilePath) {
    throw Error('You must provider a valid license file path');
  }

  return {
    content: null,
    prepend: [getLicenseTextFromFile(licenseFilePath)],
  };
};

export default { plugin };
