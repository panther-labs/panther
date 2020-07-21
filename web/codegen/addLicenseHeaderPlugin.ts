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
