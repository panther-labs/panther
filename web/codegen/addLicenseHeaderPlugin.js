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
var __awaiter =
  (this && this.__awaiter) ||
  function (thisArg, _arguments, P, generator) {
    function adopt(value) {
      return value instanceof P
        ? value
        : new P(function (resolve) {
            resolve(value);
          });
    }
    return new (P || (P = Promise))(function (resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator['throw'](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  };
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.plugin = void 0;
const fs_1 = __importDefault(require('fs'));
const path_1 = __importDefault(require('path'));
const getLicenseTextFromFile = licenseFilePath => {
  const licenseText = fs_1.default.readFileSync(
    path_1.default.resolve(__dirname, licenseFilePath),
    {
      encoding: 'utf-8',
    }
  );
  const licenseLines = licenseText.trim().split(/\r?\n/);
  return `/**\n${licenseLines.map(licenseLine => `* ${licenseLine}`).join('\n')}\n*/\n`; // prettier-ignore
};
exports.plugin = (schema, documents, { licenseFilePath }) =>
  __awaiter(void 0, void 0, void 0, function* () {
    if (!licenseFilePath) {
      throw Error('You must provider a valid license file path');
    }
    return {
      content: null,
      prepend: [getLicenseTextFromFile(licenseFilePath)],
    };
  });
exports.default = { plugin: exports.plugin };
