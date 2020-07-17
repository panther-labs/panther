'use strict';
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
