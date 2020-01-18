/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program [The enterprise software] is licensed under the terms of a commercial license
 * available from Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

/* eslint-disable no-param-reassign */
const fs = require('fs');
const klawSync = require('klaw-sync');

class DirContentReplacementPlugin {
  constructor({ dir, mapper }) {
    this.dir = dir;
    this.mapper = mapper;
  }

  apply(compiler) {
    if (!fs.existsSync(this.dir)) {
      return;
    }

    const filePaths = klawSync(this.dir, {
      nodir: true,
      traverseAll: true,
    }).map(f => f.path);

    const originToDestinationFilePathMapping = {};
    filePaths.forEach(filePath => {
      originToDestinationFilePathMapping[this.mapper(filePath)] = filePath;
    });
    const originAbsFilePaths = Object.keys(originToDestinationFilePathMapping);

    compiler.hooks.normalModuleFactory.tap('PantherEnterpriseReplacementPlugin', nmf => {
      nmf.hooks.afterResolve.tap('PantherEnterpriseReplacementPlugin', result => {
        if (!result) {
          return undefined;
        }

        if (originAbsFilePaths.includes(result.resource)) {
          result.resource = originToDestinationFilePathMapping[result.resource];
        }

        return result;
      });
    });
  }
}

module.exports = DirContentReplacementPlugin;
