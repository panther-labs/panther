/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program [The enterprise software] is licensed under the terms of a commercial license
 * available from Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

/** 
 * Copyright (C) 2020 Panther Labs Inc  
 *  
 * This program [The enterprise software] is licensed under the terms of a commercial license 
 * available from Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com. 
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial, 
 * falls under the Panther Commercial License to the extent it is permitted.  
 */ 

const path = require('path'); 
const DirContentReplacementPlugin = require('./build-utils/dir-content-replacement-plugin');  
const openSourceWebpackConfig = require('../../web/webpack.config.js'); 

module.exports = {  
  ...openSourceWebpackConfig, 
  plugins: [  
    ...openSourceWebpackConfig.plugins, 
    new DirContentReplacementPlugin({ 
      dir: path.resolve(__dirname, 'src'),  
      mapper: filePath => filePath.replace('/enterprise', ''),  
    }), 
  ],  
};
