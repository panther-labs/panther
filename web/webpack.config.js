/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* eslint-disable prefer-object-spread */

const path = require('path');
const resolve = require('resolve');
const webpack = require('webpack');
const InlineChunkHtmlPlugin = require('react-dev-utils/InlineChunkHtmlPlugin');
const TerserPlugin = require('terser-webpack-plugin');
const ManifestPlugin = require('webpack-manifest-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const ForkTsCheckerWebpackPlugin = require('fork-ts-checker-webpack-plugin');
const ReactRefreshWebpackPlugin = require('@pmmmwh/react-refresh-webpack-plugin');
const CopyPlugin = require('copy-webpack-plugin');
const CompressionPlugin = require('compression-webpack-plugin');

const isEnvDevelopment = process.env.NODE_ENV === 'development';
const isEnvProduction = process.env.NODE_ENV === 'production';

module.exports = {
  // webpack automatically makes optimisations depending on the environment that runs. We want to
  // make sure to only pass it `development` during dev
  mode: isEnvProduction ? 'production' : isEnvDevelopment && 'development',
  // Stop compilation early in production, saving time
  bail: isEnvProduction,
  // add a proper source map in order to debug the code easier through the sources tab.
  devtool: isEnvProduction ? 'source-map' : isEnvDevelopment && 'cheap-module-source-map',
  output: {
    // This will prevent webpack-dev-server from loading incorrectly because of react-router-v4.
    publicPath: '/',
    // Where to put the compiled files
    path: path.resolve(__dirname, 'dist'),
    // We want to add hash-names only in production. Else we will have a fixed name
    filename: isEnvProduction ? '[name].[contenthash:8].js' : isEnvDevelopment && 'bundle.js',
    // There are also additional JS chunk files if you use code splitting.
    chunkFilename: isEnvProduction
      ? '[name].[contenthash:8].chunk.js'
      : isEnvDevelopment && '[name].chunk.js',
    // add /* filename */ comments to the generated output
    pathinfo: true,
    // Tell webpack to free memory of assets after emiting
    // TODO: remove this when upgrading to webpack 5, since it will become the new default
    futureEmitAssets: true,
    // Point sourcemap entries to original disk location (format as URL on Windows)
    devtoolModuleFilenameTemplate: isEnvProduction
      ? info =>
          path
            .relative(path.resolve(__dirname, 'src'), info.absoluteResourcePath)
            .replace(/\\/g, '/')
      : isEnvDevelopment && (info => path.resolve(info.absoluteResourcePath).replace(/\\/g, '/')),
  },
  entry: path.resolve(__dirname, 'src/index.tsx'),
  // When we are developing locally, we want to add a `devServer` configuration
  devServer: isEnvDevelopment
    ? {
        host: '0.0.0.0',
        publicPath: '/',
        historyApiFallback: {
          disableDotRule: true,
        },
        // Where will the webpack-dev-server attempt to load the content from. We add public
        // so that we can have access to files that don't pass through webpack (i.e. they are not
        // imported through Javascript)
        contentBase: path.join(__dirname, 'public'),
        // Enable gzip compression of generated files.
        compress: true,
        // By default files from `contentBase` will not trigger a page reload.
        watchContentBase: true,
        // Enable hot reloading server. It will provide /sockjs-node/ endpoint
        // for the WebpackDevServer client so it can learn when the files were
        // updated. Note that only changes to CSS are currently hot reloaded.
        // JS changes will refresh the browser.
        hot: true,
        // WebpackDevServer is noisy by default. We make it a bit "quiter" for the devs
        quiet: true,
        // Dont'watch changes in node_modules
        watchOptions: {
          ignored: /node_modules/,
        },
      }
    : undefined,
  optimization: {
    minimize: isEnvProduction,
    minimizer: [
      // This is only used in production mode
      new TerserPlugin({
        terserOptions: {
          parse: {
            // we want terser to parse ecma 8 code. However, we don't want it
            // to apply any minfication steps that turns valid ecma 5 code
            // into invalid ecma 5 code.
            ecma: 8,
          },
          compress: {
            ecma: 5,
            warnings: false,
            comparisons: false,
            inline: 2,
          },
          mangle: {
            safari10: true,
          },
          output: {
            ecma: 5,
            comments: false,
            ascii_only: true,
          },
        },
        parallel: true,
        sourceMap: true,
      }),
    ],
    // Automatically split vendor and commons
    splitChunks: {
      chunks: 'all',
      name: false,
    },
    // Keep the runtime chunk separated to enable long term caching
    runtimeChunk: {
      name: entrypoint => `runtime-${entrypoint.name}`,
    },
  },
  module: {
    // enforce a javascript `strict` mode on different files
    strictExportPresence: true,
    // lint all the files before passing them through the appropriate loaders
    rules: [
      {
        test: /\.(js|mjs|jsx|ts|tsx)$/,
        exclude: /node_modules/,
        loader: require.resolve('babel-loader'),
        options: {
          // This is a feature of `babel-loader` for webpack (not Babel itself).
          // It enables caching results in ./node_modules/.cache/babel-loader/
          // directory for faster rebuilds.
          cacheDirectory: true,
          cacheCompression: isEnvProduction,
          compact: isEnvProduction,
          plugins: isEnvDevelopment ? [require.resolve('react-refresh/babel')] : undefined,
        },
      },
      {
        test: /\.(png|svg|jpg|gif)$/,
        use: ['file-loader', 'image-webpack-loader'],
        enforce: 'pre',
      },
      {
        test: /\.hbs$/,
        loader: 'handlebars-loader',
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.mjs', '.js'],
    alias: {
      Assets: path.resolve(__dirname, 'src/assets/'),
      Components: path.resolve(__dirname, 'src/components/'),
      Generated: path.resolve(__dirname, '__generated__'),
      Helpers: path.resolve(__dirname, 'src/helpers/'),
      Pages: path.resolve(__dirname, 'src/pages'),
      Hooks: path.resolve(__dirname, 'src/hooks'),
      Hoc: path.resolve(__dirname, 'src/hoc'),
      Source: path.resolve(__dirname, 'src/'),

      // make sure that all the packages that attempt to resolve the following packages utilise the
      // same version, so we don't end up bundling multiple versions of it.
      // the same version
      'aws-sdk': path.resolve(__dirname, '../node_modules/aws-sdk'),
      'apollo-link': path.resolve(__dirname, '../node_modules/@apollo/client'),
    },
  },
  plugins: [
    // Expose all environment variables to the front-end code. This seems like a security flaw,
    // but webpack doesn't include what it doesn't need. This means that only the variables read
    // and utilised by the front-end will end up in the JS bundles. All the other will be lost.
    new webpack.EnvironmentPlugin(Object.keys(process.env)),
    // When in production mode, we want to see the progress in the terminal
    isEnvProduction && new webpack.ProgressPlugin(),
    // When in production mode we want to make sure to delete any previous content before we proceed
    isEnvProduction && new CleanWebpackPlugin(),
    // add any content that is present in the "/public" folder to the "/dist" without processing it
    isEnvProduction &&
      new CopyPlugin([
        {
          from: path.resolve(__dirname, 'public'),
          to: path.resolve(__dirname, 'dist'),
          ignore: ['*.hbs'],
        },
      ]),
    // Add scripts to the final HTML
    new HtmlWebpackPlugin(
      Object.assign(
        {},
        {
          inject: true,
          template: path.resolve(__dirname, 'public/index.hbs'),
          filename: './index.html',
          templateParameters: process.env,
        },
        // If we are in production, we make sure to also minify the HTML
        isEnvProduction
          ? {
              minify: {
                removeComments: true,
                collapseWhitespace: true,
                removeRedundantAttributes: true,
                useShortDoctype: true,
                removeEmptyAttributes: true,
                removeStyleLinkTypeAttributes: true,
                keepClosingSlash: true,
                minifyJS: true,
                minifyCSS: true,
                minifyURLs: true,
              },
            }
          : undefined
      )
    ),
    // Makes sure to inline the generated manifest to the HTML
    isEnvProduction && new InlineChunkHtmlPlugin(HtmlWebpackPlugin, [/runtime-.+[.]js/]),
    // This is currently an experimental feature supported only by react-native, but released
    // through the official React repo. Up until now we utilise a custom webpack-plugin (since
    // the official one exists only for react-native's Metro)
    isEnvDevelopment && new ReactRefreshWebpackPlugin({ disableRefreshCheck: true }),
    // Generate a manifest file which contains a mapping of all asset filenames
    // to their corresponding output file so that tools can pick it up without
    // having to parse `index.html`.
    new ManifestPlugin({
      fileName: 'asset-manifest.json',
      publicPath: '/',
      generate: (seed, files) => {
        const manifestFiles = files.reduce((manifest, file) => {
          manifest[file.name] = file.path; // eslint-disable-line
          return manifest;
        }, seed);

        return {
          files: manifestFiles,
        };
      },
    }),
    // Create a forked process (thread) that performs the TS checks. We currently don't have
    // `ts-loader` loaded at all, so the TS compilation is handled by `babel-loader` through the
    // `@babel/preset-typescript`. That means that we don't have any TS checks on compilation time
    // (since those were previously handled by `ts-loader`). This plugin makes sure to ONLY perform
    // the checks without compiling anything
    new ForkTsCheckerWebpackPlugin({
      typescript: resolve.sync('typescript', {
        basedir: path.resolve(__dirname, '../node_modules'),
      }),
      async: isEnvDevelopment,
      useTypescriptIncrementalApi: true,
      checkSyntacticErrors: true,
      tsconfig: path.resolve(__dirname, '../tsconfig.json'),
      reportFiles: [
        '**',
        '!**/__tests__/**',
        '!**/?(*.)(spec|test).*',
        '!**/src/setupProxy.*',
        '!**/src/setupTests.*',
      ],
      watch: path.resolve(__dirname, 'src'),
      silent: true,
    }),
    isEnvProduction &&
      new CompressionPlugin({
        test: /\.(js|svg)$/,
        filename: '[path].br[query]',
        algorithm: 'brotliCompress',
        compressionOptions: { level: 11 },
      }),
  ].filter(Boolean),
};
