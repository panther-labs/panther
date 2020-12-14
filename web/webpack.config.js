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

/* eslint-disable prefer-object-spread */

const path = require('path');
const resolve = require('resolve');
const webpack = require('webpack');
const InlineChunkHtmlPlugin = require('react-dev-utils/InlineChunkHtmlPlugin');
const TerserPlugin = require('terser-webpack-plugin');
const ManifestPlugin = require('webpack-manifest-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');
const ForkTsCheckerWebpackPlugin = require('fork-ts-checker-webpack-plugin');
const ReactRefreshWebpackPlugin = require('@pmmmwh/react-refresh-webpack-plugin');
const CopyPlugin = require('copy-webpack-plugin');
const CompressionPlugin = require('compression-webpack-plugin');

const isEnvDevelopment = process.env.NODE_ENV === 'development';
const isEnvProduction = process.env.NODE_ENV === 'production';
const isPerformanceAnalysis = Boolean(process.env.PERFORMANCE_ANALYSIS);

module.exports = {
  // webpack automatically makes optimisations depending on the environment that runs. We want to
  // make sure to only pass it `development` during dev
  mode: isEnvProduction ? 'production' : isEnvDevelopment && 'development',
  // Stop compilation early in production, saving time
  bail: isEnvProduction,
  // add a proper source map in order to debug the code easier through the sources tab.
  devtool: isEnvProduction ? 'source-map' : isEnvDevelopment && 'cheap-module-source-map',
  // Dont'watch changes in node_modules
  watchOptions: {
    ignored: /node_modules/,
  },

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
        test: /\.(jpe?g|png|gif)$/,
        loader: 'url-loader',
        options: {
          limit: 10 * 1024,
        },
      },
      {
        test: /\.svg$/,
        exclude: /node_modules/,
        use: [
          {
            loader: 'svg-url-loader',
            options: {
              limit: 10 * 1024,
              noquotes: true,
            },
          },
          {
            loader: 'svgo-loader',
            options: {
              plugins: [{ removeTitle: true }, { mergePaths: true }],
              multipass: true,
            },
          },
        ],
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
      Public: path.resolve(__dirname, 'public/'),

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
          ignore: ['*.ejs'],
        },
      ]),
    // Add scripts to the final HTML
    new HtmlWebpackPlugin({
      inject: true,
      // We are using `html-loader` here for an EJS template (instead of the `ejs-loader`).
      // The reason for that is that we have an EJS template, filled with template parameters
      // that are going to be replaced in runtime. HtmlWebpackPlugin throws an error if those
      // parameters are not provided during build time and there was no way to get around it.
      // Basically, if those were undefined during build time, the EJS failed to compile. The
      // only way to bypass that is to force HtmlWebpackPlugin to treat this template as a
      // simple HTML and leave those template parameters untouched. Of course, we couldn't just
      // remove this plugin entirely, since we need it for the CSS/JS tag injection
      template: `html-loader!${path.resolve(__dirname, 'public/index.ejs')}`,
      filename: 'index.ejs',
      minify: isEnvProduction
        ? {
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
          }
        : undefined,
    }),
    // Makes sure to inline the generated manifest to the HTML
    isEnvProduction && new InlineChunkHtmlPlugin(HtmlWebpackPlugin, [/runtime-.+[.]js/]),
    // This is currently an experimental feature supported only by react-native, but released
    // through the official React repo. Up until now we utilise a custom webpack-plugin (since
    // the official one exists only for react-native's Metro)
    isEnvDevelopment && new webpack.HotModuleReplacementPlugin(),
    isEnvDevelopment && new ReactRefreshWebpackPlugin({ overlay: { sockIntegration: 'whm' } }),
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
      tsconfig: path.resolve(__dirname, './tsconfig.json'),
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
    isPerformanceAnalysis && new BundleAnalyzerPlugin(),
  ].filter(Boolean),
};
