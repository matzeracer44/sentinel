const path = require('path');
const CopyWebpackPlugin = require('copy-webpack-plugin');

const isDev = process.env.NODE_ENV === 'development';
const resolveFromProject = (segments) => path.resolve(__dirname, ...segments);

module.exports = {
  mode: isDev ? 'development' : 'production',
  target: 'electron-main',
  devtool: isDev ? 'inline-source-map' : false,
  entry: {
    main: resolveFromProject(['src/main/main.ts']),
  },
  output: {
    path: resolveFromProject(['dist/main']),
    filename: '[name].js',
  },
  resolve: {
    extensions: ['.ts', '.js', '.json'],
    alias: {
      '@': resolveFromProject(['src']),
      '@main': resolveFromProject(['src/main']),
      '@renderer': resolveFromProject(['src/renderer']),
    },
  },
  node: {
    __dirname: false,
    __filename: false,
  },
  externals: {
    electron: 'commonjs electron',
    'better-sqlite3': 'commonjs better-sqlite3',
    'classic-level': 'commonjs classic-level',
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.node$/,
        loader: 'node-loader',
      },
    ],
  },
  optimization: {
    usedExports: false,
    sideEffects: true,
    concatenateModules: false,
  },
  plugins: [
    new CopyWebpackPlugin({
      patterns: [
        {
          from: resolveFromProject(['assets']),
          to: resolveFromProject(['dist/assets']),
        },
      ],
    }),
  ],
};