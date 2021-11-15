import autoExternal from 'rollup-plugin-auto-external';
import del from 'rollup-plugin-delete';
import { terser } from 'rollup-plugin-terser';
import ts from 'rollup-plugin-ts';

export const isProduction = process.env.NODE_ENV === 'production';
if (isProduction) console.info('Building for production!');

export const buildPluginsSection = () => [
  del({ targets: 'dist/*' }),
  ts({
    tsconfig: 'tsconfig.build.json',
  }),
  terser(),
  autoExternal(),
];

export const buildConfig = ({ pkg, plugins }) => ({
  input: 'src/index.ts',
  output: [
    {
      file: pkg.module,
      format: 'esm',
      sourcemap: true,
    },
    {
      file: pkg.main,
      format: 'cjs',
      sourcemap: true,
    },
  ],
  plugins: plugins ?? buildPluginsSection(),
  external: ['multiformats/hashes/identity'],
});
