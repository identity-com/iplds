import pkg from './package.json';
import ts from "rollup-plugin-ts";
import del from 'rollup-plugin-delete';
import { terser } from "rollup-plugin-terser";
import { builtinModules } from "module";

export default {
  input: "src/index.ts",
  output: [
    {
      file: pkg.main,
      format: "esm",
      sourcemap: true,
    }
  ],
  plugins: [
    del({ targets: 'dist/*' }),
    ts(),
    terser()
  ],
  external: [
    'multiformats/hashes/identity',
    ...builtinModules,
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}),
  ]
};
