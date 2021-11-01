module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint/eslint-plugin'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/eslint-recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'plugin:sonarjs/recommended',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'plugin:prettier/recommended',
  ],
  env: {
    node: true,
    jest: true,
  },
  rules: {
    '@typescript-eslint/member-ordering': 'error',
    '@typescript-eslint/naming-convention': [
      'error',
      {
        selector: 'variableLike',
        format: ['camelCase', 'UPPER_CASE'],
        leadingUnderscore: 'forbid',
        trailingUnderscore: 'forbid',
      },
    ],
    '@typescript-eslint/no-floating-promises': 'error',
    '@typescript-eslint/no-throw-literal': 'error',
    '@typescript-eslint/no-unnecessary-boolean-literal-compare': 'error',
    '@typescript-eslint/no-unnecessary-condition': 'error',
    '@typescript-eslint/no-unused-vars': 'off',
    '@typescript-eslint/no-unused-vars-experimental': ['error', { ignoredNamesRegex: '^_' }],
    '@typescript-eslint/prefer-for-of': 'error',
    '@typescript-eslint/prefer-nullish-coalescing': 'error',
    '@typescript-eslint/prefer-optional-chain': 'error',
    '@typescript-eslint/prefer-readonly': 'error',
    '@typescript-eslint/promise-function-async': 'error',
    '@typescript-eslint/restrict-plus-operands': ['error', { checkCompoundAssignments: true }],
    '@typescript-eslint/restrict-template-expressions': ['error', { allowAny: true }],
    '@typescript-eslint/switch-exhaustiveness-check': 'error',
    '@typescript-eslint/unified-signatures': 'error',
    '@typescript-eslint/return-await': 'off',
    '@typescript-eslint/no-useless-constructor': 'error',
    '@typescript-eslint/no-unsafe-member-access': 'error',
    '@typescript-eslint/no-unsafe-return': 'error',
    '@typescript-eslint/no-unsafe-assignment': 'warn',
    '@typescript-eslint/explicit-function-return-type': [
      'error',
      {
        allowExpressions: true,
        allowTypedFunctionExpressions: true,
      },
    ],

    'prettier/prettier': [
      'error',
      {
        'endOfLine': 'auto'
      },
    ],
    
    // eslint:recommended additional rules & best practices
    'no-extra-parens': 'error',
    'no-template-curly-in-string': 'error',
    'require-atomic-updates': 'error',
    'consistent-return': 'error',
    curly: 'error',
    'default-case': 'error',
    'dot-notation': 'error',
    eqeqeq: 'error',
    'grouped-accessor-pairs': 'error',
    'guard-for-in': 'error',
    'no-else-return': 'error',
    'no-empty-function': ['error', { allow: ['constructors'] }],
    'no-eval': 'error',
    'no-extend-native': 'error',
    'no-floating-decimal': 'error',
    'no-implicit-coercion': 'error',
    'no-new-func': 'error',
    'no-new-wrappers': 'error',
    'no-self-compare': 'error',
    'no-unused-expressions': 'error',
    'no-useless-call': 'error',
    'no-useless-concat': 'error',
    'prefer-promise-reject-errors': 'error',
    'prefer-regex-literals': 'error',
    radix: 'error',
    'func-style': ['error', 'expression'],
    'max-depth': ['error', 3],
    'multiline-ternary': ['error', 'always'],
    'no-lonely-if': 'error',
    'no-nested-ternary': 'error',
    'no-unneeded-ternary': 'error',
    'no-useless-computed-key': 'error',
    'require-await': 'error',
  },
  overrides: [
    {
      files: ['*.test.ts'],
      rules: {
        '@typescript-eslint/no-unsafe-assignment': 'off',
      },
    },
  ],
};
