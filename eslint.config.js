import eslint from '@eslint/js';
import prettier from 'eslint-config-prettier';

export default [
  {
    ignores: ['dist/**', 'node_modules/**', 'test-results/**', '**/*.ts'],
  },
  eslint.configs.recommended,
  {
    rules: {
      'no-undef': 'off',
      'no-unused-vars': 'off',
      curly: ['error', 'all'],
    },
  },
  prettier,
];
