import globals from "globals";
import pluginJs from "@eslint/js";
import jest from "eslint-plugin-jest";

export default [
  {files: ["**/*.js"], languageOptions: {sourceType: "commonjs"}},
  {languageOptions: { globals: globals.node }},
  {
    files: ["test/**"],
    ...jest.configs['flat/recommended'],
    rules: {
      ...jest.configs['flat/recommended'].rules,
    },
  },
  pluginJs.configs.recommended,
];