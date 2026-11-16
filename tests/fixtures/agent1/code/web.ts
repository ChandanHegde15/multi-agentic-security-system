// Hand-written fixture for Agent 1 tests. Never executed.
import express from "express";
import { readFile } from "node:fs/promises";
import path from 'path';
import type { Request } from "express";
import * as _ from 'lodash/fp';
import '@scope/side-effect/styles.css';
export { helper } from "./helper";
export * from "@other/pkg";
const axios = require("axios");
const local = require('./local');
const lazy = await import("chalk");
const name = "left-pad";
const computed = require(name);
const msg = "require('not-a-real-dep')";
const tpl = `import x from "also-not-real"`;
/* import commented from "commented-out"; */
// const old = require("old-dep");
const re = /import\s+from "regex-not-real"/;
const obj = { require: 1 };
console.log(obj.require, import.meta.url);
