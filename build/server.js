"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// node_modules/fastify-plugin/lib/getPluginName.js
var require_getPluginName = __commonJS({
  "node_modules/fastify-plugin/lib/getPluginName.js"(exports2, module2) {
    "use strict";
    var fpStackTracePattern = /at\s{1}(?:.*\.)?plugin\s{1}.*\n\s*(.*)/;
    var fileNamePattern = /(\w*(\.\w*)*)\..*/;
    module2.exports = function getPluginName(fn) {
      if (fn.name.length > 0)
        return fn.name;
      const stackTraceLimit = Error.stackTraceLimit;
      Error.stackTraceLimit = 10;
      try {
        throw new Error("anonymous function");
      } catch (e) {
        Error.stackTraceLimit = stackTraceLimit;
        return extractPluginName(e.stack);
      }
    };
    function extractPluginName(stack) {
      const m = stack.match(fpStackTracePattern);
      return m ? m[1].split(/[/\\]/).slice(-1)[0].match(fileNamePattern)[1] : "anonymous";
    }
    module2.exports.extractPluginName = extractPluginName;
  }
});

// node_modules/fastify-plugin/lib/toCamelCase.js
var require_toCamelCase = __commonJS({
  "node_modules/fastify-plugin/lib/toCamelCase.js"(exports2, module2) {
    "use strict";
    module2.exports = function toCamelCase(name) {
      if (name[0] === "@") {
        name = name.slice(1).replace("/", "-");
      }
      const newName = name.replace(/-(.)/g, function(match, g1) {
        return g1.toUpperCase();
      });
      return newName;
    };
  }
});

// node_modules/fastify-plugin/plugin.js
var require_plugin = __commonJS({
  "node_modules/fastify-plugin/plugin.js"(exports2, module2) {
    "use strict";
    var getPluginName = require_getPluginName();
    var toCamelCase = require_toCamelCase();
    var count = 0;
    function plugin(fn, options = {}) {
      let autoName = false;
      if (typeof fn.default !== "undefined") {
        fn = fn.default;
      }
      if (typeof fn !== "function") {
        throw new TypeError(
          `fastify-plugin expects a function, instead got a '${typeof fn}'`
        );
      }
      if (typeof options === "string") {
        options = {
          fastify: options
        };
      }
      if (typeof options !== "object" || Array.isArray(options) || options === null) {
        throw new TypeError("The options object should be an object");
      }
      if (options.fastify !== void 0 && typeof options.fastify !== "string") {
        throw new TypeError(`fastify-plugin expects a version string, instead got '${typeof options.fastify}'`);
      }
      if (!options.name) {
        autoName = true;
        options.name = getPluginName(fn) + "-auto-" + count++;
      }
      fn[Symbol.for("skip-override")] = options.encapsulate !== true;
      fn[Symbol.for("fastify.display-name")] = options.name;
      fn[Symbol.for("plugin-meta")] = options;
      if (!fn.default) {
        fn.default = fn;
      }
      const camelCase = toCamelCase(options.name);
      if (!autoName && !fn[camelCase]) {
        fn[camelCase] = fn;
      }
      return fn;
    }
    module2.exports = plugin;
    module2.exports.default = plugin;
    module2.exports.fastifyPlugin = plugin;
  }
});

// node_modules/@fastify/Cookie/cookie.js
var require_cookie = __commonJS({
  "node_modules/@fastify/Cookie/cookie.js"(exports2, module2) {
    "use strict";
    var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
    function parse(str, opt) {
      if (typeof str !== "string") {
        throw new TypeError("argument str must be a string");
      }
      const dec = opt?.decode || decodeURIComponent;
      const result = {};
      const strLen = str.length;
      let pos = 0;
      let terminatorPos = 0;
      while (true) {
        if (terminatorPos === strLen)
          break;
        terminatorPos = str.indexOf(";", pos);
        if (terminatorPos === -1)
          terminatorPos = strLen;
        let eqIdx = str.indexOf("=", pos);
        if (eqIdx === -1)
          break;
        if (eqIdx > terminatorPos) {
          pos = terminatorPos + 1;
          continue;
        }
        const key = str.substring(pos, eqIdx++).trim();
        if (result[key] === void 0) {
          const val = str.charCodeAt(eqIdx) === 34 ? str.substring(eqIdx + 1, terminatorPos - 1).trim() : str.substring(eqIdx, terminatorPos).trim();
          result[key] = !(dec === decodeURIComponent && val.indexOf("%") === -1) ? tryDecode(val, dec) : val;
        }
        pos = terminatorPos + 1;
      }
      return result;
    }
    function serialize(name, val, opt) {
      const enc = opt?.encode || encodeURIComponent;
      if (typeof enc !== "function") {
        throw new TypeError("option encode is invalid");
      }
      if (name && !fieldContentRegExp.test(name)) {
        throw new TypeError("argument name is invalid");
      }
      const value = enc(val);
      if (value && !fieldContentRegExp.test(value)) {
        throw new TypeError("argument val is invalid");
      }
      let str = name + "=" + value;
      if (opt == null)
        return str;
      if (opt.maxAge != null) {
        const maxAge = +opt.maxAge;
        if (!isFinite(maxAge)) {
          throw new TypeError("option maxAge is invalid");
        }
        str += "; Max-Age=" + Math.trunc(maxAge);
      }
      if (opt.domain) {
        if (!fieldContentRegExp.test(opt.domain)) {
          throw new TypeError("option domain is invalid");
        }
        str += "; Domain=" + opt.domain;
      }
      if (opt.path) {
        if (!fieldContentRegExp.test(opt.path)) {
          throw new TypeError("option path is invalid");
        }
        str += "; Path=" + opt.path;
      }
      if (opt.priority) {
        const priority = typeof opt.priority === "string" ? opt.priority.toLowerCase() : opt.priority;
        switch (priority) {
          case "low":
            str += "; Priority=Low";
            break;
          case "medium":
            str += "; Priority=Medium";
            break;
          case "high":
            str += "; Priority=High";
            break;
          default:
            throw new TypeError("option priority is invalid");
        }
      }
      if (opt.expires) {
        if (typeof opt.expires.toUTCString !== "function") {
          throw new TypeError("option expires is invalid");
        }
        str += "; Expires=" + opt.expires.toUTCString();
      }
      if (opt.httpOnly) {
        str += "; HttpOnly";
      }
      if (opt.secure) {
        str += "; Secure";
      }
      if (opt.partitioned) {
        str += "; Partitioned";
      }
      if (opt.sameSite) {
        const sameSite = typeof opt.sameSite === "string" ? opt.sameSite.toLowerCase() : opt.sameSite;
        switch (sameSite) {
          case true:
            str += "; SameSite=Strict";
            break;
          case "lax":
            str += "; SameSite=Lax";
            break;
          case "strict":
            str += "; SameSite=Strict";
            break;
          case "none":
            str += "; SameSite=None";
            break;
          default:
            throw new TypeError("option sameSite is invalid");
        }
      }
      return str;
    }
    function tryDecode(str, decode) {
      try {
        return decode(str);
      } catch {
        return str;
      }
    }
    module2.exports = {
      parse,
      serialize
    };
  }
});

// node_modules/@fastify/Cookie/signer.js
var require_signer = __commonJS({
  "node_modules/@fastify/Cookie/signer.js"(exports2, module2) {
    "use strict";
    var crypto = require("crypto");
    var base64PaddingRE = /=/gu;
    function Signer(secrets, algorithm = "sha256") {
      if (!(this instanceof Signer)) {
        return new Signer(secrets, algorithm);
      }
      this.secrets = Array.isArray(secrets) ? secrets : [secrets];
      this.signingKey = this.secrets[0];
      this.algorithm = algorithm;
      validateSecrets(this.secrets);
      validateAlgorithm(this.algorithm);
    }
    function validateSecrets(secrets) {
      for (let i = 0; i < secrets.length; ++i) {
        const secret = secrets[i];
        if (typeof secret !== "string" && Buffer.isBuffer(secret) === false) {
          throw new TypeError("Secret key must be a string or Buffer.");
        }
      }
    }
    function validateAlgorithm(algorithm) {
      try {
        crypto.createHmac(algorithm, crypto.randomBytes(16));
      } catch (e) {
        throw new TypeError(`Algorithm ${algorithm} not supported.`);
      }
    }
    function _sign(value, secret, algorithm) {
      if (typeof value !== "string") {
        throw new TypeError("Cookie value must be provided as a string.");
      }
      return value + "." + crypto.createHmac(algorithm, secret).update(value).digest("base64").replace(base64PaddingRE, "");
    }
    function _unsign(signedValue, secrets, algorithm) {
      if (typeof signedValue !== "string") {
        throw new TypeError("Signed cookie string must be provided.");
      }
      const value = signedValue.slice(0, signedValue.lastIndexOf("."));
      const actual = Buffer.from(signedValue.slice(signedValue.lastIndexOf(".") + 1));
      for (let i = 0; i < secrets.length; ++i) {
        const secret = secrets[i];
        const expected = Buffer.from(crypto.createHmac(algorithm, secret).update(value).digest("base64").replace(base64PaddingRE, ""));
        if (expected.length === actual.length && crypto.timingSafeEqual(expected, actual)) {
          return {
            valid: true,
            renew: secret !== secrets[0],
            value
          };
        }
      }
      return {
        valid: false,
        renew: false,
        value: null
      };
    }
    Signer.prototype.sign = function(value) {
      return _sign(value, this.signingKey, this.algorithm);
    };
    Signer.prototype.unsign = function(signedValue) {
      return _unsign(signedValue, this.secrets, this.algorithm);
    };
    function sign(value, secret, algorithm = "sha256") {
      const secrets = Array.isArray(secret) ? secret : [secret];
      validateSecrets(secrets);
      return _sign(value, secrets[0], algorithm);
    }
    function unsign(signedValue, secret, algorithm = "sha256") {
      const secrets = Array.isArray(secret) ? secret : [secret];
      validateSecrets(secrets);
      return _unsign(signedValue, secrets, algorithm);
    }
    module2.exports = Signer;
    module2.exports.signerFactory = Signer;
    module2.exports.Signer = Signer;
    module2.exports.sign = sign;
    module2.exports.unsign = unsign;
  }
});

// node_modules/@fastify/Cookie/plugin.js
var require_plugin2 = __commonJS({
  "node_modules/@fastify/Cookie/plugin.js"(exports2, module2) {
    "use strict";
    var fp = require_plugin();
    var cookie2 = require_cookie();
    var { Signer, sign, unsign } = require_signer();
    var kReplySetCookies = Symbol("fastify.reply.setCookies");
    var kReplySetCookiesHookRan = Symbol("fastify.reply.setCookiesHookRan");
    function fastifyCookieSetCookie(reply, name, value, options) {
      parseCookies(reply.server, reply.request, reply);
      const opts = Object.assign({}, options);
      if (opts.expires && Number.isInteger(opts.expires)) {
        opts.expires = new Date(opts.expires);
      }
      if (opts.signed) {
        value = reply.signCookie(value);
      }
      if (opts.secure === "auto") {
        if (isConnectionSecure(reply.request)) {
          opts.secure = true;
        } else {
          opts.sameSite = "lax";
          opts.secure = false;
        }
      }
      reply[kReplySetCookies].set(`${name};${opts.domain};${opts.path || "/"}`, { name, value, opts });
      if (reply[kReplySetCookiesHookRan]) {
        setCookies(reply);
      }
      return reply;
    }
    function fastifyCookieClearCookie(reply, name, options) {
      const opts = Object.assign({ path: "/" }, options, {
        expires: /* @__PURE__ */ new Date(1),
        signed: void 0,
        maxAge: void 0
      });
      return fastifyCookieSetCookie(reply, name, "", opts);
    }
    function parseCookies(fastify2, request, reply) {
      if (reply[kReplySetCookies])
        return;
      const cookieHeader = request.raw.headers.cookie;
      request.cookies = cookieHeader ? fastify2.parseCookie(cookieHeader) : {};
      reply[kReplySetCookies] = /* @__PURE__ */ new Map();
    }
    function onReqHandlerWrapper(fastify2, hook) {
      return hook === "preParsing" ? function fastifyCookieHandler(fastifyReq, fastifyRes, payload, done) {
        parseCookies(fastify2, fastifyReq, fastifyRes);
        done();
      } : function fastifyCookieHandler(fastifyReq, fastifyRes, done) {
        parseCookies(fastify2, fastifyReq, fastifyRes);
        done();
      };
    }
    function setCookies(reply) {
      const setCookieHeaderValue = reply.getHeader("Set-Cookie");
      let cookieValue;
      if (setCookieHeaderValue === void 0) {
        if (reply[kReplySetCookies].size === 1) {
          const c = reply[kReplySetCookies].values().next().value;
          reply.header("Set-Cookie", cookie2.serialize(c.name, c.value, c.opts));
          reply[kReplySetCookies].clear();
          return;
        }
        cookieValue = [];
      } else if (typeof setCookieHeaderValue === "string") {
        cookieValue = [setCookieHeaderValue];
      } else {
        cookieValue = setCookieHeaderValue;
      }
      for (const c of reply[kReplySetCookies].values()) {
        cookieValue.push(cookie2.serialize(c.name, c.value, c.opts));
      }
      reply.removeHeader("Set-Cookie");
      reply.header("Set-Cookie", cookieValue);
      reply[kReplySetCookies].clear();
    }
    function fastifyCookieOnSendHandler(fastifyReq, fastifyRes, payload, done) {
      if (!fastifyRes[kReplySetCookies]) {
        done();
        return;
      }
      if (fastifyRes[kReplySetCookies].size) {
        setCookies(fastifyRes);
      }
      fastifyRes[kReplySetCookiesHookRan] = true;
      done();
    }
    function plugin(fastify2, options, next) {
      const secret = options.secret;
      const hook = getHook(options.hook);
      if (hook === void 0) {
        return next(new Error("@fastify/cookie: Invalid value provided for the hook-option. You can set the hook-option only to false, 'onRequest' , 'preParsing' , 'preValidation' or 'preHandler'"));
      }
      const isSigner = !secret || typeof secret.sign === "function" && typeof secret.unsign === "function";
      const signer = isSigner ? secret : new Signer(secret, options.algorithm || "sha256");
      fastify2.decorate("serializeCookie", cookie2.serialize);
      fastify2.decorate("parseCookie", parseCookie);
      if (secret !== void 0) {
        fastify2.decorate("signCookie", signCookie);
        fastify2.decorate("unsignCookie", unsignCookie);
        fastify2.decorateRequest("signCookie", signCookie);
        fastify2.decorateRequest("unsignCookie", unsignCookie);
        fastify2.decorateReply("signCookie", signCookie);
        fastify2.decorateReply("unsignCookie", unsignCookie);
      }
      fastify2.decorateRequest("cookies", null);
      fastify2.decorateReply(kReplySetCookies, null);
      fastify2.decorateReply(kReplySetCookiesHookRan, false);
      fastify2.decorateReply("cookie", setCookie);
      fastify2.decorateReply("setCookie", setCookie);
      fastify2.decorateReply("clearCookie", clearCookie);
      if (hook) {
        fastify2.addHook(hook, onReqHandlerWrapper(fastify2, hook));
        fastify2.addHook("onSend", fastifyCookieOnSendHandler);
      }
      next();
      function parseCookie(cookieHeader) {
        return cookie2.parse(cookieHeader, options.parseOptions);
      }
      function signCookie(value) {
        return signer.sign(value);
      }
      function unsignCookie(value) {
        return signer.unsign(value);
      }
      function setCookie(name, value, cookieOptions) {
        const opts = Object.assign({}, options.parseOptions, cookieOptions);
        return fastifyCookieSetCookie(this, name, value, opts);
      }
      function clearCookie(name, cookieOptions) {
        const opts = Object.assign({}, options.parseOptions, cookieOptions);
        return fastifyCookieClearCookie(this, name, opts);
      }
    }
    function getHook(hook = "onRequest") {
      const hooks = {
        onRequest: "onRequest",
        preParsing: "preParsing",
        preValidation: "preValidation",
        preHandler: "preHandler",
        [false]: false
      };
      return hooks[hook];
    }
    function isConnectionSecure(request) {
      return request.raw.socket?.encrypted === true || request.headers["x-forwarded-proto"] === "https";
    }
    var fastifyCookie = fp(plugin, {
      fastify: "4.x",
      name: "@fastify/cookie"
    });
    module2.exports = fastifyCookie;
    module2.exports.default = fastifyCookie;
    module2.exports.fastifyCookie = fastifyCookie;
    module2.exports.serialize = cookie2.serialize;
    module2.exports.parse = cookie2.parse;
    module2.exports.signerFactory = Signer;
    module2.exports.Signer = Signer;
    module2.exports.sign = sign;
    module2.exports.unsign = unsign;
  }
});

// src/app.ts
var import_fastify = __toESM(require("fastify"));
var import_Cookie = __toESM(require_plugin2());

// src/routes/transactions.ts
var import_zod2 = require("zod");
var import_node_crypto = require("crypto");

// src/database.ts
var import_knex = require("knex");

// src/env/index.ts
var import_dotenv = require("dotenv");
var import_zod = require("zod");
if (process.env.NODE_ENV === "test") {
  (0, import_dotenv.config)({ path: ".env.test" });
} else {
  (0, import_dotenv.config)();
}
var envSchema = import_zod.z.object({
  NODE_ENV: import_zod.z.enum(["development", "test", "production"]).default("production"),
  DATABASE_URL: import_zod.z.string(),
  PORT: import_zod.z.number().default(3333)
});
var _env = envSchema.safeParse(process.env);
if (_env.success === false) {
  console.error("Invalid environment variables!", _env.error.format());
  throw new Error("Invalid environment variables.");
}
var env = _env.data;

// src/database.ts
var config2 = {
  client: "sqlite",
  connection: {
    filename: env.DATABASE_URL
  },
  useNullAsDefault: true,
  migrations: {
    extension: "ts",
    directory: "./db/migrations"
  }
};
var knex = (0, import_knex.knex)(config2);

// src/middlewares/check-session-id-exists.ts
async function checkSessionIdExists(request, reply) {
  const sessionId = request.cookies.sessionId;
  if (!sessionId) {
    return reply.status(401).send({
      error: "Unauthorized."
    });
  }
}

// src/routes/transactions.ts
async function transactionsRoutes(app2) {
  app2.addHook("preHandler", async (request, reply) => {
    console.log(`[${request.method}] ${request.url}`);
  });
  app2.get(
    "/",
    {
      preHandler: [checkSessionIdExists]
    },
    async (request) => {
      const { sessionId } = request.cookies;
      const transactions = await knex("transactions").where("session_id", sessionId).select();
      return { transactions };
    }
  );
  app2.get(
    "/:id",
    {
      preHandler: [checkSessionIdExists]
    },
    async (request) => {
      const getTransactionsBodySchema = import_zod2.z.object({
        id: import_zod2.z.string().uuid()
      });
      const { id } = getTransactionsBodySchema.parse(request.params);
      const { sessionId } = request.cookies;
      const transaction = await knex("transactions").where({
        session_id: sessionId,
        id
      }).first();
      return { transaction };
    }
  );
  app2.get(
    "/summary",
    {
      preHandler: [checkSessionIdExists]
    },
    async (request) => {
      const { sessionId } = request.cookies;
      const summary = await knex("transactions").where("session_id", sessionId).sum("amount", { as: "amount" }).first();
      return { summary };
    }
  );
  app2.post("/", async (request, reply) => {
    const createTransactionsBodySchema = import_zod2.z.object({
      title: import_zod2.z.string(),
      amount: import_zod2.z.number(),
      type: import_zod2.z.enum(["credit", "debit"])
    });
    const { title, amount, type } = createTransactionsBodySchema.parse(
      request.body
    );
    let sessionId = request.cookies.sessionId;
    if (!sessionId) {
      sessionId = (0, import_node_crypto.randomUUID)();
      reply.cookie("sessionId", sessionId, {
        path: "/",
        maxAge: 60 * 60 * 24 * 7
        // 7 days
      });
    }
    await knex("transactions").insert({
      id: (0, import_node_crypto.randomUUID)(),
      title,
      amount: type === "credit" ? amount : amount * -1,
      session_id: sessionId
    });
    return reply.status(201).send();
  });
}

// src/app.ts
var app = (0, import_fastify.default)();
app.register(import_Cookie.default);
app.register(transactionsRoutes, {
  prefix: "transactions"
});

// src/server.ts
app.listen({
  port: env.PORT
}).then(() => {
  console.log("HTTP Server Runnig!");
});
/*! Bundled license information:

@fastify/Cookie/cookie.js:
  (*!
   * Adapted from https://github.com/jshttp/cookie
   *
   * (The MIT License)
   *
   * Copyright (c) 2012-2014 Roman Shtylman <shtylman@gmail.com>
   * Copyright (c) 2015 Douglas Christopher Wilson <doug@somethingdoug.com>
   *
   * Permission is hereby granted, free of charge, to any person obtaining
   * a copy of this software and associated documentation files (the
   * 'Software'), to deal in the Software without restriction, including
   * without limitation the rights to use, copy, modify, merge, publish,
   * distribute, sublicense, and/or sell copies of the Software, and to
   * permit persons to whom the Software is furnished to do so, subject to
   * the following conditions:
   *
   * The above copyright notice and this permission notice shall be
   * included in all copies or substantial portions of the Software.
   *
   * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
   * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
   * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
   * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
   * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
   * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
   *)
*/
