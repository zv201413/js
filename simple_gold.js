// ============================================================
// 歪麦金币 —— 签到 + 用户信息 + 视频任务金币（对齐原版 wmbwc.js 写法）
// 写法：内嵌纯JS CryptoJS + chavyleung Env.js，无 Node 依赖，QX/Loon/Surge/Node 通用
//
// 【App 触发模式】（与原版一致）打开 App 进"我的"页面自动执行：
//   原版利用 QX 重写拦截 api_user_info_one，从 $request 拿 token/userId 跑任务
//   QuantumultX 配置：
//   [rewrite_local]
//   ^https:\/\/wmapp-api\.waimaimingtang\.com\/api\/api\/v2\/user\/api_user_info_one url script-request-body https://gist.githubusercontent.com/zv201413/8a75d97445bcb3861dcb066fb5f5bfda/raw/simple_gold.js
//   [MITM]
//   hostname = wmapp-api.waimaimingtang.com
//
// 【定时/独立模式】读 wmbwc_data 多账号数组自动跑
//   存储复用原版 wmbwc_data：[{"userId":"userId","token":"token","userName":"userName"},...]
//   Node 本地调试：同目录放 wmbwc_data.json（与 wmbwc_data 格式一致）后 node simple_gold.js
// ============================================================
// ===== CryptoJS 4.2.0（纯 JS，内嵌） =====

// 紧凑 AES-128-ECB + PKCS7（纯 JS 函数式，无全局泄漏、无依赖）
// 通过 Node crypto 多向量一致性验证
var wmbAes = (function () {
  var Sb = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
  var Rc = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
  // 逆 S-box（由 Sb 求逆元表推导）
  var Rsb = new Array(256);
  for (var i0 = 0; i0 < 256; i0++) Rsb[Sb[i0]] = i0;
  function xt(x){ return ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff; }
  function gmul(a, b){ var r = 0; while (b) { if (b & 1) r ^= a; a = xt(a); b >>>= 1; } return r; }
  function expand(key) {
    var rk = new Array(176), i, j, t;
    for (i = 0; i < 16; i++) rk[i] = key[i];
    for (i = 4; i < 44; i++) {
      t = [rk[(i-1)*4], rk[(i-1)*4+1], rk[(i-1)*4+2], rk[(i-1)*4+3]];
      if (i % 4 === 0) t = [Sb[t[1]] ^ Rc[i/4 - 1], Sb[t[2]], Sb[t[3]], Sb[t[0]]];
      for (j = 0; j < 4; j++) rk[i*4+j] = rk[(i-4)*4+j] ^ t[j];
    }
    return rk;
  }
  function addK(s, rk, round){ var o = round*16; for (var i = 0; i < 16; i++) s[i] ^= rk[o+i]; }
  function sub(s){ for (var i = 0; i < 16; i++) s[i] = Sb[s[i]]; }
  function invSub(s){ for (var i = 0; i < 16; i++) s[i] = Rsb[s[i]]; }
  function shift(s){ // 状态按列主序: s[4*c+r]
    function g(r, c){ return s[4*c+r]; }
    var t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;                       // row1 左移1
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;             // row2 左移2
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;                    // row3 左移3
  }
  function invShift(s){
    var t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
  }
  function mix(s){
    for (var c = 0; c < 4; c++) {
      var o = c*4;
      var a0 = s[o], a1 = s[o+1], a2 = s[o+2], a3 = s[o+3];
      s[o]   = xt(a0) ^ (xt(a1) ^ a1) ^ a2 ^ a3;
      s[o+1] = a0 ^ xt(a1) ^ (xt(a2) ^ a2) ^ a3;
      s[o+2] = a0 ^ a1 ^ xt(a2) ^ (xt(a3) ^ a3);
      s[o+3] = (xt(a0) ^ a0) ^ a1 ^ a2 ^ xt(a3);
    }
  }
  function invMix(s){
    for (var c = 0; c < 4; c++) {
      var o = c*4;
      var a0 = s[o], a1 = s[o+1], a2 = s[o+2], a3 = s[o+3];
      s[o]   = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
      s[o+1] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
      s[o+2] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11);
      s[o+3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14);
    }
  }
  function encBlock(rk, p){
    var s = p.slice();
    addK(s, rk, 0);
    for (var r = 1; r <= 9; r++) { sub(s); shift(s); mix(s); addK(s, rk, r); }
    sub(s); shift(s); addK(s, rk, 10);
    return s;
  }
  function decBlock(rk, c){
    var s = c.slice();
    addK(s, rk, 10);
    for (var r = 9; r >= 1; r--) { invShift(s); invSub(s); addK(s, rk, r); invMix(s); }
    invShift(s); invSub(s); addK(s, rk, 0);
    return s;
  }
  function toBytes(str){ // UTF-8 编码
    var b = [], i = 0;
    while (i < str.length) {
      var c = str.charCodeAt(i++);
      if (c < 0x80) b.push(c);
      else if (c < 0x800) b.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c >= 0xd800 && c <= 0xdbff && i < str.length) {
        var c2 = str.charCodeAt(i++);
        var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
        b.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      } else b.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return b;
  }
  function fromBytes(b){ var s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return s; }
  var B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function b64(b){
    var s = "";
    for (var i = 0; i < b.length; i += 3) {
      var n = (b[i] << 16) | ((i+1 < b.length ? b[i+1] : 0) << 8) | (i+2 < b.length ? b[i+2] : 0);
      s += B64C[(n >> 18) & 63] + B64C[(n >> 12) & 63] + (i+1 < b.length ? B64C[(n >> 6) & 63] : "=") + (i+2 < b.length ? B64C[n & 63] : "=");
    }
    return s;
  }
  function unb64(s){
    var idx = {};
    for (var i = 0; i < 64; i++) idx[B64C[i]] = i;
    var out = [], v = 0, bits = 0;
    for (var j = 0; j < s.length; j++) {
      var c = s.charAt(j);
      if (c === "=") break;
      var n = idx[c];
      if (n === undefined) continue;
      v = (v << 6) | n; bits += 6;
      if (bits >= 8) { bits -= 8; out.push((v >> bits) & 0xff); }
    }
    return out;
  }
  function keyBytes(keyStr){ return toBytes(keyStr); }
  return {
    // 输入明文/密文均为 UTF-8 字符串，返回 base64
    encrypt: function (plain, keyStr) {
      var rk = expand(keyBytes(keyStr));
      var p = toBytes(plain);
      // PKCS7 填充
      var pad = 16 - (p.length % 16);
      for (var i = 0; i < pad; i++) p.push(pad);
      var out = [];
      for (var o = 0; o < p.length; o += 16) {
        var blk = encBlock(rk, p.slice(o, o + 16));
        for (var k = 0; k < 16; k++) out.push(blk[k]);
      }
      return b64(out);
    },
    // 输入 base64，输出 UTF-8 明文；失败返回 null
    decrypt: function (b64text, keyStr) {
      try {
        var rk = expand(keyBytes(keyStr));
        var c = unb64(b64text);
        if (!c || c.length % 16 !== 0) return null;
        var out = [];
        for (var o = 0; o < c.length; o += 16) {
          var blk = decBlock(rk, c.slice(o, o + 16));
          for (var k = 0; k < 16; k++) out.push(blk[k]);
        }
        var pad = out[out.length - 1];
        if (!pad || pad < 1 || pad > 16) return null;
        // 去 PKCS7
        var len = out.length - pad;
        var s = "";
        for (var i = 0; i < len; i++) s += String.fromCharCode(out[i]);
        return decodeURIComponent(escape(s)); // UTF-8 → JS 字符串
      } catch (e) { return null; }
    }
  };
})();

//From chavyleung's Env.js
function Env(t, e) { class s { constructor(t) { this.env = t } send(t, e = "GET") { t = "string" == typeof t ? { url: t } : t; let s = this.get; return "POST" === e && (s = this.post), new Promise(((e, i) => { s.call(this, t, ((t, s, o) => { t ? i(t) : e(s) })) })) } get(t) { return this.send.call(this.env, t) } post(t) { return this.send.call(this.env, t, "POST") } } return new class { constructor(t, e) { this.logLevels = { debug: 0, info: 1, warn: 2, error: 3 }, this.logLevelPrefixs = { debug: "[DEBUG] ", info: "[INFO] ", warn: "[WARN] ", error: "[ERROR] " }, this.logLevel = "info", this.name = t, this.http = new s(this), this.data = null, this.dataFile = "box.dat", this.logs = [], this.isMute = !1, this.isNeedRewrite = !1, this.logSeparator = "\n", this.encoding = "utf-8", this.startTime = (new Date).getTime(), Object.assign(this, e), this.log("", `🔔${this.name}, 开始!`) } getEnv() { return "undefined" != typeof $environment && $environment["surge-version"] ? "Surge" : "undefined" != typeof $environment && $environment["stash-version"] ? "Stash" : "undefined" != typeof module && module.exports ? "Node.js" : "undefined" != typeof $task ? "Quantumult X" : "undefined" != typeof $loon ? "Loon" : "undefined" != typeof $rocket ? "Shadowrocket" : void 0 } isNode() { return "Node.js" === this.getEnv() } isQuanX() { return "Quantumult X" === this.getEnv() } isSurge() { return "Surge" === this.getEnv() } isLoon() { return "Loon" === this.getEnv() } isShadowrocket() { return "Shadowrocket" === this.getEnv() } isStash() { return "Stash" === this.getEnv() } toObj(t, e = null) { try { return JSON.parse(t) } catch { return e } } toStr(t, e = null, ...s) { try { return JSON.stringify(t, ...s) } catch { return e } } getjson(t, e) { let s = e; if (this.getdata(t)) try { s = JSON.parse(this.getdata(t)) } catch { } return s } setjson(t, e) { try { return this.setdata(JSON.stringify(t), e) } catch { return !1 } } getScript(t) { return new Promise((e => { this.get({ url: t }, ((t, s, i) => e(i))) })) } runScript(t, e) { return new Promise((s => { let i = this.getdata("@chavy_boxjs_userCfgs.httpapi"); i = i ? i.replace(/\n/g, "").trim() : i; let o = this.getdata("@chavy_boxjs_userCfgs.httpapi_timeout"); o = o ? 1 * o : 20, o = e && e.timeout ? e.timeout : o; const [r, a] = i.split("@"), n = { url: `http://${a}/v1/scripting/evaluate`, body: { script_text: t, mock_type: "cron", timeout: o }, headers: { "X-Key": r, Accept: "*/*" }, timeout: o }; this.post(n, ((t, e, i) => s(i))) })).catch((t => this.logErr(t))) } loaddata() { if (!this.isNode()) return {}; { this.fs = this.fs ? this.fs : require("fs"), this.path = this.path ? this.path : require("path"); const t = this.path.resolve(this.dataFile), e = this.path.resolve(process.cwd(), this.dataFile), s = this.fs.existsSync(t), i = !s && this.fs.existsSync(e); if (!s && !i) return {}; { const i = s ? t : e; try { return JSON.parse(this.fs.readFileSync(i)) } catch (t) { return {} } } } } writedata() { if (this.isNode()) { this.fs = this.fs ? this.fs : require("fs"), this.path = this.path ? this.path : require("path"); const t = this.path.resolve(this.dataFile), e = this.path.resolve(process.cwd(), this.dataFile), s = this.fs.existsSync(t), i = !s && this.fs.existsSync(e), o = JSON.stringify(this.data); s ? this.fs.writeFileSync(t, o) : i ? this.fs.writeFileSync(e, o) : this.fs.writeFileSync(t, o) } } lodash_get(t, e, s) { const i = e.replace(/\[(\d+)\]/g, ".$1").split("."); let o = t; for (const t of i) if (o = Object(o)[t], void 0 === o) return s; return o } lodash_set(t, e, s) { return Object(t) !== t || (Array.isArray(e) || (e = e.toString().match(/[^.[\]]+/g) || []), e.slice(0, -1).reduce(((t, s, i) => Object(t[s]) === t[s] ? t[s] : t[s] = Math.abs(e[i + 1]) >> 0 == +e[i + 1] ? [] : {}), t)[e[e.length - 1]] = s), t } getdata(t) { let e = this.getval(t); if (/^@/.test(t)) { const [, s, i] = /^@(.*?)\.(.*?)$/.exec(t), o = s ? this.getval(s) : ""; if (o) try { const t = JSON.parse(o); e = t ? this.lodash_get(t, i, "") : e } catch (t) { e = "" } } return e } setdata(t, e) { let s = !1; if (/^@/.test(e)) { const [, i, o] = /^@(.*?)\.(.*?)$/.exec(e), r = this.getval(i), a = i ? "null" === r ? null : r || "{}" : "{}"; try { const e = JSON.parse(a); this.lodash_set(e, o, t), s = this.setval(JSON.stringify(e), i) } catch (e) { const r = {}; this.lodash_set(r, o, t), s = this.setval(JSON.stringify(r), i) } } else s = this.setval(t, e); return s } getval(t) { switch (this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": return $persistentStore.read(t); case "Quantumult X": return $prefs.valueForKey(t); case "Node.js": return this.data = this.loaddata(), this.data[t]; default: return this.data && this.data[t] || null } } setval(t, e) { switch (this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": return $persistentStore.write(t, e); case "Quantumult X": return $prefs.setValueForKey(t, e); case "Node.js": return this.data = this.loaddata(), this.data[e] = t, this.writedata(), !0; default: return this.data && this.data[e] || null } } initGotEnv(t) { this.got = this.got ? this.got : require("got"), this.cktough = this.cktough ? this.cktough : require("tough-cookie"), this.ckjar = this.ckjar ? this.ckjar : new this.cktough.CookieJar, t && (t.headers = t.headers ? t.headers : {}, t && (t.headers = t.headers ? t.headers : {}, void 0 === t.headers.cookie && void 0 === t.headers.Cookie && void 0 === t.cookieJar && (t.cookieJar = this.ckjar))) } get(t, e = (() => { })) { switch (t.headers && (delete t.headers["Content-Type"], delete t.headers["Content-Length"], delete t.headers["content-type"], delete t.headers["content-length"]), t.params && (t.url += "?" + this.queryStr(t.params)), void 0 === t.followRedirect || t.followRedirect || ((this.isSurge() || this.isLoon()) && (t["auto-redirect"] = !1), this.isQuanX() && (t.opts ? t.opts.redirection = !1 : t.opts = { redirection: !1 })), this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": default: this.isSurge() && this.isNeedRewrite && (t.headers = t.headers || {}, Object.assign(t.headers, { "X-Surge-Skip-Scripting": !1 })), $httpClient.get(t, ((t, s, i) => { !t && s && (s.body = i, s.statusCode = s.status ? s.status : s.statusCode, s.status = s.statusCode), e(t, s, i) })); break; case "Quantumult X": this.isNeedRewrite && (t.opts = t.opts || {}, Object.assign(t.opts, { hints: !1 })), $task.fetch(t).then((t => { const { statusCode: s, statusCode: i, headers: o, body: r, bodyBytes: a } = t; e(null, { status: s, statusCode: i, headers: o, body: r, bodyBytes: a }, r, a) }), (t => e(t && t.error || "UndefinedError"))); break; case "Node.js": let s = require("iconv-lite"); this.initGotEnv(t), this.got(t).on("redirect", ((t, e) => { try { if (t.headers["set-cookie"]) { const s = t.headers["set-cookie"].map(this.cktough.Cookie.parse).toString(); s && this.ckjar.setCookieSync(s, null), e.cookieJar = this.ckjar } } catch (t) { this.logErr(t) } })).then((t => { const { statusCode: i, statusCode: o, headers: r, rawBody: a } = t, n = s.decode(a, this.encoding); e(null, { status: i, statusCode: o, headers: r, rawBody: a, body: n }, n) }), (t => { const { message: i, response: o } = t; e(i, o, o && s.decode(o.rawBody, this.encoding)) })); break } } post(t, e = (() => { })) { const s = t.method ? t.method.toLocaleLowerCase() : "post"; switch (t.body && t.headers && !t.headers["Content-Type"] && !t.headers["content-type"] && (t.headers["content-type"] = "application/x-www-form-urlencoded"), t.headers && (delete t.headers["Content-Length"], delete t.headers["content-length"]), void 0 === t.followRedirect || t.followRedirect || ((this.isSurge() || this.isLoon()) && (t["auto-redirect"] = !1), this.isQuanX() && (t.opts ? t.opts.redirection = !1 : t.opts = { redirection: !1 })), this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": default: this.isSurge() && this.isNeedRewrite && (t.headers = t.headers || {}, Object.assign(t.headers, { "X-Surge-Skip-Scripting": !1 })), $httpClient[s](t, ((t, s, i) => { !t && s && (s.body = i, s.statusCode = s.status ? s.status : s.statusCode, s.status = s.statusCode), e(t, s, i) })); break; case "Quantumult X": t.method = s, this.isNeedRewrite && (t.opts = t.opts || {}, Object.assign(t.opts, { hints: !1 })), $task.fetch(t).then((t => { const { statusCode: s, statusCode: i, headers: o, body: r, bodyBytes: a } = t; e(null, { status: s, statusCode: i, headers: o, body: r, bodyBytes: a }, r, a) }), (t => e(t && t.error || "UndefinedError"))); break; case "Node.js": let i = require("iconv-lite"); this.initGotEnv(t); const { url: o, ...r } = t; this.got[s](o, r).then((t => { const { statusCode: s, statusCode: o, headers: r, rawBody: a } = t, n = i.decode(a, this.encoding); e(null, { status: s, statusCode: o, headers: r, rawBody: a, body: n }, n) }), (t => { const { message: s, response: o } = t; e(s, o, o && i.decode(o.rawBody, this.encoding)) })); break } } time(t, e = null) { const s = e ? new Date(e) : new Date; let i = { "M+": s.getMonth() + 1, "d+": s.getDate(), "H+": s.getHours(), "m+": s.getMinutes(), "s+": s.getSeconds(), "q+": Math.floor((s.getMonth() + 3) / 3), S: s.getMilliseconds() }; /(y+)/.test(t) && (t = t.replace(RegExp.$1, (s.getFullYear() + "").substr(4 - RegExp.$1.length))); for (let e in i) new RegExp("(" + e + ")").test(t) && (t = t.replace(RegExp.$1, 1 == RegExp.$1.length ? i[e] : ("00" + i[e]).substr(("" + i[e]).length))); return t } queryStr(t) { let e = ""; for (const s in t) { let i = t[s]; null != i && "" !== i && ("object" == typeof i && (i = JSON.stringify(i)), e += `${s}=${i}&`) } return e = e.substring(0, e.length - 1), e } msg(e = t, s = "", i = "", o = {}) { const r = t => { const { $open: e, $copy: s, $media: i, $mediaMime: o } = t; switch (typeof t) { case void 0: return t; case "string": switch (this.getEnv()) { case "Surge": case "Stash": default: return { url: t }; case "Loon": case "Shadowrocket": return t; case "Quantumult X": return { "open-url": t }; case "Node.js": return }case "object": switch (this.getEnv()) { case "Surge": case "Stash": case "Shadowrocket": default: { const r = {}; let a = t.openUrl || t.url || t["open-url"] || e; a && Object.assign(r, { action: "open-url", url: a }); let n = t["update-pasteboard"] || t.updatePasteboard || s; if (n && Object.assign(r, { action: "clipboard", text: n }), i) { let t, e, s; if (i.startsWith("http")) t = i; else if (i.startsWith("data:")) { const [t] = i.split(";"), [, o] = i.split(","); e = o, s = t.replace("data:", "") } else { e = i, s = (t => { const e = { JVBERi0: "application/pdf", R0lGODdh: "image/gif", R0lGODlh: "image/gif", iVBORw0KGgo: "image/png", "/9j/": "image/jpg" }; for (var s in e) if (0 === t.indexOf(s)) return e[s]; return null })(i) } Object.assign(r, { "media-url": t, "media-base64": e, "media-base64-mime": o ?? s }) } return Object.assign(r, { "auto-dismiss": t["auto-dismiss"], sound: t.sound }), r } case "Loon": { const s = {}; let o = t.openUrl || t.url || t["open-url"] || e; o && Object.assign(s, { openUrl: o }); let r = t.mediaUrl || t["media-url"]; return i?.startsWith("http") && (r = i), r && Object.assign(s, { mediaUrl: r }), console.log(JSON.stringify(s)), s } case "Quantumult X": { const o = {}; let r = t["open-url"] || t.url || t.openUrl || e; r && Object.assign(o, { "open-url": r }); let a = t["media-url"] || t.mediaUrl; i?.startsWith("http") && (a = i), a && Object.assign(o, { "media-url": a }); let n = t["update-pasteboard"] || t.updatePasteboard || s; return n && Object.assign(o, { "update-pasteboard": n }), console.log(JSON.stringify(o)), o } case "Node.js": return }default: return } }; if (!this.isMute) switch (this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": default: $notification.post(e, s, i, r(o)); break; case "Quantumult X": $notify(e, s, i, r(o)); break; case "Node.js": break }if (!this.isMuteLog) { let t = ["", "==============📣系统通知📣=============="]; t.push(e), s && t.push(s), i && t.push(i), console.log(t.join("\n")), this.logs = this.logs.concat(t) } } debug(...t) { this.logLevels[this.logLevel] <= this.logLevels.debug && (t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(`${this.logLevelPrefixs.debug}${t.map((t => t ?? String(t))).join(this.logSeparator)}`)) } info(...t) { this.logLevels[this.logLevel] <= this.logLevels.info && (t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(`${this.logLevelPrefixs.info}${t.map((t => t ?? String(t))).join(this.logSeparator)}`)) } warn(...t) { this.logLevels[this.logLevel] <= this.logLevels.warn && (t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(`${this.logLevelPrefixs.warn}${t.map((t => t ?? String(t))).join(this.logSeparator)}`)) } error(...t) { this.logLevels[this.logLevel] <= this.logLevels.error && (t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(`${this.logLevelPrefixs.error}${t.map((t => t ?? String(t))).join(this.logSeparator)}`)) } log(...t) { t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(t.map((t => t ?? String(t))).join(this.logSeparator)) } logErr(t, e) { switch (this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": case "Quantumult X": default: this.log("", `❗️${this.name}, 错误!`, e, t); break; case "Node.js": this.log("", `❗️${this.name}, 错误!`, e, void 0 !== t.message ? t.message : t, t.stack); break } } wait(t) { return new Promise((e => setTimeout(e, t))) } done(t = {}) { const e = ((new Date).getTime() - this.startTime) / 1e3; switch (this.log("", `🔔${this.name}, 结束! 🕛 ${e} 秒`), this.log(), this.getEnv()) { case "Surge": case "Loon": case "Stash": case "Shadowrocket": case "Quantumult X": default: $done(t); break; case "Node.js": process.exit(1) } } }(t, e) }

// ============================================================
// 业务代码（紧凑 AES + Env.js + wmbwc_data，无任何外部依赖）
// ============================================================

var $ = new Env("歪麦金币");

var AES_KEY = "jnd674751fh6fkgu";
var SIGN_KEY = "asdf545asdf4545d";
var HOST = "wmapp-api.waimaimingtang.com";
var PATH_PREFIX = "/api/api/v2/user/";
var DEFAULT_CITY = "南宁市";

function aesEncrypt(plain, key) { return wmbAes.encrypt(plain, key); }
function aesDecrypt(b64, key) { return wmbAes.decrypt(b64, key); }

// ---------- 存储：复用原版 wmbwc_data ----------
function loadAccounts() {
  var raw = $.getdata("wmbwc_data");
  if (!raw && $.isNode()) {
    // Node 本地调试：读同目录 wmbwc_data.json（与 wmbwc_data 格式一致）
    try {
      var fs = require("fs"), path = require("path");
      var dir = (typeof process !== "undefined" && process.argv && process.argv[1])
        ? path.dirname(process.argv[1]) : ".";
      raw = fs.readFileSync(path.join(dir, "wmbwc_data.json"), "utf8");
    } catch (e) { raw = null; }
  }
  if (!raw) return [];
  try {
    var arr = JSON.parse(raw);
    var out = [];
    for (var i = 0; i < arr.length; i++) if (arr[i] && arr[i].token) out.push(arr[i]);
    return out;
  } catch (e) { return []; }
}

// ---------- HTTP：Env.js 统一封装（QX/Loon/Surge）；Node 本地用 curl 直连 ----------
var execFileSync = null;
if (typeof require !== "undefined") {
  try { execFileSync = require("child_process").execFileSync; } catch (e) {}
}

function httpPostNode(url, body, headers) {
  var args = ["-s", "--max-time", "15", "--noproxy", "*", "-X", "POST", url];
  for (var k in headers) args.push("-H", k + ": " + headers[k]);
  args.push("--data-binary", body);
  return execFileSync("curl", args, { encoding: "utf8" });
}

function parseResp(text) {
  var env = null;
  try { env = JSON.parse(decB64(text)); } catch (e1) {
    try { env = JSON.parse(text); } catch (e2) { env = null; }
  }
  if (!env) return { raw: (text || "").slice(0, 150) };
  var out = { code: env.code, message: env.message || "" };
  if (env.data && typeof env.data === "string" && env.data.length > 8) {
    try { out.data = JSON.parse(aesDecrypt(env.data, AES_KEY)); }
    catch (e3) {
      try { out.data = aesDecrypt(env.data, AES_KEY); }
      catch (e4) { out.data = "(不可解)"; }
    }
  } else out.data = env.data;
  return out;
}

function apiPost(token, service, params) {
  return new Promise(function (resolve) {
    var ts = String(Date.now());
    var nonce = String(Math.floor(Math.random() * 1e16));
    while (nonce.length < 16) nonce = "0" + nonce;
    nonce = nonce.slice(0, 16);
    var sign = aesEncrypt(ts + nonce, SIGN_KEY);
    var reqBody = {};
    reqBody.serviceNoStr = service;
    for (var k in params) reqBody[k] = params[k];
    var body = JSON.stringify({ json: aesEncrypt(JSON.stringify(reqBody), AES_KEY) });
    var headers = {
      "x-user-agent": "user-agent",
      "content-type": "application/json;charset=UTF-8",
      "system": "iOS",
      "timestamp": ts,
      "nonce": nonce,
      "appversion": "1.1.154",
      "application": "app",
      "apiversion": "1",
      "token": token,
      "x-fetch-ts": ts,
      "user-agent": "Dart/3.7 (dart:io)",
      "appchannel": "App Store",
      "sign": sign
    };
    var url = "https://" + HOST + PATH_PREFIX + service;
    if ($.isNode()) {
      try { resolve(parseResp(httpPostNode(url, body, headers))); }
      catch (e) { resolve({ raw: String(e && e.message || e).slice(0, 150) }); }
      return;
    }
    $.post({ url: url, headers: headers, body: body }, function (err, resp, data) {
      if (err) { resolve({ raw: String(err).slice(0, 150) }); return; }
      resolve(parseResp(data || ""));
    });
  });
}

// base64 → UTF-8 字符串（QX/Loon 有 atob；Node 无则自实现）
function decB64(s) {
  if (typeof atob !== "undefined") {
    var bin = atob(s), out = "";
    for (var i = 0; i < bin.length; i++) out += String.fromCharCode(bin.charCodeAt(i));
    return out;
  }
  // 简易 UTF-8 base64 解码（Node/无 atob 环境）
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var bytes = [];
  var b = 0, bits = 0;
  for (var j = 0; j < s.length; j++) {
    var c = s.charAt(j);
    if (c === "=") break;
    var v = chars.indexOf(c);
    if (v < 0) continue;
    b = (b << 6) | v; bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((b >> bits) & 0xff);
    }
  }
  var str = "";
  for (var m = 0; m < bytes.length; m++) str += String.fromCharCode(bytes[m]);
  return decodeURIComponent(escape(str));
}

// ---------- 业务 ----------
function now() {
  try {
    return new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai", hour12: false,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit"
    }).format(new Date());
  } catch (e) { return new Date().toLocaleString(); }
}

function fmtBalance(o) {
  function pick(k) { return (o[k] === undefined || o[k] === null) ? "-" : o[k]; }
  return "  可提现 money         = " + pick("money") + " 元\n" +
         "  累计返利 rebateMoney = " + pick("rebateMoney") + " 元\n" +
         "  积分 integral        = " + pick("integral") + "\n" +
         "  米粒 riceGrain       = " + pick("riceGrainResidue") + "\n" +
         "  今日奖励 toDayReward = " + pick("toDayRewardAmount") + "\n" +
         "  奖励 rewardAmount    = " + pick("rewardAmount") + "\n" +
         "  VIP到期              = " + pick("vipEndDate");
}

function runAccount(acct, city) {
  return new Promise(function (resolve) {
    var label = acct.userName || acct.userId || acct.token.slice(0, 8) + "...";
    $.log("\n===== 账号: " + label + " =====");
    var p1 = acct.userId ? { userId: acct.userId, city: city } : { city: city };
    apiPost(acct.token, "api_user_info_one", p1).then(function (info) {
      if (info.code === 1 && info.data) {
        $.log("① 用户信息 ✅\n" + fmtBalance(info.data));
      } else {
        $.log("① 用户信息 ❌ " + JSON.stringify(info).slice(0, 140));
      }
      return apiPost(acct.token, "api_user_sign_in", { userId: acct.userId, userBehavior: "sign_in_v2" });
    }).then(function (signIn) {
      var msg = signIn.message || (signIn.data ? JSON.stringify(signIn.data) : "(无消息)");
      $.log((signIn.code === 1 ? "② 签到 ✅" : "② 签到 ⚠️") + " → " + String(msg).slice(0, 100));
      return apiPost(acct.token, "api_user_video_task_token", {});
    }).then(function (vt) {
      if (vt.code === 1 && typeof vt.data === "string" && vt.data.length > 8) {
        $.log("③ 视频任务：拿到token " + vt.data.slice(0, 13) + "...");
        return apiPost(acct.token, "api_user_task_finish", {
          taskKey: "view_video", userId: acct.userId, token: vt.data
        }).then(function (fin) {
          var extra = fin.data ? JSON.stringify(fin.data).slice(0, 100) : "";
          $.log("   完成结果: " + (fin.code === 1 ? "✅ 成功" : "⚠️ " + (fin.message || "失败")) + (extra ? " " + extra : ""));
        });
      }
      $.log("③ 视频任务：拿token失败 " + JSON.stringify(vt).slice(0, 100));
      return Promise.resolve();
    }).then(function () {
      return apiPost(acct.token, "api_user_info_one", p1);
    }).then(function (info2) {
      if (info2.code === 1 && info2.data) $.log("④ 复查余额:\n" + fmtBalance(info2.data));
      resolve();
    }).catch(function (e) {
      $.logErr(e);
      resolve();
    });
  });
}

// ---------- App 触发模式（对齐原版：script-request-body 重写） ----------
// 打开 App 进"我的"页面 → App 调 api_user_info_one → 被 QX/Loon 拦截触发本脚本
// 从 $request 拿 token（请求头）和 userId（请求体解密）→ 跑任务 → $done({}) 放行
function runFromRequest() {
  $.log("\n===== App 触发模式 =====");
  var headers = $request.headers || {};
  var token = headers["token"] || headers["Token"] || "";
  var userId = "";
  var bodyRaw = $request.body || "";
  if (bodyRaw) {
    try {
      var innerRaw = null;
      try {
        var l1 = JSON.parse(bodyRaw);
        if (l1 && l1.json) innerRaw = aesDecrypt(l1.json, AES_KEY);
        else innerRaw = bodyRaw;
      } catch (e1) { innerRaw = bodyRaw; }
      if (innerRaw) {
        var inner = JSON.parse(innerRaw);
        userId = inner.userId || "";
      }
    } catch (e2) { $.log("⚠️ 请求体解析失败: " + (e2 && e2.message || e2)); }
  }
  $.log("从App请求获取 token=" + token.slice(0, 8) + "... userId=" + userId);
  if (!token) { $.log("⚠️ 请求头无 token，直接放行"); return Promise.resolve(); }
  return runAccount({ token: token, userId: userId, userName: "App触发" }, DEFAULT_CITY);
}

function main() {
  var isRewrite = typeof $request !== "undefined" && $request && $request.headers;
  var p;
  if (isRewrite) {
    $.log("[" + now() + "] 歪麦金币 开始 (App触发模式)");
    p = runFromRequest();
  } else {
    $.log("[" + now() + "] 歪麦金币 开始 (wmbwc_data 多账号)");
    var accounts = loadAccounts();
    if (!accounts.length) {
      $.log("❌ 读不到 wmbwc_data：");
      $.log("   - QX/Loon：确认存储里有 wmbwc_data（原版签到脚本在维护）");
      $.log("   - Node：把导出的 wmbwc_data 存为同目录 wmbwc_data.json");
      p = Promise.resolve();
    } else {
      var city = DEFAULT_CITY;
      if (typeof process !== "undefined" && process.env && process.env.WM_CITY) city = process.env.WM_CITY;
      p = Promise.resolve();
      for (var i = 0; i < accounts.length; i++) {
        (function (acct) { p = p.then(function () { return runAccount(acct, city); }); })(accounts[i]);
      }
      p = p.then(function () {
        $.log("\n[" + now() + "] 全部 " + accounts.length + " 个账号执行完毕");
      });
    }
  }
  return p.then(function () {
    if (isRewrite) {
      $.log("[" + now() + "] App触发完成，放行原请求");
      if (typeof $done !== "undefined") $done({});
    } else {
      $.done();
    }
  }, function (e) {
    $.logErr(e);
    if (isRewrite) { if (typeof $done !== "undefined") $done({}); }
    else $.done();
  });
}

main();
