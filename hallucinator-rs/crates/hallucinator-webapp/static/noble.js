// Vendored: @noble/ciphers 2.4.0 (gcm) and @noble/hashes 2.4.0 (hkdf, sha256),
// the versions Catelier's web client uses. Used by e2e.js when the page is on
// plain http, where crypto.subtle does not exist. Do not edit: rebuild it.
//
// Built with rolldown (from Catelier's web/node_modules) as one IIFE that sets
// the global `HalluNoble`, from this entry file:
//   export { gcm } from "@noble/ciphers/aes.js";
//   export { hkdf } from "@noble/hashes/hkdf.js";
//   export { sha256 } from "@noble/hashes/sha2.js";
// with { format: "iife", name: "HalluNoble", treeshake: true, minify: false }.
//
// The MIT License (MIT)
//
// Copyright (c) 2022 Paul Miller (https://paulmillr.com)
// Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the “Software”), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

var HalluNoble = (function(exports) {

Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
//#region @noble/ciphers/utils.js
	function isBytes$1(a) {
		return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
	}
	const atitle$1 = (title) => title ? `"${title}" ` : "";
	function abool(value, title = "") {
		if (typeof value !== "boolean") throw new TypeError(atitle$1(title) + "expected boolean, got type=" + typeof value);
		return value;
	}
	function anumber$1(n, title = "") {
		if (typeof n !== "number") throw new TypeError(atitle$1(title) + "expected number, got " + typeof n);
		if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(atitle$1(title) + "expected integer >= 0, got " + n);
		return n;
	}
	function abytes$1(value, length, title = "") {
		if (isBytes$1(value) && (length === void 0 || value.length === length)) return value;
		if (length !== void 0) anumber$1(length, "length");
		const bytes = isBytes$1(value);
		const ofLen = length !== void 0 ? ` of length ${length}` : "";
		const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
		const message = atitle$1(title) + "expected Uint8Array" + ofLen + ", got " + got;
		if (!bytes) throw new TypeError(message);
		throw new RangeError(message);
	}
	function aexists$1(instance, checkFinished = true) {
		if (instance.destroyed) throw new Error("hash was destroyed");
		if (checkFinished && instance.finished) throw new Error("digest() was already called");
	}
	function aoutput$1(out, instance) {
		abytes$1(out, void 0, "output");
		const min = instance.outputLen;
		if (!(out.length >= min)) throw new RangeError("\"output\" expected length >= " + min);
	}
	function aoutput32(out, instance) {
		aoutput$1(out, instance);
		if (!isAligned32(out)) throw new Error("invalid output, must be aligned");
	}
	function u8(arr) {
		return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
	}
	function u32(arr) {
		return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
	}
	function clean$1(...arrays) {
		for (let i = 0; i < arrays.length; i++) arrays[i].fill(0);
	}
	function createView$1(arr) {
		return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
	}
	const isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
	function byteSwap(word) {
		return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
	}
	const swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n) >>> 0;
	function byteSwap32(arr) {
		for (let i = 0; i < arr.length; i++) arr[i] = byteSwap(arr[i]);
		return arr;
	}
	const swap32IfBE = isLE ? (u) => u : byteSwap32;
	function equalBytes(a, b) {
		a = abytes$1(a);
		b = abytes$1(b);
		if (a.length !== b.length) return false;
		let diff = 0;
		for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
		return diff === 0;
	}
	function wrapMacConstructor(keyLen, macCons, fromMsg) {
		const mac = macCons;
		const getArgs = fromMsg || (() => []);
		const macC = (msg, key) => mac(key, ...getArgs(msg)).update(msg).digest();
		const tmp = mac(new Uint8Array(keyLen), ...getArgs(/* @__PURE__ */ new Uint8Array(0)));
		macC.outputLen = tmp.outputLen;
		macC.blockLen = tmp.blockLen;
		macC.create = (key, ...args) => mac(key, ...args);
		return macC;
	}
	const wrapCipher = (params, constructor) => {
		function wrappedCipher(key, ...args) {
			abytes$1(key, void 0, "key");
			if (params.nonceLength !== void 0) {
				const nonce = args[0];
				abytes$1(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
			}
			const tagl = params.tagLength;
			const aadStart = params.nonceLength !== void 0 ? 1 : 0;
			if (!params.withAAD) {
				for (let i = aadStart; i < args.length; i++) if (isBytes$1(args[i])) throw new Error("AAD not supported");
			}
			if (params.withAAD && args[aadStart] !== void 0) abytes$1(args[aadStart], void 0, "AAD");
			const cipher = constructor(key, ...args);
			const checkOutput = (fnLength, output) => {
				if (output !== void 0) {
					if (fnLength !== 2) throw new Error("cipher output not supported");
					abytes$1(output, void 0, "output");
				}
			};
			let called = false;
			return {
				encrypt(data, output) {
					if (called) throw new Error("cannot encrypt() twice with same key + nonce");
					called = true;
					abytes$1(data, void 0, "data");
					checkOutput(cipher.encrypt.length, output);
					return cipher.encrypt(data, output);
				},
				decrypt(data, output) {
					abytes$1(data, void 0, "data");
					if (tagl && data.length < tagl) throw new Error("\"ciphertext\" expected length >= tagLength=" + tagl);
					checkOutput(cipher.decrypt.length, output);
					return cipher.decrypt(data, output);
				}
			};
		}
		Object.assign(wrappedCipher, params);
		return wrappedCipher;
	};
	function getOutput(expectedLength, out, onlyAligned = true) {
		if (out === void 0) return new Uint8Array(expectedLength);
		abytes$1(out, expectedLength, "output");
		if (onlyAligned && !isAligned32(out)) throw new Error("invalid output, must be aligned");
		return out;
	}
	function u64Lengths(dataLength, aadLength, isLE) {
		anumber$1(dataLength);
		anumber$1(aadLength);
		abool(isLE);
		const num = /* @__PURE__ */ new Uint8Array(16);
		const view = createView$1(num);
		view.setBigUint64(0, BigInt(aadLength), isLE);
		view.setBigUint64(8, BigInt(dataLength), isLE);
		return num;
	}
	function isAligned32(bytes) {
		return bytes.byteOffset % 4 === 0;
	}
	function copyBytes(bytes) {
		return Uint8Array.from(abytes$1(bytes));
	}

//#endregion
//#region @noble/ciphers/_polyval.js
	const BLOCK_SIZE$1 = 16;
	const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
	const ZEROS32 = /* @__PURE__ */ u32(ZEROS16);
	const POLY$1 = 225;
	const mul2$1 = (s0, s1, s2, s3) => {
		const hiBit = s3 & 1;
		return {
			s3: s2 << 31 | s3 >>> 1,
			s2: s1 << 31 | s2 >>> 1,
			s1: s0 << 31 | s1 >>> 1,
			s0: s0 >>> 1 ^ POLY$1 << 24 & -(hiBit & 1)
		};
	};
	const swapLE = (n) => (n >>> 0 & 255) << 24 | (n >>> 8 & 255) << 16 | (n >>> 16 & 255) << 8 | n >>> 24 & 255 | 0;
	const estimateWindow = (bytes) => {
		if (bytes > 65536) return 8;
		if (bytes > 1024) return 4;
		return 2;
	};
	var GHASH = class {
		blockLen = BLOCK_SIZE$1;
		outputLen = BLOCK_SIZE$1;
		s0 = 0;
		s1 = 0;
		s2 = 0;
		s3 = 0;
		finished = false;
		destroyed = false;
		t;
		W;
		windowSize;
		constructor(key, expectedLength) {
			abytes$1(key, 16, "key");
			key = copyBytes(key);
			const kView = createView$1(key);
			let k0 = kView.getUint32(0, false);
			let k1 = kView.getUint32(4, false);
			let k2 = kView.getUint32(8, false);
			let k3 = kView.getUint32(12, false);
			const doubles = [];
			for (let i = 0; i < 128; i++) {
				doubles.push({
					s0: swapLE(k0),
					s1: swapLE(k1),
					s2: swapLE(k2),
					s3: swapLE(k3)
				});
				({s0: k0, s1: k1, s2: k2, s3: k3} = mul2$1(k0, k1, k2, k3));
			}
			const W = estimateWindow(expectedLength || 1024);
			if (![
				1,
				2,
				4,
				8
			].includes(W)) throw new Error("ghash: invalid window size, expected 2, 4 or 8");
			this.W = W;
			const windows = 128 / W;
			const windowSize = this.windowSize = 2 ** W;
			const items = [];
			for (let w = 0; w < windows; w++) for (let byte = 0; byte < windowSize; byte++) {
				let s0 = 0, s1 = 0, s2 = 0, s3 = 0;
				for (let j = 0; j < W; j++) {
					if (!(byte >>> W - j - 1 & 1)) continue;
					const { s0: d0, s1: d1, s2: d2, s3: d3 } = doubles[W * w + j];
					s0 ^= d0, s1 ^= d1, s2 ^= d2, s3 ^= d3;
				}
				items.push({
					s0,
					s1,
					s2,
					s3
				});
			}
			this.t = items;
		}
		_updateBlock(s0, s1, s2, s3) {
			s0 ^= this.s0, s1 ^= this.s1, s2 ^= this.s2, s3 ^= this.s3;
			const { W, t, windowSize } = this;
			let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
			const mask = (1 << W) - 1;
			let w = 0;
			for (const num of [
				s0,
				s1,
				s2,
				s3
			]) for (let bytePos = 0; bytePos < 4; bytePos++) {
				const byte = num >>> 8 * bytePos & 255;
				for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
					const bit = byte >>> W * bitPos & mask;
					const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit];
					o0 ^= e0, o1 ^= e1, o2 ^= e2, o3 ^= e3;
					w += 1;
				}
			}
			this.s0 = o0;
			this.s1 = o1;
			this.s2 = o2;
			this.s3 = o3;
		}
		update(data) {
			aexists$1(this);
			abytes$1(data);
			data = copyBytes(data);
			const b32 = u32(data);
			const blocks = Math.floor(data.length / BLOCK_SIZE$1);
			const left = data.length % BLOCK_SIZE$1;
			for (let i = 0; i < blocks; i++) this._updateBlock(swap8IfBE(b32[i * 4 + 0]), swap8IfBE(b32[i * 4 + 1]), swap8IfBE(b32[i * 4 + 2]), swap8IfBE(b32[i * 4 + 3]));
			if (left) {
				ZEROS16.set(data.subarray(blocks * BLOCK_SIZE$1));
				this._updateBlock(swap8IfBE(ZEROS32[0]), swap8IfBE(ZEROS32[1]), swap8IfBE(ZEROS32[2]), swap8IfBE(ZEROS32[3]));
				clean$1(ZEROS32);
			}
			return this;
		}
		destroy() {
			this.destroyed = true;
			const { t } = this;
			for (const elm of t) elm.s0 = 0, elm.s1 = 0, elm.s2 = 0, elm.s3 = 0;
		}
		digestInto(out) {
			aexists$1(this);
			aoutput32(out, this);
			this.finished = true;
			const { s0, s1, s2, s3 } = this;
			const o32 = u32(out);
			o32[0] = s0;
			o32[1] = s1;
			o32[2] = s2;
			o32[3] = s3;
			if (!isLE) swap32IfBE(o32.subarray(0, BLOCK_SIZE$1 / 4));
		}
		digest() {
			const res = new Uint8Array(BLOCK_SIZE$1);
			this.digestInto(res);
			this.destroy();
			return res;
		}
	};
	const ghash = /* @__PURE__ */ wrapMacConstructor(16, (key, expectedLength) => new GHASH(key, expectedLength), (msg) => [msg.length]);

//#endregion
//#region @noble/ciphers/aes.js
	const BLOCK_SIZE = 16;
	const BLOCK_SIZE32 = 4;
	const EMPTY_BLOCK = /* @__PURE__ */ new Uint8Array(BLOCK_SIZE);
	const POLY = 283;
	function validateKeyLength(key) {
		if (![
			16,
			24,
			32
		].includes(key.length)) throw new Error("\"aes key\" expected Uint8Array of length 16/24/32, got length=" + key.length);
	}
	function mul2(n) {
		return n << 1 ^ POLY & -(n >> 7);
	}
	function mul(a, b) {
		let res = 0;
		for (; b > 0; b >>= 1) {
			res ^= a & -(b & 1);
			a = mul2(a);
		}
		return res;
	}
	const sbox = /* @__PURE__ */ (() => {
		const t = /* @__PURE__ */ new Uint8Array(256);
		for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x)) t[i] = x;
		const box = /* @__PURE__ */ new Uint8Array(256);
		box[0] = 99;
		for (let i = 0; i < 255; i++) {
			let x = t[255 - i];
			x |= x << 8;
			box[t[i]] = (x ^ x >> 4 ^ x >> 5 ^ x >> 6 ^ x >> 7 ^ 99) & 255;
		}
		clean$1(t);
		return box;
	})();
	const rotr32_8 = (n) => n << 24 | n >>> 8;
	const rotl32_8 = (n) => n << 8 | n >>> 24;
	function genTtable(sbox, fn) {
		if (sbox.length !== 256) throw new Error("wrong sbox length");
		const T0 = (/* @__PURE__ */ new Uint32Array(256)).map((_, j) => fn(sbox[j]));
		const T1 = T0.map(rotl32_8);
		const T2 = T1.map(rotl32_8);
		const T3 = T2.map(rotl32_8);
		const T01 = /* @__PURE__ */ new Uint32Array(65536);
		const T23 = /* @__PURE__ */ new Uint32Array(65536);
		const sbox2 = /* @__PURE__ */ new Uint16Array(65536);
		for (let i = 0; i < 256; i++) for (let j = 0; j < 256; j++) {
			const idx = i * 256 + j;
			T01[idx] = T0[i] ^ T1[j];
			T23[idx] = T2[i] ^ T3[j];
			sbox2[idx] = sbox[i] << 8 | sbox[j];
		}
		return {
			sbox,
			sbox2,
			T0,
			T1,
			T2,
			T3,
			T01,
			T23
		};
	}
	const tableEncoding = /* @__PURE__ */ genTtable(sbox, (s) => mul(s, 3) << 24 | s << 16 | s << 8 | mul(s, 2));
	const xPowers = /* @__PURE__ */ (() => {
		const p = /* @__PURE__ */ new Uint8Array(16);
		for (let i = 0, x = 1; i < 16; i++, x = mul2(x)) p[i] = x;
		return p;
	})();
	function expandKeyLE(key) {
		abytes$1(key);
		const len = key.length;
		validateKeyLength(key);
		const { sbox2 } = tableEncoding;
		const toClean = [];
		if (!isLE || !isAligned32(key)) toClean.push(key = copyBytes(key));
		const k32 = swap32IfBE(u32(key));
		const Nk = k32.length;
		const subByte = (n) => applySbox(sbox2, n, n, n, n);
		const xk = new Uint32Array(len + 28);
		xk.set(k32);
		for (let i = Nk; i < xk.length; i++) {
			let t = xk[i - 1];
			if (i % Nk === 0) t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1];
			else if (Nk > 6 && i % Nk === 4) t = subByte(t);
			xk[i] = xk[i - Nk] ^ t;
		}
		clean$1(...toClean);
		return xk;
	}
	function apply0123(T01, T23, s0, s1, s2, s3) {
		return T01[s0 << 8 & 65280 | s1 >>> 8 & 255] ^ T23[s2 >>> 8 & 65280 | s3 >>> 24 & 255];
	}
	function applySbox(sbox2, s0, s1, s2, s3) {
		return sbox2[s0 & 255 | s1 & 65280] | sbox2[s2 >>> 16 & 255 | s3 >>> 16 & 65280] << 16;
	}
	function encrypt(xk, s0, s1, s2, s3) {
		const { sbox2, T01, T23 } = tableEncoding;
		let k = 0;
		s0 ^= xk[k++], s1 ^= xk[k++], s2 ^= xk[k++], s3 ^= xk[k++];
		const rounds = xk.length / 4 - 2;
		for (let i = 0; i < rounds; i++) {
			const t0 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
			const t1 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
			const t2 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
			const t3 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
			s0 = t0, s1 = t1, s2 = t2, s3 = t3;
		}
		return {
			s0: xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3),
			s1: xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0),
			s2: xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1),
			s3: xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2)
		};
	}
	function ctr32(xk, isLE, nonce, src, dst) {
		abytes$1(nonce, BLOCK_SIZE, "nonce");
		abytes$1(src);
		dst = getOutput(src.length, dst);
		const ctr = nonce;
		const c32 = u32(ctr);
		const view = createView$1(ctr);
		const src32 = u32(src);
		const dst32 = u32(dst);
		const ctrPos = isLE ? 0 : 12;
		const srcLen = src.length;
		let ctrNum = view.getUint32(ctrPos, isLE);
		for (let i = 0; i + 4 <= src32.length; i += 4) {
			const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
			dst32[i + 0] = src32[i + 0] ^ swap8IfBE(s0);
			dst32[i + 1] = src32[i + 1] ^ swap8IfBE(s1);
			dst32[i + 2] = src32[i + 2] ^ swap8IfBE(s2);
			dst32[i + 3] = src32[i + 3] ^ swap8IfBE(s3);
			ctrNum = ctrNum + 1 >>> 0;
			view.setUint32(ctrPos, ctrNum, isLE);
		}
		const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
		if (start < srcLen) {
			const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
			const b32 = new Uint32Array([
				s0,
				s1,
				s2,
				s3
			]);
			swap32IfBE(b32);
			const buf = u8(b32);
			for (let i = start, pos = 0; i < srcLen; i++, pos++) dst[i] = src[i] ^ buf[pos];
			clean$1(b32);
		}
		return dst;
	}
	function computeTag(fn, isLE, key, data, AAD) {
		const aadLength = AAD ? AAD.length : 0;
		const h = fn.create(key, data.length + aadLength);
		if (AAD) h.update(AAD);
		const num = u64Lengths(8 * data.length, 8 * aadLength, isLE);
		h.update(data);
		h.update(num);
		const res = h.digest();
		clean$1(num);
		return res;
	}
	const gcm = /* @__PURE__ */ wrapCipher({
		blockSize: 16,
		nonceLength: 12,
		tagLength: 16,
		withAAD: true,
		varSizeNonce: true
	}, function aesgcm(key, nonce, AAD) {
		if (nonce.length < 8) throw new Error("aes/gcm: invalid nonce length");
		const tagLength = 16;
		function _computeTag(authKey, tagMask, data) {
			const tag = computeTag(ghash, false, authKey, data, AAD);
			for (let i = 0; i < tagMask.length; i++) tag[i] ^= tagMask[i];
			return tag;
		}
		function deriveKeys() {
			const xk = expandKeyLE(key);
			const authKey = EMPTY_BLOCK.slice();
			const counter = EMPTY_BLOCK.slice();
			ctr32(xk, false, counter, counter, authKey);
			if (nonce.length === 12) counter.set(nonce);
			else {
				const nonceLen = EMPTY_BLOCK.slice();
				createView$1(nonceLen).setBigUint64(8, BigInt(nonce.length * 8), false);
				const g = ghash.create(authKey).update(nonce).update(nonceLen);
				g.digestInto(counter);
				g.destroy();
			}
			return {
				xk,
				authKey,
				counter,
				tagMask: ctr32(xk, false, counter, EMPTY_BLOCK)
			};
		}
		return {
			encrypt(plaintext) {
				const { xk, authKey, counter, tagMask } = deriveKeys();
				const out = new Uint8Array(plaintext.length + tagLength);
				const toClean = [
					xk,
					authKey,
					counter,
					tagMask
				];
				if (!isAligned32(plaintext)) toClean.push(plaintext = copyBytes(plaintext));
				ctr32(xk, false, counter, plaintext, out.subarray(0, plaintext.length));
				const tag = _computeTag(authKey, tagMask, out.subarray(0, out.length - tagLength));
				toClean.push(tag);
				out.set(tag, plaintext.length);
				clean$1(...toClean);
				return out;
			},
			decrypt(ciphertext) {
				const { xk, authKey, counter, tagMask } = deriveKeys();
				const toClean = [
					xk,
					authKey,
					tagMask,
					counter
				];
				if (!isAligned32(ciphertext)) toClean.push(ciphertext = copyBytes(ciphertext));
				const data = ciphertext.subarray(0, -16);
				const passedTag = ciphertext.subarray(-16);
				const tag = _computeTag(authKey, tagMask, data);
				toClean.push(tag);
				if (!equalBytes(tag, passedTag)) {
					clean$1(...toClean);
					throw new Error("aes-gcm: invalid tag");
				}
				const out = ctr32(xk, false, counter, data);
				clean$1(...toClean);
				return out;
			}
		};
	});

//#endregion
//#region @noble/hashes/utils.js
	function isBytes(a) {
		return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
	}
	const atitle = (title) => title ? `"${title}" ` : "";
	function anumber(n, title = "") {
		if (typeof n !== "number") throw new TypeError(atitle(title) + "expected number, got " + typeof n);
		if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
		return n;
	}
	function abytes(value, length, title = "") {
		if (isBytes(value) && (length === void 0 || value.length === length)) return value;
		if (length !== void 0) anumber(length, "length");
		const bytes = isBytes(value);
		const ofLen = length !== void 0 ? ` of length ${length}` : "";
		const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
		const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
		if (!bytes) throw new TypeError(message);
		throw new RangeError(message);
	}
	function ahash(h) {
		if (typeof h !== "function" || typeof h.create !== "function") throw new TypeError("expected hash wrapped by utils.createHasher");
		anumber(h.outputLen);
		anumber(h.blockLen);
		if (h.outputLen < 1 || h.blockLen < 1) throw new Error("hash blockLen / outputLen must be >= 1");
	}
	const aobject = (value, label) => {
		if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
	};
	const aopts = (value, label) => {
		aobject(value, label);
		const proto = Object.getPrototypeOf(value);
		if (proto !== Object.prototype && proto !== null) throw new TypeError(`"${label}" expected plain object`);
		if (Object.hasOwn(value, "__proto__")) throw new TypeError(`"${label}.__proto__" is not allowed`);
	};
	function aexists(instance, checkFinished = true) {
		if (instance.destroyed) throw new Error("hash was destroyed");
		if (checkFinished && instance.finished) throw new Error("digest() was already called");
	}
	function aoutput(out, instance) {
		abytes(out, void 0, "output");
		const min = instance.outputLen;
		if (!(out.length >= min)) throw new RangeError("\"output\" expected length >= " + min);
	}
	function clean(...arrays) {
		for (let i = 0; i < arrays.length; i++) arrays[i].fill(0);
	}
	function createView(arr) {
		return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
	}
	function rotr(word, shift) {
		return word << 32 - shift | word >>> shift;
	}
	function checkOpts(defaults, opts, title = "opts") {
		aopts(defaults, "defaults");
		if (opts !== void 0) aopts(opts, title);
		return Object.assign(Object.create(null), defaults, opts);
	}
	function createHasher(hashCons, info = {}) {
		if (typeof hashCons !== "function") throw new TypeError("\"hashCons\" expected function, got type=" + typeof hashCons);
		info = checkOpts({}, info, "info");
		const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
		const tmp = hashCons(void 0);
		hashC.outputLen = tmp.outputLen;
		hashC.blockLen = tmp.blockLen;
		hashC.canXOF = tmp.canXOF;
		hashC.create = (opts) => hashCons(opts);
		Object.assign(hashC, info);
		return Object.freeze(hashC);
	}
	const oidNist = (suffix) => ({ oid: Uint8Array.from([
		6,
		9,
		96,
		134,
		72,
		1,
		101,
		3,
		4,
		2,
		suffix
	]) });

//#endregion
//#region @noble/hashes/hmac.js
	var _HMAC = class {
		oHash;
		iHash;
		blockLen;
		outputLen;
		canXOF = false;
		finished = false;
		destroyed = false;
		constructor(hash, key) {
			ahash(hash);
			abytes(key, void 0, "key");
			this.iHash = hash.create();
			if (typeof this.iHash.update !== "function") throw new Error("expected Hash instance");
			this.blockLen = this.iHash.blockLen;
			this.outputLen = this.iHash.outputLen;
			const blockLen = this.blockLen;
			const pad = new Uint8Array(blockLen);
			pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
			for (let i = 0; i < pad.length; i++) pad[i] ^= 54;
			this.iHash.update(pad);
			this.oHash = hash.create();
			for (let i = 0; i < pad.length; i++) pad[i] ^= 106;
			this.oHash.update(pad);
			clean(pad);
		}
		update(buf) {
			aexists(this);
			this.iHash.update(buf);
			return this;
		}
		digestInto(out) {
			aexists(this);
			aoutput(out, this);
			this.finished = true;
			const buf = out.subarray(0, this.outputLen);
			this.iHash.digestInto(buf);
			this.oHash.update(buf);
			this.oHash.digestInto(buf);
			this.destroy();
		}
		digest() {
			const out = new Uint8Array(this.oHash.outputLen);
			this.digestInto(out);
			return out;
		}
		_cloneInto(to) {
			to ||= Object.create(Object.getPrototypeOf(this), {});
			const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
			to = to;
			to.finished = finished;
			to.destroyed = destroyed;
			to.blockLen = blockLen;
			to.outputLen = outputLen;
			to.canXOF = canXOF;
			to.oHash = oHash._cloneInto(to.oHash);
			to.iHash = iHash._cloneInto(to.iHash);
			return to;
		}
		clone() {
			return this._cloneInto();
		}
		destroy() {
			this.destroyed = true;
			this.oHash.destroy();
			this.iHash.destroy();
		}
	};
	const hmac = /* @__PURE__ */ (() => {
		const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
		hmac_.create = (hash, key) => new _HMAC(hash, key);
		return hmac_;
	})();

//#endregion
//#region @noble/hashes/hkdf.js
	const HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);
	const EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();
	function expand(hash, prk, info, length = 32, _recycled) {
		ahash(hash);
		anumber(length, "length");
		abytes(prk, void 0, "prk");
		const olen = hash.outputLen;
		if (prk.length < olen) throw new Error("\"prk\" must be at least HashLen octets");
		if (length > 255 * olen) throw new Error("Length must be <= 255*HashLen");
		const blocks = Math.ceil(length / olen);
		if (info === void 0) info = EMPTY_BUFFER;
		else abytes(info, void 0, "info");
		if (!blocks) {
			if (_recycled) clean(prk);
			return /* @__PURE__ */ new Uint8Array();
		}
		const okm = _recycled && blocks === 1 ? prk : new Uint8Array(blocks * olen);
		const { iHash, oHash } = hmac.create(hash, prk);
		const T = _recycled ? prk : new Uint8Array(olen);
		const worker = blocks > 1 ? _recycled?.iHash || hash.create() : void 0;
		for (let counter = 0; counter < blocks - 1; counter++) {
			HKDF_COUNTER[0] = counter + 1;
			const iWork = iHash._cloneInto(worker);
			if (counter) iWork.update(T);
			iWork.update(info).update(HKDF_COUNTER).digestInto(T);
			oHash._cloneInto(worker).update(T).digestInto(T);
			okm.set(T, olen * counter);
		}
		HKDF_COUNTER[0] = blocks;
		if (blocks > 1) iHash.update(T);
		iHash.update(info).update(HKDF_COUNTER).digestInto(T);
		oHash.update(T).digestInto(T);
		okm.set(T, olen * (blocks - 1));
		iHash.destroy();
		oHash.destroy();
		worker?.destroy();
		if (T !== okm) clean(T);
		clean(HKDF_COUNTER);
		if (length === okm.length) return okm;
		const res = okm.slice(0, length);
		clean(okm);
		return res;
	}
	const hkdf = (hash, ikm, salt, info, length) => {
		ahash(hash);
		if (salt === void 0) salt = new Uint8Array(hash.outputLen);
		const HMAC = hmac.create(hash, salt).update(ikm);
		return expand(hash, HMAC.digest(), info, length, HMAC);
	};

//#endregion
//#region @noble/hashes/_u64.js
	const fromNumH = (n) => n / 2 ** 32 | 0;
	const fromNumL = (n) => n >>> 0;
	function setU64FromNum(view, byteOffset, n, isLE) {
		const h = fromNumH(n);
		const l = fromNumL(n);
		view.setUint32(byteOffset, isLE ? l : h, isLE);
		view.setUint32(byteOffset + 4, isLE ? h : l, isLE);
	}

//#endregion
//#region @noble/hashes/_md.js
	function Chi(a, b, c) {
		return a & b ^ ~a & c;
	}
	function Maj(a, b, c) {
		return a & b ^ a & c ^ b & c;
	}
	var HashMD = class {
		blockLen;
		outputLen;
		canXOF = false;
		padOffset;
		isLE;
		buffer;
		view;
		finished = false;
		length = 0;
		pos = 0;
		destroyed = false;
		constructor(blockLen, outputLen, padOffset, isLE) {
			this.blockLen = blockLen;
			this.outputLen = outputLen;
			this.padOffset = padOffset;
			this.isLE = isLE;
			this.buffer = new Uint8Array(blockLen);
			this.view = createView(this.buffer);
		}
		update(data) {
			aexists(this);
			abytes(data);
			const { view, buffer, blockLen } = this;
			const len = data.length;
			let processed = false;
			for (let pos = 0; pos < len;) {
				const take = Math.min(blockLen - this.pos, len - pos);
				if (take === blockLen) {
					const dataView = createView(data);
					for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos);
					processed = true;
					continue;
				}
				buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
				this.pos += take;
				pos += take;
				if (this.pos === blockLen) {
					this.process(view, 0);
					this.pos = 0;
					processed = true;
				}
			}
			this.length += data.length;
			if (processed) this.roundClean();
			return this;
		}
		digestInto(out) {
			aexists(this);
			aoutput(out, this);
			this.finished = true;
			const { buffer, view, blockLen, isLE } = this;
			let { pos } = this;
			buffer[pos++] = 128;
			buffer.fill(0, pos);
			if (this.padOffset > blockLen - pos) {
				this.process(view, 0);
				buffer.fill(0);
			}
			setU64FromNum(view, blockLen - 8, this.length * 8, isLE);
			this.process(view, 0);
			this.roundClean();
			const oview = out === buffer ? view : createView(out);
			const len = this.outputLen;
			const outLen = len / 4;
			const state = this.get();
			if (len % 4 || outLen > state.length) throw new Error("invalid outputLen");
			for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
		}
		digest() {
			const { buffer, outputLen } = this;
			this.digestInto(buffer);
			const res = buffer.slice(0, outputLen);
			this.destroy();
			return res;
		}
		_cloneIntoMeta(to) {
			const { buffer, length, finished, destroyed, pos } = this;
			to.destroyed = destroyed;
			to.finished = finished;
			to.length = length;
			to.pos = pos;
			if (pos) to.buffer.set(buffer);
			return to;
		}
		clone() {
			return this._cloneInto();
		}
	};
	const SHA256_IV = /* @__PURE__ */ Uint32Array.from([
		1779033703,
		3144134277,
		1013904242,
		2773480762,
		1359893119,
		2600822924,
		528734635,
		1541459225
	]);

//#endregion
//#region @noble/hashes/sha2.js
	const SHA256_K = /* @__PURE__ */ Uint32Array.from([
		1116352408,
		1899447441,
		3049323471,
		3921009573,
		961987163,
		1508970993,
		2453635748,
		2870763221,
		3624381080,
		310598401,
		607225278,
		1426881987,
		1925078388,
		2162078206,
		2614888103,
		3248222580,
		3835390401,
		4022224774,
		264347078,
		604807628,
		770255983,
		1249150122,
		1555081692,
		1996064986,
		2554220882,
		2821834349,
		2952996808,
		3210313671,
		3336571891,
		3584528711,
		113926993,
		338241895,
		666307205,
		773529912,
		1294757372,
		1396182291,
		1695183700,
		1986661051,
		2177026350,
		2456956037,
		2730485921,
		2820302411,
		3259730800,
		3345764771,
		3516065817,
		3600352804,
		4094571909,
		275423344,
		430227734,
		506948616,
		659060556,
		883997877,
		958139571,
		1322822218,
		1537002063,
		1747873779,
		1955562222,
		2024104815,
		2227730452,
		2361852424,
		2428436474,
		2756734187,
		3204031479,
		3329325298
	]);
	const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
	var SHA2_32B = class extends HashMD {
		A = 0;
		B = 0;
		C = 0;
		D = 0;
		E = 0;
		F = 0;
		G = 0;
		H = 0;
		constructor(outputLen, IV) {
			super(64, outputLen, 8, false);
			this.A = IV[0] | 0;
			this.B = IV[1] | 0;
			this.C = IV[2] | 0;
			this.D = IV[3] | 0;
			this.E = IV[4] | 0;
			this.F = IV[5] | 0;
			this.G = IV[6] | 0;
			this.H = IV[7] | 0;
		}
		get() {
			const { A, B, C, D, E, F, G, H } = this;
			return [
				A,
				B,
				C,
				D,
				E,
				F,
				G,
				H
			];
		}
		set(A, B, C, D, E, F, G, H) {
			this.A = A | 0;
			this.B = B | 0;
			this.C = C | 0;
			this.D = D | 0;
			this.E = E | 0;
			this.F = F | 0;
			this.G = G | 0;
			this.H = H | 0;
		}
		_cloneInto(to) {
			(to ||= new this.constructor()).set(...this.get());
			return this._cloneIntoMeta(to);
		}
		process(view, offset) {
			for (let i = 0; i < 16; i++, offset += 4) SHA256_W[i] = view.getUint32(offset, false);
			for (let i = 16; i < 64; i++) {
				const W15 = SHA256_W[i - 15];
				const W2 = SHA256_W[i - 2];
				const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
				const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
				SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
			}
			let { A, B, C, D, E, F, G, H } = this;
			for (let i = 0; i < 64; i++) {
				const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
				const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
				const T2 = (rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + Maj(A, B, C) | 0;
				H = G;
				G = F;
				F = E;
				E = D + T1 | 0;
				D = C;
				C = B;
				B = A;
				A = T1 + T2 | 0;
			}
			A = A + this.A | 0;
			B = B + this.B | 0;
			C = C + this.C | 0;
			D = D + this.D | 0;
			E = E + this.E | 0;
			F = F + this.F | 0;
			G = G + this.G | 0;
			H = H + this.H | 0;
			this.set(A, B, C, D, E, F, G, H);
		}
		roundClean() {
			clean(SHA256_W);
		}
		destroy() {
			this.destroyed = true;
			this.set(0, 0, 0, 0, 0, 0, 0, 0);
			clean(this.buffer);
		}
	};
	var _SHA256 = class extends SHA2_32B {
		constructor() {
			super(32, SHA256_IV);
		}
	};
	const sha256 = /* @__PURE__ */ createHasher(() => new _SHA256(), /* @__PURE__ */ oidNist(1));

//#endregion
exports.gcm = gcm;
exports.hkdf = hkdf;
exports.sha256 = sha256;
return exports;
})({});