import{n as _t,d as Ro,c6 as Vt,c1 as ze,c0 as ve,f3 as $c,cc as Yc}from"./index-DYpL5sf4.js";/**
 * @license
 * Copyright 2020 Google LLC. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =============================================================================
 */var Ds=function(r,t){return(Ds=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,n){e.__proto__=n}||function(e,n){for(var o in n)n.hasOwnProperty(o)&&(e[o]=n[o])})(r,t)};function yt(r,t){function e(){this.constructor=r}Ds(r,t),r.prototype=t===null?Object.create(t):(e.prototype=t.prototype,new e)}function X(r,t,e,n){return new(e||(e=Promise))((function(o,a){function i(c){try{u(n.next(c))}catch(l){a(l)}}function s(c){try{u(n.throw(c))}catch(l){a(l)}}function u(c){c.done?o(c.value):new e((function(l){l(c.value)})).then(i,s)}u((n=n.apply(r,[])).next())}))}function $(r,t){var e,n,o,a,i={label:0,sent:function(){if(1&o[0])throw o[1];return o[1]},trys:[],ops:[]};return a={next:s(0),throw:s(1),return:s(2)},typeof Symbol=="function"&&(a[Symbol.iterator]=function(){return this}),a;function s(u){return function(c){return(function(l){if(e)throw new TypeError("Generator is already executing.");for(;i;)try{if(e=1,n&&(o=2&l[0]?n.return:l[0]?n.throw||((o=n.return)&&o.call(n),0):n.next)&&!(o=o.call(n,l[1])).done)return o;switch(n=0,o&&(l=[2&l[0],o.value]),l[0]){case 0:case 1:o=l;break;case 4:return i.label++,{value:l[1],done:!1};case 5:i.label++,n=l[1],l=[0];continue;case 7:l=i.ops.pop(),i.trys.pop();continue;default:if(!(o=(o=i.trys).length>0&&o[o.length-1])&&(l[0]===6||l[0]===2)){i=0;continue}if(l[0]===3&&(!o||l[1]>o[0]&&l[1]<o[3])){i.label=l[1];break}if(l[0]===6&&i.label<o[1]){i.label=o[1],o=l;break}if(o&&i.label<o[2]){i.label=o[2],i.ops.push(l);break}o[2]&&i.ops.pop(),i.trys.pop();continue}l=t.call(r,i)}catch(h){l=[6,h],n=0}finally{e=o=0}if(5&l[0])throw l[1];return{value:l[0]?l[1]:void 0,done:!0}})([u,c])}}}var Jc=(function(){function r(t){this.global=t,this.flags={},this.flagRegistry={},this.urlFlags={},this.populateURLFlags()}return r.prototype.setPlatform=function(t,e){this.platform!=null&&console.warn("Platform "+this.platformName+" has already been set. Overwriting the platform with "+e+"."),this.platformName=t,this.platform=e},r.prototype.registerFlag=function(t,e,n){if(this.flagRegistry[t]={evaluationFn:e,setHook:n},this.urlFlags[t]!=null){var o=this.urlFlags[t];console.warn("Setting feature override from URL "+t+": "+o+"."),this.set(t,o)}},r.prototype.get=function(t){return t in this.flags?this.flags[t]:(this.flags[t]=this.evaluateFlag(t),this.flags[t])},r.prototype.getNumber=function(t){return this.get(t)},r.prototype.getBool=function(t){return this.get(t)},r.prototype.getFlags=function(){return this.flags},Object.defineProperty(r.prototype,"features",{get:function(){return this.flags},enumerable:!0,configurable:!0}),r.prototype.set=function(t,e){if(this.flagRegistry[t]==null)throw new Error("Cannot set flag "+t+" as it has not been registered.");this.flags[t]=e,this.flagRegistry[t].setHook!=null&&this.flagRegistry[t].setHook(e)},r.prototype.evaluateFlag=function(t){if(this.flagRegistry[t]==null)throw new Error("Cannot evaluate flag '"+t+"': no evaluation function found.");return this.flagRegistry[t].evaluationFn()},r.prototype.setFlags=function(t){this.flags=Object.assign({},t)},r.prototype.reset=function(){this.flags={},this.urlFlags={},this.populateURLFlags()},r.prototype.populateURLFlags=function(){var t=this;if(this.global!==void 0&&this.global.location!==void 0&&this.global.location.search!==void 0){var e,n,o=(e=this.global.location.search,n={},e.replace(/[?&]([^=?&]+)(?:=([^&]*))?/g,(function(a){for(var i=[],s=1;s<arguments.length;s++)i[s-1]=arguments[s];return Qc(n,i[0],i[1]),i.join("=")})),n);"tfjsflags"in o&&o.tfjsflags.split(",").forEach((function(a){var i=a.split(":"),s=i[0],u=i[1];t.urlFlags[s]=(function(c,l){if((l=l.toLowerCase())==="true"||l==="false")return l==="true";if(""+ +l===l)return+l;throw new Error("Could not parse value flag value "+l+" for flag "+c+".")})(s,u)}))}},r})();function Qc(r,t,e){r[decodeURIComponent(t)]=decodeURIComponent(e||"")}function L(){return As}var As=null,Mr=new Map,ea=new Map;function Ts(r,t){var e=Fs(r,t);return Mr.get(e)}function Zc(r){return ea.get(r)}function ki(r){for(var t=Mr.entries(),e=[];;){var n=t.next(),o=n.done,a=n.value;if(o)break;var i=a[0],s=a[1];i.split("_")[0]===r&&e.push(s)}return e}function Ns(r){var t=r.kernelName,e=r.backendName,n=Fs(t,e);if(Mr.has(n))throw new Error("The kernel '"+t+"' for backend '"+e+"' is already registered");Mr.set(n,r)}function el(r){var t=r.kernelName;ea.has(t)&&console.warn("Overriding the gradient for '"+t+"'"),ea.set(t,r)}function Fs(r,t){return t+"_"+r}function ta(r,t,e){return Math.max(r,Math.min(t,e))}function Ps(r){return r%2==0?r:r+1}function tl(r){for(var t=0,e=0;e<r.length;e++)t+=r[e];return t}function I(r,t){if(!r)throw new Error(typeof t=="string"?t:t())}function xe(r,t,e){e===void 0&&(e=""),I(Ue(r,t),(function(){return e+" Shapes "+r+" and "+t+" must match"}))}function Xn(r){I(r!=null,(function(){return"The input to the tensor constructor must be a non-null value."}))}function Hn(r,t,e){if(t===void 0&&(t=[]),e===void 0&&(e=!1),t==null&&(t=[]),Array.isArray(r)||At(r)&&!e)for(var n=0;n<r.length;++n)Hn(r[n],t,e);else t.push(r);return t}function Y(r){if(r.length===0)return 1;for(var t=r[0],e=1;e<r.length;e++)t*=r[e];return t}function Ue(r,t){if(r===t)return!0;if(r==null||t==null||r.length!==t.length)return!1;for(var e=0;e<r.length;e++)if(r[e]!==t[e])return!1;return!0}function Te(r){return r%1==0}function nl(r){if(Math.tanh!=null)return Math.tanh(r);if(r===1/0)return 1;if(r===-1/0)return-1;var t=Math.exp(2*r);return(t-1)/(t+1)}function na(r){var t=Math.ceil(Math.sqrt(r));return[t,Math.ceil(r/t)]}function On(r,t){return t<=r.length?r:r+" ".repeat(t-r.length)}function Si(r,t,e){return t===void 0&&(t=function(n){return 0}),new Promise((function(n,o){var a=0,i=function(){if(r())n();else{a++;var s=t(a);e!=null&&a>=e?o():setTimeout(i,s)}};i()}))}function rl(r,t){for(var e=1,n=-1,o=0;o<r.length;++o)if(r[o]>=0)e*=r[o];else if(r[o]===-1){if(n!==-1)throw Error("Shapes can only have 1 implicit size. Found -1 at dim "+n+" and dim "+o);n=o}else if(r[o]<0)throw Error("Shapes can not be < 0. Found "+r[o]+" at dim "+o);if(n===-1){if(t>0&&t!==e)throw Error("Size("+t+") must match the product of shape "+r);return r}if(e===0)throw Error("Cannot infer the missing size in ["+r+"] when there are 0 elements");if(t%e!=0)throw Error("The implicit shape can't be a fractional number. Got "+t+" / "+e);var a=r.slice();return a[n]=t/e,a}function Le(r,t){var e=t.length;return I((r=r==null?t.map((function(n,o){return o})):[].concat(r)).every((function(n){return n>=-e&&n<e})),(function(){return"All values in axis param must be in range [-"+e+", "+e+") but got axis "+r})),I(r.every((function(n){return Te(n)})),(function(){return"All values in axis param must be integers but got axis "+r})),r.map((function(n){return n<0?e+n:n}))}function dn(r,t){for(var e=[],n=[],o=t!=null&&Array.isArray(t)&&t.length===0,a=t==null||o?null:Le(t,r).sort(),i=0,s=0;s<r.length;++s){if(a!=null){if(a[i]===s&&r[s]!==1)throw new Error("Can't squeeze axis "+s+" since its dim '"+r[s]+"' is not 1");(a[i]==null||a[i]>s)&&r[s]===1&&(e.push(r[s]),n.push(s)),a[i]<=s&&i++}r[s]!==1&&(e.push(r[s]),n.push(s))}return{newShape:e,keptDims:n}}function rr(r,t){var e=null;if(r==null||r==="float32")e=new Float32Array(t);else if(r==="int32")e=new Int32Array(t);else{if(r!=="bool")throw new Error("Unknown data type "+r);e=new Uint8Array(t)}return e}function Or(r,t){var e=null;if(r==null||r==="float32")e=new Float32Array(t);else if(r==="int32")e=new Int32Array(t);else if(r==="bool")e=new Uint8Array(t);else{if(r!=="string")throw new Error("Unknown data type "+r);e=new Array(t)}return e}function ol(r,t){for(var e=0;e<r.length;e++){var n=r[e];if(isNaN(n)||!isFinite(n))throw Error("A tensor of type "+t+" being uploaded contains "+n+".")}}function al(r){return r==="bool"||r==="complex64"||r==="float32"||r==="int32"||r==="string"}function il(r,t){return t!=="complex64"&&(t!=="float32"||r==="complex64")&&(t!=="int32"||r==="float32"||r==="complex64")&&(t!=="bool"||r!=="bool")}function At(r){return r instanceof Float32Array||r instanceof Int32Array||r instanceof Uint8Array}function Ms(r){if(r==="float32"||r==="int32")return 4;if(r==="complex64")return 8;if(r==="bool")return 1;throw new Error("Unknown dtype "+r)}function sl(r){if(r==null)return 0;var t=0;return r.forEach((function(e){return t+=e.length})),t}function Ea(r){return typeof r=="string"||r instanceof String}function ul(r){return typeof r=="boolean"}function cl(r){return typeof r=="number"}function lr(r){return Array.isArray(r)?lr(r[0]):r instanceof Float32Array?"float32":r instanceof Int32Array||r instanceof Uint8Array?"int32":cl(r)?"float32":Ea(r)?"string":ul(r)?"bool":"float32"}function ra(r){return!!(r&&r.constructor&&r.call&&r.apply)}function oa(r,t){for(var e=t;e<r;++e)if(r%e==0)return e;return r}function Tt(r){var t=r.length;if(t<2)return[];var e=new Array(t-1);e[t-2]=r[t-1];for(var n=t-3;n>=0;--n)e[n]=e[n+1]*r[n+1];return e}function Os(r,t,e){if(t==="string")throw new Error("Cannot convert a string[] to a TypedArray");if(Array.isArray(r)&&(r=Hn(r)),e&&ol(r,t),(function(a,i){return a instanceof Float32Array&&i==="float32"||a instanceof Int32Array&&i==="int32"||a instanceof Uint8Array&&i==="bool"})(r,t))return r;if(t==null||t==="float32"||t==="complex64")return new Float32Array(r);if(t==="int32")return new Int32Array(r);if(t==="bool"){for(var n=new Uint8Array(r.length),o=0;o<n.length;++o)Math.round(r[o])!==0&&(n[o]=1);return n}throw new Error("Unknown data type "+t)}function Di(r,t){if(r.length===0)return t[0];var e=r.reduce((function(n,o){return n*o}));if(e===0)return[];if(e!==t.length)throw new Error("["+r+"] does not match the input size.");return(function n(o,a,i){var s=new Array;if(a.length===1)for(var u=a[0],c=0;c<u;c++)s[c]=i[o+c];else{u=a[0];var l=a.slice(1),h=l.reduce((function(f,p){return f*p}));for(c=0;c<u;c++)s[c]=n(o+c*h,l,i)}return s})(0,r,t)}function Bs(r,t){for(var e=hr(r,t),n=0;n<e.length;n++)e[n]=1;return e}function hr(r,t){if(t==null||t==="float32"||t==="complex64")return new Float32Array(r);if(t==="int32")return new Int32Array(r);if(t==="bool")return new Uint8Array(r);throw new Error("Unknown data type "+t)}function Rt(){return L().platform.now()}function Ls(r){r.forEach((function(t){I(Number.isInteger(t)&&t>=0,(function(){return"Tensor must have a shape comprised of positive integers but got shape ["+r+"]."}))}))}function ll(r,t){return t===void 0&&(t="utf-8"),t=t||"utf-8",L().platform.encode(r,t)}function Br(r,t){return t===void 0&&(t="utf-8"),t=t||"utf-8",L().platform.decode(r,t)}function Ai(r,t,e){if(t===0)return 0;if(t===1)return r[0];for(var n=r[r.length-1],o=0;o<r.length-1;++o)n+=e[o]*r[o];return n}function hl(r,t,e){if(t===0)return[];if(t===1)return[r];for(var n=new Array(t),o=0;o<n.length-1;++o)n[o]=Math.floor(r/e[o]),r-=n[o]*e[o];return n[n.length-1]=r,n}var fl=(function(){function r(t,e){this.backendTimer=t,this.logger=e,e==null&&(this.logger=new pl)}return r.prototype.profileKernel=function(t,e,n){var o,a=this,i=this.backendTimer.time((function(){o=n()}));return o.forEach((function(s){s.data().then((function(u){(function(c,l,h){if(l!=="float32")return!1;for(var f=0;f<c.length;f++){var p=c[f];if(isNaN(p)||!isFinite(p))return console.warn("Found "+p+" in the result of '"+h+"'"),!0}})(u,s.dtype,t),i.then((function(c){var l="";c.getExtraProfileInfo!=null&&(l=c.getExtraProfileInfo()),a.logger.logKernelProfile(t,s,u,c.kernelMs,e,l)}))}))})),o},r})(),pl=(function(){function r(){}return r.prototype.logKernelProfile=function(t,e,n,o,a,i){var s=typeof o=="number"?On(o+"ms",9):o.error,u=On(t,25),c=e.rank,l=e.size,h=On(e.shape.toString(),14),f="";for(var p in a){var d=a[p].shape||e.shape,v=d.length;f+=p+": "+v+"D "+(v>0?d:"")+" "}console.log("%c"+u+"	%c"+s+"	%c"+c+"D "+h+"	%c"+l+"	%c"+f+"	%c"+i,"font-weight:bold","color:red","color:blue","color: orange","color: green","color: steelblue")},r})(),Ti=20,Yn=3,ko=7;function dl(r,t,e,n){var o=Tt(t),a=(function(c,l,h,f){var p=Y(l),d=f[f.length-1],v=new Array(d).fill(0),m=l.length,g=h==="complex64"?Qn(c):c;if(m>1)for(var x=0;x<p/d;x++)for(var b=x*d,y=0;y<d;y++)v[y]=Math.max(v[y],Jn(g[b+y],0,h).length);return v})(r,t,e,o),i=t.length,s=(function c(l,h,f,p,d,v){v===void 0&&(v=!0);var m=f==="complex64"?2:1,g=h[0],x=h.length;if(x===0)return f==="complex64"?[Jn(Qn(l)[0],0,f)]:f==="bool"?[Ws(l[0])]:[l[0].toString()];if(x===1){if(g>Ti){var b=Yn*m,y=Array.from(l.slice(0,b)),w=Array.from(l.slice((g-Yn)*m,g*m));return f==="complex64"&&(y=Qn(y),w=Qn(w)),["["+y.map((function(B,V){return Jn(B,d[V],f)})).join(", ")+", ..., "+w.map((function(B,V){return Jn(B,d[g-Yn+V],f)})).join(", ")+"]"]}return["["+(f==="complex64"?Qn(l):Array.from(l)).map((function(B,V){return Jn(B,d[V],f)})).join(", ")+"]"]}var C=h.slice(1),S=p.slice(1),k=p[0]*m,R=[];if(g>Ti){for(var E=0;E<Yn;E++){var T=(A=E*k)+k;R.push.apply(R,c(l.slice(A,T),C,f,S,d,!1))}for(R.push("..."),E=g-Yn;E<g;E++)T=(A=E*k)+k,R.push.apply(R,c(l.slice(A,T),C,f,S,d,E===g-1))}else for(E=0;E<g;E++){var A;T=(A=E*k)+k,R.push.apply(R,c(l.slice(A,T),C,f,S,d,E===g-1))}var P=x===2?",":"";for(R[0]="["+R[0]+P,E=1;E<R.length-1;E++)R[E]=" "+R[E]+P;var O=`,
`;for(E=2;E<x;E++)O+=`
`;return R[R.length-1]=" "+R[R.length-1]+"]"+(v?"":O),R})(r,t,e,o,a),u=["Tensor"];return n&&(u.push("  dtype: "+e),u.push("  rank: "+i),u.push("  shape: ["+t+"]"),u.push("  values:")),u.push(s.map((function(c){return"    "+c})).join(`
`)),u.join(`
`)}function Jn(r,t,e){return On(Array.isArray(r)?parseFloat(r[0].toFixed(ko))+" + "+parseFloat(r[1].toFixed(ko))+"j":Ea(r)?"'"+r+"'":e==="bool"?Ws(r):parseFloat(r.toFixed(ko)).toString(),t)}function Ws(r){return r===0?"false":"true"}function Qn(r){for(var t=[],e=0;e<r.length;e+=2)t.push([r[e],r[e+1]]);return t}var or=(function(){function r(t,e,n){var o=this;if(this.dtype=e,this.shape=t.slice(),this.size=Y(t),n!=null){var a=n.length;I(a===this.size,(function(){return"Length of values '"+a+"' does not match the size inferred by the shape '"+o.size+"'."}))}if(e==="complex64")throw new Error("complex64 dtype TensorBuffers are not supported. Please create a TensorBuffer for the real and imaginary parts separately and call tf.complex(real, imag).");this.values=n||Or(e,this.size),this.strides=Tt(t)}return r.prototype.set=function(t){for(var e=this,n=[],o=1;o<arguments.length;o++)n[o-1]=arguments[o];n.length===0&&(n=[0]),I(n.length===this.rank,(function(){return"The number of provided coordinates ("+n.length+") must match the rank ("+e.rank+")"}));var a=this.locToIndex(n);this.values[a]=t},r.prototype.get=function(){for(var t=[],e=0;e<arguments.length;e++)t[e]=arguments[e];t.length===0&&(t=[0]);for(var n=0,o=0,a=t;o<a.length;o++){var i=a[o];if(i<0||i>=this.shape[n]){var s="Requested out of range element at "+t+".   Buffer shape="+this.shape;throw new Error(s)}n++}for(var u=t[t.length-1],c=0;c<t.length-1;++c)u+=this.strides[c]*t[c];return this.values[u]},r.prototype.locToIndex=function(t){if(this.rank===0)return 0;if(this.rank===1)return t[0];for(var e=t[t.length-1],n=0;n<t.length-1;++n)e+=this.strides[n]*t[n];return e},r.prototype.indexToLoc=function(t){if(this.rank===0)return[];if(this.rank===1)return[t];for(var e=new Array(this.shape.length),n=0;n<e.length-1;++n)e[n]=Math.floor(t/this.strides[n]),t-=e[n]*this.strides[n];return e[e.length-1]=t,e},Object.defineProperty(r.prototype,"rank",{get:function(){return this.shape.length},enumerable:!0,configurable:!0}),r.prototype.toTensor=function(){return kt().makeTensor(this.values,this.shape,this.dtype)},r})(),kt=null,M=null,Us=null,Ie=(function(){function r(t,e,n,o){this.kept=!1,this.isDisposedInternal=!1,this.shape=t.slice(),this.dtype=e||"float32",this.size=Y(t),this.strides=Tt(t),this.dataId=n,this.id=o,this.rankType=this.rank<5?this.rank.toString():"higher"}return r.prototype.flatten=function(){return this.throwIfDisposed(),this.as1D()},r.prototype.asScalar=function(){return this.throwIfDisposed(),I(this.size===1,(function(){return"The array must have only 1 element."})),this.reshape([])},r.prototype.as1D=function(){return this.throwIfDisposed(),this.reshape([this.size])},r.prototype.as2D=function(t,e){return this.throwIfDisposed(),this.reshape([t,e])},r.prototype.as3D=function(t,e,n){return this.throwIfDisposed(),this.reshape([t,e,n])},r.prototype.as4D=function(t,e,n,o){return this.throwIfDisposed(),this.reshape([t,e,n,o])},r.prototype.as5D=function(t,e,n,o,a){return this.throwIfDisposed(),this.reshape([t,e,n,o,a])},r.prototype.asType=function(t){return this.throwIfDisposed(),M.cast(this,t)},Object.defineProperty(r.prototype,"rank",{get:function(){return this.shape.length},enumerable:!0,configurable:!0}),r.prototype.buffer=function(){return X(this,void 0,void 0,(function(){var t;return $(this,(function(e){switch(e.label){case 0:return[4,this.data()];case 1:return t=e.sent(),[2,M.buffer(this.shape,this.dtype,t)]}}))}))},r.prototype.bufferSync=function(){return M.buffer(this.shape,this.dtype,this.dataSync())},r.prototype.array=function(){return X(this,void 0,void 0,(function(){var t;return $(this,(function(e){switch(e.label){case 0:return[4,this.data()];case 1:return t=e.sent(),[2,Di(this.shape,t)]}}))}))},r.prototype.arraySync=function(){return Di(this.shape,this.dataSync())},r.prototype.data=function(){return X(this,void 0,void 0,(function(){var t,e;return $(this,(function(n){switch(n.label){case 0:return this.throwIfDisposed(),t=kt().read(this.dataId),this.dtype!=="string"?[3,2]:[4,t];case 1:e=n.sent();try{return[2,e.map((function(o){return Br(o)}))]}catch{throw new Error("Failed to decode the string bytes into utf-8. To get the original bytes, call tensor.bytes().")}n.label=2;case 2:return[2,t]}}))}))},r.prototype.dataSync=function(){this.throwIfDisposed();var t=kt().readSync(this.dataId);if(this.dtype==="string")try{return t.map((function(e){return Br(e)}))}catch{throw new Error("Failed to decode the string bytes into utf-8. To get the original bytes, call tensor.bytes().")}return t},r.prototype.bytes=function(){return X(this,void 0,void 0,(function(){var t;return $(this,(function(e){switch(e.label){case 0:return this.throwIfDisposed(),[4,kt().read(this.dataId)];case 1:return t=e.sent(),this.dtype==="string"?[2,t]:[2,new Uint8Array(t.buffer)]}}))}))},r.prototype.dispose=function(){this.isDisposed||(kt().disposeTensor(this),this.isDisposedInternal=!0)},Object.defineProperty(r.prototype,"isDisposed",{get:function(){return this.isDisposedInternal},enumerable:!0,configurable:!0}),r.prototype.throwIfDisposed=function(){if(this.isDisposed)throw new Error("Tensor is disposed.")},r.prototype.toFloat=function(){return this.asType("float32")},r.prototype.toInt=function(){return this.asType("int32")},r.prototype.toBool=function(){return this.asType("bool")},r.prototype.print=function(t){return t===void 0&&(t=!1),M.print(this,t)},r.prototype.reshape=function(t){return this.throwIfDisposed(),M.reshape(this,t)},r.prototype.reshapeAs=function(t){return this.throwIfDisposed(),this.reshape(t.shape)},r.prototype.expandDims=function(t){return t===void 0&&(t=0),M.expandDims(this,t)},r.prototype.cumsum=function(t,e,n){return t===void 0&&(t=0),e===void 0&&(e=!1),n===void 0&&(n=!1),M.cumsum(this,t,e,n)},r.prototype.squeeze=function(t){return this.throwIfDisposed(),M.squeeze(this,t)},r.prototype.clone=function(){return this.throwIfDisposed(),M.clone(this)},r.prototype.oneHot=function(t,e,n){return this.throwIfDisposed(),M.oneHot(this,t,e,n)},r.prototype.toString=function(t){return t===void 0&&(t=!1),dl(this.dataSync(),this.shape,this.dtype,t)},r.prototype.tile=function(t){return this.throwIfDisposed(),M.tile(this,t)},r.prototype.gather=function(t,e){return e===void 0&&(e=0),this.throwIfDisposed(),M.gather(this,t,e)},r.prototype.matMul=function(t,e,n){return e===void 0&&(e=!1),n===void 0&&(n=!1),this.throwIfDisposed(),M.matMul(this,t,e,n)},r.prototype.dot=function(t){return this.throwIfDisposed(),M.dot(this,t)},r.prototype.norm=function(t,e,n){return t===void 0&&(t="euclidean"),e===void 0&&(e=null),n===void 0&&(n=!1),this.throwIfDisposed(),M.norm(this,t,e,n)},r.prototype.slice=function(t,e){return this.throwIfDisposed(),M.slice(this,t,e)},r.prototype.reverse=function(t){return this.throwIfDisposed(),M.reverse(this,t)},r.prototype.concat=function(t,e){return e===void 0&&(e=0),this.throwIfDisposed(),t instanceof r&&(t=[t]),M.concat([this].concat(t),e)},r.prototype.split=function(t,e){return e===void 0&&(e=0),this.throwIfDisposed(),M.split(this,t,e)},r.prototype.stack=function(t,e){return e===void 0&&(e=0),M.stack([this,t],e)},r.prototype.unstack=function(t){return t===void 0&&(t=0),M.unstack(this,t)},r.prototype.pad=function(t,e){return e===void 0&&(e=0),M.pad(this,t,e)},r.prototype.batchNormalization=function(t,e,n,o,a){return n===void 0&&(n=.001),Us("tf.batchNormalization() is going away. Use tf.batchNorm() instead, and note the positional argument change of scale, offset, and varianceEpsilon"),this.batchNorm(t,e,a,o,n)},r.prototype.batchNorm=function(t,e,n,o,a){return a===void 0&&(a=.001),this.throwIfDisposed(),M.batchNorm(this,t,e,n,o,a)},r.prototype.all=function(t,e){return t===void 0&&(t=null),e===void 0&&(e=!1),this.throwIfDisposed(),M.all(this,t,e)},r.prototype.any=function(t,e){return t===void 0&&(t=null),e===void 0&&(e=!1),this.throwIfDisposed(),M.any(this,t,e)},r.prototype.logSumExp=function(t,e){return t===void 0&&(t=null),e===void 0&&(e=!1),this.throwIfDisposed(),M.logSumExp(this,t,e)},r.prototype.sum=function(t,e){return t===void 0&&(t=null),e===void 0&&(e=!1),this.throwIfDisposed(),M.sum(this,t,e)},r.prototype.prod=function(t,e){return t===void 0&&(t=null),e===void 0&&(e=!1),this.throwIfDisposed(),M.prod(this,t,e)},r.prototype.mean=function(t,e){return t===void 0&&(t=null),e===void 0&&(e=!1),this.throwIfDisposed(),M.mean(this,t,e)},r.prototype.min=function(t,e){return t===void 0&&(t=null),e===void 0&&(e=!1),this.throwIfDisposed(),M.min(this,t,e)},r.prototype.max=function(t,e){return t===void 0&&(t=null),e===void 0&&(e=!1),this.throwIfDisposed(),M.max(this,t,e)},r.prototype.argMin=function(t){return t===void 0&&(t=null),this.throwIfDisposed(),M.argMin(this,t)},r.prototype.argMax=function(t){return t===void 0&&(t=null),this.throwIfDisposed(),M.argMax(this,t)},r.prototype.cast=function(t){return this.throwIfDisposed(),M.cast(this,t)},r.prototype.add=function(t){return this.throwIfDisposed(),M.add(this,t)},r.prototype.addStrict=function(t){return this.throwIfDisposed(),M.addStrict(this,t)},r.prototype.atan2=function(t){return this.throwIfDisposed(),M.atan2(this,t)},r.prototype.sub=function(t){return this.throwIfDisposed(),M.sub(this,t)},r.prototype.subStrict=function(t){return this.throwIfDisposed(),M.subStrict(this,t)},r.prototype.pow=function(t){return this.throwIfDisposed(),M.pow(this,t)},r.prototype.powStrict=function(t){return this.throwIfDisposed(),M.powStrict(this,t)},r.prototype.mul=function(t){return this.throwIfDisposed(),M.mul(this,t)},r.prototype.mulStrict=function(t){return this.throwIfDisposed(),M.mulStrict(this,t)},r.prototype.div=function(t){return this.throwIfDisposed(),M.div(this,t)},r.prototype.divNoNan=function(t){return this.throwIfDisposed(),M.divNoNan(this,t)},r.prototype.floorDiv=function(t){return this.throwIfDisposed(),M.floorDiv(this,t)},r.prototype.divStrict=function(t){return this.throwIfDisposed(),M.divStrict(this,t)},r.prototype.minimum=function(t){return this.throwIfDisposed(),M.minimum(this,t)},r.prototype.minimumStrict=function(t){return this.throwIfDisposed(),M.minimumStrict(this,t)},r.prototype.maximum=function(t){return this.throwIfDisposed(),M.maximum(this,t)},r.prototype.maximumStrict=function(t){return this.throwIfDisposed(),M.maximumStrict(this,t)},r.prototype.mod=function(t){return this.throwIfDisposed(),M.mod(this,t)},r.prototype.modStrict=function(t){return this.throwIfDisposed(),M.modStrict(this,t)},r.prototype.squaredDifferenceStrict=function(t){return this.throwIfDisposed(),M.squaredDifferenceStrict(this,t)},r.prototype.transpose=function(t){return this.throwIfDisposed(),M.transpose(this,t)},r.prototype.notEqual=function(t){return this.throwIfDisposed(),M.notEqual(this,t)},r.prototype.notEqualStrict=function(t){return this.throwIfDisposed(),M.notEqualStrict(this,t)},r.prototype.less=function(t){return this.throwIfDisposed(),M.less(this,t)},r.prototype.lessStrict=function(t){return this.throwIfDisposed(),M.lessStrict(this,t)},r.prototype.equal=function(t){return this.throwIfDisposed(),M.equal(this,t)},r.prototype.equalStrict=function(t){return this.throwIfDisposed(),M.equalStrict(this,t)},r.prototype.lessEqual=function(t){return this.throwIfDisposed(),M.lessEqual(this,t)},r.prototype.lessEqualStrict=function(t){return this.throwIfDisposed(),M.lessEqualStrict(this,t)},r.prototype.greater=function(t){return this.throwIfDisposed(),M.greater(this,t)},r.prototype.greaterStrict=function(t){return this.throwIfDisposed(),M.greaterStrict(this,t)},r.prototype.greaterEqual=function(t){return this.throwIfDisposed(),M.greaterEqual(this,t)},r.prototype.greaterEqualStrict=function(t){return this.throwIfDisposed(),M.greaterEqualStrict(this,t)},r.prototype.logicalAnd=function(t){return this.throwIfDisposed(),M.logicalAnd(this,t)},r.prototype.logicalOr=function(t){return this.throwIfDisposed(),M.logicalOr(this,t)},r.prototype.logicalNot=function(){return this.throwIfDisposed(),M.logicalNot(this)},r.prototype.logicalXor=function(t){return this.throwIfDisposed(),M.logicalXor(this,t)},r.prototype.where=function(t,e){return this.throwIfDisposed(),M.where(t,this,e)},r.prototype.neg=function(){return this.throwIfDisposed(),M.neg(this)},r.prototype.ceil=function(){return this.throwIfDisposed(),M.ceil(this)},r.prototype.floor=function(){return this.throwIfDisposed(),M.floor(this)},r.prototype.sign=function(){return this.throwIfDisposed(),M.sign(this)},r.prototype.isNaN=function(){return this.throwIfDisposed(),M.isNaN(this)},r.prototype.isInf=function(){return this.throwIfDisposed(),M.isInf(this)},r.prototype.isFinite=function(){return this.throwIfDisposed(),M.isFinite(this)},r.prototype.exp=function(){return this.throwIfDisposed(),M.exp(this)},r.prototype.expm1=function(){return this.throwIfDisposed(),M.expm1(this)},r.prototype.log=function(){return this.throwIfDisposed(),M.log(this)},r.prototype.log1p=function(){return this.throwIfDisposed(),M.log1p(this)},r.prototype.sqrt=function(){return this.throwIfDisposed(),M.sqrt(this)},r.prototype.rsqrt=function(){return this.throwIfDisposed(),M.rsqrt(this)},r.prototype.square=function(){return this.throwIfDisposed(),M.square(this)},r.prototype.reciprocal=function(){return this.throwIfDisposed(),M.reciprocal(this)},r.prototype.abs=function(){return this.throwIfDisposed(),M.abs(this)},r.prototype.clipByValue=function(t,e){return this.throwIfDisposed(),M.clipByValue(this,t,e)},r.prototype.relu=function(){return this.throwIfDisposed(),M.relu(this)},r.prototype.relu6=function(){return this.throwIfDisposed(),M.relu6(this)},r.prototype.elu=function(){return this.throwIfDisposed(),M.elu(this)},r.prototype.selu=function(){return this.throwIfDisposed(),M.selu(this)},r.prototype.leakyRelu=function(t){return t===void 0&&(t=.2),this.throwIfDisposed(),M.leakyRelu(this,t)},r.prototype.prelu=function(t){return this.throwIfDisposed(),M.prelu(this,t)},r.prototype.sigmoid=function(){return this.throwIfDisposed(),M.sigmoid(this)},r.prototype.logSigmoid=function(){return this.throwIfDisposed(),M.logSigmoid(this)},r.prototype.softplus=function(){return this.throwIfDisposed(),M.softplus(this)},r.prototype.zerosLike=function(){return this.throwIfDisposed(),M.zerosLike(this)},r.prototype.onesLike=function(){return this.throwIfDisposed(),M.onesLike(this)},r.prototype.sin=function(){return this.throwIfDisposed(),M.sin(this)},r.prototype.cos=function(){return this.throwIfDisposed(),M.cos(this)},r.prototype.tan=function(){return this.throwIfDisposed(),M.tan(this)},r.prototype.asin=function(){return this.throwIfDisposed(),M.asin(this)},r.prototype.acos=function(){return this.throwIfDisposed(),M.acos(this)},r.prototype.atan=function(){return this.throwIfDisposed(),M.atan(this)},r.prototype.sinh=function(){return this.throwIfDisposed(),M.sinh(this)},r.prototype.cosh=function(){return this.throwIfDisposed(),M.cosh(this)},r.prototype.tanh=function(){return this.throwIfDisposed(),M.tanh(this)},r.prototype.asinh=function(){return this.throwIfDisposed(),M.asinh(this)},r.prototype.acosh=function(){return this.throwIfDisposed(),M.acosh(this)},r.prototype.atanh=function(){return this.throwIfDisposed(),M.atanh(this)},r.prototype.erf=function(){return this.throwIfDisposed(),M.erf(this)},r.prototype.round=function(){return this.throwIfDisposed(),M.round(this)},r.prototype.step=function(t){return t===void 0&&(t=0),this.throwIfDisposed(),M.step(this,t)},r.prototype.softmax=function(t){return t===void 0&&(t=-1),this.throwIfDisposed(),M.softmax(this,t)},r.prototype.logSoftmax=function(t){return t===void 0&&(t=-1),this.throwIfDisposed(),M.logSoftmax(this,t)},r.prototype.resizeBilinear=function(t,e){return e===void 0&&(e=!1),this.throwIfDisposed(),M.image.resizeBilinear(this,t,e)},r.prototype.resizeNearestNeighbor=function(t,e){return e===void 0&&(e=!1),this.throwIfDisposed(),M.image.resizeNearestNeighbor(this,t,e)},r.prototype.conv1d=function(t,e,n,o,a,i){return o===void 0&&(o="NWC"),a===void 0&&(a=1),this.throwIfDisposed(),M.conv1d(this,t,e,n,o,a,i)},r.prototype.conv2d=function(t,e,n,o,a,i){return o===void 0&&(o="NHWC"),a===void 0&&(a=[1,1]),this.throwIfDisposed(),M.conv2d(this,t,e,n,o,a,i)},r.prototype.conv2dTranspose=function(t,e,n,o,a){return this.throwIfDisposed(),M.conv2dTranspose(this,t,e,n,o,a)},r.prototype.depthwiseConv2D=function(t,e,n,o,a,i){return o===void 0&&(o="NHWC"),a===void 0&&(a=[1,1]),this.throwIfDisposed(),M.depthwiseConv2d(this,t,e,n,o,a,i)},r.prototype.separableConv2d=function(t,e,n,o,a,i){return a===void 0&&(a=[1,1]),i===void 0&&(i="NHWC"),this.throwIfDisposed(),M.separableConv2d(this,t,e,n,o,a,i)},r.prototype.avgPool=function(t,e,n,o){return this.throwIfDisposed(),M.avgPool(this,t,e,n,o)},r.prototype.maxPool=function(t,e,n,o){return this.throwIfDisposed(),M.maxPool(this,t,e,n,o)},r.prototype.localResponseNormalization=function(t,e,n,o){return t===void 0&&(t=5),e===void 0&&(e=1),n===void 0&&(n=1),o===void 0&&(o=.5),M.localResponseNormalization(this,t,e,n,o)},r.prototype.pool=function(t,e,n,o,a){return this.throwIfDisposed(),M.pool(this,t,e,n,o,a)},r.prototype.variable=function(t,e,n){return t===void 0&&(t=!0),this.throwIfDisposed(),kt().makeVariable(this,t,e,n)},r.prototype.unsortedSegmentSum=function(t,e){return this.throwIfDisposed(),M.unsortedSegmentSum(this,t,e)},r.prototype.batchToSpaceND=function(t,e){return this.throwIfDisposed(),M.batchToSpaceND(this,t,e)},r.prototype.spaceToBatchND=function(t,e){return this.throwIfDisposed(),M.spaceToBatchND(this,t,e)},r.prototype.topk=function(t,e){return t===void 0&&(t=1),e===void 0&&(e=!0),this.throwIfDisposed(),M.topk(this,t,e)},r.prototype.stridedSlice=function(t,e,n,o,a,i,s,u){return o===void 0&&(o=0),a===void 0&&(a=0),i===void 0&&(i=0),s===void 0&&(s=0),u===void 0&&(u=0),this.throwIfDisposed(),M.stridedSlice(this,t,e,n,o,a,i,s,u)},r.prototype.depthToSpace=function(t,e){return this.throwIfDisposed(),M.depthToSpace(this,t,e)},r.prototype.fft=function(){return this.throwIfDisposed(),M.spectral.fft(this)},r.prototype.ifft=function(){return this.throwIfDisposed(),M.spectral.ifft(this)},r.prototype.rfft=function(){return this.throwIfDisposed(),M.spectral.rfft(this)},r.prototype.irfft=function(){return this.throwIfDisposed(),M.spectral.irfft(this)},r})();Object.defineProperty(Ie,Symbol.hasInstance,{value:function(r){return!!r&&r.dataId!=null&&r.shape!=null&&r.dtype!=null}});var Ni,aa,ia,sa,ua,jn=(function(r){function t(e,n,o,a){var i=r.call(this,e.shape,e.dtype,e.dataId,a)||this;return i.trainable=n,i.name=o,i}return yt(t,r),t.prototype.assign=function(e){if(e.dtype!==this.dtype)throw new Error("dtype of the new value ("+e.dtype+") and previous value ("+this.dtype+") must match");if(!Ue(e.shape,this.shape))throw new Error("shape of the new value ("+e.shape+") and previous value ("+this.shape+") must match");kt().disposeTensor(this),this.dataId=e.dataId,kt().incRef(this,null)},t.prototype.dispose=function(){kt().disposeVariable(this),this.isDisposedInternal=!0},t})(Ie);Object.defineProperty(jn,Symbol.hasInstance,{value:function(r){return r instanceof Ie&&r.assign!=null&&r.assign instanceof Function}}),(function(r){r.R0="R0",r.R1="R1",r.R2="R2",r.R3="R3",r.R4="R4",r.R5="R5",r.R6="R6"})(Ni||(Ni={})),(function(r){r.float32="float32",r.int32="int32",r.bool="int32",r.complex64="complex64"})(aa||(aa={})),(function(r){r.float32="float32",r.int32="int32",r.bool="bool",r.complex64="complex64"})(ia||(ia={})),(function(r){r.float32="float32",r.int32="float32",r.bool="float32",r.complex64="complex64"})(sa||(sa={})),(function(r){r.float32="complex64",r.int32="complex64",r.bool="complex64",r.complex64="complex64"})(ua||(ua={}));var vl={float32:sa,int32:aa,bool:ia,complex64:ua};function He(r,t){if(r==="string"||t==="string"){if(r==="string"&&t==="string")return"string";throw new Error("Can not upcast "+r+" with "+t)}return vl[r][t]}function So(r){return He(r,"int32")}function ke(r,t){if(r.dtype===t.dtype)return[r,t];var e=He(r.dtype,t.dtype);return[r.cast(e),t.cast(e)]}function ml(r,t){I(r.dtype===t.dtype,(function(){return"The dtypes of the first("+r.dtype+") and second("+t.dtype+") input must match"}))}function Vs(r){var t=[];return(function e(n,o,a){if(n!=null){if(n instanceof Ie)return void o.push(n);if(i=n,!(!Array.isArray(i)&&typeof i!="object")){var i,s=n;for(var u in s){var c=s[u];a.has(c)||(a.add(c),e(c,o,a))}}}})(r,t,new Set),t}var Do,Fi=(function(){function r(){this.registeredVariables={},this.nextTapeNodeId=0,this.numBytes=0,this.numTensors=0,this.numStringTensors=0,this.numDataBuffers=0,this.gradientDepth=0,this.kernelDepth=0,this.scopeStack=[],this.numDataMovesStack=[],this.nextScopeId=0,this.tensorInfo=new WeakMap,this.profiling=!1,this.activeProfile={newBytes:0,newTensors:0,peakBytes:0,kernels:[],result:null}}return r.prototype.dispose=function(){for(var t in this.registeredVariables)this.registeredVariables[t].dispose()},r})(),gl=(function(){function r(t){this.ENV=t,this.registry={},this.registryFactory={},this.pendingBackendInitId=0,this.state=new Fi}return r.prototype.ready=function(){return X(this,void 0,void 0,(function(){var t,e,n;return $(this,(function(o){switch(o.label){case 0:if(this.pendingBackendInit!=null)return[2,this.pendingBackendInit.then((function(){}))];if(this.backendInstance!=null)return[2];t=this.getSortedBackends(),e=0,o.label=1;case 1:return e<t.length?(n=t[e],[4,this.initializeBackend(n).success]):[3,5];case 2:return o.sent()?[4,this.setBackend(n)]:[3,4];case 3:return o.sent(),[2];case 4:return e++,[3,1];case 5:throw new Error("Could not initialize any backends, all backend initializations failed.")}}))}))},Object.defineProperty(r.prototype,"backend",{get:function(){if(this.pendingBackendInit!=null)throw new Error("Backend '"+this.backendName+"' has not yet been initialized. Make sure to await tf.ready() or await tf.setBackend() before calling other methods");if(this.backendInstance==null){var t=this.initializeBackendsAndReturnBest(),e=t.name;if(t.asyncInit)throw new Error("The highest priority backend '"+e+"' has not yet been initialized. Make sure to await tf.ready() or await tf.setBackend() before calling other methods");this.setBackend(e)}return this.backendInstance},enumerable:!0,configurable:!0}),r.prototype.backendNames=function(){return Object.keys(this.registryFactory)},r.prototype.findBackend=function(t){return!(t in this.registry)&&(!(t in this.registryFactory)||this.initializeBackend(t).asyncInit)?null:this.registry[t]},r.prototype.findBackendFactory=function(t){return t in this.registryFactory?this.registryFactory[t].factory:null},r.prototype.registerBackend=function(t,e,n){return n===void 0&&(n=1),t in this.registryFactory?(console.warn(t+" backend was already registered. Reusing existing backend factory."),!1):(this.registryFactory[t]={factory:e,priority:n},!0)},r.prototype.setBackend=function(t){return X(this,void 0,void 0,(function(){var e,n,o;return $(this,(function(a){switch(a.label){case 0:if(this.registryFactory[t]==null)throw new Error("Backend name '"+t+"' not found in registry");return this.backendName=t,this.registry[t]!=null?[3,4]:(this.backendInstance=null,e=this.initializeBackend(t),n=e.success,e.asyncInit?[4,n]:[3,2]);case 1:return o=a.sent(),[3,3];case 2:o=n,a.label=3;case 3:if(!o)return[2,!1];a.label=4;case 4:return this.backendInstance=this.registry[t],this.setupRegisteredKernels(),this.profiler=new fl(this.backendInstance),[2,!0]}}))}))},r.prototype.setupRegisteredKernels=function(){var t=this;ki(this.backendName).forEach((function(e){e.setupFunc!=null&&e.setupFunc(t.backendInstance)}))},r.prototype.disposeRegisteredKernels=function(t){var e=this;ki(t).forEach((function(n){n.disposeFunc!=null&&n.disposeFunc(e.registry[t])}))},r.prototype.initializeBackend=function(t){var e=this,n=this.registryFactory[t];if(n==null)throw new Error("Cannot initialize backend "+t+", no registration found.");try{var o=n.factory();if(Promise.resolve(o)===o){var a=++this.pendingBackendInitId,i=o.then((function(s){return!(a<e.pendingBackendInitId)&&(e.registry[t]=s,e.pendingBackendInit=null,!0)})).catch((function(s){return!(a<e.pendingBackendInitId)&&(e.pendingBackendInit=null,console.warn("Initialization of backend "+t+" failed"),console.warn(s.stack||s.message),!1)}));return this.pendingBackendInit=i,{success:i,asyncInit:!0}}return this.registry[t]=o,{success:!0,asyncInit:!1}}catch(s){return console.warn("Initialization of backend "+t+" failed"),console.warn(s.stack||s.message),{success:!1,asyncInit:!1}}},r.prototype.removeBackend=function(t){if(!(t in this.registryFactory))throw new Error(t+" backend not found in registry");this.backendName===t&&this.pendingBackendInit!=null&&this.pendingBackendInitId++,t in this.registry&&(this.disposeRegisteredKernels(t),this.registry[t].dispose(),delete this.registry[t]),delete this.registryFactory[t],this.backendName===t&&(this.pendingBackendInit=null,this.backendName=null,this.backendInstance=null)},r.prototype.getSortedBackends=function(){var t=this;if(Object.keys(this.registryFactory).length===0)throw new Error("No backend found in registry.");return Object.keys(this.registryFactory).sort((function(e,n){return t.registryFactory[n].priority-t.registryFactory[e].priority}))},r.prototype.initializeBackendsAndReturnBest=function(){for(var t=this.getSortedBackends(),e=0;e<t.length;e++){var n=t[e],o=this.initializeBackend(n),a=o.success,i=o.asyncInit;if(i||a)return{name:n,asyncInit:i}}throw new Error("Could not initialize any backends, all backend initializations failed.")},r.prototype.moveData=function(t,e){var n=this.state.tensorInfo.get(e),o=n.backend,a=this.readSync(e);o.disposeData(e),n.backend=t,t.move(e,a,n.shape,n.dtype),this.shouldCheckForMemLeaks()&&this.state.numDataMovesStack[this.state.numDataMovesStack.length-1]++},r.prototype.tidy=function(t,e){var n,o=this,a=null;if(e==null){if(typeof t!="function")throw new Error("Please provide a function to tidy()");e=t}else{if(typeof t!="string"&&!(t instanceof String))throw new Error("When calling with two arguments, the first argument to tidy() must be a string");if(typeof e!="function")throw new Error("When calling with two arguments, the 2nd argument to tidy() must be a function");a=t}return this.scopedRun((function(){return o.startScope(a)}),(function(){return o.endScope(n)}),(function(){return(n=e())instanceof Promise&&console.error("Cannot return a Promise inside of tidy."),n}))},r.prototype.scopedRun=function(t,e,n){t();try{var o=n();return e(),o}catch(a){throw e(),a}},r.prototype.nextTensorId=function(){return r.nextTensorId++},r.prototype.nextVariableId=function(){return r.nextVariableId++},r.prototype.clone=function(t){var e=this.makeTensorFromDataId(t.dataId,t.shape,t.dtype),n={x:t};return this.addTapeNode(this.state.activeScope.name,n,[e],(function(o){return{x:function(){return o.toFloat()}}}),[]),e},r.prototype.runKernel=function(t,e,n,o,a){return this.runKernelFunc(null,e,null,t,n,o,a)},r.prototype.shouldCheckForMemLeaks=function(){return this.ENV.getBool("IS_TEST")},r.prototype.checkKernelForMemLeak=function(t,e,n){var o=this.backend.numDataIds(),a=0;n.forEach((function(u){a+=u.dtype==="complex64"?3:1}));var i=this.state.numDataMovesStack[this.state.numDataMovesStack.length-1],s=o-e-a-i;if(s>0)throw new Error("Backend '"+this.backendName+"' has an internal memory leak ("+s+" data ids) after running '"+t+"'")},r.prototype.runKernelFunc=function(t,e,n,o,a,i,s){var u,c=this;i===void 0&&(i=[]),s===void 0&&(s=[]);var l=[],h=this.isTapeOn();o==null&&(o=this.state.activeScope!=null?this.state.activeScope.name:"");var f,p=function(x){h&&(l=x.map((function(b){return c.keep(c.clone(b))})))},d=this.state.numBytes,v=this.state.numTensors;this.shouldCheckForMemLeaks()&&this.state.numDataMovesStack.push(0);var m,g=Ts(o,this.backendName);return f=g!=null?function(){var x=c.backend.numDataIds();m=g.kernelFunc({inputs:e,attrs:a,backend:c.backend});var b=Array.isArray(m)?m:[m];c.shouldCheckForMemLeaks()&&c.checkKernelForMemLeak(o,x,b);var y=b.map((function(C){var S=C.dataId,k=C.shape,R=C.dtype;return c.makeTensorFromDataId(S,k,R)})),w=y.filter((function(C,S){return s[S]}));return p((i||[]).slice().concat(w)),y}:function(){var x=c.backend.numDataIds();m=c.tidy((function(){return t(c.backend,p)}));var b=Array.isArray(m)?m:[m];return c.shouldCheckForMemLeaks()&&c.checkKernelForMemLeak(o,x,b),b},this.scopedRun((function(){return c.state.kernelDepth++}),(function(){return c.state.kernelDepth--}),(function(){u=c.ENV.getBool("DEBUG")?c.profiler.profileKernel(o,e,(function(){return f()})):f()})),h&&this.addTapeNode(o,e,u,n,l),this.state.profiling&&this.state.activeProfile.kernels.push({name:o,bytesAdded:this.state.numBytes-d,totalBytesSnapshot:this.state.numBytes,tensorsAdded:this.state.numTensors-v,totalTensorsSnapshot:this.state.numTensors,inputShapes:Object.keys(e).map((function(x){return e[x].shape})),outputShapes:u.map((function(x){return x.shape}))}),Array.isArray(m)?u:u[0]},r.prototype.makeTensor=function(t,e,n,o){if(t==null)throw new Error("Values passed to engine.makeTensor() are null");n=n||"float32",o=o||this.backend;var a=t;n==="string"&&Ea(t[0])&&(a=t.map((function(l){return ll(l)})));var i=o.write(a,e,n),s=new Ie(e,n,i,this.nextTensorId());if(this.incRef(s,o),n==="string"){var u=this.state.tensorInfo.get(i),c=sl(a);this.state.numBytes+=c-u.bytes,u.bytes=c}return s},r.prototype.makeTensorFromDataId=function(t,e,n,o){var a=new Ie(e,n=n||"float32",t,this.nextTensorId());return this.incRef(a,o),a},r.prototype.makeVariable=function(t,e,n,o){e===void 0&&(e=!0),n=n||this.nextVariableId().toString(),o!=null&&o!==t.dtype&&(t=t.asType(o));var a=new jn(t,e,n,this.nextTensorId());if(this.state.registeredVariables[a.name]!=null)throw new Error("Variable with name "+a.name+" was already registered");return this.state.registeredVariables[a.name]=a,this.incRef(a,this.backend),a},r.prototype.incRef=function(t,e){var n=this.state.tensorInfo.has(t.dataId)?this.state.tensorInfo.get(t.dataId).refCount:0;if(this.state.numTensors++,t.dtype==="string"&&this.state.numStringTensors++,n===0){this.state.numDataBuffers++;var o=0;t.dtype!=="complex64"&&t.dtype!=="string"&&(o=t.size*Ms(t.dtype)),this.state.tensorInfo.set(t.dataId,{backend:e||this.backend,dtype:t.dtype,shape:t.shape,bytes:o,refCount:0}),this.state.numBytes+=o}this.state.tensorInfo.get(t.dataId).refCount++,t instanceof jn||this.track(t)},r.prototype.disposeTensor=function(t){if(this.state.tensorInfo.has(t.dataId)){this.state.numTensors--,t.dtype==="string"&&this.state.numStringTensors--;var e=this.state.tensorInfo.get(t.dataId);e.refCount<=1?(t.dtype!=="complex64"&&(this.state.numBytes-=e.bytes),this.state.numDataBuffers--,e.backend.disposeData(t.dataId),this.state.tensorInfo.delete(t.dataId)):this.state.tensorInfo.get(t.dataId).refCount--}},r.prototype.disposeVariables=function(){for(var t in this.state.registeredVariables){var e=this.state.registeredVariables[t];this.disposeVariable(e)}},r.prototype.disposeVariable=function(t){this.disposeTensor(t),this.state.registeredVariables[t.name]!=null&&delete this.state.registeredVariables[t.name]},r.prototype.memory=function(){var t=this.backend.memory();return t.numTensors=this.state.numTensors,t.numDataBuffers=this.state.numDataBuffers,t.numBytes=this.state.numBytes,this.state.numStringTensors>0&&(t.unreliable=!0,t.reasons==null&&(t.reasons=[]),t.reasons.push("Memory usage by string tensors is approximate (2 bytes per character)")),t},r.prototype.profile=function(t){return X(this,void 0,void 0,(function(){var e,n;return $(this,(function(o){return this.state.profiling=!0,e=this.state.numBytes,n=this.state.numTensors,this.state.activeProfile.kernels=[],this.state.activeProfile.result=t(),this.state.profiling=!1,this.state.activeProfile.peakBytes=Math.max.apply(Math,this.state.activeProfile.kernels.map((function(a){return a.totalBytesSnapshot}))),this.state.activeProfile.newBytes=this.state.numBytes-e,this.state.activeProfile.newTensors=this.state.numTensors-n,[2,this.state.activeProfile]}))}))},r.prototype.isTapeOn=function(){return this.state.gradientDepth>0&&this.state.kernelDepth===0},r.prototype.addTapeNode=function(t,e,n,o,a){var i=this,s={id:this.state.nextTapeNodeId++,kernelName:t,inputs:e,outputs:n,saved:a},u=Zc(t);u!=null&&(o=u.gradFunc),o!=null&&(s.gradient=function(c){return c=c.map((function(l,h){if(l==null){var f=n[h],p=hr(f.size,f.dtype);return i.makeTensor(p,f.shape,f.dtype)}return l})),o(c.length>1?c:c[0],a)}),this.state.activeTape.push(s)},r.prototype.keep=function(t){return t.kept=!0,t},r.prototype.startTape=function(){this.state.gradientDepth===0&&(this.state.activeTape=[]),this.state.gradientDepth++},r.prototype.endTape=function(){this.state.gradientDepth--},r.prototype.startScope=function(t){var e={track:[],name:"unnamed scope",id:this.state.nextScopeId++};t&&(e.name=t),this.state.scopeStack.push(e),this.state.activeScope=e},r.prototype.endScope=function(t){for(var e=this,n=Vs(t),o=new Set(n.map((function(u){return u.id}))),a=0;a<this.state.activeScope.track.length;a++){var i=this.state.activeScope.track[a];i.kept||o.has(i.id)||i.dispose()}var s=this.state.scopeStack.pop();this.state.activeScope=this.state.scopeStack.length===0?null:this.state.scopeStack[this.state.scopeStack.length-1],n.forEach((function(u){u.kept||u.scopeId!==s.id||e.track(u)}))},r.prototype.gradients=function(t,e,n,o){var a=this;if(o===void 0&&(o=!1),I(e.length>0,(function(){return"gradients() received an empty list of xs."})),n!=null&&n.dtype!=="float32")throw new Error("dy must have 'float32' dtype, but has '"+n.dtype+"'");var i=this.scopedRun((function(){return a.startTape()}),(function(){return a.endTape()}),(function(){return a.tidy("forward",t)}));I(i instanceof Ie,(function(){return"The result y returned by f() must be a tensor."}));var s=(function(u,c,l){for(var h={},f={},p=0;p<c.length;p++)h[c[p].id]=!0;for(p=0;p<u.length;p++){var d=(C=u[p]).inputs;for(var v in d){for(var m=d[v],g=!1,x=0;x<c.length;x++)if(h[m.id]){C.outputs.forEach((function(E){return h[E.id]=!0})),g=!0,f[C.id]=!0;break}if(g)break}}var b={};b[l.id]=!0;var y={};for(p=u.length-1;p>=0;p--)for(d=(C=u[p]).inputs,x=0;x<C.outputs.length;x++)if(b[C.outputs[x].id]){for(var v in d)b[d[v].id]=!0,y[C.id]=!0;break}var w=[];for(p=0;p<u.length;p++){var C;if(f[(C=u[p]).id]&&y[C.id]){var S={};for(var v in C.inputs){var k=C.inputs[v];h[k.id]&&(S[v]=k)}var R=Object.assign({},C);R.inputs=S,R.outputs=C.outputs,w.push(R)}}return w})(this.state.activeTape,e,i);if(!o&&s.length===0&&e.length>0)throw new Error("Cannot compute gradient of y=f(x) with respect to x. Make sure that the f you passed encloses all operations that lead from x to y.");return this.tidy("backward",(function(){var u,c,l={};l[i.id]=n??(u=i.shape,c=Bs(Y(u),"float32"),N.makeTensor(c,u,"float32")),(function(f,p,d){for(var v=function(g){var x=p[g],b=[];if(x.outputs.forEach((function(S){var k=f[S.id];k!=null?b.push(k):b.push(null)})),x.gradient==null)throw new Error("Cannot compute gradient: gradient function not found for "+x.kernelName+".");var y=x.gradient(b),w=function(S){if(!(S in y))throw new Error("Cannot backprop through input "+S+". Available gradients found: "+Object.keys(y)+".");var k=d((function(){return y[S]()}));if(k.dtype!=="float32")throw new Error("Error in gradient for op "+x.kernelName+". The gradient of input "+S+" must have 'float32' dtype, but has '"+k.dtype+"'");var R=x.inputs[S];if(!Ue(k.shape,R.shape))throw new Error("Error in gradient for op "+x.kernelName+". The gradient of input '"+S+"' has shape '"+k.shape+"', which does not match the shape of the input '"+R.shape+"'");if(f[R.id]==null)f[R.id]=k;else{var E=f[R.id];f[R.id]=E.add(k),E.dispose()}};for(var C in x.inputs)w(C)},m=p.length-1;m>=0;m--)v(m)})(l,s,(function(f){return a.tidy(f)}));var h=e.map((function(f){return l[f.id]}));return a.state.gradientDepth===0&&(a.state.activeTape.forEach((function(f){for(var p=0,d=f.saved;p<d.length;p++)d[p].dispose()})),a.state.activeTape=null),{value:i,grads:h}}))},r.prototype.customGrad=function(t){var e=this;return I(ra(t),(function(){return"The f passed in customGrad(f) must be a function."})),function(){for(var n,o=[],a=0;a<arguments.length;a++)o[a]=arguments[a];I(o.every((function(s){return s instanceof Ie})),(function(){return"The args passed in customGrad(f)(x1, x2,...) must all be tensors"}));var i={};return o.forEach((function(s,u){i[u]=s})),e.runKernelFunc((function(s,u){return I((n=t.apply(void 0,o.concat([u]))).value instanceof Ie,(function(){return"The function f passed in customGrad(f) must return an object where `obj.value` is a tensor"})),I(ra(n.gradFunc),(function(){return"The function f passed in customGrad(f) must return an object where `obj.gradFunc` is a function."})),n.value}),i,(function(s,u){var c=n.gradFunc(s,u),l=Array.isArray(c)?c:[c];I(l.length===o.length,(function(){return"The function f passed in customGrad(f) must return an object where `obj.gradFunc` is a function that returns the same number of tensors as inputs passed to f(...)."})),I(l.every((function(f){return f instanceof Ie})),(function(){return"The function f passed in customGrad(f) must return an object where `obj.gradFunc` is a function that returns a list of only tensors."}));var h={};return l.forEach((function(f,p){h[p]=function(){return f}})),h}))}},r.prototype.readSync=function(t){return this.state.tensorInfo.get(t).backend.readSync(t)},r.prototype.read=function(t){return this.state.tensorInfo.get(t).backend.read(t)},r.prototype.time=function(t){return X(this,void 0,void 0,(function(){var e,n;return $(this,(function(o){switch(o.label){case 0:return e=Rt(),[4,this.backend.time(t)];case 1:return(n=o.sent()).wallMs=Rt()-e,[2,n]}}))}))},r.prototype.track=function(t){return this.state.activeScope!=null&&(t.scopeId=this.state.activeScope.id,this.state.activeScope.track.push(t)),t},Object.defineProperty(r.prototype,"registeredVariables",{get:function(){return this.state.registeredVariables},enumerable:!0,configurable:!0}),r.prototype.reset=function(){for(var t in this.pendingBackendInitId++,this.state.dispose(),this.ENV.reset(),this.state=new Fi,this.registry)this.disposeRegisteredKernels(t),this.registry[t].dispose(),delete this.registry[t];this.backendName=null,this.backendInstance=null,this.pendingBackendInit=null},r.nextTensorId=0,r.nextVariableId=0,r})(),N=(function(){var r=(function(){if(Do==null){var e=void 0;if(typeof window<"u")e=window;else if(typeof global<"u")e=global;else if(typeof process<"u")e=process;else{if(typeof self>"u")throw new Error("Could not find a global object");e=self}Do=e}return Do})();if(r._tfengine==null){var t=new Jc(r);r._tfengine=new gl(t)}return(function(e){As=e})(r._tfengine.ENV),kt=function(){return r._tfengine},r._tfengine})();function zs(){return typeof window<"u"&&window.document!=null||typeof WorkerGlobalScope<"u"}var zt=L();zt.registerFlag("DEBUG",(function(){return!1}),(function(r){r&&console.warn("Debugging mode is ON. The output of every math call will be downloaded to CPU and checked for NaNs. This significantly impacts performance.")})),zt.registerFlag("IS_BROWSER",(function(){return zs()})),zt.registerFlag("IS_NODE",(function(){return typeof process<"u"&&process.versions!==void 0&&process.versions.node!==void 0})),zt.registerFlag("IS_CHROME",(function(){return typeof navigator<"u"&&navigator!=null&&navigator.userAgent!=null&&/Chrome/.test(navigator.userAgent)&&/Google Inc/.test(navigator.vendor)})),zt.registerFlag("PROD",(function(){return!1})),zt.registerFlag("TENSORLIKE_CHECK_SHAPE_CONSISTENCY",(function(){return zt.getBool("DEBUG")})),zt.registerFlag("DEPRECATION_WARNINGS_ENABLED",(function(){return!0})),zt.registerFlag("IS_TEST",(function(){return!1}));var ar,st,it,fn={},Ao={alpha:!1,antialias:!1,premultipliedAlpha:!1,preserveDrawingBuffer:!1,depth:!1,stencil:!1,failIfMajorPerformanceCaveat:!0};function yl(r,t){fn[r]=t}function Pt(r){r in fn||(fn[r]=(function(e){if(e!==1&&e!==2)throw new Error("Cannot get WebGL rendering context, WebGL is disabled.");var n=(function(o){if(typeof OffscreenCanvas<"u"&&o===2)return new OffscreenCanvas(300,150);if(typeof document<"u")return document.createElement("canvas");throw new Error("Cannot create a canvas in this context")})(e);return n.addEventListener("webglcontextlost",(function(o){o.preventDefault(),delete fn[e]}),!1),e===1?n.getContext("webgl",Ao)||n.getContext("experimental-webgl",Ao):n.getContext("webgl2",Ao)})(r));var t=fn[r];return t.isContextLost()?(delete fn[r],Pt(r)):(t.disable(t.DEPTH_TEST),t.disable(t.STENCIL_TEST),t.disable(t.BLEND),t.disable(t.DITHER),t.disable(t.POLYGON_OFFSET_FILL),t.disable(t.SAMPLE_COVERAGE),t.enable(t.SCISSOR_TEST),t.enable(t.CULL_FACE),t.cullFace(t.BACK),fn[r])}function oo(r,t){return[t,r]}function er(r){var t=Y(r);return na(Math.ceil(t/4))}function fr(r,t){return[Math.max(1,Math.ceil(t/2)),Math.max(1,Math.ceil(r/2))]}function Ia(r,t){var e,n,o,a,i,s,u,c,l,h=r;return L().getNumber("WEBGL_VERSION")===2?(e=h.R32F,n=h.R16F,o=h.RGBA16F,a=h.RGBA32F,i=h.RED,s=4,u=1,c=h.HALF_FLOAT,l=h.FLOAT):(e=r.RGBA,n=r.RGBA,o=r.RGBA,a=h.RGBA,i=r.RGBA,s=4,u=4,c=t!=null?t.HALF_FLOAT_OES:null,l=r.FLOAT),{internalFormatFloat:e,internalFormatHalfFloat:n,internalFormatPackedHalfFloat:o,internalFormatPackedFloat:a,textureFormatFloat:i,downloadTextureFormat:r.RGBA,downloadUnpackNumChannels:s,defaultNumChannels:u,textureTypeHalfFloat:c,textureTypeFloat:l}}function J(r,t,e){var n=e();return t&&(function(o){var a=o.getError();if(a!==o.NO_ERROR)throw new Error("WebGL Error: "+Cl(o,a))})(r),n}(function(r){r[r.DENSE=0]="DENSE",r[r.SHARED_BATCH=1]="SHARED_BATCH"})(ar||(ar={})),(function(r){r[r.RENDER=0]="RENDER",r[r.UPLOAD=1]="UPLOAD",r[r.PIXELS=2]="PIXELS",r[r.DOWNLOAD=3]="DOWNLOAD"})(st||(st={})),(function(r){r[r.UNPACKED_FLOAT16=0]="UNPACKED_FLOAT16",r[r.UNPACKED_FLOAT32=1]="UNPACKED_FLOAT32",r[r.PACKED_4X1_UNSIGNED_BYTE=2]="PACKED_4X1_UNSIGNED_BYTE",r[r.PACKED_2X2_FLOAT32=3]="PACKED_2X2_FLOAT32",r[r.PACKED_2X2_FLOAT16=4]="PACKED_2X2_FLOAT16"})(it||(it={}));var xl=596e-10,bl=65504;function wl(r){return!!(L().getBool("WEBGL_RENDER_FLOAT32_ENABLED")||r===0||xl<Math.abs(r)&&Math.abs(r)<bl)}function Cl(r,t){switch(t){case r.NO_ERROR:return"NO_ERROR";case r.INVALID_ENUM:return"INVALID_ENUM";case r.INVALID_VALUE:return"INVALID_VALUE";case r.INVALID_OPERATION:return"INVALID_OPERATION";case r.INVALID_FRAMEBUFFER_OPERATION:return"INVALID_FRAMEBUFFER_OPERATION";case r.OUT_OF_MEMORY:return"OUT_OF_MEMORY";case r.CONTEXT_LOST_WEBGL:return"CONTEXT_LOST_WEBGL";default:return"Unknown error code "+t}}function br(r,t,e){return jt(r,t,(function(){return r.getExtension(e)}),'Extension "'+e+'" not supported on this browser.')}function _l(r,t,e){var n=jt(r,t,(function(){return r.createShader(r.VERTEX_SHADER)}),"Unable to create vertex WebGLShader.");if(J(r,t,(function(){return r.shaderSource(n,e)})),J(r,t,(function(){return r.compileShader(n)})),r.getShaderParameter(n,r.COMPILE_STATUS)===!1)throw console.log(r.getShaderInfoLog(n)),new Error("Failed to compile vertex shader.");return n}function El(r,t,e){var n=jt(r,t,(function(){return r.createShader(r.FRAGMENT_SHADER)}),"Unable to create fragment WebGLShader.");if(J(r,t,(function(){return r.shaderSource(n,e)})),J(r,t,(function(){return r.compileShader(n)})),r.getShaderParameter(n,r.COMPILE_STATUS)===!1)throw(function(o,a){var i=Il.exec(a);if(i==null)return console.log("Couldn't parse line number in error: "+a),void console.log(o);for(var s=+i[1],u=o.split(`
`),c=u.length.toString().length+2,l=u.map((function(m,g){return On((g+1).toString(),c)+m})),h=0,f=0;f<l.length;f++)h=Math.max(l[f].length,h);var p=l.slice(0,s-1),d=l.slice(s-1,s),v=l.slice(s);console.log(p.join(`
`)),console.log(a.split(`
`)[0]),console.log("%c "+On(d[0],h),"border:1px solid red; background-color:#e3d2d2; color:#a61717"),console.log(v.join(`
`))})(e,r.getShaderInfoLog(n)),new Error("Failed to compile fragment shader.");return n}var To,No,Il=/ERROR: [0-9]+:([0-9]+):/g;function Rl(r,t){return jt(r,t,(function(){return r.createProgram()}),"Unable to create WebGLProgram.")}function kl(r,t,e){if(J(r,t,(function(){return r.linkProgram(e)})),r.getProgramParameter(e,r.LINK_STATUS)===!1)throw console.log(r.getProgramInfoLog(e)),new Error("Failed to link vertex and fragment shaders.")}function Fo(r,t,e){if(J(r,t,(function(){return r.validateProgram(e)})),r.getProgramParameter(e,r.VALIDATE_STATUS)===!1)throw console.log(r.getProgramInfoLog(e)),new Error("Shader program validation failed.")}function Sl(r,t,e){var n=jt(r,t,(function(){return r.createBuffer()}),"Unable to create WebGLBuffer");return J(r,t,(function(){return r.bindBuffer(r.ARRAY_BUFFER,n)})),J(r,t,(function(){return r.bufferData(r.ARRAY_BUFFER,e,r.STATIC_DRAW)})),n}function Dl(r,t,e){var n=jt(r,t,(function(){return r.createBuffer()}),"Unable to create WebGLBuffer");return J(r,t,(function(){return r.bindBuffer(r.ELEMENT_ARRAY_BUFFER,n)})),J(r,t,(function(){return r.bufferData(r.ELEMENT_ARRAY_BUFFER,e,r.STATIC_DRAW)})),n}function Al(r,t){return jt(r,t,(function(){return r.createTexture()}),"Unable to create WebGLTexture.")}function Tl(r,t){var e=L().getNumber("WEBGL_MAX_TEXTURE_SIZE");if(r<=0||t<=0){var n="["+r+"x"+t+"]";throw new Error("Requested texture size "+n+" is invalid.")}if(r>e||t>e)throw n="["+r+"x"+t+"]",new Error("Requested texture size "+n+" greater than WebGL maximum on this browser / GPU "+("["+e+"x"+e+"]")+".")}function Nl(r,t){return jt(r,t,(function(){return r.createFramebuffer()}),"Unable to create WebGLFramebuffer.")}function Pi(r,t,e,n,o,a,i,s){var u=r.getAttribLocation(e,n);return u!==-1&&(J(r,t,(function(){return r.bindBuffer(r.ARRAY_BUFFER,o)})),J(r,t,(function(){return r.vertexAttribPointer(u,a,r.FLOAT,!1,i,s)})),J(r,t,(function(){return r.enableVertexAttribArray(u)})),!0)}function Fl(r,t,e,n){Ll(r,n),J(r,t,(function(){return r.activeTexture(r.TEXTURE0+n)})),J(r,t,(function(){return r.bindTexture(r.TEXTURE_2D,e)}))}function Pl(r,t,e,n){return jt(r,t,(function(){return r.getUniformLocation(e,n)}),'uniform "'+n+'" not present in program.')}function Ml(r,t,e){return r.getUniformLocation(t,e)}function Ol(r,t,e,n,o,a){J(r,t,(function(){return Fl(r,t,n,a)})),J(r,t,(function(){return r.uniform1i(o,a)}))}function Po(r,t,e,n){J(r,t,(function(){return r.bindFramebuffer(r.FRAMEBUFFER,n)})),J(r,t,(function(){return r.framebufferTexture2D(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0,r.TEXTURE_2D,e,0)}))}function Mi(r,t,e){J(r,t,(function(){return r.bindFramebuffer(r.FRAMEBUFFER,e)})),J(r,t,(function(){return r.framebufferTexture2D(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0,r.TEXTURE_2D,null,0)}))}function wr(r){var t=r.checkFramebufferStatus(r.FRAMEBUFFER);if(t!==r.FRAMEBUFFER_COMPLETE)throw new Error("Error binding framebuffer: "+Bl(r,t))}function Bl(r,t){switch(t){case r.FRAMEBUFFER_INCOMPLETE_ATTACHMENT:return"FRAMEBUFFER_INCOMPLETE_ATTACHMENT";case r.FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT:return"FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT";case r.FRAMEBUFFER_INCOMPLETE_DIMENSIONS:return"FRAMEBUFFER_INCOMPLETE_DIMENSIONS";case r.FRAMEBUFFER_UNSUPPORTED:return"FRAMEBUFFER_UNSUPPORTED";default:return"unknown error "+t}}function jt(r,t,e,n){var o=J(r,t,(function(){return e()}));if(o==null)throw new Error(n);return o}function Ll(r,t){var e=r.MAX_COMBINED_TEXTURE_IMAGE_UNITS-1,n=t+r.TEXTURE0;if(n<r.TEXTURE0||n>e)throw new Error("textureUnit must be in "+("[gl.TEXTURE0, gl.TEXTURE"+e+"]")+".")}function Lr(r,t){return t===void 0&&(t=2),Y(r.slice(0,r.length-t))}function Wr(r){if(r.length===0)throw Error("Cannot get rows and columns of an empty shape array.");return[r.length>1?r[r.length-2]:1,r[r.length-1]]}function Mo(r){var t=[1,1,1];return r.length===0||r.length===1&&r[0]===1||(t=[Lr(r)].concat(Wr(r))),t}function Wl(r,t){var e;t===void 0&&(t=!1);var n=L().getNumber("WEBGL_MAX_TEXTURE_SIZE");if(t&&(n*=2,(r=r.map((function(c,l){return l>=r.length-2?Ps(r[l]):r[l]}))).length===1&&(r=[2,r[0]])),r.length!==2){var o=dn(r);r=o.newShape}var a=Y(r);if(r.length<=1&&a<=n)return[1,a];if(r.length===2&&r[0]<=n&&r[1]<=n)return r;if(r.length===3&&r[0]*r[1]<=n&&r[2]<=n)return[r[0]*r[1],r[2]];if(r.length===3&&r[0]<=n&&r[1]*r[2]<=n)return[r[0],r[1]*r[2]];if(r.length===4&&r[0]*r[1]*r[2]<=n&&r[3]<=n)return[r[0]*r[1]*r[2],r[3]];if(r.length===4&&r[0]<=n&&r[1]*r[2]*r[3]<=n)return[r[0],r[1]*r[2]*r[3]];if(t){var i=Lr(r),s=2,u=2;return r.length&&(s=(e=Wr(r))[0],u=e[1]),na(a=i*(s/2)*(u/2)).map((function(c){return 2*c}))}return na(a)}function Cr(r){return r%2==0}function _r(r,t){if(Ue(r=r.slice(-2),t=t.slice(-2))||!r.length||!t.length||r[0]===0||r[1]===0||t[0]===0||t[1]===0)return!0;if(r.length!==t.length){var e=r.slice(-1)[0],n=t.slice(-1)[0];if(e===n||Cr(e)&&Cr(n)&&(r[0]===1||t[0]===1))return!0}return r[1]===t[1]&&Cr(r[0])&&Cr(t[0])}function Ul(r){if(To==null){var t=Pt(r);To=t.getParameter(t.MAX_TEXTURE_SIZE)}return To}function Vl(r){if(No==null){var t=Pt(r);No=t.getParameter(t.MAX_TEXTURE_IMAGE_UNITS)}return Math.min(16,No)}function zl(r){if(r===0)return 0;var t=Pt(r);return pt(t,"EXT_disjoint_timer_query_webgl2")&&r===2?2:pt(t,"EXT_disjoint_timer_query")?1:0}function pt(r,t){return r.getExtension(t)!=null}function Oi(r){try{if(Pt(r)!=null)return!0}catch{return!1}return!1}function Gl(r){if(r===0)return!1;var t=Pt(r);if(r===1){if(!pt(t,"OES_texture_float"))return!1}else if(!pt(t,"EXT_color_buffer_float"))return!1;return ca(t)}function Hl(r){if(r===0)return!1;var t=Pt(r);if(r!==1){if(pt(t,"EXT_color_buffer_float"))return ca(t);if(pt(t,"EXT_color_buffer_half_float")){var e=t.getExtension("EXT_color_buffer_half_float");return(function(n,o){var a=Ia(n,o),i=n.createTexture();n.bindTexture(n.TEXTURE_2D,i),n.texImage2D(n.TEXTURE_2D,0,a.internalFormatHalfFloat,1,1,0,a.textureFormatFloat,a.textureTypeHalfFloat,null);var s=n.createFramebuffer();n.bindFramebuffer(n.FRAMEBUFFER,s),n.framebufferTexture2D(n.FRAMEBUFFER,n.COLOR_ATTACHMENT0,n.TEXTURE_2D,i,0);var u=n.checkFramebufferStatus(n.FRAMEBUFFER)===n.FRAMEBUFFER_COMPLETE;return n.bindTexture(n.TEXTURE_2D,null),n.bindFramebuffer(n.FRAMEBUFFER,null),n.deleteTexture(i),n.deleteFramebuffer(s),u})(t,e)}return!1}return!!pt(t,"OES_texture_float")&&!!pt(t,"WEBGL_color_buffer_float")&&ca(t)}function ca(r){var t=Ia(r),e=r.createTexture();r.bindTexture(r.TEXTURE_2D,e),r.texImage2D(r.TEXTURE_2D,0,t.internalFormatFloat,1,1,0,t.textureFormatFloat,t.textureTypeFloat,null);var n=r.createFramebuffer();r.bindFramebuffer(r.FRAMEBUFFER,n),r.framebufferTexture2D(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0,r.TEXTURE_2D,e,0);var o=r.checkFramebufferStatus(r.FRAMEBUFFER)===r.FRAMEBUFFER_COMPLETE;return r.bindTexture(r.TEXTURE_2D,null),r.bindFramebuffer(r.FRAMEBUFFER,null),r.deleteTexture(e),r.deleteFramebuffer(n),o}function jl(r){return r===2&&Pt(r).fenceSync!=null}var ne=L();function Gs(r){L().getBool("DEPRECATION_WARNINGS_ENABLED")&&console.warn(r+" You can disable deprecation warnings with tf.disableDeprecationWarnings().")}function K(r,t){return N.tidy(r,t)}function tt(r){Vs(r).forEach((function(t){return t.dispose()}))}function ql(r){return N.keep(r)}function Ur(){for(var r=[],t=0;t<arguments.length;t++)r[t]=arguments[t];L().getBool("IS_TEST")||console.warn.apply(console,r)}function un(r,t){var e=r;if(At(r))return t==="string"?[]:[r.length];if(!Array.isArray(r))return[];for(var n=[];Array.isArray(e)||At(e)&&t!=="string";)n.push(e.length),e=e[0];return Array.isArray(r)&&L().getBool("TENSORLIKE_CHECK_SHAPE_CONSISTENCY")&&(function o(a,i,s){if(s=s||[],!Array.isArray(a)&&!At(a))return void I(i.length===0,(function(){return"Element arr["+s.join("][")+"] is a primitive, but should be an array/TypedArray of "+i[0]+" elements"}));I(i.length>0,(function(){return"Element arr["+s.join("][")+"] should be a primitive, but is an array of "+a.length+" elements"})),I(a.length===i[0],(function(){return"Element arr["+s.join("][")+"] should have "+i[0]+" elements, but has "+a.length+" elements"}));for(var u=i.slice(1),c=0;c<a.length;++c)o(a[c],u,s.concat(c))})(r,n,[]),n}function Bi(r,t,e,n){if(r!=null&&(r!=="numeric"&&r!==t||r==="numeric"&&t==="string"))throw new Error("Argument '"+e+"' passed to '"+n+"' must be "+r+" tensor, but got "+t+" tensor")}function _(r,t,e,n){if(n===void 0&&(n="numeric"),r instanceof Ie)return Bi(n,r.dtype,t,e),r;var o=lr(r);if(o!=="string"&&["bool","int32","float32"].indexOf(n)>=0&&(o=n),Bi(n,o,t,e),r==null||!At(r)&&!Array.isArray(r)&&typeof r!="number"&&typeof r!="boolean"&&typeof r!="string"){var a=r==null?"null":r.constructor.name;throw new Error("Argument '"+t+"' passed to '"+e+"' must be a Tensor or TensorLike, but got '"+a+"'")}var i=un(r,o);At(r)||Array.isArray(r)||(r=[r]);var s=o!=="string"?Os(r,o,L().getBool("DEBUG")):Hn(r,[],!0);return N.makeTensor(s,i,o)}function Vr(r,t,e,n){if(n===void 0&&(n="numeric"),!Array.isArray(r))throw new Error("Argument "+t+" passed to "+e+" must be a `Tensor[]` or `TensorLike[]`");return r.map((function(o,a){return _(o,t+"["+a+"]",e)}),n)}function Hs(r,t){for(var e=0;e<r.length;++e)if(r[r.length-e-1]!==t-1-e)return!1;return!0}function Kl(r,t,e){for(var n=r.length+t.length,o=[],a=0,i=0,s=0;s<n;s++)e.indexOf(s)===-1?o.push(r[a++]):o.push(t[i++]);return o}function qe(r,t){for(var e=[],n=r.length,o=0;o<n;o++)t.indexOf(o)===-1&&e.push(r[o]);return[e,t.map((function(a){return r[a]}))]}function nt(r,t){return Kl(r,t.map((function(e){return 1})),t)}function at(r,t,e){I(Hs(t,e),(function(){return r+" supports only inner-most axes for now. Got axes "+t+" and rank-"+e+" input."}))}function Mt(r,t){if(Hs(r,t))return null;for(var e=[],n=0;n<t;++n)r.indexOf(n)===-1&&e.push(n);return r.forEach((function(o){return e.push(o)})),e}function Ra(r){return r.map((function(t,e){return[e,t]})).sort((function(t,e){return t[1]-e[1]})).map((function(t){return t[0]}))}function Ot(r,t){for(var e=[],n=t-r;n<t;++n)e.push(n);return e}function Xl(r,t){var e=r[0].length;r.forEach((function(o,a){I(o.length===e,(function(){return"Error in concat"+e+"D: rank of tensors["+a+"] must be the same as the rank of the rest ("+e+")"}))})),I(t>=0&&t<e,(function(){return"Error in concat"+e+"D: axis must be between 0 and "+(e-1)+"."}));var n=r[0];r.forEach((function(o,a){for(var i=0;i<e;i++)I(i===t||o[i]===n[i],(function(){return"Error in concat"+e+"D: Shape of tensors["+a+"] ("+o+") does not match the shape of the rest ("+n+") along the non-concatenated axis "+a+"."}))}))}function qn(r,t){for(var e=r[0].slice(),n=1;n<r.length;n++)e[t]+=r[n][t];return e}function D(r){var t=Object.keys(r);if(t.length!==1)throw new Error("Please provide an object with a single key (operation name) mapping to a function. Got an object with "+t.length+" keys.");var e=t[0],n=r[e];e.endsWith("_")&&(e=e.substring(0,e.length-1));var o=function(){for(var a=[],i=0;i<arguments.length;i++)a[i]=arguments[i];N.startScope(e);try{var s=n.apply(void 0,a);return s instanceof Promise&&console.error("Cannot return a Promise inside of tidy."),N.endScope(s),s}catch(u){throw N.endScope(null),u}};return Object.defineProperty(o,"name",{value:e,configurable:!0}),o}ne.registerFlag("HAS_WEBGL",(function(){return ne.getNumber("WEBGL_VERSION")>0})),ne.registerFlag("WEBGL_VERSION",(function(){return Oi(2)?2:Oi(1)?1:0})),ne.registerFlag("WEBGL_BUFFER_SUPPORTED",(function(){return ne.get("WEBGL_VERSION")===2})),ne.registerFlag("WEBGL_CPU_FORWARD",(function(){return!0})),ne.registerFlag("WEBGL_FORCE_F16_TEXTURES",(function(){return!1})),ne.registerFlag("WEBGL_PACK",(function(){return ne.getBool("HAS_WEBGL")})),ne.registerFlag("WEBGL_PACK_NORMALIZATION",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_PACK_CLIP",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_PACK_DEPTHWISECONV",(function(){return!1})),ne.registerFlag("WEBGL_PACK_BINARY_OPERATIONS",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_PACK_UNARY_OPERATIONS",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_PACK_ARRAY_OPERATIONS",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_PACK_IMAGE_OPERATIONS",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_PACK_REDUCE",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_LAZILY_UNPACK",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_CONV_IM2COL",(function(){return ne.getBool("WEBGL_PACK")})),ne.registerFlag("WEBGL_MAX_TEXTURE_SIZE",(function(){return Ul(ne.getNumber("WEBGL_VERSION"))})),ne.registerFlag("WEBGL_MAX_TEXTURES_IN_SHADER",(function(){return Vl(ne.getNumber("WEBGL_VERSION"))})),ne.registerFlag("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION",(function(){var r=ne.getNumber("WEBGL_VERSION");return r===0?0:zl(r)})),ne.registerFlag("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_RELIABLE",(function(){return ne.getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION")>0&&(r=navigator.userAgent||navigator.vendor||window.opera,!(/(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge |maemo|midp|mmp|mobile.+firefox|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows ce|xda|xiino/i.test(r)||/1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i.test(r.substr(0,4))));var r})),ne.registerFlag("WEBGL_RENDER_FLOAT32_CAPABLE",(function(){return Gl(ne.getNumber("WEBGL_VERSION"))})),ne.registerFlag("WEBGL_RENDER_FLOAT32_ENABLED",(function(){return!ne.getBool("WEBGL_FORCE_F16_TEXTURES")&&ne.getBool("WEBGL_RENDER_FLOAT32_CAPABLE")})),ne.registerFlag("WEBGL_DOWNLOAD_FLOAT_ENABLED",(function(){return Hl(ne.getNumber("WEBGL_VERSION"))})),ne.registerFlag("WEBGL_FENCE_API_ENABLED",(function(){return jl(ne.getNumber("WEBGL_VERSION"))})),ne.registerFlag("WEBGL_SIZE_UPLOAD_UNIFORM",(function(){return ne.getBool("WEBGL_RENDER_FLOAT32_ENABLED")?4:0})),Us=Gs;var Ge=D({complex_:function(r,t){var e=_(r,"real","complex"),n=_(t,"imag","complex");return xe(e.shape,n.shape,"real and imag shapes, "+e.shape+" and "+n.shape+", must match in call to tf.complex()."),N.runKernelFunc((function(o){return o.complex(e,n)}),{$real:e,$imag:n})}}),ft=D({real_:function(r){var t=_(r,"input","real");return N.runKernelFunc((function(e){return e.real(t)}),{$input:t})}}),St=D({imag_:function(r){var t=_(r,"input","imag");return N.runKernelFunc((function(e){return e.imag(t)}),{$input:t})}});function je(r,t,e){return cn(r,t,un(r,e),e)}function cn(r,t,e,n){if(n==null&&(n=lr(r)),n==="complex64")throw new Error("Cannot construct a complex64 tensor directly. Please use tf.complex(real, imag).");if(!At(r)&&!Array.isArray(r)&&typeof r!="number"&&typeof r!="boolean"&&typeof r!="string")throw new Error("values passed to tensor(values) must be a number/boolean/string or an array of numbers/booleans/strings, or a TypedArray");if(t!=null){Ls(t);var o=Y(t),a=Y(e);I(o===a,(function(){return"Based on the provided shape, ["+t+"], the tensor should have "+o+" values but has "+a}));for(var i=0;i<e.length;++i){var s=e[i],u=i!==e.length-1||s!==Y(t.slice(i));I(e[i]===t[i]||!u,(function(){return"Error creating a new Tensor. Inferred shape ("+e+") does not match the provided shape ("+t+"). "}))}}return At(r)||Array.isArray(r)||(r=[r]),t=t||e,r=n!=="string"?Os(r,n,L().getBool("DEBUG")):Hn(r,[],!0),N.makeTensor(r,t,n)}function j(r,t){if((At(r)&&t!=="string"||Array.isArray(r))&&t!=="complex64")throw new Error("Error creating a new Scalar: value must be a primitive (number|boolean|string)");if(t==="string"&&At(r)&&!(r instanceof Uint8Array))throw new Error("When making a scalar from encoded string, the value must be `Uint8Array`.");return cn(r,[],[],t)}function Ne(r,t){Xn(r);var e=un(r,t);if(e.length!==1)throw new Error("tensor1d() requires values to be a flat/TypedArray");return cn(r,null,e,t)}function nn(r,t,e){if(Xn(r),t!=null&&t.length!==2)throw new Error("tensor2d() requires shape to have two numbers");var n=un(r,e);if(n.length!==2&&n.length!==1)throw new Error("tensor2d() requires values to be number[][] or flat/TypedArray");if(n.length===1&&t==null)throw new Error("tensor2d() requires shape to be provided when `values` are a flat/TypedArray");return cn(r,t,n,e)}function ka(r,t,e){if(Xn(r),t!=null&&t.length!==3)throw new Error("tensor3d() requires shape to have three numbers");var n=un(r,e);if(n.length!==3&&n.length!==1)throw new Error("tensor3d() requires values to be number[][][] or flat/TypedArray");if(n.length===1&&t==null)throw new Error("tensor3d() requires shape to be provided when `values` are a flat array");return cn(r,t,n,e)}function Ze(r,t,e){if(Xn(r),t!=null&&t.length!==4)throw new Error("tensor4d() requires shape to have four numbers");var n=un(r,e);if(n.length!==4&&n.length!==1)throw new Error("tensor4d() requires values to be number[][][][] or flat/TypedArray");if(n.length===1&&t==null)throw new Error("tensor4d() requires shape to be provided when `values` are a flat array");return cn(r,t,n,e)}function $l(r,t,e){if(Xn(r),t!=null&&t.length!==5)throw new Error("tensor5d() requires shape to have five numbers");var n=un(r,e);if(n.length!==5&&n.length!==1)throw new Error("tensor5d() requires values to be number[][][][][] or flat/TypedArray");if(n.length===1&&t==null)throw new Error("tensor5d() requires shape to be provided when `values` are a flat array");return cn(r,t,n,e)}function Yl(r,t,e){if(Xn(r),t!=null&&t.length!==6)throw new Error("tensor6d() requires shape to have six numbers");var n=un(r,e);if(n.length!==6&&n.length!==1)throw new Error("tensor6d() requires values to be number[][][][][][] or flat/TypedArray");if(n.length===1&&t==null)throw new Error("tensor6d() requires shape to be provided when `values` are a flat array");return cn(r,t=t||n,n,e)}function Jl(r,t,e,n){return t===void 0&&(t=!0),N.makeVariable(r,t,e,n)}function $n(r,t){if(t===void 0&&(t="float32"),t==="complex64"){var e=$n(r,"float32"),n=Ce(r,"float32");return Ge(e,n)}var o=Bs(Y(r),t);return N.makeTensor(o,r,t)}function Ce(r,t){if(t===void 0&&(t="float32"),t==="complex64"){var e=Ce(r,"float32"),n=Ce(r,"float32");return Ge(e,n)}var o=hr(Y(r),t);return N.makeTensor(o,r,t)}function Nt(r,t,e){return N.runKernelFunc((function(n){return n.fill(r,t,e)}),{})}function Ql(r,t,e){if(e<=0)throw new Error("The number of values should be positive.");return N.runKernelFunc((function(n){return n.linspace(r,t,e)}),{})}function zr(r,t,e,n){if(e===void 0&&(e=1),n===void 0&&(n="float32"),e===0)throw new Error("Cannot have a step of zero");if(r===t||r<t&&e<0||t<r&&e>1)return Ce([0],n);var o=hr(Math.abs(Math.ceil((t-r)/e)),n);t<r&&e===1&&(e=-1),o[0]=r;for(var a=1;a<o.length;a++)o[a]=o[a-1]+e;return Ne(o,n)}var js=D({onesLike_:function(r){var t=_(r,"x","onesLike");if(t.dtype==="complex64"){var e=js(ft(t)),n=me(St(t));return Ge(e,n)}return N.runKernelFunc((function(o){return o.onesLike(t)}),{$x:t},(function(o,a){return{$x:function(){return me(o)}}}))}}),me=D({zerosLike_:function(r){var t=_(r,"x","zerosLike");return N.runKernelFunc((function(e){return e.zerosLike(t)}),{$x:t},(function(e,n){return{$x:function(){return me(e)}}}))}}),Pe=D({concat_:function(r,t){t===void 0&&(t=0),I(r.length>=1,(function(){return"Pass at least one tensor to concat"}));var e=Vr(r,"tensors","concat");e[0].dtype==="complex64"&&e.forEach((function(s){if(s.dtype!=="complex64")throw new Error(`Cannot concatenate complex64 tensors with a tensor
          with dtype `+s.dtype+". ")})),t=Le(t,e[0].shape)[0];var n=qn(e.map((function(s){return s.shape})),t);if(Y(n)===0)return je([],n);if((e=e.filter((function(s){return s.size>0}))).length===1)return e[0];var o=e.map((function(s){return s.shape}));Xl(o,t);var a=e,i={axis:t};return N.runKernelFunc((function(s){return s.concat(e,t)}),a,(function(s){var u=o.map((function(c){return c[t]}));return Sa(s,u,t).map((function(c){return function(){return c}}))}),"Concat",i)}}),Zl=D({concat1d_:function(r){return Pe(r,0)}}),eh=D({concat2d_:function(r,t){return Pe(r,t)}}),th=D({concat3d_:function(r,t){return Pe(r,t)}}),nh=D({concat4d_:function(r,t){return Pe(r,t)}}),Sa=D({split_:function(r,t,e){e===void 0&&(e=0);var n,o=_(r,"x","split");return e=Le(e,o.shape)[0],typeof t=="number"?(I(o.shape[e]%t==0,(function(){return"Number of splits must evenly divide the axis."})),n=new Array(t).fill(o.shape[e]/t)):(I(o.shape[e]===t.reduce((function(a,i){return a+i})),(function(){return"The sum of sizes must match the size of the axis dimension."})),n=t),N.runKernelFunc((function(a){return a.split(o,n,e)}),{$x:o},(function(a){return{$x:function(){return Pe(a,e)}}}))}});function bn(r,t){return r(t={exports:{}},t.exports),t.exports}var rh=bn((function(r){(function(t,e,n){function o(s){var u,c=this,l=(u=4022871197,function(h){h=h.toString();for(var f=0;f<h.length;f++){var p=.02519603282416938*(u+=h.charCodeAt(f));p-=u=p>>>0,u=(p*=u)>>>0,u+=4294967296*(p-=u)}return 23283064365386963e-26*(u>>>0)});c.next=function(){var h=2091639*c.s0+23283064365386963e-26*c.c;return c.s0=c.s1,c.s1=c.s2,c.s2=h-(c.c=0|h)},c.c=1,c.s0=l(" "),c.s1=l(" "),c.s2=l(" "),c.s0-=l(s),c.s0<0&&(c.s0+=1),c.s1-=l(s),c.s1<0&&(c.s1+=1),c.s2-=l(s),c.s2<0&&(c.s2+=1),l=null}function a(s,u){return u.c=s.c,u.s0=s.s0,u.s1=s.s1,u.s2=s.s2,u}function i(s,u){var c=new o(s),l=u&&u.state,h=c.next;return h.int32=function(){return 4294967296*c.next()|0},h.double=function(){return h()+11102230246251565e-32*(2097152*h()|0)},h.quick=h,l&&(typeof l=="object"&&a(l,c),h.state=function(){return a(c,{})}),h}e&&e.exports?e.exports=i:this.alea=i})(0,r)})),oh=bn((function(r){(function(t,e,n){function o(s){var u=this,c="";u.x=0,u.y=0,u.z=0,u.w=0,u.next=function(){var h=u.x^u.x<<11;return u.x=u.y,u.y=u.z,u.z=u.w,u.w^=u.w>>>19^h^h>>>8},s===(0|s)?u.x=s:c+=s;for(var l=0;l<c.length+64;l++)u.x^=0|c.charCodeAt(l),u.next()}function a(s,u){return u.x=s.x,u.y=s.y,u.z=s.z,u.w=s.w,u}function i(s,u){var c=new o(s),l=u&&u.state,h=function(){return(c.next()>>>0)/4294967296};return h.double=function(){do var f=((c.next()>>>11)+(c.next()>>>0)/4294967296)/2097152;while(f===0);return f},h.int32=c.next,h.quick=h,l&&(typeof l=="object"&&a(l,c),h.state=function(){return a(c,{})}),h}e&&e.exports?e.exports=i:this.xor128=i})(0,r)})),ah=bn((function(r){(function(t,e,n){function o(s){var u=this,c="";u.next=function(){var h=u.x^u.x>>>2;return u.x=u.y,u.y=u.z,u.z=u.w,u.w=u.v,(u.d=u.d+362437|0)+(u.v=u.v^u.v<<4^h^h<<1)|0},u.x=0,u.y=0,u.z=0,u.w=0,u.v=0,s===(0|s)?u.x=s:c+=s;for(var l=0;l<c.length+64;l++)u.x^=0|c.charCodeAt(l),l==c.length&&(u.d=u.x<<10^u.x>>>4),u.next()}function a(s,u){return u.x=s.x,u.y=s.y,u.z=s.z,u.w=s.w,u.v=s.v,u.d=s.d,u}function i(s,u){var c=new o(s),l=u&&u.state,h=function(){return(c.next()>>>0)/4294967296};return h.double=function(){do var f=((c.next()>>>11)+(c.next()>>>0)/4294967296)/2097152;while(f===0);return f},h.int32=c.next,h.quick=h,l&&(typeof l=="object"&&a(l,c),h.state=function(){return a(c,{})}),h}e&&e.exports?e.exports=i:this.xorwow=i})(0,r)})),ih=bn((function(r){(function(t,e,n){function o(s){var u=this;u.next=function(){var c,l,h=u.x,f=u.i;return c=h[f],l=(c^=c>>>7)^c<<24,l^=(c=h[f+1&7])^c>>>10,l^=(c=h[f+3&7])^c>>>3,l^=(c=h[f+4&7])^c<<7,c=h[f+7&7],l^=(c^=c<<13)^c<<9,h[f]=l,u.i=f+1&7,l},(function(c,l){var h,f=[];if(l===(0|l))f[0]=l;else for(l=""+l,h=0;h<l.length;++h)f[7&h]=f[7&h]<<15^l.charCodeAt(h)+f[h+1&7]<<13;for(;f.length<8;)f.push(0);for(h=0;h<8&&f[h]===0;++h);for(h==8?f[7]=-1:f[h],c.x=f,c.i=0,h=256;h>0;--h)c.next()})(u,s)}function a(s,u){return u.x=s.x.slice(),u.i=s.i,u}function i(s,u){s==null&&(s=+new Date);var c=new o(s),l=u&&u.state,h=function(){return(c.next()>>>0)/4294967296};return h.double=function(){do var f=((c.next()>>>11)+(c.next()>>>0)/4294967296)/2097152;while(f===0);return f},h.int32=c.next,h.quick=h,l&&(l.x&&a(l,c),h.state=function(){return a(c,{})}),h}e&&e.exports?e.exports=i:this.xorshift7=i})(0,r)})),sh=bn((function(r){(function(t,e,n){function o(s){var u=this;u.next=function(){var c,l,h=u.w,f=u.X,p=u.i;return u.w=h=h+1640531527|0,l=f[p+34&127],c=f[p=p+1&127],l^=l<<13,c^=c<<17,l^=l>>>15,c^=c>>>12,l=f[p]=l^c,u.i=p,l+(h^h>>>16)|0},(function(c,l){var h,f,p,d,v,m=[],g=128;for(l===(0|l)?(f=l,l=null):(l+="\0",f=0,g=Math.max(g,l.length)),p=0,d=-32;d<g;++d)l&&(f^=l.charCodeAt((d+32)%l.length)),d===0&&(v=f),f^=f<<10,f^=f>>>15,f^=f<<4,f^=f>>>13,d>=0&&(v=v+1640531527|0,p=(h=m[127&d]^=f+v)==0?p+1:0);for(p>=128&&(m[127&(l&&l.length||0)]=-1),p=127,d=512;d>0;--d)f=m[p+34&127],h=m[p=p+1&127],f^=f<<13,h^=h<<17,f^=f>>>15,h^=h>>>12,m[p]=f^h;c.w=v,c.X=m,c.i=p})(u,s)}function a(s,u){return u.i=s.i,u.w=s.w,u.X=s.X.slice(),u}function i(s,u){s==null&&(s=+new Date);var c=new o(s),l=u&&u.state,h=function(){return(c.next()>>>0)/4294967296};return h.double=function(){do var f=((c.next()>>>11)+(c.next()>>>0)/4294967296)/2097152;while(f===0);return f},h.int32=c.next,h.quick=h,l&&(l.X&&a(l,c),h.state=function(){return a(c,{})}),h}e&&e.exports?e.exports=i:this.xor4096=i})(0,r)})),uh=bn((function(r){(function(t,e,n){function o(s){var u=this,c="";u.next=function(){var h=u.b,f=u.c,p=u.d,d=u.a;return h=h<<25^h>>>7^f,f=f-p|0,p=p<<24^p>>>8^d,d=d-h|0,u.b=h=h<<20^h>>>12^f,u.c=f=f-p|0,u.d=p<<16^f>>>16^d,u.a=d-h|0},u.a=0,u.b=0,u.c=-1640531527,u.d=1367130551,s===Math.floor(s)?(u.a=s/4294967296|0,u.b=0|s):c+=s;for(var l=0;l<c.length+20;l++)u.b^=0|c.charCodeAt(l),u.next()}function a(s,u){return u.a=s.a,u.b=s.b,u.c=s.c,u.d=s.d,u}function i(s,u){var c=new o(s),l=u&&u.state,h=function(){return(c.next()>>>0)/4294967296};return h.double=function(){do var f=((c.next()>>>11)+(c.next()>>>0)/4294967296)/2097152;while(f===0);return f},h.int32=c.next,h.quick=h,l&&(typeof l=="object"&&a(l,c),h.state=function(){return a(c,{})}),h}e&&e.exports?e.exports=i:this.tychei=i})(0,r)})),pn=bn((function(r){(function(t,e){var n,o=this,a=256,i=6,s="random",u=e.pow(a,i),c=e.pow(2,52),l=2*c,h=a-1;function f(g,x,b){var y=[],w=v((function k(R,E){var T,A=[],P=typeof R;if(E&&P=="object")for(T in R)try{A.push(k(R[T],E-1))}catch{}return A.length?A:P=="string"?R:R+"\0"})((x=x==1?{entropy:!0}:x||{}).entropy?[g,m(t)]:g??(function(){try{var k;return n&&(k=n.randomBytes)?k=k(a):(k=new Uint8Array(a),(o.crypto||o.msCrypto).getRandomValues(k)),m(k)}catch{var R=o.navigator,E=R&&R.plugins;return[+new Date,o,E,o.screen,m(t)]}})(),3),y),C=new p(y),S=function(){for(var k=C.g(i),R=u,E=0;k<c;)k=(k+E)*a,R*=a,E=C.g(1);for(;k>=l;)k/=2,R/=2,E>>>=1;return(k+E)/R};return S.int32=function(){return 0|C.g(4)},S.quick=function(){return C.g(4)/4294967296},S.double=S,v(m(C.S),t),(x.pass||b||function(k,R,E,T){return T&&(T.S&&d(T,C),k.state=function(){return d(C,{})}),E?(e[s]=k,R):k})(S,w,"global"in x?x.global:this==e,x.state)}function p(g){var x,b=g.length,y=this,w=0,C=y.i=y.j=0,S=y.S=[];for(b||(g=[b++]);w<a;)S[w]=w++;for(w=0;w<a;w++)S[w]=S[C=h&C+g[w%b]+(x=S[w])],S[C]=x;(y.g=function(k){for(var R,E=0,T=y.i,A=y.j,P=y.S;k--;)R=P[T=h&T+1],E=E*a+P[h&(P[T]=P[A=h&A+R])+(P[A]=R)];return y.i=T,y.j=A,E})(a)}function d(g,x){return x.i=g.i,x.j=g.j,x.S=g.S.slice(),x}function v(g,x){for(var b,y=g+"",w=0;w<y.length;)x[h&w]=h&(b^=19*x[h&w])+y.charCodeAt(w++);return m(x)}function m(g){return String.fromCharCode.apply(0,g)}if(e["seed"+s]=f,v(e.random(),t),r.exports){r.exports=f;try{n=require("crypto")}catch{}}})([],Math)}));pn.alea=rh,pn.xor128=oh,pn.xorwow=ah,pn.xorshift7=ih,pn.xor4096=sh,pn.tychei=uh;var ao=pn.alea,Da=(function(){function r(t,e,n,o,a){this.mean=t,this.stdDev=e,this.dtype=n,this.nextVal=NaN,this.truncated=o,this.truncated&&(this.upper=this.mean+2*this.stdDev,this.lower=this.mean-2*this.stdDev);var i=a||Math.random();this.random=ao(i.toString())}return r.prototype.nextValue=function(){if(!isNaN(this.nextVal)){var t=this.nextVal;return this.nextVal=NaN,t}for(var e,n,o=!1;!o;){var a=void 0,i=void 0,s=void 0;do s=(a=2*this.random()-1)*a+(i=2*this.random()-1)*i;while(s>=1||s===0);var u=Math.sqrt(-2*Math.log(s)/s);e=this.mean+this.stdDev*a*u,n=this.mean+this.stdDev*i*u,this.truncated&&!this.isValidTruncated(e)||(o=!0)}return this.truncated&&!this.isValidTruncated(n)||(this.nextVal=this.convertValue(n)),this.convertValue(e)},r.prototype.convertValue=function(t){return this.dtype==null||this.dtype==="float32"?t:Math.round(t)},r.prototype.isValidTruncated=function(t){return t<=this.upper&&t>=this.lower},r})(),ch=(function(){function r(t,e,n,o){this.alpha=t,this.beta=1/e,this.dtype=n;var a=o||Math.random();this.randu=ao(a.toString()),this.randn=new Da(0,1,n,!1,this.randu()),this.d=t<1?t+2/3:t-1/3,this.c=1/Math.sqrt(9*this.d)}return r.prototype.nextValue=function(){for(var t,e,n,o,a,i;;){do o=this.randn.nextValue(),i=1+this.c*o;while(i<=0);if(i*=i*i,e=1-.331*(t=o*o)*t,n=.5*t+this.d*(1-i+Math.log(i)),(a=this.randu())<e||Math.log(a)<n)break}return i=1/this.beta*this.d*i,this.alpha<1&&(i*=Math.pow(this.randu(),1/this.alpha)),this.convertValue(i)},r.prototype.convertValue=function(t){return this.dtype==="float32"?t:Math.round(t)},r})(),lh=(function(){function r(t,e,n,o){var a=this;if(t===void 0&&(t=0),e===void 0&&(e=1),this.canReturnFloat=function(){return a.dtype==null||a.dtype==="float32"},this.min=t,this.range=e-t,this.dtype=n,o==null&&(o=Math.random()),typeof o=="number"&&(o=o.toString()),!this.canReturnFloat()&&this.range<=1)throw new Error("The difference between "+t+" - "+e+" <= 1 and dtype is not float");this.random=ao(o)}return r.prototype.convertValue=function(t){return this.canReturnFloat()?t:Math.round(t)},r.prototype.nextValue=function(){return this.convertValue(this.min+this.range*this.random())},r})();function oe(r,t,e){return t===void 0&&(t="float32"),t=t||"float32",Ls(r),new or(r,t,e)}function hh(r,t){t===void 0&&(t=!1),console.log(r.toString(t))}var qs=D({batchToSpaceND_:function(r,t,e){var n=_(r,"x","batchToSpaceND"),o=t.reduce((function(a,i){return a*i}));return I(n.rank>=1+t.length,(function(){return"input rank is "+n.rank+" but should be > than blockShape.length "+t.length})),I(e.length===t.length,(function(){return"crops.length is "+e.length+" but should be equal to blockShape.length  "+t.length})),I(n.shape[0]%o==0,(function(){return"input tensor batch is "+n.shape[0]+" but is not divisible by the product of the elements of blockShape "+t.join(" * ")+" === "+o})),N.runKernelFunc((function(a){return a.batchToSpaceND(n,t,e)}),{$x:n},(function(a){return{$x:function(){return a.spaceToBatchND(t,e)}}}))}}),fh=D({broadcastTo_:function(r,t){var e=_(r,"broadcastTo","x"),n=e.shape;if(t.some((function(u){return!(u>0)||u%1!=0})))throw new Error("broadcastTo(): Invalid broadcast shape ["+t+"].");if(t.length<e.rank)throw new Error("broadcastTo(): shape.length="+t.length+" < input.rank="+e.rank+".");if(t.length>e.rank){for(var o=e.shape.slice();o.length<t.length;)o.unshift(1);e=e.reshape(o)}for(var a=Array.from(t),i=t.length-1;i>=0;i--)if(e.shape[i]===t[i])a[i]=1;else if(e.shape[i]!==1)throw new Error("broadcastTo(): ["+n+"] cannot be broadcast to ["+t+"].");var s=a.map((function(u,c){return u>1?c:-1})).filter((function(u){return u>=0}));return s.length===0?e.clone():N.runKernelFunc((function(u){return u.tile(e,a)}),{input:e},(function(u){return{input:function(){return u.sum(s,!0)}}}))}}),ph=D({cast_:function(r,t){var e=_(r,"x","cast");if(!al(t))throw new Error("Failed to cast to unknown dtype "+t);if(t==="string"&&e.dtype!=="string"||t!=="string"&&e.dtype==="string")throw new Error("Only strings can be casted to strings");var n={dtype:t};return N.runKernelFunc((function(o){return o.cast(e,t)}),{x:e},(function(o){return{x:function(){return o.clone()}}}),"Cast",n)}}),dh=D({clone_:function(r){var t=_(r,"x","clone",null);return N.runKernelFunc((function(){return N.makeTensorFromDataId(t.dataId,t.shape,t.dtype)}),{$x:t},(function(e){return{$x:function(){return e.toFloat()}}}))}}),vh=D({cumsum_:function(r,t,e,n){t===void 0&&(t=0),e===void 0&&(e=!1),n===void 0&&(n=!1);var o=_(r,"x","cumsum"),a=Mt([t|=0],o.rank),i=o;a!=null&&(i=o.transpose(a));var s=Ot(1,o.rank)[0],u=N.runKernelFunc((function(c){return c.cumsum(i,s,e,n)}),{permutedX:i},(function(c){return{permutedX:function(){return c.cumsum(t,e,!n)}}}));return a!=null&&(u=u.transpose(a)),u}}),mh=D({depthToSpace_:function(r,t,e){e===void 0&&(e="NHWC");var n=_(r,"x","depthToSpace"),o=e==="NHWC"?n.shape[1]:n.shape[2],a=e==="NHWC"?n.shape[2]:n.shape[3],i=e==="NHWC"?n.shape[3]:n.shape[1];return I(o*t>=0,(function(){return`Negative dimension size caused by overflow when multiplying
      `+o+" and "+t+`  for depthToSpace with input shape
      `+n.shape})),I(a*t>=0,(function(){return`Negative dimension size caused by overflow when multiplying
      `+a+" and "+t+` for depthToSpace with input shape
          `+n.shape})),I(i%(t*t)==0,(function(){return"Dimension size must be evenly divisible by "+t*t+" but is "+i+" for depthToSpace with input shape "+n.shape})),N.runKernelFunc((function(s){return s.depthToSpace(n,t,e)}),{$x:n})}}),ht=D({expandDims_:function(r,t){t===void 0&&(t=0);var e=_(r,"x","expandDims",null);I(t<=e.rank,(function(){return"Axis must be <= rank of the tensor"}));var n=e.shape.slice();return t<0&&(I(-(e.rank+1)<=t,(function(){return"Axis must be in the interval ["+-(e.rank+1)+", "+e.rank+"]"})),t=e.rank+t+1),n.splice(t,0,1),mt(e,n)}}),Ks=D({eye_:function(r,t,e,n){n===void 0&&(n="float32"),t==null&&(t=r);for(var o=oe([r,t],n),a=r<=t?r:t,i=0;i<a;++i)o.set(1,i,i);var s=o.toTensor().as2D(r,t);if(e==null)return s;if(e.length===1)return Bn(ht(s,0),[e[0],1,1]);if(e.length===2)return Bn(ht(ht(s,0),0),[e[0],e[1],1,1]);if(e.length===3)return Bn(ht(ht(ht(s,0),0),0),[e[0],e[1],e[2],1,1]);throw new Error("eye() currently supports only 1D and 2D batchShapes, but received "+e.length+"D.")}}),gh=D({multinomial_:function(r,t,e,n){n===void 0&&(n=!1);var o=_(r,"logits","multinomial"),a=o.size,i=o.rank;if(a<2)throw new Error("Error in multinomial: you need at least 2 outcomes, but got "+a+".");if(i>2)throw new Error("Rank of probabilities must be 1 or 2, but is "+i);e=e||Math.random();var s=i===1?o.as2D(1,-1):o,u=N.runKernelFunc((function(c){return c.multinomial(s,n,t,e)}),{logits2D:s});return i===1?u.as1D():u}}),la=D({oneHot_:function(r,t,e,n){if(e===void 0&&(e=1),n===void 0&&(n=0),t<2)throw new Error("Error in oneHot: depth must be >=2, but it is "+t);var o=_(r,"indices","oneHot","int32"),a=o.shape.concat([t]);return o=o.flatten(),N.runKernelFunc((function(i){return i.oneHot(o,t,e,n)}),{$indices:o},(function(i){return{$indices:function(){return Ce(o.shape,"float32")}}})).reshape(a)}}),wn=D({pad_:function(r,t,e){e===void 0&&(e=0);var n=_(r,"x","pad");if(n.rank===0)throw new Error("pad(scalar) is not defined. Pass non-scalar to pad");var o={paddings:t,constantValue:e};return N.runKernelFunc((function(a){return a.pad(n,t,e)}),{x:n},(function(a){var i=t.map((function(s){return s[0]}));return{x:function(){return a.slice(i,n.shape)}}}),"PadV2",o)}}),yh=D({pad1d_:function(r,t,e){return e===void 0&&(e=0),I(t.length===2,(function(){return"Invalid number of paddings. Must be length of 2."})),wn(r,[t],e)}}),xh=D({pad2d_:function(r,t,e){return e===void 0&&(e=0),I(t.length===2&&t[0].length===2&&t[1].length===2,(function(){return"Invalid number of paddings. Must be length of 2 each."})),wn(r,t,e)}}),bh=D({pad3d_:function(r,t,e){return e===void 0&&(e=0),I(t.length===3&&t[0].length===2&&t[1].length===2&&t[2].length===2,(function(){return"Invalid number of paddings. Must be length of 2 each."})),wn(r,t,e)}}),wh=D({pad4d_:function(r,t,e){return e===void 0&&(e=0),I(t.length===4&&t[0].length===2&&t[1].length===2&&t[2].length===2&&t[3].length===2,(function(){return"Invalid number of paddings. Must be length of 2 each."})),wn(r,t,e)}}),Ch=D({rand_:function(r,t,e){var n=Y(r),o=null;if(e==null||e==="float32")o=new Float32Array(n);else if(e==="int32")o=new Int32Array(n);else{if(e!=="bool")throw new Error("Unknown data type "+e);o=new Uint8Array(n)}for(var a=0;a<n;a++)o[a]=t();return N.makeTensor(o,r,e)}}),_h=D({randomNormal_:function(r,t,e,n,o){if(t===void 0&&(t=0),e===void 0&&(e=1),n!=null&&n==="bool")throw new Error("Unsupported data type "+n);for(var a=new Da(t,e,n,!1,o),i=oe(r,n),s=0;s<i.values.length;s++)i.values[s]=a.nextValue();return i.toTensor()}}),Eh=D({randomGamma_:function(r,t,e,n,o){if(e===void 0&&(e=1),n===void 0&&(n="float32"),e==null&&(e=1),n==null&&(n="float32"),n!=="float32"&&n!=="int32")throw new Error("Unsupported data type "+n);for(var a=new ch(t,e,n,o),i=oe(r,n),s=0;s<i.values.length;s++)i.values[s]=a.nextValue();return i.toTensor()}}),Xs=D({randomUniform_:function(r,t,e,n,o){t===void 0&&(t=0),e===void 0&&(e=1),n===void 0&&(n="float32");for(var a=oe(r,n),i=new lh(t,e,null,o),s=0;s<a.values.length;s++)a.values[s]=i.nextValue();return a.toTensor()}}),mt=D({reshape_:function(r,t){var e=_(r,"x","reshape",null);t=rl(t,e.size),I(e.size===Y(t),(function(){return"new shape and old shape must have the same number of elements."}));var n={shape:t};return N.runKernelFunc((function(o){return o.reshape(e,t)}),{x:e},(function(o){return{x:function(){return o.reshape(e.shape)}}}),"Reshape",n)}}),$s=D({spaceToBatchND_:function(r,t,e){var n=_(r,"x","spaceToBatchND");return I(n.rank>=1+t.length,(function(){return"input rank "+n.rank+" should be > than [blockShape] "+t.length})),I(e.length===t.length,(function(){return"paddings.shape[0] "+e.length+" must be equal to [blockShape] "+t.length})),I(n.shape.reduce((function(o,a,i){return i>0&&i<=t.length?o&&(a+e[i-1][0]+e[i-1][1])%t[i-1]==0:o}),!0),(function(){return"input spatial dimensions "+n.shape.slice(1)+" with paddings "+e.toString()+" must be divisible by blockShapes "+t.toString()})),N.runKernelFunc((function(o){return o.spaceToBatchND(n,t,e)}),{$x:n},(function(o){return{$x:function(){return o.batchToSpaceND(t,e)}}}))}}),Ys=D({squeeze_:function(r,t){var e=_(r,"x","squeeze");return mt(e,dn(e.shape,t).newShape)}}),lt=D({stack_:function(r,t){t===void 0&&(t=0);var e=Vr(r,"tensors","stack");if(I(e.length>=1,(function(){return"Pass at least one tensor to tf.stack"})),e.length===1)return e[0].expandDims(t);var n=e[0].rank,o=e[0].shape,a=e[0].dtype;I(t<=n,(function(){return"Axis must be <= rank of the tensor"})),e.forEach((function(s){xe(o,s.shape,"All tensors passed to stack must have matching shapes")})),e.forEach((function(s){I(a===s.dtype,(function(){return"All tensors passed to stack must have matching dtypes"}))}));var i=e.map((function(s){return s.expandDims(t)}));return Pe(i,t)}}),Bn=D({tile_:function(r,t){var e=_(r,"x","tile",null);I(e.rank===t.length,(function(){return"Error in transpose: rank of input "+e.rank+" must match length of reps "+t+"."}));var n=[e],o={reps:t};return N.runKernelFunc((function(a,i){var s=a.tile(e,t);return i([e]),s}),{x:e},(function(a,i){var s=i[0];return{x:function(){var u=me(s);if(s.rank===1)for(var c=0;c<t[0];++c)u=u.add(a.slice([c*s.shape[0]],[s.shape[0]]));else if(s.rank===2)for(c=0;c<t[0];++c)for(var l=0;l<t[1];++l)u=u.add(a.slice([c*s.shape[0],l*s.shape[1]],[s.shape[0],s.shape[1]]));else if(s.rank===3)for(c=0;c<t[0];++c)for(l=0;l<t[1];++l)for(var h=0;h<t[2];++h)u=u.add(a.slice([c*s.shape[0],l*s.shape[1],h*s.shape[2]],[s.shape[0],s.shape[1],s.shape[2]]));else{if(s.rank!==4)throw new Error("Gradient for tile operation is not implemented for rank-"+s.rank+" tensors yet.");for(c=0;c<t[0];++c)for(l=0;l<t[1];++l)for(h=0;h<t[2];++h)for(var f=0;f<t[3];++f)u=u.add(a.slice([c*s.shape[0],l*s.shape[1],h*s.shape[2],f*s.shape[3]],[s.shape[0],s.shape[1],s.shape[2],s.shape[3]]))}return u}}}),"Tile",o,n)}}),Ih=D({truncatedNormal_:function(r,t,e,n,o){if(t===void 0&&(t=0),e===void 0&&(e=1),n!=null&&n==="bool")throw new Error("Unsupported data type "+n);for(var a=new Da(t,e,n,!0,o),i=oe(r,n),s=0;s<i.values.length;s++)i.values[s]=a.nextValue();return i.toTensor()}}),Me=D({unstack_:function(r,t){t===void 0&&(t=0),t=t||0;var e=_(r,"x","unstack");I(t>=-e.shape.length&&t<e.shape.length,(function(){return"Axis = "+t+" is not in [-"+e.shape.length+", "+e.shape.length+")"})),t<0&&(t+=e.shape.length);var n={axis:t};return N.runKernelFunc((function(o){return o.unstack(e,t)}),{x:e},(function(o){return{x:function(){return lt(o,t)}}}),"Unpack",n)}}),Rh=function(r,t){return X(this,void 0,void 0,(function(){var e,n,o,a,i,s,u,c,l,h;return $(this,(function(f){switch(f.label){case 0:return e=_(r,"x","setdiff1d"),n=_(t,"y","setdiff1d"),I(e.dtype===n.dtype,(function(){return"x and y should have the same dtype, but got x ("+e.dtype+") and y ("+n.dtype+")."})),I(e.rank===1,(function(){return"x should be 1D tensor, but got x ("+e.shape+")."})),I(n.rank===1,(function(){return"y should be 1D tensor, but got y ("+n.shape+")."})),[4,e.data()];case 1:return o=f.sent(),[4,n.data()];case 2:for(a=f.sent(),i=new Set(a),s=0,l=0;l<o.length;l++)i.has(o[l])||s++;for(u=new or([s],e.dtype),c=new or([s],"int32"),l=0,h=0;l<o.length;l++)i.has(o[l])||(u.values[h]=o[l],c.values[h]=l,h++);return[2,[u.toTensor(),c.toTensor()]]}}))}))};function Gr(r,t,e,n){n===void 0&&(n=!0);var o=[];if(n)(o=o.concat(t.slice(0))).push(r[0]/e),o=o.concat(r.slice(1));else{o=o.concat(r[0]);for(var a=t.length,i=0;i<a;++i)o=o.concat([r[i+1]/t[i],t[i]]);o=o.concat(r.slice(a+1))}return o}function Hr(r,t,e){e===void 0&&(e=!0);var n=[];if(e){n.push(t);for(var o=t+1;o<r;++o)o<=2*t?(n.push(o),n.push(o-(t+1))):n.push(o)}else{var a=[],i=[];for(o=1;o<r;++o)o>=2*t+1||o%2==1?i.push(o):a.push(o);n.push.apply(n,a),n.push(0),n.push.apply(n,i)}return n}function jr(r,t,e,n){n===void 0&&(n=!0);var o=[];n?o.push(r[0]/e):o.push(r[0]*e);for(var a=1;a<r.length;++a)a<=t.length?n?o.push(t[a-1]*r[a]):o.push(r[a]/t[a-1]):o.push(r[a]);return o}function Js(r,t){for(var e=[0],n=0;n<t;++n)e.push(r[n][0]);return e}function Qs(r,t,e){for(var n=r.slice(0,1),o=0;o<e;++o)n.push(r[o+1]-t[o][0]-t[o][1]);return n}function Zs(r,t){if(r.rank<1)throw new Error("tf.gatherND() expects the input to be rank 1 or higher, but the rank was "+r.rank+".");if(t.rank<1)throw new Error("tf.gatherND() expects the indices to be rank 1 or higher, but the rank was "+t.rank+".");if(t.dtype!=="int32")throw new Error("tf.gatherND() expects the indices to be int32 type, but the dtype was "+t.dtype+".");if(t.shape[t.rank-1]>r.rank)throw new Error("index innermost dimension length must be <= tensor rank; saw: "+t.shape[t.rank-1]+" vs. "+r.rank);if(r.size===0)throw new Error("Requested more than 0 entries, but input is empty. Input shape: "+r.shape+".");for(var e=t.shape,n=e[e.length-1],o=1,a=0;a<e.length-1;++a)o*=e[a];var i=r.shape,s=e.slice();s.pop();var u=1;for(a=n;a<r.rank;++a)u*=i[a],s.push(i[a]);var c=Tt(r.shape).map((function(l){return l/u})).concat([1]).slice(0,n);return[s,o,u,c]}var eu=30;function Oo(r){return r<=eu?r:oa(r,Math.floor(Math.sqrt(r)))}function kh(r,t,e){var n=t.rank>1?t.shape[t.rank-1]:1,o=t.rank>1?t.rank-1:1,a="Must have updates.shape = indices.shape[:batchDim] + shape[sliceDim:], got updates.shape: "+e.shape+", indices.shape: "+t.shape+", shape: "+r+", sliceDim: "+n+", and batchDim: "+o+".";if(e.rank<o)throw new Error(a+" update.rank < "+o+". ");if(r.length<n+(e.rank-o))throw new Error(a+" Output shape length < "+(n+(e.rank-o)));if(e.rank!==o+r.length-n)throw new Error(a+" update.rank != "+(o+r.length-n));for(var i=0;i<o;++i)if(e.shape[i]!==t.shape[i])throw new Error(a+" updates.shape["+i+"] ("+e.shape[i]+") != indices.shape["+i+"] ("+t.shape[i]+").");for(i=0;i<e.rank-o;++i)if(e.shape[i+o]!==r[i+n])throw new Error(a+" updates.shape["+(i+o)+"] ("+e.shape[i+o]+") != shape["+(i+o)+"] ("+r[i+o]+")")}function Sh(r,t,e){if(t.rank<1)throw new Error("tf.scatterND() expects the indices to be rank 1 or higher, but the rank was "+t.rank+".");if(r.rank<1)throw new Error("tf.scatterND() expects the updates to be rank 1 or higher, but the rank was "+r.rank+".");if(t.dtype!=="int32")throw new Error("The dtype of 'indices' should be int32, but got dtype: "+t.dtype);if(e.length<1)throw new Error("Output rank must be greater or equal to 1, but got shape: "+e);if(e.length===0){if(t.size===0)throw new Error("Indices specified for empty output. indices shape: "+t.shape);if(r.size===0)throw new Error("Updates specified for empty output. updates shape: "+r.shape)}kh(e,t,r)}function qr(r,t,e){for(var n=t.shape.length,o=n>1?t.shape[n-1]:1,a=e.length,i=1,s=o;s<a;++s)i*=e[s];var u=o<1?1:o;return{sliceRank:o,numUpdates:Y(t.shape)/u,sliceSize:i,strides:Tt(e.slice(0,o)).concat([1]),outputSize:Y(e)}}function Dh(r,t,e){I(r.rank===t.length,(function(){return"Error in slice"+r.rank+"D: Length of begin "+t+" must match the rank of the array ("+r.rank+")."})),I(r.rank===e.length,(function(){return"Error in slice"+r.rank+"D: Length of size "+e+" must match the rank of the array ("+r.rank+")."}));for(var n=function(a){I(t[a]+e[a]<=r.shape[a],(function(){return"Error in slice"+r.rank+"D: begin["+a+"] + size["+a+"] ("+(t[a]+e[a])+") would overflow input.shape["+a+"] ("+r.shape[a]+")"}))},o=0;o<r.rank;++o)n(o)}function Li(r){for(var t=[],e=0;r>0;)1&r&&t.push(e),r/=2,e++;return t}function Aa(r,t,e){for(var n=[],o=0;o<r.length;o++)n[o]=Math.ceil((t[o]-r[o])/e[o]);return n}function Ah(r,t,e,n,o){var a=t[o],i=e[o]||1;(r&1<<o||a==null)&&(a=i>0?Number.MIN_SAFE_INTEGER:Number.MAX_SAFE_INTEGER);var s=n[o];return a<0&&(a+=s),a=ta(0,a,s-1)}function Th(r,t,e,n,o){var a=t[o],i=e[o]||1;(r&1<<o||a==null)&&(a=i>0?Number.MAX_SAFE_INTEGER:Number.MIN_SAFE_INTEGER);var s=n[o];return a<0&&(a+=s),a=i>0?ta(0,a,s):ta(-1,a,s-1)}function tu(r,t,e){for(var n=e.length,o=0;o<e.length;o++)if(e[o]>1){n=o;break}for(o=n+1;o<e.length;o++)if(t[o]>0||e[o]!==r[o])return!1;return!0}function nu(r,t){for(var e=r.length>0?r[r.length-1]:1,n=0;n<r.length-1;n++)e+=r[n]*t[n];return e}function Nh(r,t){I(ra(r),(function(){return"The f passed in variableGrads(f) must be a function"})),I(t==null||Array.isArray(t)&&t.every((function(l){return l instanceof jn})),(function(){return"The varList passed in variableGrads(f, varList) must be an array of variables"}));var e=t!=null;if(!e)for(var n in t=[],N.registeredVariables)t.push(N.registeredVariables[n]);var o=e?t.filter((function(l){return!l.trainable})):null,a=t.length;I((t=t.filter((function(l){return l.trainable}))).length>0,(function(){return"variableGrads() expects at least one of the input variables to be trainable, but none of the "+a+" variables is trainable."}));var i=N.gradients(r,t,null,!0),s=i.value,u=i.grads;I(u.some((function(l){return l!=null})),(function(){return"Cannot find a connection between any variable and the result of the loss function y=f(x). Please make sure the operations that use variables are inside the function f passed to minimize()."})),I(s.rank===0,(function(){return"The f passed in variableGrads(f) must return a scalar, but it returned a rank-"+s.rank+" tensor"}));var c={};return t.forEach((function(l,h){u[h]!=null&&(c[l.name]=u[h])})),o!=null&&o.forEach((function(l){return c[l.name]=null})),{value:s,grads:c}}function io(r){return N.customGrad(r)}var qt=D({softmax_:function(r,t){t===void 0&&(t=-1);var e=_(r,"logits","softmax","float32");if(t===-1&&(t=e.rank-1),t!==e.rank-1)throw Error("Softmax along a non-last dimension is not yet supported. Logits was rank "+e.rank+" and dim was "+t);return N.runKernelFunc((function(n,o){var a=n.softmax(e,t);return o([a]),a}),{logits:e},(function(n,o){var a=o[0],i=n.mul(a);return{logits:function(){return i.sub(i.sum([t],!0).mul(a))}}}),"Softmax",{dim:t},[],[!0])}}),Fh=D({logSoftmax_:function(r,t){t===void 0&&(t=-1);var e=_(r,"logits","logSoftmax");if(t===-1&&(t=e.rank-1),t!==e.rank-1)throw Error("Log Softmax along a non-last dimension is not yet supported. Logits was rank "+e.rank+" and axis was "+t);return io((function(n,o){var a=n.max(t,!0),i=n.sub(a),s=i.toFloat().sub(i.exp().sum(t,!0).log());return o([s]),{value:s,gradFunc:function(u,c){var l=c[0].exp();return u.sub(u.sum(t,!0).mul(l))}}}))(e)}}),ru=(function(){function r(t,e){this.backend=t,this.dataMover=e,this.data=new WeakMap,this.dataIdsCount=0}return r.prototype.get=function(t){return this.data.has(t)||this.dataMover.moveData(this.backend,t),this.data.get(t)},r.prototype.set=function(t,e){this.dataIdsCount++,this.data.set(t,e)},r.prototype.has=function(t){return this.data.has(t)},r.prototype.delete=function(t){return this.dataIdsCount--,this.data.delete(t)},r.prototype.numDataIds=function(){return this.dataIdsCount},r})(),ou=(function(){function r(){}return r.prototype.time=function(t){return F("time")},r.prototype.read=function(t){return F("read")},r.prototype.readSync=function(t){return F("readSync")},r.prototype.numDataIds=function(){return F("numDataIds")},r.prototype.disposeData=function(t){return F("disposeData")},r.prototype.write=function(t,e,n){return F("write")},r.prototype.move=function(t,e,n,o){return F("move")},r.prototype.memory=function(){return F("memory")},r.prototype.floatPrecision=function(){return F("floatPrecision")},r.prototype.epsilon=function(){return this.floatPrecision()===32?1e-7:1e-4},r.prototype.batchMatMul=function(t,e,n,o){return F("batchMatMul")},r.prototype.fusedBatchMatMul=function(t){return t.a,t.b,t.transposeA,t.transposeB,t.bias,t.activation,t.preluActivationWeights,F("fusedBatchMatMul")},r.prototype.slice=function(t,e,n){return F("slice")},r.prototype.stridedSlice=function(t,e,n,o){return F("stridedSlice")},r.prototype.unstack=function(t,e){return F("unstack")},r.prototype.reverse=function(t,e){return F("reverse")},r.prototype.concat=function(t,e){return F("concat")},r.prototype.neg=function(t){return F("neg")},r.prototype.add=function(t,e){return F("add")},r.prototype.addN=function(t){return F("addN")},r.prototype.subtract=function(t,e){return F("subtract")},r.prototype.multiply=function(t,e){return F("multiply")},r.prototype.realDivide=function(t,e){return F("realDivide")},r.prototype.floorDiv=function(t,e){return F("floorDiv")},r.prototype.sum=function(t,e){return F("sum")},r.prototype.prod=function(t,e){return F("prod")},r.prototype.unsortedSegmentSum=function(t,e,n){return F("unsortedSegmentSum")},r.prototype.argMin=function(t,e){return F("argMin")},r.prototype.argMax=function(t,e){return F("argMax")},r.prototype.equal=function(t,e){return F("equal")},r.prototype.notEqual=function(t,e){return F("notEqual")},r.prototype.less=function(t,e){return F("less")},r.prototype.lessEqual=function(t,e){return F("lessEqual")},r.prototype.greater=function(t,e){return F("greater")},r.prototype.greaterEqual=function(t,e){return F("greaterEqual")},r.prototype.logicalNot=function(t){return F("logicalNot")},r.prototype.logicalAnd=function(t,e){return F("logicalAnd")},r.prototype.logicalOr=function(t,e){return F("logicalOr")},r.prototype.where=function(t){return F("where")},r.prototype.select=function(t,e,n){return F("select")},r.prototype.topk=function(t,e,n){return F("topk")},r.prototype.min=function(t,e){return F("min")},r.prototype.minimum=function(t,e){return F("minimum")},r.prototype.mod=function(t,e){return F("mod")},r.prototype.max=function(t,e){return F("max")},r.prototype.maximum=function(t,e){return F("maximum")},r.prototype.all=function(t,e){return F("all")},r.prototype.any=function(t,e){return F("any")},r.prototype.squaredDifference=function(t,e){return F("squaredDifference")},r.prototype.ceil=function(t){return F("ceil")},r.prototype.floor=function(t){return F("floor")},r.prototype.round=function(t){return F("round")},r.prototype.sign=function(t){return F("sign")},r.prototype.isNaN=function(t){return F("isNaN")},r.prototype.isInf=function(t){return F("isInf")},r.prototype.isFinite=function(t){return F("isFinite")},r.prototype.pow=function(t,e){return F("pow")},r.prototype.exp=function(t){return F("exp")},r.prototype.expm1=function(t){return F("expm1")},r.prototype.softmax=function(t,e){return F("softmax")},r.prototype.log=function(t){return F("log")},r.prototype.log1p=function(t){return F("log1p")},r.prototype.sqrt=function(t){return F("sqrt")},r.prototype.rsqrt=function(t){return F("rsqrt")},r.prototype.square=function(t){return F("square")},r.prototype.reciprocal=function(t){return F("reciprocal")},r.prototype.relu=function(t){return F("relu")},r.prototype.relu6=function(t){return F("relu6")},r.prototype.prelu=function(t,e){return F("prelu")},r.prototype.elu=function(t){return F("elu")},r.prototype.eluDer=function(t,e){return F("eluDer")},r.prototype.selu=function(t){return F("selu")},r.prototype.int=function(t){return F("int")},r.prototype.clip=function(t,e,n){return F("clip")},r.prototype.abs=function(t){return F("abs")},r.prototype.complexAbs=function(t){return F("complexAbs")},r.prototype.sigmoid=function(t){return F("sigmoid")},r.prototype.softplus=function(t){return F("softplus")},r.prototype.sin=function(t){return F("sin")},r.prototype.cos=function(t){return F("cos")},r.prototype.tan=function(t){return F("tan")},r.prototype.asin=function(t){return F("asin")},r.prototype.acos=function(t){return F("acos")},r.prototype.atan=function(t){return F("atan")},r.prototype.atan2=function(t,e){return F("atan2")},r.prototype.sinh=function(t){return F("sinh")},r.prototype.cosh=function(t){return F("cosh")},r.prototype.tanh=function(t){return F("tanh")},r.prototype.asinh=function(t){return F("asinh")},r.prototype.acosh=function(t){return F("acosh")},r.prototype.atanh=function(t){return F("atanh")},r.prototype.erf=function(t){return F("erf")},r.prototype.step=function(t,e){return F("step")},r.prototype.fusedConv2d=function(t){return t.input,t.filter,t.convInfo,t.bias,t.activation,t.preluActivationWeights,F("fusedConv2d")},r.prototype.conv2d=function(t,e,n){return F("conv2d")},r.prototype.conv2dDerInput=function(t,e,n){return F("conv2dDerInput")},r.prototype.conv2dDerFilter=function(t,e,n){return F("conv2dDerFilter")},r.prototype.fusedDepthwiseConv2D=function(t){return t.input,t.filter,t.convInfo,t.bias,t.activation,t.preluActivationWeights,F("fusedDepthwiseConv2D")},r.prototype.depthwiseConv2D=function(t,e,n){return F("depthwiseConv2D")},r.prototype.depthwiseConv2DDerInput=function(t,e,n){return F("depthwiseConv2DDerInput")},r.prototype.depthwiseConv2DDerFilter=function(t,e,n){return F("depthwiseConv2DDerFilter")},r.prototype.conv3d=function(t,e,n){return F("conv3d")},r.prototype.conv3dDerInput=function(t,e,n){return F("conv3dDerInput")},r.prototype.conv3dDerFilter=function(t,e,n){return F("conv3dDerFilter")},r.prototype.maxPool=function(t,e){return F("maxPool")},r.prototype.maxPoolBackprop=function(t,e,n,o){return F("maxPoolBackprop")},r.prototype.avgPool=function(t,e){return F("avgPool")},r.prototype.avgPoolBackprop=function(t,e,n){return F("avgPoolBackprop")},r.prototype.avgPool3d=function(t,e){return F("avgPool3d")},r.prototype.avgPool3dBackprop=function(t,e,n){return F("avgPool3dBackprop")},r.prototype.maxPool3d=function(t,e){return F("maxPool3d")},r.prototype.maxPool3dBackprop=function(t,e,n,o){return F("maxPool3dBackprop")},r.prototype.reshape=function(t,e){return F("reshape")},r.prototype.cast=function(t,e){return F("cast")},r.prototype.tile=function(t,e){return F("tile")},r.prototype.pad=function(t,e,n){return F("pad")},r.prototype.transpose=function(t,e){return F("transpose")},r.prototype.gather=function(t,e,n){return F("gather")},r.prototype.gatherND=function(t,e){return F("gatherND")},r.prototype.scatterND=function(t,e,n){return F("scatterND")},r.prototype.batchToSpaceND=function(t,e,n){return F("batchToSpaceND")},r.prototype.spaceToBatchND=function(t,e,n){return F("spaceToBatchND")},r.prototype.resizeBilinear=function(t,e,n,o){return F("resizeBilinear")},r.prototype.resizeBilinearBackprop=function(t,e,n){return F("resizeBilinearBackprop")},r.prototype.resizeNearestNeighbor=function(t,e,n,o){return F("resizeNearestNeighbor")},r.prototype.resizeNearestNeighborBackprop=function(t,e,n){return F("resizeNearestNeighborBackprop")},r.prototype.batchNormalization=function(t,e,n,o,a,i){return F("batchNormalization")},r.prototype.localResponseNormalization4D=function(t,e,n,o,a){return F("localResponseNormalization4D")},r.prototype.LRNGrad=function(t,e,n,o,a,i,s){return F("LRNGrad")},r.prototype.multinomial=function(t,e,n,o){return F("multinomial")},r.prototype.oneHot=function(t,e,n,o){return F("oneHot")},r.prototype.cumsum=function(t,e,n,o){return F("cumsum")},r.prototype.nonMaxSuppression=function(t,e,n,o,a){return F("nonMaxSuppression")},r.prototype.fft=function(t){return F("fft")},r.prototype.ifft=function(t){return F("ifft")},r.prototype.complex=function(t,e){return F("complex")},r.prototype.real=function(t){return F("real")},r.prototype.imag=function(t){return F("imag")},r.prototype.cropAndResize=function(t,e,n,o,a,i){return F("cropAndResize")},r.prototype.depthToSpace=function(t,e,n){return F("depthToSpace")},r.prototype.split=function(t,e,n){return F("split")},r.prototype.sparseToDense=function(t,e,n,o){return F("sparseToDense")},r.prototype.diag=function(t){return F("diag")},r.prototype.fill=function(t,e,n){return F("fill")},r.prototype.onesLike=function(t){return F("onesLike")},r.prototype.zerosLike=function(t){return F("zerosLike")},r.prototype.linspace=function(t,e,n){return F("linspace")},r.prototype.dispose=function(){return F("dispose")},r})();function F(r){throw new Error("'"+r+"' not yet implemented or not found in the registry. Did you forget to import the kernel?")}function en(r,t){for(var e=r.length,n=[],o=0;o<e;o++){var a=e-1-o,i=r[a]||1;(t[t.length-1-o]||1)>1&&i===1&&n.unshift(a)}return n}function Oe(r,t){for(var e=[],n=0;n<t.length;n++){var o=r[r.length-n-1],a=t.length-n-1,i=t[a];(o==null||o===1&&i>1)&&e.unshift(a)}return e}function le(r,t){for(var e=[],n=Math.max(r.length,t.length),o=0;o<n;o++){var a=r[r.length-o-1];a==null&&(a=1);var i=t[t.length-o-1];if(i==null&&(i=1),a===1)e.unshift(i);else if(i===1)e.unshift(a);else{if(a!==i)throw Error("Operands could not be broadcast together with shapes "+r+" and "+t+".");e.unshift(a)}}return e}function ir(r,t,e,n,o,a,i){i===void 0&&(i="channelsLast");var s,u=$r(t),c=u[0],l=u[1];if(i==="channelsLast")s=[c,l,r[3],r[3]];else{if(i!=="channelsFirst")throw new Error("Unknown dataFormat "+i);s=[c,l,r[1],r[1]]}return Cn(r,s,e,n,o,a,!1,i)}function Kr(r,t,e,n,o,a,i){i===void 0&&(i="NDHWC");var s,u,c=ha(t),l=c[0],h=c[1],f=c[2];if(i==="NDHWC")u="channelsLast",s=[l,h,f,r[4],r[4]];else{if(i!=="NCDHW")throw new Error("Unknown dataFormat "+i);u="channelsFirst",s=[l,h,f,r[1],r[1]]}return Xr(r,s,e,n,o,!1,u,a)}function Cn(r,t,e,n,o,a,i,s){i===void 0&&(i=!1),s===void 0&&(s="channelsLast");var u=[-1,-1,-1,-1],c=u[0],l=u[1],h=u[2],f=u[3];if(s==="channelsLast")c=r[0],l=r[1],h=r[2],f=r[3];else{if(s!=="channelsFirst")throw new Error("Unknown dataFormat "+s);c=r[0],f=r[1],l=r[2],h=r[3]}var p,d=t[0],v=t[1],m=t[3],g=$r(e),x=g[0],b=g[1],y=$r(n),w=y[0],C=y[1],S=Ln(d,w),k=Ln(v,C),R=(function(O,B,V,W,U,G,H,q){var ee,te,ie;if(typeof O=="number"){ee={top:O,bottom:O,left:O,right:O,type:O===0?"VALID":"NUMBER"};var se=(function(fe,be,ge,Se,_e){Se==null&&(Se=au(fe,be,ge));var Ee=fe[0],bt=fe[1],wt=tr((Ee-be+2*Se)/ge+1,_e);I(Te(wt),(function(){return"The output # of rows ("+wt+") must be an integer. Change the stride and/or zero pad parameters"}));var ot=tr((bt-be+2*Se)/ge+1,_e);return I(Te(ot),(function(){return"The output # of columns ("+ot+") must be an integer. Change the stride and/or zero pad parameters"})),[wt,ot]})([B,V],G,W,O,q);te=se[0],ie=se[1]}else if(O==="same"){te=Math.ceil(B/W),ie=Math.ceil(V/U);var ce=Math.max(0,(te-1)*W+G-B),pe=Math.max(0,(ie-1)*U+H-V),he=Math.floor(ce/2),de=ce-he,Ae=Math.floor(pe/2);ee={top:he,bottom:de,left:Ae,right:pe-Ae,type:"SAME"}}else{if(O!=="valid")throw Error("Unknown padding parameter: "+O);ee={top:0,bottom:0,left:0,right:0,type:"VALID"},te=Math.ceil((B-G+1)/W),ie=Math.ceil((V-H+1)/U)}return{padInfo:ee,outHeight:te,outWidth:ie}})(o,l,h,x,b,S,k,a),E=R.padInfo,T=R.outHeight,A=R.outWidth,P=i?m*f:m;return s==="channelsFirst"?p=[c,P,T,A]:s==="channelsLast"&&(p=[c,T,A,P]),{batchSize:c,dataFormat:s,inHeight:l,inWidth:h,inChannels:f,outHeight:T,outWidth:A,outChannels:P,padInfo:E,strideHeight:x,strideWidth:b,filterHeight:d,filterWidth:v,effectiveFilterHeight:S,effectiveFilterWidth:k,dilationHeight:w,dilationWidth:C,inShape:r,outShape:p,filterShape:t}}function Xr(r,t,e,n,o,a,i,s){a===void 0&&(a=!1),i===void 0&&(i="channelsLast");var u=[-1,-1,-1,-1,-1],c=u[0],l=u[1],h=u[2],f=u[3],p=u[4];if(i==="channelsLast")c=r[0],l=r[1],h=r[2],f=r[3],p=r[4];else{if(i!=="channelsFirst")throw new Error("Unknown dataFormat "+i);c=r[0],p=r[1],l=r[2],h=r[3],f=r[4]}var d,v=t[0],m=t[1],g=t[2],x=t[4],b=ha(e),y=b[0],w=b[1],C=b[2],S=ha(n),k=S[0],R=S[1],E=S[2],T=Ln(v,k),A=Ln(m,R),P=Ln(g,E),O=(function(H,q,ee,te,ie,se,ce,pe,he,de,Ae){var fe,be,ge,Se;if(typeof H=="number"){fe={top:H,bottom:H,left:H,right:H,front:H,back:H,type:H===0?"VALID":"NUMBER"};var _e=(function(Rn,Ut,wo,kn,Ct,Co){Ct==null&&(Ct=au(Rn,Ut,kn));var qc=Rn[0],Kc=Rn[1],Xc=Rn[2],_o=tr((qc-Ut+2*Ct)/kn+1,Co);I(Te(_o),(function(){return"The output # of depths ("+_o+") must be an integer. Change the stride and/or zero pad parameters"}));var Eo=tr((Kc-Ut+2*Ct)/kn+1,Co);I(Te(Eo),(function(){return"The output # of rows ("+Eo+") must be an integer. Change the stride and/or zero pad parameters"}));var Io=tr((Xc-Ut+2*Ct)/kn+1,Co);return I(Te(Io),(function(){return"The output # of columns ("+Io+") must be an integer. Change the stride and/or zero pad parameters"})),[_o,Eo,Io,wo]})([q,ee,te,1],pe,1,ie,H,Ae);be=_e[0],ge=_e[1],Se=_e[2]}else if(H==="same"){be=Math.ceil(q/ie),ge=Math.ceil(ee/se),Se=Math.ceil(te/ce);var Ee=(be-1)*ie+pe-q,bt=(ge-1)*se+he-ee,wt=(Se-1)*ce+de-te,ot=Math.floor(Ee/2),In=Ee-ot,Lt=Math.floor(bt/2),Jt=bt-Lt,Wt=Math.floor(wt/2);fe={top:Lt,bottom:Jt,left:Wt,right:wt-Wt,front:ot,back:In,type:"SAME"}}else{if(H!=="valid")throw Error("Unknown padding parameter: "+H);fe={top:0,bottom:0,left:0,right:0,front:0,back:0,type:"VALID"},be=Math.ceil((q-pe+1)/ie),ge=Math.ceil((ee-he+1)/se),Se=Math.ceil((te-de+1)/ce)}return{padInfo:fe,outDepth:be,outHeight:ge,outWidth:Se}})(o,l,h,f,y,w,C,T,A,P,s),B=O.padInfo,V=O.outDepth,W=O.outHeight,U=O.outWidth,G=a?x*p:x;return i==="channelsFirst"?d=[c,G,V,W,U]:i==="channelsLast"&&(d=[c,V,W,U,G]),{batchSize:c,dataFormat:i,inDepth:l,inHeight:h,inWidth:f,inChannels:p,outDepth:V,outHeight:W,outWidth:U,outChannels:G,padInfo:B,strideDepth:y,strideHeight:w,strideWidth:C,filterDepth:v,filterHeight:m,filterWidth:g,effectiveFilterDepth:T,effectiveFilterHeight:A,effectiveFilterWidth:P,dilationDepth:k,dilationHeight:R,dilationWidth:E,inShape:r,outShape:d,filterShape:t}}function au(r,t,e,n){n===void 0&&(n=1);var o=Ln(t,n);return Math.floor((r[0]*(e-1)-e+o)/2)}function $r(r){return typeof r=="number"?[r,r,r]:r.length===2?[r[0],r[1],1]:r}function ha(r){return typeof r=="number"?[r,r,r]:r}function Ln(r,t){return t<=1?r:r+(r-1)*(t-1)}function tr(r,t){if(!t)return r;switch(t){case"round":return Math.round(r);case"ceil":return Math.ceil(r);case"floor":return Math.floor(r);default:throw new Error("Unknown roundingMode "+t)}}function Kn(r){var t=$r(r),e=t[0],n=t[1],o=t[2];return e===1&&n===1&&o===1}function rt(r,t){return Kn(r)||Kn(t)}function Ta(r){if(r==="NHWC")return"channelsLast";if(r==="NCHW")return"channelsFirst";throw new Error("Unknown dataFormat "+r)}function iu(r,t,e){if(t==="complex64"){if(r.dtype==="complex64")return r.clone();var n=Ce(r.shape),o=r.toFloat(),a=e.complex(o,n);return n.dispose(),o.dispose(),a}if(!il(r.dtype,t))return N.makeTensorFromDataId(r.dataId,r.shape,t);if(r.dtype==="complex64"){var i=e.real(r);return a=i.cast(t),i.dispose(),a}if(t==="int32")return e.int(r);if(t==="bool"){var s=j(0,r.dtype);return a=e.notEqual(r,s),s.dispose(),a}throw new Error("Error in Cast: failed to cast "+r.dtype+" to "+t)}function fa(r,t){return N.makeTensorFromDataId(r.dataId,t,r.dtype)}function su(r,t,e){var n=(t-r)/(e-1),o=hr(e,"float32");o[0]=r;for(var a=1;a<o.length;a++)o[a]=o[a-1]+n;return Ne(o,"float32")}function pa(r,t){if(r.length!==t.length)throw new Error("Cannot merge real and imag arrays of different lengths. real:"+r.length+", imag: "+t.length+".");for(var e=new Float32Array(2*r.length),n=0;n<e.length;n+=2)e[n]=r[n/2],e[n+1]=t[n/2];return e}function Wi(r,t){return{real:r[2*t],imag:r[2*t+1]}}function Ph(r,t,e,n){r[2*n]=t,r[2*n+1]=e}function Mh(r,t,e){var n=(e?2:-2)*Math.PI*(r/t);return{real:Math.cos(n),imag:Math.sin(n)}}function Oh(r,t,e){var n=(function(a,i,s){return(function(u,c,l){for(var h=0,f=u.length,p=0,d=!1;h<f;){var v=l(c,u[p=h+(f-h>>>1)]);v>0?h=p+1:(f=p,d=!v)}return d?h:-h-1})(a,i,s||Bh)})(r,t,e),o=n<0?-(n+1):n;r.splice(o,0,t)}function Bh(r,t){return r>t?1:r<t?-1:0}function Na(r,t,e,n,o){return uu(r,t,e,n,o,0).selectedIndices}function Fa(r,t,e,n,o,a){var i=uu(r,t,e,n,o,a);return i.numValidOutputs.dispose(),{selectedIndices:i.selectedIndices,selectedScores:i.selectedScores}}function uu(r,t,e,n,o,a,i,s){s===void 0&&(s=!1);for(var u=Array.from(t).map((function(y,w){return{score:y,boxIndex:w,suppressBeginIndex:0}})).filter((function(y){return y.score>o})).sort(Ui),c=a>0?-.5/a:0,l=[],h=[];l.length<e&&u.length>0;){var f=u.pop(),p=f.score,d=f.boxIndex,v=f.suppressBeginIndex;if(p<o)break;for(var m=!1,g=l.length-1;g>=v;--g){var x=Lh(r,d,l[g]);if(x>=n){m=!0;break}if(f.score=f.score*Wh(n,c,x),f.score<=o)break}f.suppressBeginIndex=l.length,m||(f.score===p?(l.push(d),h.push(f.score)):f.score>o&&Oh(u,f,Ui))}var b=l.length;return s&&(l.fill(0,b),h.fill(0,b)),{selectedIndices:Ne(l,"int32"),selectedScores:Ne(h,"float32"),numValidOutputs:j(b,"int32")}}function Lh(r,t,e){var n=r.subarray(4*t,4*t+4),o=r.subarray(4*e,4*e+4),a=Math.min(n[0],n[2]),i=Math.min(n[1],n[3]),s=Math.max(n[0],n[2]),u=Math.max(n[1],n[3]),c=Math.min(o[0],o[2]),l=Math.min(o[1],o[3]),h=Math.max(o[0],o[2]),f=Math.max(o[1],o[3]),p=(s-a)*(u-i),d=(h-c)*(f-l);if(p<=0||d<=0)return 0;var v=Math.max(a,c),m=Math.max(i,l),g=Math.min(s,h),x=Math.min(u,f),b=Math.max(g-v,0)*Math.max(x-m,0);return b/(p+d-b)}function Wh(r,t,e){var n=Math.exp(t*e*e);return e<=r?n:0}function Ui(r,t){return r.score-t.score||r.score===t.score&&t.boxIndex-r.boxIndex}function cu(r,t,e){var n=new Array(r.rank).fill(0),o=r.shape.slice();return t.map((function(a){o[e]=a;var i=r.slice(n,o);return n[e]+=a,i}))}function lu(r,t){for(var e=new Array(r.rank),n=0;n<e.length;n++)e[n]=r.shape[n]*t[n];var o=oe(e,r.dtype);for(n=0;n<o.values.length;++n){for(var a=o.indexToLoc(n),i=new Array(r.rank),s=0;s<i.length;s++)i[s]=a[s]%r.shape[s];var u=r.locToIndex(i);o.values[n]=r.values[u]}return o.toTensor()}function hu(r,t,e,n,o){for(var a=t[t.length-1],i=[r.length/a,a],s=i[0],u=i[1],c=rr(e,s*n),l=rr("int32",s*n),h=0;h<s;h++){for(var f=h*u,p=r.subarray(f,f+u),d=[],v=0;v<p.length;v++)d.push({value:p[v],index:v});d.sort((function(y,w){return w.value-y.value}));var m=h*n,g=c.subarray(m,m+n),x=l.subarray(m,m+n);for(v=0;v<n;v++)g[v]=d[v].value,x[v]=d[v].index}var b=t.slice();return b[b.length-1]=n,[je(c,b,e),je(l,b,"int32")]}function Pa(r,t){for(var e=[],n=0;n<t.length;n++)t[n]&&e.push(n);var o=oe(r,"int32"),a=oe([e.length,r.length],"int32");for(n=0;n<e.length;n++){var i=o.indexToLoc(e[n]),s=n*r.length;a.values.set(i,s)}return a.toTensor()}var Uh=function(r,t){this.outputShape=[],this.outputShape=r,this.variableNames=t.map((function(o,a){return"T"+a}));var e=[];this.variableNames.forEach((function(o){e.push("float v"+o+" = get"+o+"AtOutCoords();")}));var n=this.variableNames.map((function(o){return"v"+o})).join(" + ");this.userCode=`
      void main() {
        `+e.join(`
        `)+`

        float result = `+n+`;
        setOutput(result);
      }
    `},Vh=function(r,t){this.outputShape=[],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=r,this.variableNames=t.map((function(o,a){return"T"+a}));var e=[];this.variableNames.forEach((function(o){e.push("vec4 v"+o+" = get"+o+"AtOutCoords();")}));var n=this.variableNames.map((function(o){return"v"+o})).join(" + ");this.userCode=`
      void main() {
        `+e.join(`
        `)+`

        vec4 result = `+n+`;
        setOutput(result);
      }
    `},zh=function(r,t,e){this.variableNames=["A"];var n=r.windowSize,o=r.batchSize,a=r.inSize,i=Math.ceil(a/n);e||this.variableNames.push("bestIndicesA"),this.outputShape=[o,i];var s=t==="max"?">":"<",u=e?"inOffset + i;":"round(getBestIndicesA(batch, inOffset + i));";this.userCode=`
      void main() {
        ivec2 coords = getOutputCoords();
        int batch = coords[0];
        int outIdx = coords[1];
        int inOffset = outIdx * `+n+`;

        int bestIndex = inOffset;
        float bestValue = getA(batch, bestIndex);

        for (int i = 0; i < `+n+`; i++) {
          int inIdx = `+u+`;
          float candidate = getA(batch, inIdx);
          if (candidate `+s+` bestValue) {
            bestValue = candidate;
            bestIndex = inIdx;
          }
        }
        setOutput(float(bestIndex));
      }
    `};function fu(r,t){return["x","y","z","w","u","v"].slice(0,t).map((function(e){return r+"."+e}))}function et(r,t){return t===1?[r]:fu(r,t)}function Xe(){var r,t,e,n,o,a,i,s,u,c;return L().getNumber("WEBGL_VERSION")===2?(r="#version 300 es",t="in",e="out",n="in",o="texture",a="outputColor",i="out vec4 outputColor;",s=`
      bool isnan_custom(float val) {
        return (val > 0.0 || val < 0.0) ? false : val != 0.0;
      }

      bvec4 isnan_custom(vec4 val) {
        return bvec4(isnan_custom(val.x),
          isnan_custom(val.y), isnan_custom(val.z), isnan_custom(val.w));
      }

      #define isnan(value) isnan_custom(value)
    `,u="",c=`
      #define round(value) newRound(value)
      int newRound(float value) {
        return int(floor(value + 0.5));
      }

      ivec4 newRound(vec4 value) {
        return ivec4(floor(value + vec4(0.5)));
      }
    `):(r="",t="attribute",e="varying",n="varying",o="texture2D",a="gl_FragColor",i="",s=`
      #define isnan(value) isnan_custom(value)
      bool isnan_custom(float val) {
        return (val > 0. || val < 1. || val == 0.) ? false : true;
      }
      bvec4 isnan_custom(vec4 val) {
        return bvec4(isnan(val.x), isnan(val.y), isnan(val.z), isnan(val.w));
      }
    `,u=`
      uniform float INFINITY;

      bool isinf(float val) {
        return abs(val) == INFINITY;
      }
      bvec4 isinf(vec4 val) {
        return equal(abs(val), vec4(INFINITY));
      }
    `,c=`
      int round(float value) {
        return int(floor(value + 0.5));
      }

      ivec4 round(vec4 value) {
        return ivec4(floor(value + vec4(0.5)));
      }
    `),{version:r,attribute:t,varyingVs:e,varyingFs:n,texture2D:o,output:a,defineOutput:i,defineSpecialNaN:s,defineSpecialInf:u,defineRound:c}}function vn(r,t,e){e===void 0&&(e="index");var n=Tt(t);return n.map((function(o,a){return"int "+r[a]+" = "+e+" / "+o+"; "+(a===n.length-1?"int "+r[a+1]+" = "+e+" - "+r[a]+" * "+o:"index -= "+r[a]+" * "+o)+";"})).join("")}function Ma(r){var t=Tt(r).map((function(e){return e.toString()}));return`
  int getFlatIndex(ivec3 coords) {
    return coords.x * `+t[0]+" + coords.y * "+t[1]+` + coords.z;
  }
`}var pu=`
  const float FLOAT_MAX = 1.70141184e38;
  const float FLOAT_MIN = 1.17549435e-38;

  lowp vec4 encode_float(highp float v) {
    if (isnan(v)) {
      return vec4(255, 255, 255, 255);
    }

    highp float av = abs(v);

    if(av < FLOAT_MIN) {
      return vec4(0.0, 0.0, 0.0, 0.0);
    } else if(v > FLOAT_MAX) {
      return vec4(0.0, 0.0, 128.0, 127.0) / 255.0;
    } else if(v < -FLOAT_MAX) {
      return vec4(0.0, 0.0,  128.0, 255.0) / 255.0;
    }

    highp vec4 c = vec4(0,0,0,0);

    highp float e = floor(log2(av));
    highp float m = exp2(fract(log2(av))) - 1.0;

    c[2] = floor(128.0 * m);
    m -= c[2] / 128.0;
    c[1] = floor(32768.0 * m);
    m -= c[1] / 32768.0;
    c[0] = floor(8388608.0 * m);

    highp float ebias = e + 127.0;
    c[3] = floor(ebias / 2.0);
    ebias -= c[3] * 2.0;
    c[2] += floor(ebias) * 128.0;

    c[3] += 128.0 * step(0.0, -v);

    return c / 255.0;
  }
`;function Gh(r,t,e,n){var o=[];r.forEach((function(p){var d=Y(p.shapeInfo.logicalShape);p.shapeInfo.isUniform?o.push("uniform float "+p.name+(d>1?"["+d+"]":"")+";"):(o.push("uniform sampler2D "+p.name+";"),o.push("uniform int offset"+p.name+";"))}));var a,i,s=o.join(`
`),u=r.map((function(p){return(function(d,v,m){m===void 0&&(m=!1);var g="";g+=m?du(d):Nn(d);var x=d.shapeInfo.logicalShape,b=v.logicalShape;return x.length<=b.length&&(g+=m?(function(y,w){var C,S=y.name,k=S.charAt(0).toUpperCase()+S.slice(1),R="get"+k+"AtOutCoords",E=y.shapeInfo.logicalShape.length,T=w.logicalShape.length,A=en(y.shapeInfo.logicalShape,w.logicalShape),P=we(T),O=T-E,B=["x","y","z","w","u","v"];C=E===0?"":T<2&&A.length>=1?"coords = 0;":A.map((function(ee){return"coords."+B[ee+O]+" = 0;"})).join(`
`);var V="";V=T<2&&E>0?"coords":y.shapeInfo.logicalShape.map((function(ee,te){return"coords."+B[te+O]})).join(", ");var W="return outputValue;",U=Y(y.shapeInfo.logicalShape)===1,G=Y(w.logicalShape)===1;if(E!==1||U||G){if(U&&!G)W=T===1?`
        return vec4(outputValue.x, outputValue.x, 0., 0.);
      `:`
        return vec4(outputValue.x);
      `;else if(A.length){var H=E-2,q=E-1;A.indexOf(H)>-1&&A.indexOf(q)>-1?W="return vec4(outputValue.x);":A.indexOf(H)>-1?W="return vec4(outputValue.x, outputValue.y, outputValue.x, outputValue.y);":A.indexOf(q)>-1&&(W="return vec4(outputValue.xx, outputValue.zz);")}}else W=`
      return vec4(outputValue.xy, outputValue.xy);
    `;return`
    vec4 `+R+`() {
      `+P+` coords = getOutputCoords();
      `+C+`
      vec4 outputValue = get`+k+"("+V+`);
      `+W+`
    }
  `})(d,v):(function(y,w){var C=y.name,S=C.charAt(0).toUpperCase()+C.slice(1),k="get"+S+"AtOutCoords",R=w.texShape,E=y.shapeInfo.texShape,T=y.shapeInfo.logicalShape.length,A=w.logicalShape.length;if(!y.shapeInfo.isUniform&&T===A&&y.shapeInfo.flatOffset==null&&Ue(E,R))return`
      float `+k+`() {
        return sampleTexture(`+C+`, resultUV);
      }
    `;var P,O=we(A),B=en(y.shapeInfo.logicalShape,w.logicalShape),V=A-T,W=["x","y","z","w","u","v"];P=T===0?"":A<2&&B.length>=1?"coords = 0;":B.map((function(G){return"coords."+W[G+V]+" = 0;"})).join(`
`);var U="";return U=A<2&&T>0?"coords":y.shapeInfo.logicalShape.map((function(G,H){return"coords."+W[H+V]})).join(", "),`
    float `+k+`() {
      `+O+` coords = getOutputCoords();
      `+P+`
      return get`+S+"("+U+`);
    }
  `})(d,v)),g})(p,t,n)})).join(`
`),c=t.texShape,l=Xe(),h=(function(p){return`
    float sampleTexture(sampler2D textureSampler, vec2 uv) {
      return `+p.texture2D+`(textureSampler, uv).r;
    }
  `})(l),f=(function(p){return p.version+`
    precision highp float;
    precision highp int;
    precision highp sampler2D;
    `+p.varyingFs+` vec2 resultUV;
    `+p.defineOutput+`
    const vec2 halfCR = vec2(0.5, 0.5);

    struct ivec5
    {
      int x;
      int y;
      int z;
      int w;
      int u;
    };

    struct ivec6
    {
      int x;
      int y;
      int z;
      int w;
      int u;
      int v;
    };

    uniform float NAN;
    `+p.defineSpecialNaN+`
    `+p.defineSpecialInf+`
    `+p.defineRound+`

    int imod(int x, int y) {
      return x - y * (x / y);
    }

    int idiv(int a, int b, float sign) {
      int res = a / b;
      int mod = imod(a, b);
      if (sign < 0. && mod != 0) {
        res -= 1;
      }
      return res;
    }

    //Based on the work of Dave Hoskins
    //https://www.shadertoy.com/view/4djSRW
    #define HASHSCALE1 443.8975
    float random(float seed){
      vec2 p = resultUV * seed;
      vec3 p3  = fract(vec3(p.xyx) * HASHSCALE1);
      p3 += dot(p3, p3.yzx + 19.19);
      return fract((p3.x + p3.y) * p3.z);
    }

    `+Hh+`
    `+jh+`
    `+qh+`
  `})(l);return t.isPacked?(a=(function(p,d){switch(p.length){case 0:return`
    int getOutputCoords() {
      return 0;
    }
  `;case 1:return(function(y,w){var C=[Math.ceil(w[0]/2),Math.ceil(w[1]/2)];return C[0]===1?`
      int getOutputCoords() {
        return 2 * int(resultUV.x * `+C[1]+`.0);
      }
    `:C[1]===1?`
      int getOutputCoords() {
        return 2 * int(resultUV.y * `+C[0]+`.0);
      }
    `:`
    int getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
                             vec2(`+C[0]+", "+C[1]+`));
      return 2 * (resTexRC.x * `+C[1]+` + resTexRC.y);
    }
  `})(0,d);case 2:return(function(y,w){var C=[Math.ceil(w[0]/2),Math.ceil(w[1]/2)];if(Ue(y,w))return`
      ivec2 getOutputCoords() {
        return 2 * ivec2(resultUV.yx * vec2(`+C[0]+", "+C[1]+`));
      }
    `;var S=Math.ceil(y[1]/2);return`
    ivec2 getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
                             vec2(`+C[0]+", "+C[1]+`));

      int index = resTexRC.x * `+C[1]+` + resTexRC.y;
      int r = 2 * (index / `+S+`);
      int c = imod(index, `+S+`) * 2;

      return ivec2(r, c);
    }
  `})(p,d);case 3:return v=p,m=d,g=[Math.ceil(m[0]/2),Math.ceil(m[1]/2)],x=Math.ceil(v[2]/2),b=x*Math.ceil(v[1]/2),`
    ivec3 getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
                             vec2(`+g[0]+", "+g[1]+`));
      int index = resTexRC.x * `+g[1]+` + resTexRC.y;

      int b = index / `+b+`;
      index -= b * `+b+`;

      int r = 2 * (index / `+x+`);
      int c = imod(index, `+x+`) * 2;

      return ivec3(b, r, c);
    }
  `;default:return(function(y,w){for(var C=[Math.ceil(w[0]/2),Math.ceil(w[1]/2)],S=Math.ceil(y[y.length-1]/2),k=S*Math.ceil(y[y.length-2]/2),R=k,E="",T="b, r, c",A=2;A<y.length-1;A++)R*=y[y.length-A-1],E=`
      int b`+A+" = index / "+R+`;
      index -= b`+A+" * "+R+`;
    `+E,T="b"+A+", "+T;return`
    ivec`+y.length+` getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
                             vec2(`+C[0]+", "+C[1]+`));
      int index = resTexRC.x * `+C[1]+` + resTexRC.y;

      `+E+`

      int b = index / `+k+`;
      index -= b * `+k+`;

      int r = 2 * (index / `+S+`);
      int c = imod(index, `+S+`) * 2;

      return ivec`+y.length+"("+T+`);
    }
  `})(p,d)}var v,m,g,x,b})(t.logicalShape,c),i=(function(p){return`
    void setOutput(vec4 val) {
      `+p.output+` = val;
    }
  `})(l)):(a=(function(p,d){switch(p.length){case 0:return`
    int getOutputCoords() {
      return 0;
    }
  `;case 1:return(function(g,x){return x[0]===1?`
      int getOutputCoords() {
        return int(resultUV.x * `+x[1]+`.0);
      }
    `:x[1]===1?`
      int getOutputCoords() {
        return int(resultUV.y * `+x[0]+`.0);
      }
    `:`
    int getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
                             vec2(`+x[0]+", "+x[1]+`));
      return resTexRC.x * `+x[1]+` + resTexRC.y;
    }
  `})(0,d);case 2:return(function(g,x){return Ue(g,x)?`
      ivec2 getOutputCoords() {
        return ivec2(resultUV.yx * vec2(`+x[0]+", "+x[1]+`));
      }
    `:g[1]===1?`
      ivec2 getOutputCoords() {
        ivec2 resTexRC = ivec2(resultUV.yx *
                               vec2(`+x[0]+", "+x[1]+`));
        int index = resTexRC.x * `+x[1]+` + resTexRC.y;
        return ivec2(index, 0);
      }
    `:g[0]===1?`
      ivec2 getOutputCoords() {
        ivec2 resTexRC = ivec2(resultUV.yx *
                               vec2(`+x[0]+", "+x[1]+`));
        int index = resTexRC.x * `+x[1]+` + resTexRC.y;
        return ivec2(0, index);
      }
    `:`
    ivec2 getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
                             vec2(`+x[0]+", "+x[1]+`));
      int index = resTexRC.x * `+x[1]+` + resTexRC.y;
      int r = index / `+g[1]+`;
      int c = index - r * `+g[1]+`;
      return ivec2(r, c);
    }
  `})(p,d);case 3:return v=d,m=vn(["r","c","d"],p),`
    ivec3 getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
                             vec2(`+v[0]+", "+v[1]+`));
      int index = resTexRC.x * `+v[1]+` + resTexRC.y;
      `+m+`
      return ivec3(r, c, d);
    }
  `;case 4:return(function(g,x){var b=vn(["r","c","d","d2"],g);return`
    ivec4 getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
        vec2(`+x[0]+", "+x[1]+`));
      int index = resTexRC.x * `+x[1]+` + resTexRC.y;
      `+b+`
      return ivec4(r, c, d, d2);
    }
  `})(p,d);case 5:return(function(g,x){var b=vn(["r","c","d","d2","d3"],g);return`
    ivec5 getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx * vec2(`+x[0]+`,
                             `+x[1]+`));

      int index = resTexRC.x * `+x[1]+` + resTexRC.y;

      `+b+`

      ivec5 outShape = ivec5(r, c, d, d2, d3);
      return outShape;
    }
  `})(p,d);case 6:return(function(g,x){var b=vn(["r","c","d","d2","d3","d4"],g);return`
    ivec6 getOutputCoords() {
      ivec2 resTexRC = ivec2(resultUV.yx *
        vec2(`+x[0]+", "+x[1]+`));
      int index = resTexRC.x * `+x[1]+` + resTexRC.y;

      `+b+`

      ivec6 result = ivec6(r, c, d, d2, d3, d4);
      return result;
    }
  `})(p,d);default:throw new Error(p.length+"-D output sampling is not yet supported")}var v,m})(t.logicalShape,c),i=(function(p){return`
    void setOutput(float val) {
      `+p.output+` = vec4(val, 0, 0, 0);
    }
  `})(l)),n&&(f+=Kh),[f,h,i,s,a,u,e].join(`
`)}function Nn(r){var t=r.shapeInfo.logicalShape;switch(t.length){case 0:return(function(e){var n=e.name,o="get"+n.charAt(0).toUpperCase()+n.slice(1);if(e.shapeInfo.isUniform)return"float "+o+"() {return "+n+";}";var a=e.shapeInfo.texShape,i=a[0],s=a[1];if(i===1&&s===1)return`
      float `+o+`() {
        return sampleTexture(`+n+`, halfCR);
      }
    `;var u=e.shapeInfo.texShape,c=u[0],l=u[1],h=hn(n);return`
    float `+o+`() {
      vec2 uv = uvFromFlat(`+c+", "+l+", "+h+`);
      return sampleTexture(`+n+`, uv);
    }
  `})(r);case 1:return(function(e){var n=e.name,o="get"+n.charAt(0).toUpperCase()+n.slice(1);if(e.shapeInfo.isUniform)return`
      float `+o+`(int index) {
        `+Sn(e)+`
      }
    `;var a=e.shapeInfo.texShape,i=a[0],s=a[1];if(s===1&&i===1)return`
      float `+o+`(int index) {
        return sampleTexture(`+n+`, halfCR);
      }
    `;var u=hn(n);return s===1?`
      float `+o+`(int index) {
        vec2 uv = vec2(0.5, (float(index + `+u+") + 0.5) / "+i+`.0);
        return sampleTexture(`+n+`, uv);
      }
    `:i===1?`
      float `+o+`(int index) {
        vec2 uv = vec2((float(index + `+u+") + 0.5) / "+s+`.0, 0.5);
        return sampleTexture(`+n+`, uv);
      }
    `:`
    float `+o+`(int index) {
      vec2 uv = uvFromFlat(`+i+", "+s+", index + "+u+`);
      return sampleTexture(`+n+`, uv);
    }
  `})(r);case 2:return(function(e){var n=e.shapeInfo.logicalShape,o=e.name,a="get"+o.charAt(0).toUpperCase()+o.slice(1),i=e.shapeInfo.texShape;if(i!=null&&Ue(n,i)){var s=i[0],u=i[1];return`
    float `+a+`(int row, int col) {
      vec2 uv = (vec2(col, row) + halfCR) / vec2(`+u+".0, "+s+`.0);
      return sampleTexture(`+o+`, uv);
    }
  `}var c=dn(n),l=c.newShape,h=c.keptDims,f=l;if(f.length<n.length){var p=Fn(e,f);return`
      `+Nn(p)+`
      float `+a+`(int row, int col) {
        return `+a+"("+Pn(["row","col"],h)+`);
      }
    `}if(e.shapeInfo.isUniform)return`
      float `+a+`(int row, int col) {
        int index = round(dot(vec2(row, col), vec2(`+n[1]+`, 1)));
        `+Sn(e)+`
      }
    `;var d=i[0],v=i[1],m=hn(o);return v===1?`
    float `+a+`(int row, int col) {
      float index = dot(vec3(row, col, `+m+"), vec3("+n[1]+`, 1, 1));
      vec2 uv = vec2(0.5, (index + 0.5) / `+d+`.0);
      return sampleTexture(`+o+`, uv);
    }
  `:d===1?`
    float `+a+`(int row, int col) {
      float index = dot(vec3(row, col, `+m+"), vec3("+n[1]+`, 1, 1));
      vec2 uv = vec2((index + 0.5) / `+v+`.0, 0.5);
      return sampleTexture(`+o+`, uv);
    }
  `:`
  float `+a+`(int row, int col) {
    // Explicitly use integer operations as dot() only works on floats.
    int index = row * `+n[1]+" + col + "+m+`;
    vec2 uv = uvFromFlat(`+d+", "+v+`, index);
    return sampleTexture(`+o+`, uv);
  }
`})(r);case 3:return(function(e){var n=e.shapeInfo.logicalShape,o=e.name,a="get"+o.charAt(0).toUpperCase()+o.slice(1),i=n[1]*n[2],s=n[2],u=dn(n),c=u.newShape,l=u.keptDims,h=c;if(h.length<n.length){var f=Fn(e,h);return`
        `+Nn(f)+`
        float `+a+`(int row, int col, int depth) {
          return `+a+"("+Pn(["row","col","depth"],l)+`);
        }
      `}if(e.shapeInfo.isUniform)return`
      float `+a+`(int row, int col, int depth) {
        int index = round(dot(vec3(row, col, depth),
                          vec3(`+i+", "+s+`, 1)));
        `+Sn(e)+`
      }
    `;var p=e.shapeInfo.texShape,d=p[0],v=p[1],m=e.shapeInfo.flatOffset;if(v===i&&m==null)return`
        float `+a+`(int row, int col, int depth) {
          float texR = float(row);
          float texC = dot(vec2(col, depth), vec2(`+s+`, 1));
          vec2 uv = (vec2(texC, texR) + halfCR) /
                     vec2(`+v+".0, "+d+`.0);
          return sampleTexture(`+o+`, uv);
        }
      `;if(v===s&&m==null)return`
    float `+a+`(int row, int col, int depth) {
      float texR = dot(vec2(row, col), vec2(`+n[1]+`, 1));
      float texC = float(depth);
      vec2 uv = (vec2(texC, texR) + halfCR) / vec2(`+v+".0, "+d+`.0);
      return sampleTexture(`+o+`, uv);
    }
  `;var g=hn(o);return`
      float `+a+`(int row, int col, int depth) {
        // Explicitly use integer operations as dot() only works on floats.
        int index = row * `+i+" + col * "+s+" + depth + "+g+`;
        vec2 uv = uvFromFlat(`+d+", "+v+`, index);
        return sampleTexture(`+o+`, uv);
      }
  `})(r);case 4:return(function(e){var n=e.shapeInfo.logicalShape,o=e.name,a="get"+o.charAt(0).toUpperCase()+o.slice(1),i=n[3],s=n[2]*i,u=n[1]*s,c=dn(n),l=c.newShape,h=c.keptDims;if(l.length<n.length){var f=Fn(e,l);return`
      `+Nn(f)+`
      float `+a+`(int row, int col, int depth, int depth2) {
        return `+a+"("+Pn(["row","col","depth","depth2"],h)+`);
      }
    `}if(e.shapeInfo.isUniform)return`
      float `+a+`(int row, int col, int depth, int depth2) {
        int index = round(dot(vec4(row, col, depth, depth2),
                          vec4(`+u+", "+s+", "+i+`, 1)));
        `+Sn(e)+`
      }
    `;var p=e.shapeInfo.flatOffset,d=e.shapeInfo.texShape,v=d[0],m=d[1];if(m===u&&p==null)return`
      float `+a+`(int row, int col, int depth, int depth2) {
        float texR = float(row);
        float texC =
            dot(vec3(col, depth, depth2),
                vec3(`+s+", "+i+`, 1));
        vec2 uv = (vec2(texC, texR) + halfCR) /
                   vec2(`+m+".0, "+v+`.0);
        return sampleTexture(`+o+`, uv);
      }
    `;if(m===i&&p==null)return`
      float `+a+`(int row, int col, int depth, int depth2) {
        float texR = dot(vec3(row, col, depth),
                         vec3(`+n[1]*n[2]+", "+n[2]+`, 1));
        float texC = float(depth2);
        vec2 uv = (vec2(texC, texR) + halfCR) /
                  vec2(`+m+".0, "+v+`.0);
        return sampleTexture(`+o+`, uv);
      }
    `;var g=hn(o);return`
    float `+a+`(int row, int col, int depth, int depth2) {
      // Explicitly use integer operations as dot() only works on floats.
      int index = row * `+u+" + col * "+s+` +
          depth * `+i+` + depth2;
      vec2 uv = uvFromFlat(`+v+", "+m+", index + "+g+`);
      return sampleTexture(`+o+`, uv);
    }
  `})(r);case 5:return(function(e){var n=e.shapeInfo.logicalShape,o=e.name,a="get"+o.charAt(0).toUpperCase()+o.slice(1),i=n[4],s=n[3]*i,u=n[2]*s,c=n[1]*u,l=dn(n),h=l.newShape,f=l.keptDims;if(h.length<n.length){var p=Fn(e,h);return`
      `+Nn(p)+`
      float `+a+`(int row, int col, int depth, int depth2, int depth3) {
        return `+a+"("+Pn(["row","col","depth","depth2","depth3"],f)+`);
      }
    `}if(e.shapeInfo.isUniform)return`
      float `+a+`(int row, int col, int depth, int depth2, int depth3) {
        float index = dot(
          vec4(row, col, depth, depth2),
          vec4(`+c+", "+u+", "+s+", "+i+`)) +
          depth3;
        `+Sn(e)+`
      }
    `;var d=e.shapeInfo.flatOffset,v=e.shapeInfo.texShape,m=v[0],g=v[1];if(g===c&&d==null)return`
      float `+a+`(int row, int col, int depth, int depth2, int depth3) {
        int texR = row;
        float texC = dot(vec4(col, depth, depth2, depth3),
                         vec4(`+u+", "+s+", "+i+`, 1));
        vec2 uv = (vec2(texC, texR) + halfCR) /
                   vec2(`+g+".0, "+m+`.0);
        return sampleTexture(`+o+`, uv);
      }
    `;if(g===i&&d==null)return`
      float `+a+`(int row, int col, int depth, int depth2, int depth3) {
        float texR = dot(
          vec4(row, col, depth, depth2),
          vec4(`+n[1]*n[2]*n[3]+`,
               `+n[2]*n[3]+", "+n[3]+`, 1));
        int texC = depth3;
        vec2 uv = (vec2(texC, texR) + halfCR) /
                  vec2(`+g+".0, "+m+`.0);
        return sampleTexture(`+o+`, uv);
      }
    `;var x=hn(o);return`
    float `+a+`(int row, int col, int depth, int depth2, int depth3) {
      // Explicitly use integer operations as dot() only works on floats.
      int index = row * `+c+" + col * "+u+" + depth * "+s+` +
          depth2 * `+i+" + depth3 + "+x+`;
      vec2 uv = uvFromFlat(`+m+", "+g+`, index);
      return sampleTexture(`+o+`, uv);
    }
  `})(r);case 6:return(function(e){var n=e.shapeInfo.logicalShape,o=e.name,a="get"+o.charAt(0).toUpperCase()+o.slice(1),i=dn(n),s=i.newShape,u=i.keptDims;if(s.length<n.length){var c=Fn(e,s);return`
      `+Nn(c)+`
      float `+a+`(int row, int col, int depth,
                    int depth2, int depth3, int depth4) {
        return `+a+"("+Pn(["row","col","depth","depth2","depth3","depth4"],u)+`);
      }
    `}var l=n[5],h=n[4]*l,f=n[3]*h,p=n[2]*f,d=n[1]*p;if(e.shapeInfo.isUniform)return`
      float `+a+`(int row, int col, int depth,
                  int depth2, int depth3, int depth4) {
        int index = round(dot(
          vec4(row, col, depth, depth2),
          vec4(`+d+", "+p+", "+f+", "+h+`)) +
          dot(
            vec2(depth3, depth4),
            vec2(`+l+`, 1)));
        `+Sn(e)+`
      }
    `;var v=e.shapeInfo.flatOffset,m=e.shapeInfo.texShape,g=m[0],x=m[1];if(x===d&&v==null)return`
      float `+a+`(int row, int col, int depth,
                    int depth2, int depth3, int depth4) {
        int texR = row;
        float texC = dot(vec4(col, depth, depth2, depth3),
          vec4(`+p+", "+f+", "+h+", "+l+`)) +
               float(depth4);
        vec2 uv = (vec2(texC, texR) + halfCR) /
                   vec2(`+x+".0, "+g+`.0);
        return sampleTexture(`+o+`, uv);
      }
    `;if(x===l&&v==null)return`
      float `+a+`(int row, int col, int depth,
                    int depth2, int depth3, int depth4) {
        float texR = dot(vec4(row, col, depth, depth2),
          vec4(`+n[1]*n[2]*n[3]*n[4]+`,
               `+n[2]*n[3]*n[4]+`,
               `+n[3]*n[4]+`,
               `+n[4]+`)) + float(depth3);
        int texC = depth4;
        vec2 uv = (vec2(texC, texR) + halfCR) /
                  vec2(`+x+".0, "+g+`.0);
        return sampleTexture(`+o+`, uv);
      }
    `;var b=hn(o);return`
    float `+a+`(int row, int col, int depth,
                  int depth2, int depth3, int depth4) {
      // Explicitly use integer operations as dot() only works on floats.
      int index = row * `+d+" + col * "+p+" + depth * "+f+` +
          depth2 * `+h+" + depth3 * "+l+" + depth4 + "+b+`;
      vec2 uv = uvFromFlat(`+g+", "+x+`, index);
      return sampleTexture(`+o+`, uv);
    }
  `})(r);default:throw new Error(t.length+"-D input sampling is not yet supported")}}function du(r){var t,e,n;switch(r.shapeInfo.logicalShape.length){case 0:return t=r.name,e="get"+t.charAt(0).toUpperCase()+t.slice(1),n=Xe(),`
    vec4 `+e+`() {
      return `+n.texture2D+"("+t+`, halfCR);
    }
  `;case 1:return(function(o){var a=o.name,i="get"+a.charAt(0).toUpperCase()+a.slice(1),s=o.shapeInfo.texShape,u=[Math.ceil(s[0]/2),Math.ceil(s[1]/2)],c=Xe();return`
    vec4 `+i+`(int index) {
      vec2 uv = packedUVfrom1D(
        `+u[0]+", "+u[1]+`, index);
      return `+c.texture2D+"("+a+`, uv);
    }
  `})(r);case 2:return(function(o){var a=o.shapeInfo.logicalShape,i=o.name,s="get"+i.charAt(0).toUpperCase()+i.slice(1),u=o.shapeInfo.texShape,c=u[0],l=u[1],h=Xe();if(u!=null&&Ue(a,u))return`
      vec4 `+s+`(int row, int col) {
        vec2 uv = (vec2(col, row) + halfCR) / vec2(`+l+".0, "+c+`.0);

        return `+h.texture2D+"("+i+`, uv);
      }
    `;var f=[Math.ceil(u[0]/2),Math.ceil(u[1]/2)],p=Math.ceil(a[1]/2);return`
    vec4 `+s+`(int row, int col) {
      vec2 uv = packedUVfrom2D(`+p+", "+f[0]+", "+f[1]+`, row, col);
      return `+h.texture2D+"("+i+`, uv);
    }
  `})(r);case 3:return(function(o){var a=o.shapeInfo.logicalShape,i=o.name,s="get"+i.charAt(0).toUpperCase()+i.slice(1),u=o.shapeInfo.texShape,c=[Math.ceil(u[0]/2),Math.ceil(u[1]/2)];if(a[0]===1){var l=a.slice(1),h=Fn(o,l);return`
        `+du(h)+`
        vec4 `+s+`(int b, int row, int col) {
          return `+s+"("+Pn(["b","row","col"],[1,2])+`);
        }
      `}var f=c[0],p=c[1],d=Math.ceil(a[2]/2),v=d*Math.ceil(a[1]/2),m=Xe();return`
    vec4 `+s+`(int b, int row, int col) {
      vec2 uv = packedUVfrom3D(
        `+f+", "+p+", "+v+", "+d+`, b, row, col);
      return `+m.texture2D+"("+i+`, uv);
    }
  `})(r);default:return(function(o){for(var a=o.shapeInfo.logicalShape,i=a.length,s=o.name,u="get"+s.charAt(0).toUpperCase()+s.slice(1),c=o.shapeInfo.texShape,l=[Math.ceil(c[0]/2),Math.ceil(c[1]/2)],h=l[0],f=l[1],p=Math.ceil(a[i-1]/2),d=p*Math.ceil(a[i-2]/2),v="int b, int row, int col",m="b * "+d+" + (row / 2) * "+p+" + (col / 2)",g=2;g<i-1;g++)v="int b"+g+", "+v,d*=a[i-g-1],m="b"+g+" * "+d+" + "+m;var x=Xe();return`
    vec4 `+u+"("+v+`) {
      int index = `+m+`;
      int texR = index / `+f+`;
      int texC = index - texR * `+f+`;
      vec2 uv = (vec2(texC, texR) + halfCR) / vec2(`+f+", "+h+`);
      return `+x.texture2D+"("+s+`, uv);
    }
  `})(r)}}var Hh=`
vec2 uvFromFlat(int texNumR, int texNumC, int index) {
  int texR = index / texNumC;
  int texC = index - texR * texNumC;
  return (vec2(texC, texR) + halfCR) / vec2(texNumC, texNumR);
}
vec2 packedUVfrom1D(int texNumR, int texNumC, int index) {
  int texelIndex = index / 2;
  int texR = texelIndex / texNumC;
  int texC = texelIndex - texR * texNumC;
  return (vec2(texC, texR) + halfCR) / vec2(texNumC, texNumR);
}
`,jh=`
vec2 packedUVfrom2D(int texelsInLogicalRow, int texNumR,
  int texNumC, int row, int col) {
  int texelIndex = (row / 2) * texelsInLogicalRow + (col / 2);
  int texR = texelIndex / texNumC;
  int texC = texelIndex - texR * texNumC;
  return (vec2(texC, texR) + halfCR) / vec2(texNumC, texNumR);
}
`,qh=`
vec2 packedUVfrom3D(int texNumR, int texNumC,
    int texelsInBatch, int texelsInLogicalRow, int b,
    int row, int col) {
  int index = b * texelsInBatch + (row / 2) * texelsInLogicalRow + (col / 2);
  int texR = index / texNumC;
  int texC = index - texR * texNumC;
  return (vec2(texC, texR) + halfCR) / vec2(texNumC, texNumR);
}
`,Kh=`
  float getChannel(vec4 frag, vec2 innerDims) {
    vec2 modCoord = mod(innerDims, 2.);
    return modCoord.x == 0. ?
      (modCoord.y == 0. ? frag.r : frag.g) :
      (modCoord.y == 0. ? frag.b : frag.a);
  }
  float getChannel(vec4 frag, int dim) {
    float modCoord = mod(float(dim), 2.);
    return modCoord == 0. ? frag.r : frag.g;
  }
`;function hn(r){return"offset"+r}function Sn(r){var t=r.name,e=Y(r.shapeInfo.logicalShape);return e<2?"return "+t+";":`
    for (int i = 0; i < `+e+`; i++) {
      if (i == index) {
        return `+t+`[i];
      }
    }
  `}function we(r){if(r<=1)return"int";if(r===2)return"ivec2";if(r===3)return"ivec3";if(r===4)return"ivec4";if(r===5)return"ivec5";if(r===6)return"ivec6";throw Error("GPU for rank "+r+" is not yet supported")}function Fn(r,t){var e=JSON.parse(JSON.stringify(r));return e.shapeInfo.logicalShape=t,e}function Pn(r,t){return t.map((function(e){return r[e]})).join(", ")}var Xh=function(r,t,e,n){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!0,I(r.length>2,(function(){return"Packed arg"+(e.charAt(0).toUpperCase()+e.slice(1))+" supports only inputs with rank above 2."}));var o=r[r.length-1],a=Math.ceil(o/t);this.outputShape=r.slice(0,-1),a>1&&this.outputShape.push(a),n||this.variableNames.push("bestIndicesA");var i,s,u=this.outputShape,c=u.length,l=we(c),h=et("coords",c);if(a===1){var f=we(s=c+1);i=`
        `+f+" sourceLocR = "+f+"("+h.join()+`, 0);
        ++`+h[c-1]+`;
        `+f+" sourceLocG = "+f+"("+h.join()+`, 0);
        ++`+h[c-2]+`;
        `+f+" sourceLocA = "+f+"("+h.join()+`, 0);
        --`+h[c-1]+`;
        `+f+" sourceLocB = "+f+"("+h.join()+`, 0);
        --`+h[c-2]+";"}else s=c,i=`
        `+l+` sourceLocR = coords;
        ++`+h[c-1]+`;
        `+l+` sourceLocG = coords;
        ++`+h[c-2]+`;
        `+l+` sourceLocA = coords;
        --`+h[c-1]+`;
        `+l+` sourceLocB = coords;
        --`+h[c-2]+";";var p=["x","y","z","w","u","v"].slice(0,s),d="."+p[s-1],v=p.map((function(k){return"int "+k})),m=et("sourceLocR",s-1).concat("inIdx.r"),g=et("sourceLocG",s-1).concat("inIdx.g"),x=et("sourceLocB",s-1).concat("inIdx.b"),b=et("sourceLocA",s-1).concat("inIdx.a"),y=e==="max"?"greaterThan":"lessThan",w=n?"":`
          inIdx = round(vec4(getBestIndicesAChannel(`+m.join()+`),
                             getBestIndicesAChannel(`+g.join()+`),
                             getBestIndicesAChannel(`+x.join()+`),
                             getBestIndicesAChannel(`+b.join()+")));",C=`vec4(
            getAChannel(`+m.join()+`),
            hasNextCol ? getAChannel(`+g.join()+`) : 0.,
            hasNextRow ? getAChannel(`+x.join()+`) : 0.,
            hasNextRow && hasNextCol ? getAChannel(`+b.join()+") : 0.)",S=n?"":`
      float getBestIndicesAChannel(`+v.join()+`) {
        return getChannel(getBestIndicesA(`+p.join()+`),
                                          vec2(`+p.slice(-2).join()+`));
      }`;this.userCode=`
      float getAChannel(`+v.join()+`) {
        return getChannel(getA(`+p.join()+`),
                               vec2(`+p.slice(-2).join()+`));
      }
      `+S+`
      void main() {
        `+l+` coords = getOutputCoords();
        bool hasNextCol = `+h[c-1]+" < "+(u[c-1]-1)+`;
        bool hasNextRow = `+h[c-2]+" < "+(u[c-2]-1)+`;
        `+i+`
        ivec4 srcIdx = ivec4(sourceLocR`+d+", sourceLocG"+d+`,
          sourceLocB`+d+", sourceLocA"+d+") * "+t+`;
        ivec4 inIdx = srcIdx;
        vec4 bestIndex = vec4(inIdx);
        vec4 bestValue = `+C+`;

        for (int i = 0; i < `+t+`; i++) {
          inIdx = srcIdx;
          `+w+`
          vec4 candidate = `+C+`;
          bvec4 nan = isnan(candidate);
          bvec4 replace = bvec4(
            vec4(`+y+`(candidate, bestValue)) * (vec4(1.0) - vec4(nan)));

          bestValue = vec4(replace.x  ? candidate.x : bestValue.x,
                           replace.y  ? candidate.y : bestValue.y,
                           replace.z  ? candidate.z : bestValue.z,
                           replace.w  ? candidate.w : bestValue.w);
          bestIndex = mix(bestIndex, vec4(inIdx), vec4(replace));
          srcIdx++;
        }
        setOutput(bestIndex);
      }
    `},$h=function(r){this.variableNames=["dy"],this.outputShape=r.inShape;var t=r.filterHeight,e=r.filterWidth,n=r.strideHeight,o=r.strideWidth,a=r.dilationHeight,i=r.dilationWidth,s=r.effectiveFilterHeight,u=r.effectiveFilterWidth,c=s-1-r.padInfo.top,l=u-1-r.padInfo.left,h=1/(t*e);this.userCode=`
      const ivec2 pads = ivec2(`+c+", "+l+`);
      const float avgMultiplier = float(`+h+`);

      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int d = coords[3];

        ivec2 dyRCCorner = coords.yz - pads;
        int dyRCorner = dyRCCorner.x;
        int dyCCorner = dyRCCorner.y;

        // Convolve dy(?, ?, d) with pos mask(:, :, d) to get dx(xR, xC, d).
        // ? = to be determined. : = across all values in that axis.
        float dotProd = 0.0;
        for (int wR = 0; wR < `+s+`;
            wR += `+a+`) {
          float dyR = float(dyRCorner + wR) / `+n+`.0;

          if (dyR < 0.0 || dyR >= `+r.outHeight+`.0 || fract(dyR) > 0.0) {
            continue;
          }
          int idyR = int(dyR);

          for (int wC = 0; wC < `+u+`;
            wC+= `+i+`) {
            float dyC = float(dyCCorner + wC) / `+o+`.0;

            if (dyC < 0.0 || dyC >= `+r.outWidth+`.0 ||
                fract(dyC) > 0.0) {
              continue;
            }
            int idyC = int(dyC);

            float dyValue = getDy(b, idyR, idyC, d);

            dotProd += dyValue * avgMultiplier;
          }
        }
        setOutput(dotProd);
      }
    `},Yh=function(r){this.variableNames=["dy"],this.outputShape=r.inShape;var t=r.filterDepth,e=r.filterHeight,n=r.filterWidth,o=r.strideDepth,a=r.strideHeight,i=r.strideWidth,s=r.dilationDepth,u=r.dilationHeight,c=r.dilationWidth,l=r.effectiveFilterDepth,h=r.effectiveFilterHeight,f=r.effectiveFilterWidth,p=l-1-r.padInfo.front,d=h-1-r.padInfo.top,v=f-1-r.padInfo.left,m=1/(t*e*n);this.userCode=`
      const ivec3 pads = ivec3(`+p+", "+d+", "+v+`);
      const float avgMultiplier = float(`+m+`);

      void main() {
        ivec5 coords = getOutputCoords();
        int batch = coords.x;
        int ch = coords.u;

        ivec3 dyCorner = ivec3(coords.y, coords.z, coords.w) - pads;
        int dyDCorner = dyCorner.x;
        int dyRCorner = dyCorner.y;
        int dyCCorner = dyCorner.z;

        // Convolve dy(?, ?, ?, d) with pos mask(:, :, :, ch) to get
        // dx(xD, xR, xC, ch).
        // ? = to be determined. : = across all values in that axis.
        float dotProd = 0.0;

        for (int wD = 0; wD < `+l+`;
            wD += `+s+`) {
          float dyD = float(dyDCorner + wD) / `+o+`.0;

          if (dyD < 0.0 || dyD >= `+r.outDepth+`.0 || fract(dyD) > 0.0) {
            continue;
          }
          int idyD = int(dyD);

          for (int wR = 0; wR < `+h+`;
              wR += `+u+`) {
            float dyR = float(dyRCorner + wR) / `+a+`.0;

            if (dyR < 0.0 || dyR >= `+r.outHeight+`.0 ||
                fract(dyR) > 0.0) {
              continue;
            }
            int idyR = int(dyR);

            for (int wC = 0; wC < `+f+`;
                wC += `+c+`) {
              float dyC = float(dyCCorner + wC) / `+i+`.0;

              if (dyC < 0.0 || dyC >= `+r.outWidth+`.0 ||
                  fract(dyC) > 0.0) {
                continue;
              }
              int idyC = int(dyC);

              float dyValue = getDy(batch, idyD, idyR, idyC, ch);

              dotProd += dyValue * avgMultiplier;
            }
          }
        }
        setOutput(dotProd);
      }
    `},Jh=function(r,t,e,n,o,a){this.outputShape=[],this.variableNames=["x","mean","variance"],le(r,t),le(r,e);var i="0.0";n!=null&&(le(r,n),this.variableNames.push("offset"),i="getOffsetAtOutCoords()");var s="1.0";o!=null&&(le(r,o),this.variableNames.push("scale"),s="getScaleAtOutCoords()"),this.outputShape=r,this.userCode=`
      void main() {
        float x = getXAtOutCoords();
        float mean = getMeanAtOutCoords();
        float variance = getVarianceAtOutCoords();
        float offset = `+i+`;
        float scale = `+s+`;
        float inv = scale * inversesqrt(variance + float(`+a+`));
        setOutput(dot(vec3(x, -mean, offset), vec3(inv, inv, 1)));
      }
    `},Qh=function(r,t,e,n,o,a){this.packedInputs=!0,this.packedOutput=!0,this.variableNames=["x","mean","variance"],le(r,t),le(r,e);var i="vec4(0.0)";n!=null&&(le(r,n),this.variableNames.push("offset"),i="getOffsetAtOutCoords()");var s="vec4(1.0)";o!=null&&(le(r,o),this.variableNames.push("scale"),s="getScaleAtOutCoords()"),this.outputShape=r,this.userCode=`
      void main() {
        vec4 offset = `+i+`;
        vec4 scale = `+s+`;

        vec4 x = getXAtOutCoords();
        vec4 mean = getMeanAtOutCoords();
        vec4 variance = getVarianceAtOutCoords();

        vec4 inv = scale * inversesqrt(variance + vec4(`+a+`));

        setOutput((x - mean) * inv + offset);
      }
    `},Zh="return areal * breal - aimag * bimag;",ef="return areal * bimag + aimag * breal;",Vi=function(r,t,e){this.variableNames=["AReal","AImag","BReal","BImag"],this.outputShape=le(t,e),this.userCode=`
      float binaryOpComplex(
          float areal, float aimag, float breal, float bimag) {
        `+r+`
      }

      void main() {
        float areal = getARealAtOutCoords();
        float aimag = getAImagAtOutCoords();
        float breal = getBRealAtOutCoords();
        float bimag = getBImagAtOutCoords();
        setOutput(binaryOpComplex(areal, aimag, breal, bimag));
      }
    `},Bo="return a + b;",Lo="return a - b;",zi="return a * b;",vu="return (a < 0.) ? b * a : a;",De=function(r,t,e){this.variableNames=["A","B"],this.outputShape=le(t,e),this.userCode=`
      float binaryOperation(float a, float b) {
        `+r+`
      }

      void main() {
        float a = getAAtOutCoords();
        float b = getBAtOutCoords();
        setOutput(binaryOperation(a, b));
      }
    `},mu=`
  vec4 aLessThanZero = vec4(lessThan(a, vec4(0.)));
  return (aLessThanZero * (b * a)) + ((vec4(1.0) - aLessThanZero) * a);
`,Gt=function(r,t,e,n){n===void 0&&(n=!1),this.variableNames=["A","B"],this.supportsBroadcasting=!0,this.packedInputs=!0,this.packedOutput=!0,this.outputShape=le(t,e);var o=this.outputShape.length,a="";if(n)if(o===0||Y(this.outputShape)===1)a=`
          result.y = 0.;
          result.z = 0.;
          result.w = 0.;
        `;else if(a=`
          `+we(o)+` coords = getOutputCoords();
        `,o===1)a+=`
            result.y = (coords + 1) >= `+this.outputShape[0]+` ? 0. : result.y;
            result.z = 0.;
            result.w = 0.;
          `;else{var i=et("coords",o);a+=`
            bool nextRowOutOfBounds =
              (`+i[o-2]+" + 1) >= "+this.outputShape[o-2]+`;
            bool nextColOutOfBounds =
              (`+i[o-1]+" + 1) >= "+this.outputShape[o-1]+`;
            result.y = nextColOutOfBounds ? 0. : result.y;
            result.z = nextRowOutOfBounds ? 0. : result.z;
            result.w = nextColOutOfBounds || nextRowOutOfBounds ? 0. : result.w;
          `}this.userCode=`
      vec4 binaryOperation(vec4 a, vec4 b) {
        `+r+`
      }

      void main() {
        vec4 a = getAAtOutCoords();
        vec4 b = getBAtOutCoords();

        vec4 result = binaryOperation(a, b);
        `+a+`

        setOutput(result);
      }
    `},tf=(function(){function r(t){this.variableNames=["A"],this.outputShape=t,this.userCode=`
      uniform float minVal;
      uniform float maxVal;

      void main() {
        float value = getAAtOutCoords();
        if (isnan(value)) {
          setOutput(value);
          return;
        }

        setOutput(clamp(value, minVal, maxVal));
      }
    `}return r.prototype.getCustomSetupFunc=function(t,e){var n=this;return function(o,a){n.minLoc==null&&(n.minLoc=o.getUniformLocationNoThrow(a,"minVal"),n.maxLoc=o.getUniformLocationNoThrow(a,"maxVal")),o.gl.uniform1f(n.minLoc,t),o.gl.uniform1f(n.maxLoc,e)}},r})(),nf=(function(){function r(t){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=t,this.userCode=`
      uniform float minVal;
      uniform float maxVal;

      void main() {
        vec4 value = getAAtOutCoords();

        if (any(isnan(value))) {
          setOutput(value);
          return;
        }

        setOutput(clamp(value, vec4(minVal), vec4(maxVal)));
      }
    `}return r.prototype.getCustomSetupFunc=function(t,e){var n=this;return function(o,a){n.minLoc==null&&(n.minLoc=o.getUniformLocationNoThrow(a,"minVal"),n.maxLoc=o.getUniformLocationNoThrow(a,"maxVal")),o.gl.uniform1f(n.minLoc,t),o.gl.uniform1f(n.maxLoc,e)}},r})(),rf=function(r){this.variableNames=["real","imag"],this.outputShape=r,this.userCode=`
      void main() {
        float re = abs(getRealAtOutCoords());
        float im = abs(getImagAtOutCoords());
        float mx = max(re, im);

        // sadly the length function in glsl is not underflow-safe
        // (at least not on Intel GPUs). So the safe solution is
        // to ensure underflow-safety in all cases.
        setOutput(
          mx == 0.0 ? 0.0 : mx * length(vec2(1, min(re, im)/mx))
        );
      }
    `},of=function(r){this.outputShape=[],this.outputShape=qn(r,1),this.variableNames=r.map((function(s,u){return"T"+u}));var t=new Array(r.length-1);t[0]=r[0][1];for(var e=1;e<t.length;e++)t[e]=t[e-1]+r[e][1];var n=["if (yC < "+t[0]+") setOutput(getT0(yR, yC));"];for(e=1;e<t.length;e++){var o=t[e-1];n.push("else if (yC < "+t[e]+") setOutput(getT"+e+"(yR, yC-"+o+"));")}var a=t.length,i=t[t.length-1];n.push("else setOutput(getT"+a+"(yR, yC-"+i+"));"),this.userCode=`
      void main() {
        ivec2 coords = getOutputCoords();
        int yR = coords.x;
        int yC = coords.y;

        `+n.join(`
        `)+`
      }
    `},af=function(r,t){this.packedInputs=!0,this.packedOutput=!0,this.outputShape=[],this.outputShape=qn(r,t);var e=this.outputShape,n=e.length,o=we(n),a=et("coords",n),i=["x","y","z","w","u","v"].slice(0,n);this.variableNames=r.map((function(m,g){return"T"+g}));var s=new Array(r.length-1);s[0]=r[0][t];for(var u=1;u<s.length;u++)s[u]=s[u-1]+r[u][t];var c=i[t],l=i.slice(-2),h=i.join(),f="if ("+c+" < "+s[0]+`) {
        return getChannel(
            getT0(`+h+"), vec2("+l.join()+`));
        }`;for(u=1;u<s.length;u++){var p=s[u-1];f+=`
        if (`+c+" < "+s[u]+"  && "+c+" >= "+s[u-1]+`) {
          return getChannel(
            getT`+u+"("+Er(i,c,p)+`),
            vec2(`+Er(l,c,p)+`));
        }`}var d=s.length,v=s[s.length-1];f+=`
        return getChannel(
          getT`+d+"("+Er(i,c,v)+`),
          vec2(`+Er(l,c,v)+"));",this.userCode=`
      float getValue(`+i.map((function(m){return"int "+m}))+`) {
        `+f+`
      }

      void main() {
        `+o+` coords = getOutputCoords();
        vec4 result = vec4(getValue(`+a+`), 0., 0., 0.);

        `+a[n-1]+" = "+a[n-1]+` + 1;
        if (`+a[n-1]+" < "+e[n-1]+`) {
          result.g = getValue(`+a+`);
        }

        `+a[n-2]+" = "+a[n-2]+` + 1;
        if (`+a[n-2]+" < "+e[n-2]+`) {
          result.a = getValue(`+a+`);
        }

        `+a[n-1]+" = "+a[n-1]+` - 1;
        if (`+a[n-2]+" < "+e[n-2]+` &&
            `+a[n-1]+" < "+e[n-1]+`) {
          result.b = getValue(`+a+`);
        }
        setOutput(result);
      }
    `};function Er(r,t,e){var n=r.indexOf(t);return r.map((function(o,a){return a===n?o+" - "+e:o})).join()}var sf=function(r){this.variableNames=["x","dy"],this.outputShape=r.filterShape;var t=r.strideHeight,e=r.strideWidth,n=r.padInfo.top,o=r.padInfo.left,a=r.dataFormat==="channelsLast";this.userCode=`
      void main() {
        ivec4 coords = getOutputCoords();
        int wR = coords.x;
        int wC = coords.y;
        int d1 = coords.z;
        int d2 = coords.w;

        // Convolve x(?, ?, d1) with dy(:, :, d2) to get dw(wR, wC, d1, d2).
        // ? = to be determined. : = across all values in that axis.
        float dotProd = 0.0;

        for (int b = 0; b < `+r.batchSize+`; b++) {
          for (int yR = 0; yR < `+r.outHeight+`; yR++) {
            int xR = wR + yR * `+t+" - "+n+`;

            if (xR < 0 || xR >= `+r.inHeight+`) {
              continue;
            }

            for (int yC = 0; yC < `+r.outWidth+`; yC++) {
              int xC = wC + yC * `+e+" - "+o+`;

              if (xC < 0 || xC >= `+r.inWidth+`) {
                continue;
              }

              if (`+a+`) {
                float dyValue = getDy(b, yR, yC, d2);
                float xValue = getX(b, xR, xC, d1);
                dotProd += (xValue * dyValue);
              } else {
                float dyValue = getDy(b, d2, yR, yC);
                float xValue = getX(b, d1, xR, xC);
                dotProd += (xValue * dyValue);
              }

            }
          }
        }
        setOutput(dotProd);
      }
    `},uf=function(r){this.variableNames=["dy","W"],this.outputShape=r.inShape;var t=r.filterHeight,e=r.filterWidth,n=r.strideHeight,o=r.strideWidth,a=r.dataFormat==="channelsLast",i=t-1-r.padInfo.top,s=e-1-r.padInfo.left,u=a?1:2,c=a?2:3,l=a?3:1;this.userCode=`
      const ivec2 pads = ivec2(`+i+", "+s+`);

      void main() {
        ivec4 coords = getOutputCoords();
        int batch = coords[0];
        int d1 = coords[`+l+`];

        ivec2 dyCorner = ivec2(coords[`+u+"], coords["+c+`]) - pads;
        int dyRCorner = dyCorner.x;
        int dyCCorner = dyCorner.y;

        // Convolve dy(?, ?, d2) with w(:, :, d1, d2) to compute dx(xR, xC, d1).
        // ? = to be determined. : = across all values in that axis.
        float dotProd = 0.0;
        for (int wR = 0; wR < `+t+`; wR++) {
          float dyR = float(dyRCorner + wR) / `+n+`.0;

          if (dyR < 0.0 || dyR >= `+r.outHeight+`.0 || fract(dyR) > 0.0) {
            continue;
          }
          int idyR = int(dyR);

          int wRPerm = `+t+` - 1 - wR;

          for (int wC = 0; wC < `+e+`; wC++) {
            float dyC = float(dyCCorner + wC) / `+o+`.0;

            if (dyC < 0.0 || dyC >= `+r.outWidth+`.0 ||
                fract(dyC) > 0.0) {
              continue;
            }
            int idyC = int(dyC);

            int wCPerm = `+e+` - 1 - wC;

            for (int d2 = 0; d2 < `+r.outChannels+`; d2++) {

              if (`+a+`) {
                float xValue = getDy(batch, idyR, idyC, d2);
                float wValue = getW(wRPerm, wCPerm, d1, d2);
                dotProd += xValue * wValue;
              } else {
                float xValue = getDy(batch, d2, idyR, idyC);
                float wValue = getW(wRPerm, wCPerm, d1, d2);
                dotProd += xValue * wValue;
              }

            }
          }
        }
        setOutput(dotProd);
      }
    `},cf=function(r){this.variableNames=["x","dy"],this.outputShape=r.filterShape;var t=r.strideDepth,e=r.strideHeight,n=r.strideWidth,o=r.padInfo.front,a=r.padInfo.top,i=r.padInfo.left;this.userCode=`
      void main() {
        ivec5 coords = getOutputCoords();
        int wF = coords.x;
        int wR = coords.y;
        int wC = coords.z;
        int d1 = coords.w;
        int d2 = coords.u;

        float dotProd = 0.0;

        for (int b = 0; b < `+r.batchSize+`; b++) {
          for (int yF = 0; yF < `+r.outDepth+`; yF++) {
            int xF = wF + yF * `+t+" - "+o+`;

            if (xF < 0 || xF >= `+r.inDepth+`) {
              continue;
            }

            for (int yR = 0; yR < `+r.outHeight+`; yR++) {
              int xR = wR + yR * `+e+" - "+a+`;

              if (xR < 0 || xR >= `+r.inHeight+`) {
                continue;
              }

              for (int yC = 0; yC < `+r.outWidth+`; yC++) {
                int xC = wC + yC * `+n+" - "+i+`;

                if (xC < 0 || xC >= `+r.inWidth+`) {
                  continue;
                }

                float dyValue = getDy(b, yF, yR, yC, d2);
                float xValue = getX(b, xF, xR, xC, d1);
                dotProd += (xValue * dyValue);
              }
            }
          }
        }
        setOutput(dotProd);
      }
    `},lf=function(r){this.variableNames=["dy","W"],this.outputShape=r.inShape;var t=r.filterDepth,e=r.filterHeight,n=r.filterWidth,o=r.strideDepth,a=r.strideHeight,i=r.strideWidth,s=t-1-r.padInfo.front,u=e-1-r.padInfo.top,c=n-1-r.padInfo.left;this.userCode=`
      const ivec3 pads = ivec3(`+s+", "+u+", "+c+`);

      void main() {
        ivec5 coords = getOutputCoords();
        int batch = coords.x;
        int d1 = coords.u;


        ivec3 dyCorner = ivec3(coords.y, coords.z, coords.w) - pads;
        int dyFCorner = dyCorner.x;
        int dyRCorner = dyCorner.y;
        int dyCCorner = dyCorner.z;

        float dotProd = 0.0;
        for (int wF = 0; wF < `+t+`; wF++) {
          float dyF = float(dyFCorner + wF) / `+o+`.0;

          if (dyF < 0.0 || dyF >= `+r.outDepth+`.0 || fract(dyF) > 0.0) {
            continue;
          }
          int idyF = int(dyF);

          int wFPerm = `+t+` - 1 - wF;

          for (int wR = 0; wR < `+e+`; wR++) {
            float dyR = float(dyRCorner + wR) / `+a+`.0;

            if (dyR < 0.0 || dyR >= `+r.outHeight+`.0 ||
              fract(dyR) > 0.0) {
              continue;
            }
            int idyR = int(dyR);

            int wRPerm = `+e+` - 1 - wR;

            for (int wC = 0; wC < `+n+`; wC++) {
              float dyC = float(dyCCorner + wC) / `+i+`.0;

              if (dyC < 0.0 || dyC >= `+r.outWidth+`.0 ||
                  fract(dyC) > 0.0) {
                continue;
              }
              int idyC = int(dyC);

              int wCPerm = `+n+` - 1 - wC;

              for (int d2 = 0; d2 < `+r.outChannels+`; d2++) {
                float xValue = getDy(batch, idyF, idyR, idyC, d2);
                float wValue = getW(wFPerm, wRPerm, wCPerm, d1, d2);
                dotProd += xValue * wValue;
              }
            }
          }
        }
        setOutput(dotProd);
      }
    `},hf=function(r){this.variableNames=["x","dy"],this.outputShape=r.filterShape;var t=r.strideHeight,e=r.strideWidth,n=r.padInfo.top,o=r.padInfo.left,a=r.outChannels/r.inChannels;this.userCode=`
      void main() {
        ivec4 coords = getOutputCoords();
        int wR = coords.x;
        int wC = coords.y;
        int d1 = coords.z;
        int dm = coords.w;
        int d2 = d1 * `+a+` + dm;

        float dotProd = 0.0;

        // TO DO: Vec4 over the batch size
        for (int b = 0; b < `+r.batchSize+`; b++) {
          for (int yR = 0; yR < `+r.outHeight+`; yR++) {
            int xR = wR + yR * `+t+" - "+n+`;

            if (xR < 0 || xR >= `+r.inHeight+`) {
              continue;
            }

            for (int yC = 0; yC < `+r.outWidth+`; yC++) {
              int xC = wC + yC * `+e+" - "+o+`;

              if (xC < 0 || xC >= `+r.inWidth+`) {
                continue;
              }

              float dyValue = getDy(b, yR, yC, d2);
              float xValue = getX(b, xR, xC, d1);
              dotProd += (xValue * dyValue);
            }
          }
        }
        setOutput(dotProd);
      }
    `},ff=function(r){this.variableNames=["dy","W"],this.outputShape=r.inShape;var t=r.filterHeight,e=r.filterWidth,n=r.strideHeight,o=r.strideWidth,a=t-1-r.padInfo.top,i=e-1-r.padInfo.left,s=r.outChannels/r.inChannels;this.userCode=`
      const ivec2 pads = ivec2(`+a+", "+i+`);

      void main() {
        ivec4 coords = getOutputCoords();
        int batch = coords[0];
        int d1 = coords[3];
        ivec2 dyCorner = coords.yz - pads;
        int dyRCorner = dyCorner.x;
        int dyCCorner = dyCorner.y;

        float dotProd = 0.0;

        for (int wR = 0; wR < `+t+`; wR++) {
          float dyR = float(dyRCorner + wR) / `+n+`.0;

          if (dyR < 0.0 || dyR >= `+r.outHeight+`.0 || fract(dyR) > 0.0) {
            continue;
          }
          int idyR = int(dyR);

          int wRPerm = `+t+` - 1 - wR;

          for (int wC = 0; wC < `+e+`; wC++) {
            float dyC = float(dyCCorner + wC) / `+o+`.0;

            if (dyC < 0.0 || dyC >= `+r.outWidth+`.0 ||
                fract(dyC) > 0.0) {
              continue;
            }
            int idyC = int(dyC);

            int wCPerm = `+e+` - 1 - wC;

            // TO DO: Vec4 over the channelMul
            for (int dm = 0; dm < `+s+`; dm++) {
              int d2 = d1 * `+s+` + dm;
              float xValue = getDy(batch, idyR, idyC, d2);
              float wValue = getW(wRPerm, wCPerm, d1, dm);
              dotProd += xValue * wValue;
            }
          }
        }
        setOutput(dotProd);
      }
    `},Gi=function(r,t,e,n){t===void 0&&(t=!1),e===void 0&&(e=null),n===void 0&&(n=!1),this.variableNames=["x","W"],this.outputShape=r.outShape;var o=r.padInfo.top,a=r.padInfo.left,i=r.strideHeight,s=r.strideWidth,u=r.dilationHeight,c=r.dilationWidth,l=r.filterHeight,h=r.filterWidth,f=4*Math.floor(r.inChannels/4),p=r.inChannels%4,d=r.dataFormat==="channelsLast",v=d?1:2,m=d?2:3,g=d?3:1,x="",b="";e&&(x=n?`float activation(float a) {
          float b = getPreluActivationWeightsAtOutCoords();
          `+e+`
        }`:`
          float activation(float x) {
            `+e+`
          }
        `,b="result = activation(result);");var y=t?"result += getBiasAtOutCoords();":"";t&&this.variableNames.push("bias"),n&&this.variableNames.push("preluActivationWeights"),this.userCode=`
      `+x+`

      const ivec2 strides = ivec2(`+i+", "+s+`);
      const ivec2 pads = ivec2(`+o+", "+a+`);

      void main() {
        ivec4 coords = getOutputCoords();
        int batch = coords[0];
        int d2 = coords[`+g+`];

        ivec2 xRCCorner =
            ivec2(coords[`+v+"], coords["+m+`]) * strides - pads;
        int xRCorner = xRCCorner.x;
        int xCCorner = xRCCorner.y;

        // Convolve x(?, ?, d1) with w(:, :, d1, d2) to get y(yR, yC, d2).
        // ? = to be determined. : = across all values in that axis.
        float dotProd = 0.0;
        for (int wR = 0; wR < `+l+`; wR++) {
          int xR = xRCorner + wR * `+u+`;

          if (xR < 0 || xR >= `+r.inHeight+`) {
            continue;
          }

          for (int wC = 0; wC < `+h+`; wC++) {
            int xC = xCCorner + wC * `+c+`;

            if (xC < 0 || xC >= `+r.inWidth+`) {
              continue;
            }

            for (int d1 = 0; d1 < `+f+`; d1 += 4) {
              vec4 wValues = vec4(
                getW(wR, wC, d1, d2),
                getW(wR, wC, d1 + 1, d2),
                getW(wR, wC, d1 + 2, d2),
                getW(wR, wC, d1 + 3, d2)
              );

              if (`+d+`) {
                vec4 xValues = vec4(
                  getX(batch, xR, xC, d1),
                  getX(batch, xR, xC, d1 + 1),
                  getX(batch, xR, xC, d1 + 2),
                  getX(batch, xR, xC, d1 + 3)
                );
                dotProd += dot(xValues, wValues);
              } else {
                vec4 xValues = vec4(
                  getX(batch, d1, xR, xC),
                  getX(batch, d1 + 1, xR, xC),
                  getX(batch, d1 + 2, xR, xC),
                  getX(batch, d1 + 3, xR, xC)
                );
                dotProd += dot(xValues, wValues);
              }
            }

            if (`+(p===1)+`) {

              if (`+d+`) {
                dotProd +=
                    getX(batch, xR, xC, `+f+`) *
                    getW(wR, wC, `+f+`, d2);
              } else {
                dotProd +=
                    getX(batch, `+f+`, xR, xC) *
                    getW(wR, wC, `+f+`, d2);
              }

            } else if (`+(p===2)+`) {
              vec2 wValues = vec2(
                getW(wR, wC, `+f+`, d2),
                getW(wR, wC, `+f+` + 1, d2)
              );

              if (`+d+`) {
                vec2 xValues = vec2(
                  getX(batch, xR, xC, `+f+`),
                  getX(batch, xR, xC, `+f+` + 1)
                );
                dotProd += dot(xValues, wValues);
              } else {
                vec2 xValues = vec2(
                  getX(batch, `+f+`, xR, xC),
                  getX(batch, `+f+` + 1, xR, xC)
                );
                dotProd += dot(xValues, wValues);
              }

            } else if (`+(p===3)+`) {
              vec3 wValues = vec3(
                getW(wR, wC, `+f+`, d2),
                getW(wR, wC, `+f+` + 1, d2),
                getW(wR, wC, `+f+` + 2, d2)
              );

              if (`+d+`) {
                vec3 xValues = vec3(
                  getX(batch, xR, xC, `+f+`),
                  getX(batch, xR, xC, `+f+` + 1),
                  getX(batch, xR, xC, `+f+` + 2)
                );
                dotProd += dot(xValues, wValues);
              } else {
                vec3 xValues = vec3(
                  getX(batch, `+f+`, xR, xC),
                  getX(batch, `+f+` + 1, xR, xC),
                  getX(batch, `+f+` + 2, xR, xC)
                );
                dotProd += dot(xValues, wValues);
              }

            }
          }
        }

        float result = dotProd;
        `+y+`
        `+b+`
        setOutput(result);
      }
    `},pf=function(r){this.variableNames=["x","W"],this.outputShape=r.outShape;var t=r.padInfo.front,e=r.padInfo.top,n=r.padInfo.left,o=r.strideDepth,a=r.strideHeight,i=r.strideWidth,s=r.dilationDepth,u=r.dilationHeight,c=r.dilationWidth,l=r.filterDepth,h=r.filterHeight,f=r.filterWidth,p=4*Math.floor(r.inChannels/4),d=r.inChannels%4;this.userCode=`
      const ivec3 strides = ivec3(`+o+", "+a+", "+i+`);
      const ivec3 pads = ivec3(`+t+", "+e+", "+n+`);

      void main() {
        ivec5 coords = getOutputCoords();
        int batch = coords.x;
        int d2 = coords.u;

        ivec3 xFRCCorner = ivec3(coords.y, coords.z, coords.w) * strides - pads;
        int xFCorner = xFRCCorner.x;
        int xRCorner = xFRCCorner.y;
        int xCCorner = xFRCCorner.z;

        // Convolve x(?, ?, ?, d1) with w(:, :, :, d1, d2) to get
        // y(yF, yR, yC, d2). ? = to be determined. : = across all
        // values in that axis.
        float dotProd = 0.0;
        for (int wF = 0; wF < `+l+`; wF++) {
          int xF = xFCorner + wF * `+s+`;

          if (xF < 0 || xF >= `+r.inDepth+`) {
            continue;
          }

          for (int wR = 0; wR < `+h+`; wR++) {
            int xR = xRCorner + wR * `+u+`;

            if (xR < 0 || xR >= `+r.inHeight+`) {
              continue;
            }

            for (int wC = 0; wC < `+f+`; wC++) {
              int xC = xCCorner + wC * `+c+`;

              if (xC < 0 || xC >= `+r.inWidth+`) {
                continue;
              }

              for (int d1 = 0; d1 < `+p+`; d1 += 4) {
                vec4 xValues = vec4(
                  getX(batch, xF, xR, xC, d1),
                  getX(batch, xF, xR, xC, d1 + 1),
                  getX(batch, xF, xR, xC, d1 + 2),
                  getX(batch, xF, xR, xC, d1 + 3)
                );
                vec4 wValues = vec4(
                  getW(wF, wR, wC, d1, d2),
                  getW(wF, wR, wC, d1 + 1, d2),
                  getW(wF, wR, wC, d1 + 2, d2),
                  getW(wF, wR, wC, d1 + 3, d2)
                );

                dotProd += dot(xValues, wValues);
              }

              if (`+(d===1)+`) {
                dotProd +=
                  getX(batch, xF, xR, xC, `+p+`) *
                  getW(wF, wR, wC, `+p+`, d2);
              } else if (`+(d===2)+`) {
                vec2 xValues = vec2(
                  getX(batch, xF, xR, xC, `+p+`),
                  getX(batch, xF, xR, xC, `+p+` + 1)
                );
                vec2 wValues = vec2(
                  getW(wF, wR, wC, `+p+`, d2),
                  getW(wF, wR, wC, `+p+` + 1, d2)
                );
                dotProd += dot(xValues, wValues);
              } else if (`+(d===3)+`) {
                vec3 xValues = vec3(
                  getX(batch, xF, xR, xC, `+p+`),
                  getX(batch, xF, xR, xC, `+p+` + 1),
                  getX(batch, xF, xR, xC, `+p+` + 2)
                );
                vec3 wValues = vec3(
                  getW(wF, wR, wC, `+p+`, d2),
                  getW(wF, wR, wC, `+p+` + 1, d2),
                  getW(wF, wR, wC, `+p+` + 2, d2)
                );
                dotProd += dot(xValues, wValues);
              }
            }
          }
        }
        setOutput(dotProd);
      }
    `},Hi=function(r,t,e,n){t===void 0&&(t=!1),e===void 0&&(e=null),n===void 0&&(n=!1),this.variableNames=["x","W"],this.outputShape=r.outShape;var o=r.inHeight,a=r.inWidth,i=r.padInfo.top,s=r.padInfo.left,u=r.strideHeight,c=r.strideWidth,l=r.dilationHeight,h=r.dilationWidth,f=r.filterHeight,p=r.filterWidth,d=r.outChannels/r.inChannels,v="",m="";e&&(v=n?`float activation(float a) {
          float b = getPreluActivationWeightsAtOutCoords();
          `+e+`
        }`:`
          float activation(float x) {
            `+e+`
          }
        `,m="result = activation(result);");var g=t?"result += getBiasAtOutCoords();":"";t&&this.variableNames.push("bias"),n&&this.variableNames.push("preluActivationWeights"),this.userCode=`
      `+v+`

      const ivec2 strides = ivec2(`+u+", "+c+`);
      const ivec2 pads = ivec2(`+i+", "+s+`);

      void main() {
        ivec4 coords = getOutputCoords();
        int batch = coords.x;
        ivec2 xRCCorner = coords.yz * strides - pads;
        int d2 = coords.w;
        int d1 = d2 / `+d+`;
        int q = d2 - d1 * `+d+`;

        int xRCorner = xRCCorner.x;
        int xCCorner = xRCCorner.y;

        // Convolve x(?, ?, d1) with w(:, :, d1, q) to get y(yR, yC, d2).
        // ? = to be determined. : = across all values in that axis.
        float dotProd = 0.0;
        // TO DO(dsmilkov): Flatten the two for loops and vec4 the operations.
        for (int wR = 0; wR < `+f+`; wR++) {
          int xR = xRCorner + wR * `+l+`;

          if (xR < 0 || xR >= `+o+`) {
            continue;
          }

          for (int wC = 0; wC < `+p+`; wC++) {
            int xC = xCCorner + wC * `+h+`;

            if (xC < 0 || xC >= `+a+`) {
              continue;
            }

            float xVal = getX(batch, xR, xC, d1);
            float wVal = getW(wR, wC, d1, q);
            dotProd += xVal * wVal;
          }
        }

        float result = dotProd;
        `+g+`
        `+m+`
        setOutput(result);
      }
    `},ji=function(r,t,e,n){t===void 0&&(t=!1),e===void 0&&(e=null),n===void 0&&(n=!1),this.variableNames=["x","W"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=r.outShape;for(var o=r.inHeight,a=r.inWidth,i=r.padInfo.top,s=r.padInfo.left,u=r.strideHeight,c=r.strideWidth,l=r.dilationHeight,h=r.dilationWidth,f=r.filterHeight,p=r.filterWidth,d=p,v="int xR; int xC; int xCOffset;",m=0;m<f;m++)for(var g=0;g<p;g++)v+=`
          vec4 xTexelR`+m+"C"+2*g+` = vec4(0.);
          vec4 wR`+m+"C"+g+` = vec4(0.);
          vec4 xR`+m+"C"+g+" = vec4(0.);";for(m=0;m<f;m++)for(var x=0;x<d;x++){if(v+=`
          xR = xRCorner + `+m*l+`;
          xC = xCCorner + `+(g=2*x)*h+`;
        `,c===1){if(g<p&&(v+=s%2==1?`
                xCOffset = xC + 1;
                if(xR >= 0 && xR < `+o+" && xCOffset >= 0 && xCOffset < "+a+`) {
                  xTexelR`+m+"C"+g+` = getX(batch, xR, xCOffset, d1);

                  // Need to manually clear unused channels in case
                  // we're reading from recycled texture.
                  if(xCOffset + 1 >= `+a+`) {
                    xTexelR`+m+"C"+g+`.zw = vec2(0.);
                  }
                } else {
                  xTexelR`+m+"C"+g+` = vec4(0.);
                }

                xCOffset = xC + 1 - 2;
                if(xR >= 0 && xR < `+o+" && xCOffset >= 0 && xCOffset < "+a+`) {
                  vec4 previous = getX(batch, xR, xCOffset, d1);

                  // Need to manually clear unused channels in case
                  // we're reading from recycled texture.
                  if(xCOffset + 1 >= `+a+`) {
                    previous.zw = vec2(0.);
                  }

                  xR`+m+"C"+g+" = vec4(previous.zw, xTexelR"+m+"C"+g+`.xy);
                } else {
                  xR`+m+"C"+g+" = vec4(0, 0, xTexelR"+m+"C"+g+`.xy);
                }
              `:`
                if(xR >= 0 && xR < `+o+" && xC >= 0 && xC < "+a+`) {
                  xTexelR`+m+"C"+g+` = getX(batch, xR, xC, d1);
                } else {
                  xTexelR`+m+"C"+g+` = vec4(0.);
                }

                xR`+m+"C"+g+" = xTexelR"+m+"C"+g+`;
              `,g+1<p)){var b=s%2==0?Ps(h):h;h%2==0&&s%2==1||h%2!=0&&s%2!=1?(v+=`
                  xCOffset = xC + `+s%2+" + "+b+`;

                  if(xR >= 0 && xR < `+o+` &&
                    xCOffset >= 0 && xCOffset < `+a+`) {
                    xTexelR`+m+"C"+(g+2)+` = getX(batch, xR, xCOffset, d1);
                  }
                `,h>1&&(v+=`
                    xCOffset -= 2;
                    if(xR >= 0 && xR < `+o+` &&
                      xCOffset >= 0 && xCOffset < `+a+`) {
                      xTexelR`+m+"C"+g+` = getX(batch, xR, xCOffset, d1);
                    } else {
                      xTexelR`+m+"C"+g+` = vec4(0.);
                    }
                  `),v+=`
                  xR`+m+"C"+(g+1)+` = vec4(
                    xTexelR`+m+"C"+g+".zw, xTexelR"+m+"C"+(g+2)+`.xy);
                `):v+=`
                  xCOffset = xC + `+b+`;

                  if(xR >= 0 && xR < `+o+` &&
                    xCOffset >= 0 && xCOffset < `+a+`) {
                    xTexelR`+m+"C"+(g+2)+` = getX(batch, xR, xCOffset, d1);
                  }

                  xR`+m+"C"+(g+1)+" = xTexelR"+m+"C"+(g+2)+`;
                `}}else g<p&&(v+=`
              if(xR >= 0 && xR < `+o+`) {
            `,s%2==1?(v+=`
                xCOffset = xC + 1 - `+c+`;
                if(xCOffset >= 0 && xCOffset < `+a+`) {
                  xTexelR`+m+"C"+g+` = getX(batch, xR, xCOffset, d1);
                } else {
                  xTexelR`+m+"C"+g+` = vec4(0.);
                }

                if(xC + 1 >= 0 && xC + 1 < `+a+`) {
                  xTexelR`+m+"C"+(g+2)+` = getX(batch, xR, xC + 1, d1);
                } else {
                  xTexelR`+m+"C"+(g+2)+` = vec4(0.);
                }

                xR`+m+"C"+g+` = vec4(
                  xTexelR`+m+"C"+g+".zw, xTexelR"+m+"C"+(g+2)+`.zw);
              `,g+1<p&&(v+=`
                  vec4 final = vec4(0.);
                  xCOffset = xC + 1 + `+c+`;
                  if(xCOffset >= 0 && xCOffset < `+a+`) {
                    final = getX(batch, xR, xCOffset, d1);
                  }
                  xR`+m+"C"+(g+1)+" = vec4(xTexelR"+m+"C"+(g+2)+`.xy, final.xy);
                `)):(v+=`
                if(xC >= 0 && xC < `+a+`) {
                  xTexelR`+m+"C"+g+` = getX(batch, xR, xC, d1);
                } else {
                  xTexelR`+m+"C"+g+` = vec4(0.);
                }

                xCOffset = xC + `+c+`;
                if(xCOffset >= 0 && xCOffset < `+a+`) {
                  xTexelR`+m+"C"+(g+2)+` = getX(batch, xR, xCOffset, d1);
                } else {
                  xTexelR`+m+"C"+(g+2)+` = vec4(0.);
                }

                xR`+m+"C"+g+` = vec4(
                  xTexelR`+m+"C"+g+".xy, xTexelR"+m+"C"+(g+2)+`.xy);
              `,g+1<p&&(v+=`
                  xR`+m+"C"+(g+1)+` = vec4(
                    xTexelR`+m+"C"+g+".zw, xTexelR"+m+"C"+(g+2)+`.zw);
                `)),v+="}");g<p&&(v+=`
            vec4 wTexelR`+m+"C"+g+" = getW("+m+", "+g+`, d1, q);
            wR`+m+"C"+g+" = vec4(wTexelR"+m+"C"+g+".xz, wTexelR"+m+"C"+g+`.xz);
          `,g+1<p&&(v+=`
              vec4 wTexelR`+m+"C"+(g+1)+" = getW("+m+", "+(g+1)+`, d1, q);
              wR`+m+"C"+(g+1)+` =
                vec4(wTexelR`+m+"C"+(g+1)+".xz, wTexelR"+m+"C"+(g+1)+".xz);"))}for(m=0;m<f;m++)for(g=0;g<p;g++)v+="dotProd += xR"+m+"C"+g+" * wR"+m+"C"+g+";";var y="",w="";e&&(y=n?`vec4 activation(vec4 a) {
          vec4 b = getPreluActivationWeightsAtOutCoords();
          `+e+`
        }`:`vec4 activation(vec4 x) {
          `+e+`
        }`,w="result = activation(result);");var C=t?"result += getBiasAtOutCoords();":"";t&&this.variableNames.push("bias"),n&&this.variableNames.push("preluActivationWeights"),this.userCode=`
      `+y+`

      const ivec2 strides = ivec2(`+u+", "+c+`);
      const ivec2 pads = ivec2(`+i+", "+s+`);

      void main() {

        ivec4 coords = getOutputCoords();
        int batch = coords.x;
        ivec2 xRCCorner = coords.yz * strides - pads;
        int d2 = coords.w;
        int d1 = d2;
        int q = 0;
        int xRCorner = xRCCorner.x;
        int xCCorner = xRCCorner.y;

        vec4 dotProd = vec4(0.);

        `+v+`

        vec4 result = dotProd;
        `+C+`
        `+w+`
        setOutput(result);
      }
    `},df=function(r,t,e,n,o){this.variableNames=["Image","Boxes","BoxInd"],this.outputShape=[];var a=r[0],i=r[1],s=r[2],u=r[3],c=t[0],l=e[0],h=e[1];this.outputShape=[c,l,h,u];var f=n==="bilinear"?1:0,p=[i-1+".0",s-1+".0"],d=p[0],v=p[1],m=l>1?[""+(i-1)/(l-1),"(y2-y1) * height_ratio","y1*"+d+" + float(y)*(height_scale)"]:["0.0","0.0","0.5 * (y1+y2) * "+d],g=m[0],x=m[1],b=m[2],y=h>1?[""+(s-1)/(h-1),"(x2-x1) * width_ratio","x1*"+v+" + float(x)*(width_scale)"]:["0.0","0.0","0.5 * (x1+x2) * "+v],w=y[0],C=y[1],S=y[2];this.userCode=`
      const float height_ratio = float(`+g+`);
      const float width_ratio = float(`+w+`);
      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int y = coords[1];
        int x = coords[2];
        int d = coords[3];

        // get box vals
        float y1 = getBoxes(b,0);
        float x1 = getBoxes(b,1);
        float y2 = getBoxes(b,2);
        float x2 = getBoxes(b,3);

        // get image in batch index
        int bInd = round(getBoxInd(b));
        if(bInd < 0 || bInd >= `+a+`) {
          return;
        }

        float height_scale = `+x+`;
        float width_scale = `+C+`;

        float in_y = `+b+`;
        if( in_y < 0.0 || in_y > `+d+` ) {
          setOutput(float(`+o+`));
          return;
        }
        float in_x = `+S+`;
        if( in_x < 0.0 || in_x > `+v+` ) {
          setOutput(float(`+o+`));
          return;
        }

        vec2 sourceFracIndexCR = vec2(in_x,in_y);
        if(`+f+` == 1) {
          // Compute the four integer indices.
          ivec2 sourceFloorCR = ivec2(sourceFracIndexCR);
          ivec2 sourceCeilCR = ivec2(ceil(sourceFracIndexCR));

          float topLeft = getImage(b, sourceFloorCR.y, sourceFloorCR.x, d);
          float bottomLeft = getImage(b, sourceCeilCR.y, sourceFloorCR.x, d);
          float topRight = getImage(b, sourceFloorCR.y, sourceCeilCR.x, d);
          float bottomRight = getImage(b, sourceCeilCR.y, sourceCeilCR.x, d);

          vec2 fracCR = sourceFracIndexCR - vec2(sourceFloorCR);

          float top = topLeft + (topRight - topLeft) * fracCR.x;
          float bottom = bottomLeft + (bottomRight - bottomLeft) * fracCR.x;
          float newValue = top + (bottom - top) * fracCR.y;
          setOutput(newValue);
        } else {
          // Compute the coordinators of nearest neighbor point.
          ivec2 sourceNearestCR = ivec2(floor(
            sourceFracIndexCR + vec2(0.5,0.5)));
          float newValue = getImage(b, sourceNearestCR.y, sourceNearestCR.x, d);
          setOutput(newValue);
        }
      }
    `},vf=function(r,t,e){this.variableNames=["x"],this.outputShape=r;var n=r.length,o=r[r.length-1],a=e?"<":">";this.userCode=`
      int getIndex(int i) {
        `+(e?"return "+o+" -i - 1;":"return i;")+`
      }

      void main() {
        `+we(n)+` coords = getOutputCoords();
        int end = `+qi(n,"coords")+`;
        float val = 0.0;
        for (int i = `+o+` - 1; i >= 0; i -= 1) {
          int idx = getIndex(i);
          if (idx `+a+` end) {
            continue;
          }
          if (idx == end && `+t+`) {
            continue;
          }
          `+qi(n,"coords")+` = idx;
          val += getX(`+(function(i,s){if(i===1)return""+s;if(i===2)return s+".x, "+s+".y";if(i===3)return s+".x, "+s+".y, "+s+".z";if(i===4)return s+".x, "+s+".y, "+s+".z, "+s+".w";throw Error("Cumulative sum for rank "+i+" is not yet supported")})(n,"coords")+`);
        }
        setOutput(val);
      }
    `};function qi(r,t){if(r===1)return""+t;if(r===2)return t+".y";if(r===3)return t+".z";if(r===4)return t+".w";throw Error("Cumulative sum for rank "+r+" is not yet supported")}var mf=function(r){this.variableNames=["A"],this.packedInputs=!1,this.packedOutput=!0,this.outPackingScheme=ar.DENSE;var t=er(r),e=Xe();this.outputShape=r,this.userCode=`
      ivec3 outCoordsFromFlatIndex(int index) {
        `+vn(["r","c","d"],r)+`
        return ivec3(r, c, d);
      }

      void main() {
        ivec2 resTexRC = ivec2(resultUV.yx *
          vec2(`+t[0]+", "+t[1]+`));
        int index = 4 * (resTexRC.x * `+t[1]+` + resTexRC.y);

        vec4 result = vec4(0.);

        for (int i=0; i<4; i++) {
          int flatIndex = index + i;
          ivec3 rc = outCoordsFromFlatIndex(flatIndex);
          result[i] = getA(rc.x, rc.y, rc.z);
        }

        `+e.output+` = result;
      }
    `},gf=function(r){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!0,this.outPackingScheme=ar.DENSE;var t=er(r),e=Xe();this.outputShape=r,this.userCode=`
      ivec3 outCoordsFromFlatIndex(int index) {
        `+vn(["r","c","d"],r)+`
        return ivec3(r, c, d);
      }

      void main() {
        ivec2 resTexRC = ivec2(resultUV.yx *
          vec2(`+t[0]+", "+t[1]+`));
        int index = 4 * (resTexRC.x * `+t[1]+` + resTexRC.y);

        vec4 result = vec4(0.);

        for (int i=0; i<4; i++) {
          int flatIndex = index + i;
          ivec3 rc = outCoordsFromFlatIndex(flatIndex);
          result[i] = getChannel(getA(rc.x, rc.y, rc.z), vec2(rc.y, rc.z));
        }

        `+e.output+` = result;
      }
    `},yf=(function(){function r(t,e,n){this.variableNames=["x"],this.outputShape=[],this.outputShape=t,this.blockSize=e,this.dataFormat=n,this.userCode=`
    void main() {
      ivec4 coords = getOutputCoords();
      int b = coords[0];
      int h = `+this.getHeightCoordString()+`;
      int w = `+this.getWidthCoordString()+`;
      int d = `+this.getDepthCoordString()+`;

      int in_h = h / `+e+`;
      int offset_h = imod(h, `+e+`);
      int in_w = w / `+e+`;
      int offset_w = imod(w, `+e+`);
      int offset_d = (offset_h * `+e+` + offset_w) *
        `+this.getOutputDepthSize()+`;
      int in_d = d + offset_d;

      float result = `+this.getInputSamplingString()+`;
      setOutput(result);
    }
  `}return r.prototype.getHeightCoordString=function(){return this.dataFormat==="NHWC"?"coords[1]":"coords[2]"},r.prototype.getWidthCoordString=function(){return this.dataFormat==="NHWC"?"coords[2]":"coords[3]"},r.prototype.getDepthCoordString=function(){return this.dataFormat==="NHWC"?"coords[3]":"coords[1]"},r.prototype.getOutputDepthSize=function(){return this.dataFormat==="NHWC"?this.outputShape[3]:this.outputShape[1]},r.prototype.getInputSamplingString=function(){return this.dataFormat==="NHWC"?"getX(b, in_h, in_w, in_d)":"getX(b, in_d, in_h, in_w)"},r})(),xf=function(r){this.variableNames=["X"],this.outputShape=[r,r],this.userCode=`
      void main() {
          ivec2 coords = getOutputCoords();
          float val = coords[0] == coords[1] ? getX(coords[0]) : 0.0;
          setOutput(val);
      }
    `},bf=function(r){this.variableNames=["A"],this.outTexUsage=st.DOWNLOAD;var t=Xe();this.outputShape=r,this.userCode=`
      `+pu+`

      void main() {
        float x = getAAtOutCoords();
        `+t.output+` = encode_float(x);
      }
    `},wf=function(r){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!1,this.outTexUsage=st.DOWNLOAD;var t=Xe();this.outputShape=r,this.userCode=`
      `+pu+`

      void main() {
        ivec3 coords = getOutputCoords();
        float x = getChannel(getAAtOutCoords(), vec2(coords.y, coords.z));
        `+t.output+` = encode_float(x);
      }
    `},Cf=function(r,t,e){e===void 0&&(e=!1),this.variableNames=["A"];var n=Xe(),o=t[0],a=t[1];this.outputShape=r;var i="result";e&&(i="floor(result * 255. + 0.5)"),this.userCode=`
      `+Ma(r)+`

      void main() {
        ivec3 coords = getOutputCoords();

        int flatIndex = getFlatIndex(coords);
        int offset = imod(flatIndex, 4);

        flatIndex = idiv(flatIndex, 4, 1.);
        
        int r = flatIndex / `+a+`;
        int c = imod(flatIndex, `+a+`);
        vec2 uv = (vec2(c, r) + halfCR) / vec2(`+a+".0, "+o+`.0);
        vec4 values = `+n.texture2D+`(A, uv);

        float result;

        if(offset == 0) {
          result = values[0];
        } else if(offset == 1) {
          result = values[1];
        } else if(offset == 2) {
          result = values[2];
        } else {
          result = values[3];
        }

        `+n.output+" = vec4("+i+`, 0., 0., 0.);
      }
    `},_f=function(r,t,e){e===void 0&&(e=!1),this.variableNames=["A"],this.packedInputs=!1,this.packedOutput=!0;var n=Xe(),o=t[0],a=t[1];this.outputShape=r;var i="",s="result";e&&(s="floor(result * 255. + 0.5)");for(var u=0;u<=1;u++)for(var c=0;c<=1;c++){var l=2*u+c;i+=`
          localCoords = coords;
          if(localCoords[2] + `+c+" < "+r[2]+`) {
            localCoords[2] += `+c+`;
            if(localCoords[1] + `+u+" < "+r[1]+`) {
              localCoords[1] += `+u+`;

              flatIndex = getFlatIndex(localCoords);
              offset = imod(flatIndex, 4);

              flatIndex = idiv(flatIndex, 4, 1.);

              r = flatIndex / `+a+`;
              c = imod(flatIndex, `+a+`);
              uv = (vec2(c, r) + halfCR) / vec2(`+a+".0, "+o+`.0);
              values = `+n.texture2D+`(A, uv);

              if(offset == 0) {
                result[`+l+`] = values[0];
              } else if(offset == 1) {
                result[`+l+`] = values[1];
              } else if(offset == 2) {
                result[`+l+`] = values[2];
              } else {
                result[`+l+`] = values[3];
              }
            }
          }
        `}this.userCode=`
      `+Ma(r)+`

      void main() {
        ivec3 coords = getOutputCoords();

        vec4 result = vec4(0.);
        int flatIndex, r, c, offset;
        ivec3 localCoords;
        vec2 uv;
        vec4 values;

        `+i+`

        `+n.output+" = "+s+`;
      }
    `},Ef="return real * expR - imag * expI;",If="return real * expI + imag * expR;",Ki=function(r,t,e){this.variableNames=["real","imag"];var n=t[1];this.outputShape=t;var o=e?"2.0 * "+Math.PI:"-2.0 * "+Math.PI,a=e?n+".0":"1.0";this.userCode=`
      const float exponentMultiplier = `+o+`;

      float unaryOpComplex(float real, float expR, float imag, float expI) {
        `+r+`
      }

      float mulMatDFT(int batch, int index) {
        float indexRatio = float(index) / float(`+n+`);
        float exponentMultiplierTimesIndexRatio =
            exponentMultiplier * indexRatio;

        float result = 0.0;

        for (int i = 0; i < `+n+`; i++) {
          // x = (-2|2 * PI / N) * index * i;
          float x = exponentMultiplierTimesIndexRatio * float(i);
          float expR = cos(x);
          float expI = sin(x);
          float real = getReal(batch, i);
          float imag = getImag(batch, i);

          result +=
              unaryOpComplex(real, expR, imag, expI) / `+a+`;
        }

        return result;
      }

      void main() {
        ivec2 coords = getOutputCoords();
        setOutput(mulMatDFT(coords[0], coords[1]));
      }
    `},Rf=(function(){function r(t,e){this.outputShape=[],this.variableNames=["x"],this.outputShape=t,this.userCode=`
      uniform float value;
      void main() {
        // Input can be obtained from uniform value.
        setOutput(value);
      }
    `}return r.prototype.getCustomSetupFunc=function(t){var e=this;return function(n,o){e.valueLoc==null&&(e.valueLoc=n.getUniformLocationNoThrow(o,"value")),n.gl.uniform1f(e.valueLoc,t)}},r})(),kf=function(r,t,e){this.variableNames=["A","indices"];var n=r.slice();n[e]=t,this.outputShape=n,this.rank=n.length;var o=we(this.rank),a=(function(i,s){var u=i.length;if(u>4)throw Error("Gather for rank "+u+" is not yet supported");if(u===1)return"int(getIndices(resRC))";for(var c=["resRC.x","resRC.y","resRC.z","resRC.w"],l=[],h=0;h<i.length;h++)h===s?l.push("int(getIndices("+c[h]+"))"):l.push(""+c[h]);return l.join()})(r,e);this.userCode=`
      void main() {
        `+o+` resRC = getOutputCoords();
        setOutput(getA(`+a+`));
      }
    `},Sf=function(r,t,e){this.sliceDim=r,this.strides=t,this.variableNames=["x","indices"],this.outputShape=e;var n=we(t.length),o=we(e.length),a=this.sliceDim>1?"strides[j]":"strides";this.userCode=`
        `+n+" strides = "+n+"("+this.strides+`);
         void main() {
          `+o+` coords = getOutputCoords();
          int flattenIndex = 0;
          for (int j = 0; j < `+this.sliceDim+`; j++) {
            int index = round(getIndices(coords[0], j));
            flattenIndex += index * `+a+`;
          }
          setOutput(getX(flattenIndex, coords[1]));
        }
      `};function Df(r,t){var e=Xe();return _l(r,t,e.version+`
    precision highp float;
    `+e.attribute+` vec3 clipSpacePos;
    `+e.attribute+` vec2 uv;
    `+e.varyingVs+` vec2 resultUV;

    void main() {
      gl_Position = vec4(clipSpacePos, 1);
      resultUV = uv;
    }`)}function Af(r,t){return Sl(r,t,new Float32Array([-1,1,0,0,1,-1,-1,0,0,0,1,1,0,1,1,1,-1,0,1,0]))}function Tf(r,t){return Dl(r,t,new Uint16Array([0,1,2,2,1,3]))}function pr(r,t,e,n,o,a,i){Tl(e,n);var s=Al(r,t),u=r.TEXTURE_2D;return J(r,t,(function(){return r.bindTexture(u,s)})),J(r,t,(function(){return r.texParameteri(u,r.TEXTURE_WRAP_S,r.CLAMP_TO_EDGE)})),J(r,t,(function(){return r.texParameteri(u,r.TEXTURE_WRAP_T,r.CLAMP_TO_EDGE)})),J(r,t,(function(){return r.texParameteri(u,r.TEXTURE_MIN_FILTER,r.NEAREST)})),J(r,t,(function(){return r.texParameteri(u,r.TEXTURE_MAG_FILTER,r.NEAREST)})),J(r,t,(function(){return r.texImage2D(u,0,o,e,n,0,a,i,null)})),J(r,t,(function(){return r.bindTexture(r.TEXTURE_2D,null)})),s}function Nf(r,t,e,n,o){var a=oo(e,n);return pr(r,t,a[0],a[1],o.internalFormatFloat,o.textureFormatFloat,r.FLOAT)}function Ff(r,t,e,n,o){var a=oo(e,n);return pr(r,t,a[0],a[1],o.internalFormatHalfFloat,o.textureFormatFloat,o.textureTypeHalfFloat)}function Pf(r,t,e,n,o){var a=oo(e,n);return pr(r,t,a[0],a[1],r.RGBA,r.RGBA,r.UNSIGNED_BYTE)}function Mf(r,t,e,n,o){var a=fr(e,n);return pr(r,t,a[0],a[1],o.internalFormatPackedFloat,r.RGBA,r.FLOAT)}function Of(r,t,e,n,o){var a=fr(e,n);return pr(r,t,a[0],a[1],o.internalFormatPackedHalfFloat,r.RGBA,o.textureTypeHalfFloat)}function Bf(r,t,e,n){return J(r,t,(function(){return r.bindBuffer(r.ARRAY_BUFFER,n)})),Pi(r,t,e,"clipSpacePos",n,3,20,0)&&Pi(r,t,e,"uv",n,2,20,12)}function Lf(r,t,e,n,o,a,i){var s,u,c;J(r,t,(function(){return r.bindTexture(r.TEXTURE_2D,e)})),a instanceof Uint8Array?(s=new Uint8Array(n*o*4),u=r.UNSIGNED_BYTE,c=r.RGBA):(s=new Float32Array(n*o*4),u=r.FLOAT,c=i.internalFormatPackedFloat),s.set(a),J(r,t,(function(){return r.texImage2D(r.TEXTURE_2D,0,c,n,o,0,r.RGBA,u,s)})),J(r,t,(function(){return r.bindTexture(r.TEXTURE_2D,null)}))}function Wf(r,t,e,n){J(r,t,(function(){return r.bindTexture(r.TEXTURE_2D,e)})),n.data instanceof Uint8Array?J(r,t,(function(){return r.texImage2D(r.TEXTURE_2D,0,r.RGBA,n.width,n.height,0,r.RGBA,r.UNSIGNED_BYTE,n.data)})):J(r,t,(function(){return r.texImage2D(r.TEXTURE_2D,0,r.RGBA,r.RGBA,r.UNSIGNED_BYTE,n)})),J(r,t,(function(){return r.bindTexture(r.TEXTURE_2D,null)}))}function Uf(r,t,e,n,o){var a=r.createBuffer();J(r,t,(function(){return r.bindBuffer(r.PIXEL_PACK_BUFFER,a)}));var i=16*e*n;return J(r,t,(function(){return r.bufferData(r.PIXEL_PACK_BUFFER,i,r.STREAM_READ)})),J(r,t,(function(){return r.readPixels(0,0,n,e,r.RGBA,r.FLOAT,0)})),J(r,t,(function(){return r.bindBuffer(r.PIXEL_PACK_BUFFER,null)})),a}function Vf(r,t,e){var n=r,o=new Float32Array(e);return n.bindBuffer(n.PIXEL_PACK_BUFFER,t),n.getBufferSubData(n.PIXEL_PACK_BUFFER,0,o),n.bindBuffer(n.PIXEL_PACK_BUFFER,null),o}function zf(r,t,e,n,o){var a=oo(e,n),i=a[0],s=a[1],u=new Uint8Array(e*n*4);return J(r,t,(function(){return r.readPixels(0,0,i,s,o.downloadTextureFormat,r.UNSIGNED_BYTE,u)})),new Float32Array(u.buffer)}function Gf(r,t,e,n,o,a,i,s){var u=r,c=new Float32Array((function(l,h){var f=fr(l,h);return f[0]*f[1]*4})(a,i));return u.bindBuffer(u.PIXEL_PACK_BUFFER,t),u.getBufferSubData(u.PIXEL_PACK_BUFFER,0,c),u.bindBuffer(u.PIXEL_PACK_BUFFER,null),c}function Hf(r,t,e,n){var o=new Float32Array(e*n*4);return J(r,t,(function(){return r.readPixels(0,0,n,e,r.RGBA,r.FLOAT,o)})),o}var jf=(function(){function r(t){this.outputTexture=null,this.program=null,this.disposed=!1,this.vertexAttrsAreBound=!1,this.itemsToPoll=[];var e=L().getNumber("WEBGL_VERSION");t!=null?(this.gl=t,yl(e,t)):this.gl=Pt(e);var n="WEBGL_color_buffer_float";if(L().getNumber("WEBGL_VERSION")===1){if(this.textureFloatExtension=br(this.gl,this.debug,"OES_texture_float"),pt(this.gl,"OES_texture_half_float"))this.textureHalfFloatExtension=br(this.gl,this.debug,"OES_texture_half_float");else if(L().get("WEBGL_FORCE_F16_TEXTURES"))throw new Error("GL context does not support half float textures, yet the environment flag WEBGL_FORCE_F16_TEXTURES is set to true.");if(this.colorBufferFloatExtension=this.gl.getExtension(n),pt(this.gl,"EXT_color_buffer_half_float"))this.colorBufferHalfFloatExtension=br(this.gl,this.debug,"EXT_color_buffer_half_float");else if(L().get("WEBGL_FORCE_F16_TEXTURES"))throw new Error("GL context does not support color renderable half floats, yet the environment flag WEBGL_FORCE_F16_TEXTURES is set to true.")}else if(n="EXT_color_buffer_float",pt(this.gl,n))this.colorBufferFloatExtension=this.gl.getExtension(n);else{if(!pt(this.gl,"EXT_color_buffer_half_float"))throw new Error("GL context does not support color renderable floats");this.colorBufferHalfFloatExtension=this.gl.getExtension("EXT_color_buffer_half_float")}this.vertexBuffer=Af(this.gl,this.debug),this.indexBuffer=Tf(this.gl,this.debug),this.framebuffer=Nl(this.gl,this.debug),this.textureConfig=Ia(this.gl,this.textureHalfFloatExtension)}return Object.defineProperty(r.prototype,"debug",{get:function(){return L().getBool("DEBUG")},enumerable:!0,configurable:!0}),r.prototype.dispose=function(){var t=this;if(!this.disposed){this.program!=null&&console.warn("Disposing a GPGPUContext that still has a bound WebGLProgram. This is probably a resource leak, delete the program with GPGPUContext.deleteProgram before disposing."),this.outputTexture!=null&&console.warn("Disposing a GPGPUContext that still has a bound output matrix texture.  This is probably a resource leak, delete the output matrix texture with GPGPUContext.deleteMatrixTexture before disposing.");var e=this.gl;J(e,this.debug,(function(){return e.finish()})),J(e,this.debug,(function(){return e.bindFramebuffer(e.FRAMEBUFFER,null)})),J(e,this.debug,(function(){return e.deleteFramebuffer(t.framebuffer)})),J(e,this.debug,(function(){return e.bindBuffer(e.ARRAY_BUFFER,null)})),J(e,this.debug,(function(){return e.bindBuffer(e.ELEMENT_ARRAY_BUFFER,null)})),J(e,this.debug,(function(){return e.deleteBuffer(t.indexBuffer)})),this.disposed=!0}},r.prototype.createFloat32MatrixTexture=function(t,e){return this.throwIfDisposed(),Nf(this.gl,this.debug,t,e,this.textureConfig)},r.prototype.createFloat16MatrixTexture=function(t,e){return this.throwIfDisposed(),Ff(this.gl,this.debug,t,e,this.textureConfig)},r.prototype.createUnsignedBytesMatrixTexture=function(t,e){return this.throwIfDisposed(),Pf(this.gl,this.debug,t,e,this.textureConfig)},r.prototype.uploadPixelDataToTexture=function(t,e){this.throwIfDisposed(),Wf(this.gl,this.debug,t,e)},r.prototype.uploadDenseMatrixToTexture=function(t,e,n,o){this.throwIfDisposed(),Lf(this.gl,this.debug,t,e,n,o,this.textureConfig)},r.prototype.createFloat16PackedMatrixTexture=function(t,e){return this.throwIfDisposed(),Of(this.gl,this.debug,t,e,this.textureConfig)},r.prototype.createPackedMatrixTexture=function(t,e){return this.throwIfDisposed(),Mf(this.gl,this.debug,t,e,this.textureConfig)},r.prototype.deleteMatrixTexture=function(t){var e=this;this.throwIfDisposed(),this.outputTexture===t&&(Mi(this.gl,this.debug,this.framebuffer),this.outputTexture=null),J(this.gl,this.debug,(function(){return e.gl.deleteTexture(t)}))},r.prototype.downloadByteEncodedFloatMatrixFromOutputTexture=function(t,e,n){var o=this;return this.downloadMatrixDriver(t,(function(){return zf(o.gl,o.debug,e,n,o.textureConfig)}))},r.prototype.downloadPackedMatrixFromBuffer=function(t,e,n,o,a,i){return Gf(this.gl,t,0,0,0,a,i,this.textureConfig)},r.prototype.downloadFloat32MatrixFromBuffer=function(t,e){return Vf(this.gl,t,e)},r.prototype.createBufferFromTexture=function(t,e,n){this.bindTextureToFrameBuffer(t);var o=Uf(this.gl,this.debug,e,n,this.textureConfig);return this.unbindTextureToFrameBuffer(),o},r.prototype.createAndWaitForFence=function(){var t=this.createFence(this.gl);return this.pollFence(t)},r.prototype.createFence=function(t){var e,n,o=this;if(L().getBool("WEBGL_FENCE_API_ENABLED")){var a=t,i=a.fenceSync(a.SYNC_GPU_COMMANDS_COMPLETE,0);t.flush(),n=function(){var s=a.clientWaitSync(i,0,0);return s===a.ALREADY_SIGNALED||s===a.CONDITION_SATISFIED},e=i}else L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION")>0?(e=this.beginQuery(),this.endQuery(),n=function(){return o.isQueryAvailable(e,L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION"))}):n=function(){return!0};return{query:e,isFencePassed:n}},r.prototype.downloadMatrixFromPackedTexture=function(t,e,n){var o=this;return this.downloadMatrixDriver(t,(function(){return Hf(o.gl,o.debug,e,n)}))},r.prototype.createProgram=function(t){this.throwIfDisposed();var e=this.gl,n=El(e,this.debug,t),o=Df(e,this.debug),a=Rl(e,this.debug);return J(e,this.debug,(function(){return e.attachShader(a,o)})),J(e,this.debug,(function(){return e.attachShader(a,n)})),kl(e,this.debug,a),this.debug&&Fo(e,this.debug,a),this.vertexAttrsAreBound||(this.setProgram(a),this.vertexAttrsAreBound=Bf(e,this.debug,this.program,this.vertexBuffer)),a},r.prototype.deleteProgram=function(t){var e=this;this.throwIfDisposed(),t===this.program&&(this.program=null),t!=null&&J(this.gl,this.debug,(function(){return e.gl.deleteProgram(t)}))},r.prototype.setProgram=function(t){var e=this;this.throwIfDisposed(),this.program=t,this.program!=null&&this.debug&&Fo(this.gl,this.debug,this.program),J(this.gl,this.debug,(function(){return e.gl.useProgram(t)}))},r.prototype.getUniformLocation=function(t,e,n){return n===void 0&&(n=!0),this.throwIfDisposed(),n?Pl(this.gl,this.debug,t,e):Ml(this.gl,t,e)},r.prototype.getAttributeLocation=function(t,e){var n=this;return this.throwIfDisposed(),J(this.gl,this.debug,(function(){return n.gl.getAttribLocation(t,e)}))},r.prototype.getUniformLocationNoThrow=function(t,e){return this.throwIfDisposed(),this.gl.getUniformLocation(t,e)},r.prototype.setInputMatrixTexture=function(t,e,n){this.throwIfDisposed(),this.throwIfNoProgram(),Ol(this.gl,this.debug,this.program,t,e,n)},r.prototype.setOutputMatrixTexture=function(t,e,n){this.setOutputMatrixTextureDriver(t,n,e)},r.prototype.setOutputPackedMatrixTexture=function(t,e,n){this.throwIfDisposed();var o=fr(e,n),a=o[0],i=o[1];this.setOutputMatrixTextureDriver(t,a,i)},r.prototype.setOutputMatrixWriteRegion=function(t,e,n,o){this.setOutputMatrixWriteRegionDriver(n,t,o,e)},r.prototype.setOutputPackedMatrixWriteRegion=function(t,e,n,o){throw new Error("setOutputPackedMatrixWriteRegion not implemented.")},r.prototype.debugValidate=function(){this.program!=null&&Fo(this.gl,this.debug,this.program),wr(this.gl)},r.prototype.executeProgram=function(){this.throwIfDisposed(),this.throwIfNoProgram();var t=this.gl;this.debug&&this.debugValidate(),J(t,this.debug,(function(){return t.drawElements(t.TRIANGLES,6,t.UNSIGNED_SHORT,0)}))},r.prototype.blockUntilAllProgramsCompleted=function(){var t=this;this.throwIfDisposed(),J(this.gl,this.debug,(function(){return t.gl.finish()}))},r.prototype.getQueryTimerExtension=function(){return this.disjointQueryTimerExtension==null&&(this.disjointQueryTimerExtension=br(this.gl,this.debug,L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION")===2?"EXT_disjoint_timer_query_webgl2":"EXT_disjoint_timer_query")),this.disjointQueryTimerExtension},r.prototype.getQueryTimerExtensionWebGL2=function(){return this.getQueryTimerExtension()},r.prototype.getQueryTimerExtensionWebGL1=function(){return this.getQueryTimerExtension()},r.prototype.beginQuery=function(){if(L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION")===2){var t=this.gl,e=this.getQueryTimerExtensionWebGL2(),n=t.createQuery();return t.beginQuery(e.TIME_ELAPSED_EXT,n),n}var o=this.getQueryTimerExtensionWebGL1(),a=o.createQueryEXT();return o.beginQueryEXT(o.TIME_ELAPSED_EXT,a),a},r.prototype.endQuery=function(){if(L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION")!==2){var t=this.getQueryTimerExtensionWebGL1();t.endQueryEXT(t.TIME_ELAPSED_EXT)}else{var e=this.gl,n=this.getQueryTimerExtensionWebGL2();e.endQuery(n.TIME_ELAPSED_EXT)}},r.prototype.waitForQueryAndGetTime=function(t){return X(this,void 0,void 0,(function(){var e=this;return $(this,(function(n){switch(n.label){case 0:return[4,Si((function(){return e.disposed||e.isQueryAvailable(t,L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION"))}))];case 1:return n.sent(),[2,this.getQueryTime(t,L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_VERSION"))]}}))}))},r.prototype.getQueryTime=function(t,e){if(e===0)return null;if(e===2){var n=this.gl;return n.getQueryParameter(t,n.QUERY_RESULT)/1e6}var o=this.getQueryTimerExtensionWebGL1();return o.getQueryObjectEXT(t,o.QUERY_RESULT_EXT)/1e6},r.prototype.isQueryAvailable=function(t,e){if(e===0)return!0;if(e===2){var n=this.gl,o=this.getQueryTimerExtensionWebGL2(),a=n.getQueryParameter(t,n.QUERY_RESULT_AVAILABLE);return this.disjoint==null&&(this.disjoint=this.gl.getParameter(o.GPU_DISJOINT_EXT)),a&&!this.disjoint}return a=(o=this.getQueryTimerExtensionWebGL1()).getQueryObjectEXT(t,o.QUERY_RESULT_AVAILABLE_EXT),this.disjoint==null&&(this.disjoint=this.gl.getParameter(o.GPU_DISJOINT_EXT)),a&&!this.disjoint},r.prototype.pollFence=function(t){var e=this;return new Promise((function(n){e.addItemToPoll((function(){return t.isFencePassed()}),(function(){return n()}))}))},r.prototype.pollItems=function(){for(var t=(function(n){for(var o=0;o<n.length&&n[o]();++o);return o-1})(this.itemsToPoll.map((function(n){return n.isDoneFn}))),e=0;e<=t;++e)(0,this.itemsToPoll[e].resolveFn)();this.itemsToPoll=this.itemsToPoll.slice(t+1)},r.prototype.addItemToPoll=function(t,e){var n=this;this.itemsToPoll.push({isDoneFn:t,resolveFn:e}),this.itemsToPoll.length>1||Si((function(){return n.pollItems(),n.itemsToPoll.length===0}))},r.prototype.bindTextureToFrameBuffer=function(t){this.throwIfDisposed(),Po(this.gl,this.debug,t,this.framebuffer),this.debug&&wr(this.gl)},r.prototype.unbindTextureToFrameBuffer=function(){this.outputTexture!=null?(Po(this.gl,this.debug,this.outputTexture,this.framebuffer),this.debug&&wr(this.gl)):Mi(this.gl,this.debug,this.framebuffer)},r.prototype.downloadMatrixDriver=function(t,e){this.bindTextureToFrameBuffer(t);var n=e();return this.unbindTextureToFrameBuffer(),n},r.prototype.setOutputMatrixTextureDriver=function(t,e,n){this.throwIfDisposed();var o=this.gl;Po(o,this.debug,t,this.framebuffer),this.debug&&wr(o),this.outputTexture=t,J(o,this.debug,(function(){return o.viewport(0,0,e,n)})),J(o,this.debug,(function(){return o.scissor(0,0,e,n)}))},r.prototype.setOutputMatrixWriteRegionDriver=function(t,e,n,o){var a=this;this.throwIfDisposed(),J(this.gl,this.debug,(function(){return a.gl.scissor(t,e,n,o)}))},r.prototype.throwIfDisposed=function(){if(this.disposed)throw new Error("Attempted to use disposed GPGPUContext.")},r.prototype.throwIfNoProgram=function(){if(this.program==null)throw new Error("No GPU program is currently set.")},r})();function Xi(r,t){if(r.length!==t.length)throw Error("Binary was compiled with "+r.length+" inputs, but was executed with "+t.length+" inputs");r.forEach((function(e,n){var o=e.logicalShape,a=t[n],i=a.shape;if(!Ue(o,i))throw Error("Binary was compiled with different shapes than the current args. Shapes "+o+" and "+i+" must match");if(!e.isUniform||!a.isUniform){var s=e.texShape,u=a.isUniform?null:a.texData.texShape;if(!Ue(s,u))throw Error("Binary was compiled with different texture shapes than the current args. Shape "+s+" and "+u+" must match")}}))}var qf=function(r,t,e){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=r;for(var n=e.filterWidth,o=e.inChannels,a=e.strideWidth,i=e.strideHeight,s=e.padInfo,u=e.outWidth,c=e.dilationWidth,l=e.dilationHeight,h=e.dataFormat,f=s.left,p=s.top,d=o*n,v=Xe(),m=h==="channelsLast",g=m?0:1,x=m?1:2,b="",y=0;y<=1;y++)for(var w=0;w<=1;w++)b+=`
          blockIndex = rc.y + `+w+`;
          pos = rc.x + `+y+`;

          if(blockIndex < `+r[1]+" && pos < "+r[0]+`) {
            offsetY = int(blockIndex / (`+u+")) * "+i+" - "+p+`;
            d0 = offsetY + `+l+" * (pos / "+d+`);

            if(d0 < `+t[g]+` && d0 >= 0) {

              offsetX = int(mod(float(blockIndex), `+u+".) * "+a+". - "+f+`.);
              d1 = offsetX + `+c+" * (int(mod(float(pos), "+d+".) / "+o+`.));

              if(d1 < `+t[x]+` && d1 >= 0) {

                ch = int(mod(float(pos), `+o+`.));

                if (`+m+`) {
                  innerDims = vec2(d1, ch);
                  result[`+(2*y+w)+`] = getChannel(
                    getA(d0, int(innerDims.x),
                    int(innerDims.y)), innerDims);
                } else {
                  innerDims = vec2(d0, d1);
                  result[`+(2*y+w)+`] = getChannel(
                    getA(ch, int(innerDims.x),
                    int(innerDims.y)), innerDims);
                }
              }
            }
          }
        `;this.userCode=`
      void main() {
        ivec2 rc = getOutputCoords();

        vec4 result = vec4(0);

        int blockIndex, pos, offsetY, d0, offsetX, d1, ch;
        vec2 innerDims;

        `+b+`

        `+v.output+` = result;
      }
    `},Kf=function(r,t,e,n,o){this.variableNames=["x"],this.outputShape=[];var a,i=t,s=r[3]-1;this.outputShape=r;var u="float("+e+") + float("+n+") * sum";a=o===.5?"inversesqrt("+u+")":o===1?"1.0/("+u+")":"exp(log("+u+") * float(-"+o+"));",this.userCode=`
      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int r = coords[1];
        int c = coords[2];
        int d = coords[3];
        float x = getX(b, r, c, d);
        float sum = 0.0;
        for (int j = -`+i+"; j <= "+i+`; j++) {
          int idx = d + j;
          if (idx >= 0 && idx <=  `+s+`) {
            float z = getX(b, r, c, idx);
            sum += z * z;
          }
        }
        float val = x * `+a+`;
        setOutput(val);
      }
    `},Xf=function(r,t,e,n,o){this.variableNames=["inputImage","outputImage","dy"],this.outputShape=[],this.outputShape=r,this.depth=r[3],this.depthRadius=t,this.bias=e,this.alpha=n,this.beta=o,this.userCode=`
      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int r = coords[1];
        int c = coords[2];

        float result = 0.0;
        for (int d = 0; d < `+this.depth+`; ++d) {
          int depthBegin = int(max(0.0, float(d - `+t+`)));
          int depthEnd = int(min(float(`+this.depth+`),
              float(d + `+t+` + 1)));

          const int MIN_DEPTH_BEGIN = 0;
          const int MAX_DEPTH_END = `+this.depth+`;

          float norm = 0.0;
          for (int k = MIN_DEPTH_BEGIN; k < MAX_DEPTH_END; ++k) {
            if (k < depthBegin){
              continue;
            }
            else if (k >= depthBegin && k < depthEnd) {
              norm += getInputImage(b, r, c, k) * getInputImage(b, r, c, k);
            }
            else {
              break;
            }
          }

          norm = float(`+n+") * norm + float("+e+`);

          for(int k = MIN_DEPTH_BEGIN; k < MAX_DEPTH_END; ++k){
            if (k < depthBegin){
              continue;
            }
            else if (k >= depthBegin && k < depthEnd){
              float dyi = -2.0 * float(`+n+`)
                * float(`+o+`)
                * getInputImage(b ,r ,c, k) * getOutputImage(b, r, c, d)
                / norm;
              if (k == d) {
                dyi += pow(norm, -1.0 * `+o+`);
              }
              if (k == coords[3]) {
                dyi *= getDy(b, r, c, d);
                result += dyi;
              }
            }
            else {
              break;
            }
          }
      }
      setOutput(result);
      }
    `},$f=function(r,t,e,n,o){this.variableNames=["x"],this.outputShape=[],this.packedInputs=!0,this.packedOutput=!0;var a,i=t,s=r[3]-1;this.outputShape=r;var u="float("+e+") + float("+n+") * sum";a=o===.5?"inversesqrt("+u+")":o===1?"1.0/("+u+")":"exp(log("+u+") * float(-"+o+"));",this.userCode=`
      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords.x;
        int r = coords.y;
        int c = coords.z;
        int d = coords.w;

        bool hasNextCol = d < `+this.outputShape[3]+`;
        bool hasNextRow = c < `+this.outputShape[2]+`;

        vec4 sum = vec4(0.);
        vec4 xFragAtOutputCoords = getX(b, r, c, d);

        vec4 xAtOutputCoords = vec4(
          getChannel(xFragAtOutputCoords, vec2(c, d)),
          hasNextCol ?
            getChannel(xFragAtOutputCoords, vec2(c, d + 1)) : 0.0,
          hasNextRow ?
            getChannel(xFragAtOutputCoords , vec2(c + 1, d)) : 0.0,
          (hasNextRow && hasNextCol) ?
            getChannel(xFragAtOutputCoords, vec2(c + 1, d + 1)) : 0.0
        );

        int firstChannel = d - `+i+`;
        vec2 cache = vec2(0.);
        if(firstChannel >= 0){
          vec4 firstChannelFrag = getX(b, r, c, firstChannel);
          cache.x = getChannel(firstChannelFrag, vec2(c, firstChannel));
            if(hasNextRow){
              cache.y = getChannel(firstChannelFrag, vec2(c + 1, firstChannel));
            }
        }

        ivec2 depth = ivec2(d, d + 1);
        for (int j = - `+i+"; j <= "+i+`; j++) {
          ivec2 idx = depth + j;
          bvec2 aboveLowerBound = greaterThanEqual(idx, ivec2(0));
          bvec2 belowUpperBound = lessThanEqual(idx, ivec2(`+s+`));

          bool depthInRange = aboveLowerBound.x && belowUpperBound.x;
          bool depthPlusOneInRange = aboveLowerBound.y && belowUpperBound.y;

          if(depthInRange || depthPlusOneInRange){
            vec4 z = vec4(0.);
            vec4 xFragAtCurrentDepth;
            z.xz = cache.xy;
            if(depthPlusOneInRange && hasNextCol){
              xFragAtCurrentDepth = idx.y != d ?
                getX(b, r, c, idx.y) : xFragAtOutputCoords;
              z.y = getChannel(xFragAtCurrentDepth, vec2(c, idx.y));
              if(hasNextRow){
                z.w = getChannel(xFragAtCurrentDepth, vec2(c + 1, idx.y));
              }
            }
            cache.xy = z.yw;
            sum += z * z;
          }
        }
        vec4 result = xAtOutputCoords * `+a+`;
        setOutput(result);
      }
    `},Yf=function(r){this.variableNames=["dy","maxPos"],this.outputShape=r.inShape;var t=r.strideHeight,e=r.strideWidth,n=r.dilationHeight,o=r.effectiveFilterHeight,a=r.effectiveFilterWidth,i=o-1-r.padInfo.top,s=a-1-r.padInfo.left,u=o*a-1;this.userCode=`
      const ivec2 pads = ivec2(`+i+", "+s+`);

      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int d = coords[3];

        ivec2 dyRCCorner = coords.yz - pads;
        int dyRCorner = dyRCCorner.x;
        int dyCCorner = dyRCCorner.y;

        // Convolve dy(?, ?, d) with pos mask(:, :, d) to get dx(xR, xC, d).
        // ? = to be determined. : = across all values in that axis.
        float dotProd = 0.0;
        for (int wR = 0; wR < `+o+`;
          wR += `+n+`) {
          float dyR = float(dyRCorner + wR) / `+t+`.0;

          if (dyR < 0.0 || dyR >= `+r.outHeight+`.0 || fract(dyR) > 0.0) {
            continue;
          }
          int idyR = int(dyR);

          for (int wC = 0; wC < `+a+`; wC++) {
            float dyC = float(dyCCorner + wC) / `+e+`.0;

            if (dyC < 0.0 || dyC >= `+r.outWidth+`.0 ||
                fract(dyC) > 0.0) {
              continue;
            }
            int idyC = int(dyC);

            float dyValue = getDy(b, idyR, idyC, d);
            int maxPosValue = `+u+` - int(getMaxPos(b, idyR, idyC, d));

            // Get the current value, check it against the value from the
            // position matrix.
            int curPosValue = wR * `+a+` + wC;
            float mask = float(maxPosValue == curPosValue ? 1.0 : 0.0);

            dotProd += dyValue * mask;
          }
        }
        setOutput(dotProd);
      }
    `},Jf=function(r){this.variableNames=["dy","maxPos"],this.outputShape=r.inShape;var t=r.strideDepth,e=r.strideHeight,n=r.strideWidth,o=r.dilationDepth,a=r.dilationHeight,i=r.dilationWidth,s=r.effectiveFilterDepth,u=r.effectiveFilterHeight,c=r.effectiveFilterWidth,l=s-1-r.padInfo.front,h=u-1-r.padInfo.top,f=c-1-r.padInfo.left,p=s*u*c-1;this.userCode=`
      const ivec3 pads = ivec3(`+l+", "+h+", "+f+`);

      void main() {
        ivec5 coords = getOutputCoords();
        int batch = coords.x;
        int ch = coords.u;

        ivec3 dyCorner = ivec3(coords.y, coords.z, coords.w) - pads;
        int dyDCorner = dyCorner.x;
        int dyRCorner = dyCorner.y;
        int dyCCorner = dyCorner.z;

        // Convolve dy(?, ?, ?, ch) with pos mask(:, :, :, d) to get
        // dx(xD, xR, xC, ch).
        // ? = to be determined. : = across all values in that axis.
        float dotProd = 0.0;

        for (int wD = 0; wD < `+s+`;
           wD += `+o+`) {
          float dyD = float(dyDCorner + wD) / `+t+`.0;

          if (dyD < 0.0 || dyD >= `+r.outDepth+`.0 || fract(dyD) > 0.0) {
            continue;
          }
          int idyD = int(dyD);

          for (int wR = 0; wR < `+u+`;
              wR += `+a+`) {
            float dyR = float(dyRCorner + wR) / `+e+`.0;

            if (dyR < 0.0 || dyR >= `+r.outHeight+`.0 ||
                fract(dyR) > 0.0) {
              continue;
            }
            int idyR = int(dyR);

            for (int wC = 0; wC < `+c+`;
                wC += `+i+`) {
              float dyC = float(dyCCorner + wC) / `+n+`.0;

              if (dyC < 0.0 || dyC >= `+r.outWidth+`.0 ||
                  fract(dyC) > 0.0) {
                continue;
              }
              int idyC = int(dyC);

              float dyValue = getDy(batch, idyD, idyR, idyC, ch);
              int maxPosValue = `+p+` -
                  int(getMaxPos(batch, idyD, idyR, idyC, ch));

              // Get the current value, check it against the value from the
              // position matrix.
              int curPosValue =
                  wD * `+u+" * "+c+` +
                  wR * `+c+` + wC;
              float mask = float(maxPosValue == curPosValue ? 1.0 : 0.0);

              dotProd += dyValue * mask;
            }
          }
        }
        setOutput(dotProd);
      }
    `},Wo=function(r,t,e,n,o,a,i){e===void 0&&(e=!1),n===void 0&&(n=!1),o===void 0&&(o=!1),a===void 0&&(a=null),i===void 0&&(i=!1),this.variableNames=["matrixA","matrixB"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=t;var s=e?r[1]:r[2],u=Math.ceil(s/2),c=e?"i * 2, rc.y":"rc.y, i * 2",l=n?"rc.z, i * 2":"i * 2, rc.z",h=e?["a.xxyy","a.zzww"]:["a.xxzz","a.yyww"],f=n?["b.xzxz","b.ywyw"]:["b.xyxy","b.zwzw"],p="",d="";a&&(p=i?`vec4 activation(vec4 a) {
          vec4 b = getPreluActivationWeightsAtOutCoords();
          `+a+`
        }`:`vec4 activation(vec4 x) {
          `+a+`
        }`,d="result = activation(result);");var v=o?"result += getBiasAtOutCoords();":"";o&&this.variableNames.push("bias"),i&&this.variableNames.push("preluActivationWeights"),this.userCode=`
      `+p+`

      const float sharedDimension = `+u+`.0;

      vec4 dot2x2ARowBCol(ivec3 rc) {
        vec4 result = vec4(0);
        for (int i = 0; i < `+u+`; i++) {
          vec4 a = getMatrixA(rc.x, `+c+`);
          vec4 b = getMatrixB(rc.x, `+l+`);

          // These swizzled products need to be separately added.
          // See: https://github.com/tensorflow/tfjs/issues/1735
          result += (`+h[0]+" * "+f[0]+`);
          result += (`+h[1]+" * "+f[1]+`);
        }
        return result;
      }

      void main() {
        ivec3 rc = getOutputCoords();
        vec4 result = dot2x2ARowBCol(rc);

        `+v+`

        `+d+`

        setOutput(result);
      }
    `},Qf=(function(){function r(t,e,n){this.variableNames=["probs"],this.outputShape=[t,n],this.userCode=`
      uniform float seed;

      void main() {
        ivec2 coords = getOutputCoords();
        int batch = coords[0];

        float r = random(seed);
        float cdf = 0.0;

        for (int i = 0; i < `+(e-1)+`; i++) {
          cdf += getProbs(batch, i);

          if (r < cdf) {
            setOutput(float(i));
            return;
          }
        }

        // If no other event happened, last event happened.
        setOutput(float(`+(e-1)+`));
      }
    `}return r.prototype.getCustomSetupFunc=function(t){var e=this;return function(n,o){e.seedLoc==null&&(e.seedLoc=n.getUniformLocation(o,"seed")),n.gl.uniform1f(e.seedLoc,t)}},r})(),Zf=function(r,t,e,n){this.variableNames=["indices"],this.outputShape=[r,t],this.userCode=`
      void main() {
        ivec2 coords = getOutputCoords();
        int index = round(getIndices(coords.x));
        setOutput(mix(float(`+n+"), float("+e+`),
                      float(index == coords.y)));
      }
    `},ep=function(r){this.variableNames=["A"],this.packedInputs=!1,this.packedOutput=!0,this.outputShape=r;var t=r.length;if(t===0)this.userCode=`
        void main() {
          setOutput(vec4(getA(), 0., 0., 0.));
        }
      `;else{var e=et("rc",t),n=we(t),o=(function(s,u,c){if(s===1)return"rc > "+u[0];for(var l="",h=s-2;h<s;h++)l+=c[h]+" >= "+u[h],h<s-1&&(l+="||");return l})(t,r,e),a=(function(s,u,c,l){if(s===1)return"";var h=l.slice(-2);return`
    int r = `+h[0]+`;
    int c = `+h[1]+`;
    int rp1 = r + 1;
    int cp1 = c + 1;

    bool cEdge = cp1 >= `+u+`;
    bool rEdge = rp1 >= `+c+`;
  `})(t,r[r.length-1],r[r.length-2],e),i=(function(s,u){var c=s.length,l=(function(h,f){for(var p=[],d=0;d<=1;d++)for(var v=0;v<=1;v++){for(var m=(d===0?"r":"rp1")+", "+(v===0?"c":"cp1"),g=2;g<h;g++)m=f[f.length-1-g]+","+m;p.push(m)}return p})(c,u);return c===1?`getA(rc),
            rc + 1 >= `+s[0]+` ? 0. : getA(rc + 1),
            0, 0`:"getA("+l[0]+`),
          cEdge ? 0. : getA(`+l[1]+`),
          rEdge ? 0. : getA(`+l[2]+`),
          rEdge || cEdge ? 0. : getA(`+l[3]+")"})(r,e);this.userCode=`
        void main() {
          `+n+` rc = getOutputCoords();

          if(`+o+`) {
            setOutput(vec4(0));
          } else {
            `+a+`

            setOutput(vec4(`+i+`));
          }
        }
      `}},tp=function(r,t,e){this.variableNames=["x"],this.outputShape=t.map((function(u,c){return u[0]+r[c]+u[1]}));var n=r.length,o=we(n),a=t.map((function(u){return u[0]})).join(","),i=t.map((function(u,c){return u[0]+r[c]})).join(","),s=["coords[0]","coords[1]","coords[2]","coords[3]"].slice(0,n);this.userCode=n!==1?`
      `+o+" start = "+o+"("+a+`);
      `+o+" end = "+o+"("+i+`);

      void main() {
        `+o+` outC = getOutputCoords();
        if (any(lessThan(outC, start)) || any(greaterThanEqual(outC, end))) {
          setOutput(float(`+e+`));
        } else {
          `+o+` coords = outC - start;
          setOutput(getX(`+s+`));
        }
      }
    `:`
        int start = `+a+`;
        int end = `+i+`;

        void main() {
          int outC = getOutputCoords();
          if (outC < start || outC >= end) {
            setOutput(float(`+e+`));
          } else {
            setOutput(getX(outC - start));
          }
        }
      `},np=function(r,t,e){this.variableNames=["x"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=t.map((function(m,g){return m[0]+r[g]+m[1]}));for(var n=r.length,o=we(n),a=t.map((function(m){return m[0]})).join(","),i=t.map((function(m,g){return m[0]+r[g]})).join(","),s=et("rc",n),u=et("source",n),c=s[n-1]+" < "+this.outputShape[n-1],l=n===1?"source":"vec2("+u.slice(-2).join()+")",h=[o+" rc = outputLoc;",s[n-1]+` += 1;
       if(`+c+`) {
      `,n===1?"":`}
       rc = outputLoc;
       `+s[n-2]+` += 1;
       if(`+s[n-2]+" < "+this.outputShape[n-2]+") {",n===1?"":"  "+s[n-1]+` += 1;
         if(`+c+") {"],f=n===1?"rc < start || rc >= end":"any(lessThan(rc, start)) || any(greaterThanEqual(rc, end))",p="",d=0,v=n===1?2:4;d<v;d++)p+=`
        `+h[d]+`
        if (`+f+`) {
          result[`+d+"] = float("+e+`);
        } else {
          `+o+` source = rc - start;
          result[`+d+"] = getChannel(getX("+u.join()+"), "+l+`);
        }
      `;p+=n===1?"} ":"}}",this.userCode=`
      const `+o+" start = "+o+"("+a+`);
      const `+o+" end = "+o+"("+i+`);

      void main() {
        `+o+` outputLoc = getOutputCoords();
        vec4 result = vec4(0.);
        `+p+`
        setOutput(result);
      }
    `},Uo=function(r,t,e){if(this.variableNames=["x"],t==="avg"&&e)throw new Error("Cannot compute positions for average pool.");var n=r.filterWidth,o=r.strideHeight,a=r.strideWidth,i=r.dilationHeight,s=r.dilationWidth,u=r.effectiveFilterHeight,c=r.effectiveFilterWidth,l=r.padInfo.top,h=r.padInfo.left;this.outputShape=r.outShape;var f=t==="avg",p="0.0";if(f||(p="-1.0 / 1e-20"),e)this.userCode=`
        const ivec2 strides = ivec2(`+o+", "+a+`);
        const ivec2 pads = ivec2(`+l+", "+h+`);

        void main() {
          ivec4 coords = getOutputCoords();
          int batch = coords[0];
          int d = coords[3];

          ivec2 xRCCorner = coords.yz * strides - pads;
          int xRCorner = xRCCorner.x;
          int xCCorner = xRCCorner.y;

          // max/min x(?, ?, d) to get y(yR, yC, d).
          // ? = to be determined
          float minMaxValue = 0.0;
          float minMaxValueFound = 0.0;
          int minMaxPosition = 0;
          float avgValue = 0.0;

          for (int wR = 0; wR < `+u+`;
              wR += `+i+`) {
            int xR = xRCorner + wR;

            if (xR < 0 || xR >= `+r.inHeight+`) {
              continue;
            }

            for (int wC = 0; wC < `+c+`;
                wC += `+s+`) {
              int xC = xCCorner + wC;

              if (xC < 0 || xC >= `+r.inWidth+`) {
                continue;
              }

              float value = getX(batch, xR, xC, d);

              // If a min / max value has already been found, use it. If not,
              // use the current value.
              float currMinMaxValue = mix(
                  value, minMaxValue, minMaxValueFound);
              if (value >= currMinMaxValue) {
                minMaxValue = value;
                minMaxValueFound = 1.0;
                minMaxPosition = wR * `+c+` + wC;
              }
            }
          }
          setOutput(float(minMaxPosition));
        }
      `;else{var d=t+"("+t+"("+t+"(minMaxValue[0], minMaxValue[1]), minMaxValue[2]), minMaxValue[3])";t==="avg"&&(d="avgValue / count");var v=4*Math.floor(n/4),m=n%4,g=`
      if (`+f+`) {
        avgValue += dot(values, ones);
      } else {
        minMaxValue = max(values, minMaxValue);
      }
    `;this.userCode=`
      const ivec2 strides = ivec2(`+o+", "+a+`);
      const ivec2 pads = ivec2(`+l+", "+h+`);
      const float initializationValue = `+p+`;
      const vec4 ones = vec4(1.0, 1.0, 1.0, 1.0);

      float count = 0.0;

      float getValue(int batch, int xR, int xC, int d) {
        if (xC < 0 || xC >= `+r.inWidth+`) {
          return initializationValue;
        }
        count += 1.0;
        return getX(batch, xR, xC, d);
      }

      void main() {
        ivec4 coords = getOutputCoords();
        int batch = coords[0];
        int d = coords[3];

        ivec2 xRCCorner = coords.yz * strides - pads;
        int xRCorner = xRCCorner.x;
        int xCCorner = xRCCorner.y;

        // max/min x(?, ?, d) to get y(yR, yC, d).
        // ? = to be determined
        vec4 minMaxValue = vec4(`+p+`);
        float avgValue = 0.0;
        count = 0.0;

        for (int wR = 0; wR < `+u+`;
            wR += `+i+`) {
          int xR = xRCorner + wR;

          if (xR < 0 || xR >= `+r.inHeight+`) {
            continue;
          }

          for (int wC = 0; wC < `+v+`; wC += 4) {
            int xC = xCCorner + wC * `+s+`;

            vec4 values = vec4(
              getValue(batch, xR, xC, d),
              getValue(batch, xR, xC + `+s+`, d),
              getValue(batch, xR, xC + 2 * `+s+`, d),
              getValue(batch, xR, xC + 3 * `+s+`, d)
            );

            `+g+`
          }

          int xC = xCCorner + `+v+`;
          if (`+(m===1)+`) {
            vec4 values = vec4(
              getValue(batch, xR, xC, d),
              initializationValue,
              initializationValue,
              initializationValue
            );

            `+g+`
          } else if (`+(m===2)+`) {
            vec4 values = vec4(
              getValue(batch, xR, xC, d),
              getValue(batch, xR, xC + `+s+`, d),
              initializationValue,
              initializationValue
            );

            `+g+`
          } else if (`+(m===3)+`) {
            vec4 values = vec4(
              getValue(batch, xR, xC, d),
              getValue(batch, xR, xC + `+s+`, d),
              getValue(batch, xR, xC + 2 * `+s+`, d),
              initializationValue
            );

            `+g+`
          }
        }
        setOutput(`+d+`);
      }
    `}},Vo=function(r,t,e){if(this.variableNames=["x"],t==="avg"&&e)throw new Error("Cannot compute positions for average pool.");var n=r.filterWidth,o=r.strideDepth,a=r.strideHeight,i=r.strideWidth,s=r.dilationDepth,u=r.dilationHeight,c=r.dilationWidth,l=r.effectiveFilterDepth,h=r.effectiveFilterHeight,f=r.effectiveFilterWidth,p=r.padInfo.front,d=r.padInfo.top,v=r.padInfo.left;this.outputShape=r.outShape;var m=t==="avg",g="0.0";if(m||(g="-1.0 / 1e-20"),e)this.userCode=`
        const ivec3 strides =
            ivec3(`+o+", "+a+", "+i+`);
        const ivec3 pads = ivec3(`+p+", "+d+", "+v+`);

        void main() {
          ivec5 coords = getOutputCoords();
          int batch = coords.x;
          int ch = coords.u;

          ivec3 xCorner = ivec3(coords.y, coords.z, coords.w) * strides - pads;
          int xDCorner = xCorner.x;
          int xRCorner = xCorner.y;
          int xCCorner = xCorner.z;

          // max/min x(?, ?, ?, ch) to get y(yD, yR, yC, ch).
          // ? = to be determined
          float minMaxValue = 0.0;
          float minMaxValueFound = 0.0;
          int minMaxPosition = 0;

          for (int wD = 0; wD < `+l+`;
              wD += `+s+`) {
            int xD = xDCorner + wD;

            if (xD < 0 || xD >= `+r.inDepth+`) {
              continue;
            }

            for (int wR = 0; wR < `+h+`;
                wR += `+u+`) {
              int xR = xRCorner + wR;

              if (xR < 0 || xR >= `+r.inHeight+`) {
                continue;
              }

              for (int wC = 0; wC < `+f+`;
                  wC += `+c+`) {
                int xC = xCCorner + wC;

                if (xC < 0 || xC >= `+r.inWidth+`) {
                  continue;
                }

                float value = getX(batch, xD, xR, xC, ch);

                // If a min / max value has already been found, use it. If not,
                // use the current value.
                float currMinMaxValue = mix(
                    value, minMaxValue, minMaxValueFound);
                if (value >= currMinMaxValue) {
                  minMaxValue = value;
                  minMaxValueFound = 1.0;
                  minMaxPosition =
                      wD * `+h+" * "+f+` +
                      wR * `+f+` + wC;;
                }
              }
            }
          }
          setOutput(float(minMaxPosition));
        }
      `;else{var x=t+"("+t+"("+t+"(minMaxValue[0], minMaxValue[1]), minMaxValue[2]), minMaxValue[3])";t==="avg"&&(x="avgValue / count");var b=4*Math.floor(n/4),y=n%4,w=`
      if (`+m+`) {
        avgValue += dot(values, ones);
      } else {
        minMaxValue = max(values, minMaxValue);
      }
    `;this.userCode=`
      const ivec3 strides =
        ivec3(`+o+", "+a+", "+i+`);
      const ivec3 pads = ivec3(`+p+", "+d+", "+v+`);
      const float initializationValue = `+g+`;
      const vec4 ones = vec4(1.0, 1.0, 1.0, 1.0);

      float count = 0.0;

      float getValue(int batch, int xD, int xR, int xC, int ch) {
        if (xC < 0 || xC >= `+r.inWidth+`) {
          return initializationValue;
        }
        count += 1.0;
        return getX(batch, xD, xR, xC, ch);
      }

      void main() {
        ivec5 coords = getOutputCoords();
        int batch = coords.x;
        int ch = coords.u;

        ivec3 xCorner = ivec3(coords.y, coords.z, coords.w) * strides - pads;
        int xDCorner = xCorner.x;
        int xRCorner = xCorner.y;
        int xCCorner = xCorner.z;

        // max/min x(?, ?, ?, d) to get y(yD, yR, yC, ch).
        // ? = to be determined
        vec4 minMaxValue = vec4(`+g+`);
        float avgValue = 0.0;
        count = 0.0;

        for (int wD = 0; wD < `+l+`;
            wD += `+s+`) {
          int xD = xDCorner + wD;

          if (xD < 0 || xD >= `+r.inDepth+`) {
            continue;
          }

          for (int wR = 0; wR < `+h+`;
            wR += `+u+`) {
            int xR = xRCorner + wR;

            if (xR < 0 || xR >= `+r.inHeight+`) {
              continue;
            }

            for (int wC = 0; wC < `+b+`; wC += 4) {
              int xC = xCCorner + wC * `+c+`;

              vec4 values = vec4(
                getValue(batch, xD, xR, xC, ch),
                getValue(batch, xD, xR, xC + `+c+`, ch),
                getValue(batch, xD, xR, xC + 2 * `+c+`, ch),
                getValue(batch, xD, xR, xC + 3 * `+c+`, ch)
              );

              `+w+`
            }

            int xC = xCCorner + `+b+`;
            if (`+(y===1)+`) {
              vec4 values = vec4(
                getValue(batch, xD, xR, xC, ch),
                initializationValue,
                initializationValue,
                initializationValue
              );

              `+w+`
            } else if (`+(y===2)+`) {
              vec4 values = vec4(
                getValue(batch, xD, xR, xC, ch),
                getValue(batch, xD, xR, xC + `+c+`, ch),
                initializationValue,
                initializationValue
              );

              `+w+`
            } else if (`+(y===3)+`) {
              vec4 values = vec4(
                getValue(batch, xD, xR, xC, ch),
                getValue(batch, xD, xR, xC + `+c+`, ch),
                getValue(batch, xD, xR, xC + 2 * `+c+`, ch),
                initializationValue
              );

              `+w+`
            }
          }
          setOutput(`+x+`);
        }
      }
    `}},rp=function(r,t){this.variableNames=["x"];var e=r.windowSize,n=r.batchSize,o=r.inSize,a=Math.ceil(o/e);this.outputShape=[n,a];var i="0.0",s="";t==="prod"?i="1.0":t==="min"?(i="1.0 / 1e-20",s="min"):t==="max"&&(i="-1.0 / 1e-20",s="max");var u=t+"("+t+"("+t+"(minMaxValue[0], minMaxValue[1]), minMaxValue[2]), minMaxValue[3])";t==="sum"?u="sumValue":t==="prod"?u="prodValue":t==="all"?u="allValue":t==="any"&&(u="anyValue");var c=4*Math.floor(e/4),l=e%4,h=`
      if (`+(t==="sum")+`) {
        sumValue += dot(values, ones);
      } else if (`+(t==="prod")+`) {
        vec2 tmp = vec2(values[0], values[1]) * vec2(values[2], values[3]);
        prodValue *= tmp[0] * tmp[1];
      } else {
        minMaxValue = `+s+`(values, minMaxValue);
      }
    `,f="vec4";t==="all"?(i="1.0",h=`
        bool reducedAllValue = all(values);
        float floatedReducedAllValue = float(reducedAllValue);
        allValue = float(allValue >= 1.0 && floatedReducedAllValue >= 1.0);
      `,f="bvec4"):t==="any"&&(i="0.0",h=`
        bool reducedAnyValue = any(values);
        float floatedReducedAnyValue = float(reducedAnyValue);
        anyValue = float(anyValue >= 1.0 || floatedReducedAnyValue >= 1.0);
      `,f="bvec4");var p="";o%e>0&&(p=`
        if (inIdx < 0 || inIdx >= `+o+`) {
          return initializationValue;
        }
      `),this.userCode=`
      const float initializationValue = `+i+`;
      const vec4 ones = vec4(1.0, 1.0, 1.0, 1.0);

      float getValue(int batch, int inIdx) {
        `+p+`
        return getX(batch, inIdx);
      }

      void main() {
        ivec2 coords = getOutputCoords();
        int batch = coords[0];
        int outIdx = coords[1];
        int inOffset = outIdx * `+e+`;

        vec4 minMaxValue = vec4(`+i+`);
        float prodValue = 1.0;
        float sumValue = 0.0;
        float allValue = 1.0;
        float anyValue = 0.0;

        for (int i = 0; i < `+c+`; i += 4) {
          int inIdx = inOffset + i;
          `+f+" values = "+f+`(
            getValue(batch, inIdx),
            getValue(batch, inIdx + 1),
            getValue(batch, inIdx + 2),
            getValue(batch, inIdx + 3)
          );

          `+h+`
        }

        int inIdx = inOffset + `+c+`;
        if (`+(l===1)+`) {
          `+f+" values = "+f+`(
            getValue(batch, inIdx),
            initializationValue,
            initializationValue,
            initializationValue
          );

          `+h+`
        } else if (`+(l===2)+`) {
          `+f+" values = "+f+`(
            getValue(batch, inIdx),
            getValue(batch, inIdx + 1),
            initializationValue,
            initializationValue
          );

          `+h+`
        } else if (`+(l===3)+`) {
          `+f+" values = "+f+`(
            getValue(batch, inIdx),
            getValue(batch, inIdx + 1),
            getValue(batch, inIdx + 2),
            initializationValue
          );

          `+h+`
        }
        setOutput(`+u+`);
      }
    `},op=function(r,t){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=r;for(var e="",n=0;n<4;n++){var o="thisRC = rc;";n%2==1&&(o+="thisRC.z += 1;"),n>1&&(o+="thisRC.y += 1;"),e+=`
        `+o+`
        `+(n>0?"if(thisRC.y < rows && thisRC.z < cols){":"")+`
          int flatIndex = getFlatIndex(thisRC);

          ivec3 inputRC = inputCoordsFromReshapedOutCoords(flatIndex);
          vec2 inputRCInnerDims = vec2(float(inputRC.y),float(inputRC.z));

          result[`+n+`] =
            getChannel(getA(inputRC.x, inputRC.y, inputRC.z), inputRCInnerDims);
        `+(n>0?"}":"")+`
      `}this.userCode=`
      
    ivec3 inputCoordsFromReshapedOutCoords(int index) {
      `+vn(["r","c","d"],t)+`
      return ivec3(r, c, d);
    }
  
      `+Ma(r)+`

      void main() {
        ivec3 rc = getOutputCoords();

        vec4 result = vec4(0.);

        ivec3 thisRC;
        int rows = `+r[1]+`;
        int cols = `+r[2]+`;

        `+e+`

        setOutput(result);
      }
    `},ap=function(r,t,e){this.variableNames=["dy"],this.outputShape=[],this.outputShape=t.shape;var n=t.shape,o=n[1],a=n[2],i=r.shape,s=i[1],u=i[2],c=[e&&s>1?o-1:o,e&&u>1?a-1:a],l=[e&&s>1?s-1:s,e&&u>1?u-1:u],h=c[0]/l[0],f=c[1]/l[1],p=1/h,d=1/f,v=2*Math.ceil(p)+2,m=2*Math.ceil(d)+2;this.userCode=`
      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int d = coords[3];
        int r = coords[1];
        int c = coords[2];

        float accumulator = 0.0;

        const float heightScale = float(`+h+`);
        const float widthScale = float(`+f+`);

        const float invHeightScale = float(`+p+`);
        const float invWidthScale = float(`+d+`);

        const int winHeight = int(`+v+`);
        const int winWidth = int(`+m+`);

        // Compute bounds for where in dy we will look
        float startRLerp = floor(float(r) * invHeightScale);
        int startDyR = int(startRLerp - float(winHeight / 2));

        float startCLerp = floor(float(c) * invWidthScale);
        int startDyC = int(startCLerp - float(winWidth / 2));

        // Loop over dy
        for (int dyROffset = 0; dyROffset < winHeight; dyROffset++) {
          int dyR = dyROffset + startDyR;

          // Guard against the window exceeding the bounds of dy
          if (dyR < 0 || dyR >= `+s+`) {
            continue;
          }

          for (int dyCOffset = 0; dyCOffset < winWidth; dyCOffset++) {
            int dyC = dyCOffset + startDyC;

            // Guard against the window exceeding the bounds of dy
            if (dyC < 0 || dyC >= `+u+`) {
              continue;
            }

            float dxR = float(dyR) * heightScale;
            int topDxRIndex = int(floor(dxR));
            int bottomDxRIndex = int(min(ceil(dxR), `+(o-1)+`.0));
            float dxRLerp = dxR - float(topDxRIndex);
            float inverseDxRLerp = 1.0 - dxRLerp;

            float dxC = float(dyC) * widthScale;
            int leftDxCIndex = int(floor(dxC));
            int rightDxCIndex = int(min(ceil(dxC), `+(a-1)+`.0));
            float dxCLerp = dxC - float(leftDxCIndex);
            float inverseDxCLerp = 1.0 - dxCLerp;

            if (r == topDxRIndex && c == leftDxCIndex) {
              // topLeft
              accumulator +=
                getDy(b, dyR, dyC, d) * inverseDxRLerp * inverseDxCLerp;
            }

            if (r == topDxRIndex && c == rightDxCIndex) {
              // topRight
              accumulator += getDy(b, dyR, dyC, d) * inverseDxRLerp * dxCLerp;
            }

            if (r == bottomDxRIndex && c == leftDxCIndex) {
              // bottomLeft
              accumulator += getDy(b, dyR, dyC, d) * dxRLerp * inverseDxCLerp;
            }

            if (r == bottomDxRIndex && c == rightDxCIndex) {
              // bottomRight
              accumulator += getDy(b, dyR, dyC, d) * dxRLerp * dxCLerp;
            }
          }
        }
        // End loop over dy

        setOutput(accumulator);
      }
    `},ip=function(r,t,e,n){this.variableNames=["A"],this.outputShape=[];var o=r[0],a=r[1],i=r[2],s=r[3];this.outputShape=[o,t,e,s];var u=[n&&t>1?a-1:a,n&&e>1?i-1:i],c=[n&&t>1?t-1:t,n&&e>1?e-1:e];this.userCode=`
      const vec2 effectiveInputOverOutputRatioRC = vec2(
          `+u[0]/c[0]+`,
          `+u[1]/c[1]+`);
      const vec2 inputShapeRC = vec2(`+a+".0, "+i+`.0);

      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int d = coords[3];
        ivec2 yRC = coords.yz;

        // Fractional source index.
        vec2 sourceFracIndexRC = vec2(yRC) * effectiveInputOverOutputRatioRC;

        // Compute the four integer indices.
        ivec2 sourceFloorRC = ivec2(sourceFracIndexRC);
        ivec2 sourceCeilRC = ivec2(
          min(inputShapeRC - 1.0, ceil(sourceFracIndexRC)));

        float topLeft = getA(b, sourceFloorRC.x, sourceFloorRC.y, d);
        float bottomLeft = getA(b, sourceCeilRC.x, sourceFloorRC.y, d);
        float topRight = getA(b, sourceFloorRC.x, sourceCeilRC.y, d);
        float bottomRight = getA(b, sourceCeilRC.x, sourceCeilRC.y, d);

        vec2 fracRC = sourceFracIndexRC - vec2(sourceFloorRC);

        float top = topLeft + (topRight - topLeft) * fracRC.y;
        float bottom = bottomLeft + (bottomRight - bottomLeft) * fracRC.y;
        float newValue = top + (bottom - top) * fracRC.x;

        setOutput(newValue);
      }
    `},sp=function(r,t,e,n){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=[];var o=r[0],a=r[1],i=r[2],s=r[3];this.outputShape=[o,t,e,s];var u=[n&&t>1?a-1:a,n&&e>1?i-1:i],c=[n&&t>1?t-1:t,n&&e>1?e-1:e];this.userCode=`
      const vec3 effectiveInputOverOutputRatioRC = vec3(
          `+u[0]/c[0]+`,
          `+u[1]/c[1]+`,
          `+u[1]/c[1]+`);
      const vec3 inputShapeRC = vec3(`+a+".0, "+i+`.0,
                                     `+i+`.0);

      float getAValue(int b, int r, int c, int d) {
        return getChannel(getA(b, r, c, d), vec2(c, d));
      }

      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int d = coords[3];
        // Calculate values for next column in yRC.z.
        ivec3 yRC = coords.yzz + ivec3(0, 0, 1);

        // Fractional source index.
        vec3 sourceFracIndexRC = vec3(yRC) * effectiveInputOverOutputRatioRC;

        // Compute the four integer indices.
        ivec3 sourceFloorRC = ivec3(sourceFracIndexRC);
        ivec3 sourceCeilRC = ivec3(
          min(inputShapeRC - 1.0, ceil(sourceFracIndexRC)));

        // Should we calculate next column and row elements in 2x2 packed cell.
        bool hasNextCol = d < `+(s-1)+`;
        bool hasNextRow = coords.z < `+(e-1)+`;

        // In parallel, construct four corners for all four components in
        // packed 2x2 cell.
        vec4 topLeft = vec4(
          getAValue(b, sourceFloorRC.x, sourceFloorRC.y, d),
          hasNextCol ? getAValue(b, sourceFloorRC.x, sourceFloorRC.y, d + 1)
                     : 0.0,
          hasNextRow ? getAValue(b, sourceFloorRC.x, sourceFloorRC.z, d)
                     : 0.0,
          (hasNextRow && hasNextCol) ?
            getAValue(b, sourceFloorRC.x, sourceFloorRC.z, d + 1) : 0.0);

        vec4 bottomLeft = vec4(
          getAValue(b, sourceCeilRC.x, sourceFloorRC.y, d),
          hasNextCol ? getAValue(b, sourceCeilRC.x, sourceFloorRC.y, d + 1)
                     : 0.0,
          hasNextRow ? getAValue(b, sourceCeilRC.x, sourceFloorRC.z, d)
                     : 0.0,
          (hasNextRow && hasNextCol) ?
            getAValue(b, sourceCeilRC.x, sourceFloorRC.z, d + 1) : 0.0);

        vec4 topRight = vec4(
          getAValue(b, sourceFloorRC.x, sourceCeilRC.y, d),
          hasNextCol ? getAValue(b, sourceFloorRC.x, sourceCeilRC.y, d + 1)
                     : 0.0,
          hasNextRow ? getAValue(b, sourceFloorRC.x, sourceCeilRC.z, d)
                     : 0.0,
          (hasNextRow && hasNextCol) ?
            getAValue(b, sourceFloorRC.x, sourceCeilRC.z, d + 1) : 0.0);

        vec4 bottomRight = vec4(
          getAValue(b, sourceCeilRC.x, sourceCeilRC.y, d),
          hasNextCol ? getAValue(b, sourceCeilRC.x, sourceCeilRC.y, d + 1)
                     : 0.0,
          hasNextRow ? getAValue(b, sourceCeilRC.x, sourceCeilRC.z, d)
                     : 0.0,
          (hasNextRow && hasNextCol) ?
            getAValue(b, sourceCeilRC.x, sourceCeilRC.z, d + 1) : 0.0);

        vec3 fracRC = sourceFracIndexRC - vec3(sourceFloorRC);

        vec4 top = mix(topLeft, topRight, fracRC.yyzz);
        vec4 bottom = mix(bottomLeft, bottomRight, fracRC.yyzz);
        vec4 newValue = mix(top, bottom, fracRC.x);

        setOutput(newValue);
      }
    `},up=function(r,t,e){this.variableNames=["dy"],this.outputShape=[],this.outputShape=t.shape;var n=t.shape,o=n[1],a=n[2],i=r.shape,s=i[1],u=i[2],c=[e&&s>1?o-1:o,e&&u>1?a-1:a],l=[e&&s>1?s-1:s,e&&u>1?u-1:u],h=c[0]/l[0],f=c[1]/l[1],p=1/h,d=1/f,v=2*Math.ceil(p)+2,m=2*Math.ceil(d)+2;this.userCode=`
      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int d = coords[3];
        int r = coords[1];
        int c = coords[2];

        float accumulator = 0.0;

        const float heightScale = float(`+h+`);
        const float widthScale = float(`+f+`);

        const float invHeightScale = float(`+p+`);
        const float invWidthScale = float(`+d+`);

        const int winHeight = int(`+v+`);
        const int winWidth = int(`+m+`);

        // Compute bounds for where in dy we will look
        float startRLerp = floor(float(r) * invHeightScale);
        int startDyR = int(floor(startRLerp - float(winHeight / 2)));

        float startCLerp = floor(float(c) * invWidthScale);
        int startDyC = int(floor(startCLerp - float(winWidth / 2)));

        // Loop over dy
        for (int dyROffset = 0; dyROffset < winHeight; dyROffset++) {
          int dyR = dyROffset + startDyR;

          // Guard against the window exceeding the bounds of dy
          if (dyR < 0 || dyR >= `+s+`) {
            continue;
          }

          for (int dyCOffset = 0; dyCOffset < winWidth; dyCOffset++) {
            int dyC = dyCOffset + startDyC;

            // Guard against the window exceeding the bounds of dy
            if (dyC < 0 || dyC >= `+u+`) {
              continue;
            }

            float sourceFracRow =
              float(`+c[0]+`) *
                (float(dyR) / float(`+l[0]+`));

            float sourceFracCol =
                float(`+c[1]+`) *
                  (float(dyC) / float(`+l[1]+`));

            int sourceNearestRow = int(min(
                float(int(`+o+`) - 1),
                `+e+` ? float(round(sourceFracRow)) :
                                  float(floor(sourceFracRow))));

            int sourceNearestCol = int(min(
                float(int(`+a+`) - 1),
                `+e+` ? float(round(sourceFracCol)) :
                                  float(floor(sourceFracCol))));

            if (r == sourceNearestRow && c == sourceNearestCol) {
              accumulator += getDy(b, dyR, dyC, d);
            }
          }
        }
        // End loop over dy

        setOutput(accumulator);
      }
    `},cp=function(r,t,e,n){this.variableNames=["A"],this.outputShape=[];var o=r[0],a=r[1],i=r[2],s=r[3];this.outputShape=[o,t,e,s];var u=[n&&t>1?a-1:a,n&&e>1?i-1:i],c=[n&&t>1?t-1:t,n&&e>1?e-1:e],l=n?"0.5":"0.0";this.userCode=`
      const vec2 effectiveInputOverOutputRatioRC = vec2(
          `+u[0]/c[0]+`,
          `+u[1]/c[1]+`);
      const vec2 inputShapeRC = vec2(`+a+".0, "+i+`.0);

      void main() {
        ivec4 coords = getOutputCoords();
        int b = coords[0];
        int d = coords[3];
        ivec2 yRC = coords.yz;

        // Fractional source index.
        vec2 sourceFracIndexRC = vec2(yRC) * effectiveInputOverOutputRatioRC;

        // Compute the coordinators of nearest neighbor point.
        ivec2 sourceNearestRC = ivec2(
          min(inputShapeRC - 1.0, floor(sourceFracIndexRC + `+l+`)));

        float newValue = getA(b, sourceNearestRC.x, sourceNearestRC.y, d);

        setOutput(newValue);
      }
    `},lp=function(r,t){this.variableNames=["x"];var e=r.length;if(e>4)throw new Error("WebGL backend: Reverse of rank-"+e+" tensor is not yet supported");if(this.outputShape=r,e!==1){var n=r.map((function(a,i){return(function(s){return t.indexOf(s)!==-1&&r[s]!==1?r[s]+" - coords["+s+"] - 1":"coords["+s+"]"})(i)})).join(","),o=we(e);this.userCode=`
      void main() {
        `+o+` coords = getOutputCoords();
        setOutput(getX(`+n+`));
      }
    `}else this.userCode=`
        void main() {
          int coord = getOutputCoords();
          setOutput(getX(`+r[0]+` - coord - 1));
        }
      `},hp=function(r,t){this.variableNames=["x"],this.packedInputs=!0,this.packedOutput=!0;var e=r.length;if(e>4)throw new Error("WebGL backend: Reverse of rank-"+e+" tensor is not yet supported");this.outputShape=r;var n=et("rc",e),o=n[e-1]+" + 1 < "+this.outputShape[e-1],a=n[e-2]+" + 1 < "+this.outputShape[e-2],i=we(e);function s(u){var c=r.map((function(l,h){return(function(f,p){return t.indexOf(f)!==-1&&r[f]!==1?r[f]+" - "+p[f]+" - 1":""+p[f]})(h,u)}));return"getChannel(getX("+c.join(",")+"), vec2("+c.slice(-2).join(",")+"))"}this.userCode=e===1?`
        void main(){
          int rc = getOutputCoords();
          vec4 result = vec4(0.);
          result.r = getChannel(getX(`+r[0]+` - rc - 1),
            `+r[0]+` - rc - 1);
          if(`+o+`){
              result.g = getChannel(getX(`+r[0]+` - (rc  + 1) - 1),
                `+r[0]+` - (rc  + 1) - 1);
          }
          setOutput(result);
        }
      `:`
        void main() {
          `+i+` rc = getOutputCoords();
          vec4 result = vec4(0.);
          result.r = `+(function(u){return s(u)})(n.slice())+`;
          if(`+o+`){
            result.g = `+(function(u){return u[e-1]="("+u[e-1]+" + 1)",s(u)})(n.slice())+`;
          }
          if(`+a+`) {
            result.b = `+(function(u){return u[e-2]="("+u[e-2]+" + 1)",s(u)})(n.slice())+`;
            if(`+o+`) {
              result.a = `+(function(u){return u[e-1]="("+u[e-1]+" + 1)",u[e-2]="("+u[e-2]+" + 1)",s(u)})(n.slice())+`;
            }
          }
          setOutput(result);
        }
    `},$i=function(r,t,e,n,o,a,i){this.variableNames=["updates","indices","defaultValue"],this.outputShape=a;var s=we(o.length),u=we(a.length),c="";e===1?c="i":e===2&&(c="i, j");var l="getIndices("+c+")",h="";n===1?h="i":n===2&&(h="i, coords[1]");var f="getUpdates("+h+")",p=t>1?"strides[j]":"strides";this.userCode=`
        `+s+" strides = "+s+"("+o+`);

        void main() {
          `+u+` coords = getOutputCoords();
          float sum = 0.0;
          bool found = false;
          for (int i = 0; i < `+r+`; i++) {
            int flattenedIndex = 0;
            for (int j = 0; j < `+t+`; j++) {
              int index = round(`+l+`);
              flattenedIndex += index * `+p+`;
            }
            if (flattenedIndex == coords[0]) {
              sum += `+f+`;
              found = true;
            }
          }
          setOutput(mix(getDefaultValue(), sum, float(found)));
        }
      `},fp=function(r,t){this.variableNames=["x","segmentIds"];var e=r.windowSize,n=r.batchSize,o=r.inSize,a=r.numSegments,i=a*Math.ceil(o/e);this.outputShape=[n,i];var s=4*Math.floor(e/4),u=e%4,c=`
        sumValue += dot(values, segFilter);
    `,l="";o%e>0&&(l=`
        if (inIdx < 0 || inIdx >= `+o+`) {
          return initializationValue;
        }
      `);var h="";o%e>0&&(h=`
        if (inIdx < 0 || inIdx >= `+o+`) {
          return -1.0;
        }
      `),this.userCode=`
      const float initializationValue = 0.0;

      float getValue(int batch, int inIdx) {
        `+l+`
        return getX(batch, inIdx);
      }

      float getSegmentIdAtIndex(int inIdx) {
        `+h+`
        return getSegmentIds(inIdx);
      }

      void main() {
        ivec2 coords = getOutputCoords();
        int batch = coords[0];
        int outIdx = coords[1];
        int inOffset = int(floor(float(outIdx) / float(
          `+a+")) * float("+e+`));
        int currentSeg = int(mod(float(outIdx), float(`+a+`)));

        float sumValue = 0.0;

        for (int i = 0; i < `+s+`; i += 4) {
          int inIdx = inOffset + i;
          vec4 values = vec4(
            getValue(batch, inIdx),
            getValue(batch, inIdx + 1),
            getValue(batch, inIdx + 2),
            getValue(batch, inIdx + 3)
          );

          vec4 segFilter = vec4(
            int(getSegmentIdAtIndex(inIdx)) == currentSeg ? 1 : 0,
            int(getSegmentIdAtIndex(inIdx + 1)) == currentSeg ? 1 : 0,
            int(getSegmentIdAtIndex(inIdx + 2)) == currentSeg ? 1 : 0,
            int(getSegmentIdAtIndex(inIdx + 3)) == currentSeg ? 1 : 0
          );

          `+c+`
        }

        int inIdx = inOffset + `+s+`;
        if (`+(u===1)+`) {
          vec4 values = vec4(
            getValue(batch, inIdx),
            initializationValue,
            initializationValue,
            initializationValue
          );

          int inIdxSeg = int(getSegmentIdAtIndex(inIdx));

          vec4 segFilter = vec4(
            int(getSegmentIdAtIndex(inIdx)) == currentSeg ? 1 : 0,
            0,
            0,
            0
          );

          `+c+`
        } else if (`+(u===2)+`) {
          vec4 values = vec4(
            getValue(batch, inIdx),
            getValue(batch, inIdx + 1),
            initializationValue,
            initializationValue
          );

          vec4 segFilter = vec4(
            int(getSegmentIdAtIndex(inIdx)) == currentSeg ? 1 : 0,
            int(getSegmentIdAtIndex(inIdx + 1)) == currentSeg ? 1 : 0,
              0,
              0
          );

          `+c+`
        } else if (`+(u===3)+`) {
          vec4 values = vec4(
            getValue(batch, inIdx),
            getValue(batch, inIdx + 1),
            getValue(batch, inIdx + 2),
            initializationValue
          );

          vec4 segFilter = vec4(
            int(getSegmentIdAtIndex(inIdx)) == currentSeg ? 1 : 0,
            int(getSegmentIdAtIndex(inIdx + 1)) == currentSeg ? 1 : 0,
            int(getSegmentIdAtIndex(inIdx + 2)) == currentSeg ? 1 : 0,
            0
          );

          `+c+`
        }
        setOutput(sumValue);
      }
    `},pp=function(r,t,e){var n,o;if(this.variableNames=["c","a","b"],this.outputShape=t,e>4)throw Error("Where for rank "+e+" is not yet supported");if(e===1)o="resRC",n="resRC";else{for(var a=["resRC.x","resRC.y","resRC.z","resRC.w"],i=[],s=[],u=0;u<t.length;u++)s.push(""+a[u]),u<r&&i.push(""+a[u]);n=i.join(),o=s.join()}var c=we(e);this.userCode=`
      void main() {
        `+c+` resRC = getOutputCoords();
        float cVal = getC(`+n+`);
        if (cVal >= 1.0) {
          setOutput(getA(`+o+`));
        } else {
          setOutput(getB(`+o+`));
        }
      }
    `},dp=(function(){function r(t){this.variableNames=["source"],this.outputShape=t,this.rank=t.length;var e,n=we(this.rank),o="uniform int start["+this.rank+"];",a=(function(i){if(i===1)return"sourceLoc";if(i<=6)return zo.slice(0,i).map((function(s){return"sourceLoc."+s})).join(",");throw Error("Slicing for rank "+i+" is not yet supported")})(this.rank);e=`
        `+n+` sourceLoc;
        `+n+` coords = getOutputCoords();
        `+t.map((function(i,s){return"sourceLoc."+zo[s]+" = start["+s+"] + coords."+zo[s]+";"})).join(`
`)+`
      `,this.userCode=`
      `+o+`
      void main() {
        `+e+`
        setOutput(getSource(`+a+`));
      }
    `}return r.prototype.getCustomSetupFunc=function(t){var e=this;if(t.length!==this.rank)throw Error("The rank ("+this.rank+") of the program must match the length of start ("+t.length+")");return function(n,o){e.startLoc==null&&(e.startLoc=n.getUniformLocationNoThrow(o,"start"),e.startLoc==null)||n.gl.uniform1iv(e.startLoc,t)}},r})(),zo=["x","y","z","w","u","v"],vp=(function(){function r(t){this.variableNames=["source"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=t,this.rank=t.length;var e=we(this.rank),n=et("coords",this.rank),o=et("sourceLoc",this.rank),a=this.rank===1?"sourceLoc":"vec2("+o.slice(-2).join()+")",i="getChannel(getSource("+o.join()+"), "+a+")",s=`
      result.x = `+i+`;
      if (++`+n[this.rank-1]+" < "+t[this.rank-1]+`) {
        ++`+o[this.rank-1]+`;
        result.y = `+i+`;
        --`+o[this.rank-1]+`;
      }
    `,u=this.rank===1?"":`
      --`+n[this.rank-1]+`;
      if (++`+n[this.rank-2]+" < "+t[this.rank-2]+`) {
        ++`+o[this.rank-2]+`;
        result.z = `+i+`;
        if (++`+n[this.rank-1]+" < "+t[this.rank-1]+`) {
          ++`+o[this.rank-1]+`;
          result.w = `+i+`;
        }
      }
    `,c=this.rank<=4?`sourceLoc = coords +
            `+e+"("+t.map((function(l,h){return"start["+h+"]"})).join()+");":t.map((function(l,h){return o[h]+" = "+n[h]+" + start["+h+"];"})).join(`
`);this.userCode=`
      uniform int start[`+this.rank+`];
      void main() {
        `+e+` coords = getOutputCoords();
        `+e+` sourceLoc;
        `+c+`
        vec4 result = vec4(0.);
        `+s+`
        `+u+`
        setOutput(result);
      }
    `}return r.prototype.getCustomSetupFunc=function(t){var e=this;if(t.length!==this.rank)throw Error("The rank ("+this.rank+") of the program must match the length of start ("+t.length+")");return function(n,o){e.startLoc==null&&(e.startLoc=n.getUniformLocationNoThrow(o,"start"),e.startLoc==null)||n.gl.uniform1iv(e.startLoc,t)}},r})(),mp=function(r,t,e){this.variableNames=["x"],this.outputShape=e;var n=e.length,o=we(e.length),a=we(e.length),i="";if(n===1)i="coords * strides + begin";else{var s=0;i=e.map((function(u,c){return s++,e.length===1?"coords * strides["+c+"] + begin["+c+"]":"coords["+(s-1)+"] * strides["+c+"] + begin["+c+"]"})).join(",")}this.userCode=`
      `+o+" begin = "+o+"("+r+`);
      `+o+" strides = "+o+"("+t+`);

      void main() {
        `+a+` coords = getOutputCoords();
        setOutput(getX(`+i+`));
      }
    `},gp=(function(){function r(t){this.gpgpu=t,this.numUsedTextures=0,this.numFreeTextures=0,this.freeTextures={},this.logEnabled=!1,this.usedTextures={}}return r.prototype.acquireTexture=function(t,e,n){var o,a=Yi(e,n),i=Ji(t,a,n);if(i in this.freeTextures||(this.freeTextures[i]=[]),i in this.usedTextures||(this.usedTextures[i]=[]),this.freeTextures[i].length>0){this.numFreeTextures--,this.numUsedTextures++,this.log();var s=this.freeTextures[i].shift();return this.usedTextures[i].push(s),s}return this.numUsedTextures++,this.log(),a===it.PACKED_2X2_FLOAT32?o=this.gpgpu.createPackedMatrixTexture(t[0],t[1]):a===it.PACKED_2X2_FLOAT16?o=this.gpgpu.createFloat16PackedMatrixTexture(t[0],t[1]):a===it.UNPACKED_FLOAT32?o=this.gpgpu.createFloat32MatrixTexture(t[0],t[1]):a===it.UNPACKED_FLOAT16?o=this.gpgpu.createFloat16MatrixTexture(t[0],t[1]):a===it.PACKED_4X1_UNSIGNED_BYTE&&(o=this.gpgpu.createUnsignedBytesMatrixTexture(t[0],t[1])),this.usedTextures[i].push(o),o},r.prototype.releaseTexture=function(t,e,n,o){if(this.freeTextures!=null){var a=Ji(e,Yi(n,o),o);a in this.freeTextures||(this.freeTextures[a]=[]),this.freeTextures[a].push(t),this.numFreeTextures++,this.numUsedTextures--;var i=this.usedTextures[a],s=i.indexOf(t);if(s<0)throw new Error("Cannot release a texture that was never provided by this texture manager");i.splice(s,1),this.log()}},r.prototype.log=function(){if(this.logEnabled){var t=this.numFreeTextures+this.numUsedTextures;console.log("Free/Used",this.numFreeTextures+" / "+this.numUsedTextures,"("+t+")")}},r.prototype.getNumUsedTextures=function(){return this.numUsedTextures},r.prototype.getNumFreeTextures=function(){return this.numFreeTextures},r.prototype.dispose=function(){var t=this;if(this.freeTextures!=null){for(var e in this.freeTextures)this.freeTextures[e].forEach((function(n){t.gpgpu.deleteMatrixTexture(n)}));for(var e in this.usedTextures)this.usedTextures[e].forEach((function(o){t.gpgpu.deleteMatrixTexture(o)}));this.freeTextures=null,this.usedTextures=null,this.numUsedTextures=0,this.numFreeTextures=0}},r})();function Yi(r,t){if(r===st.UPLOAD)return it.PACKED_2X2_FLOAT32;if(r===st.RENDER||r==null)return(function(e){return L().getBool("WEBGL_RENDER_FLOAT32_ENABLED")?e?it.PACKED_2X2_FLOAT32:it.UNPACKED_FLOAT32:e?it.PACKED_2X2_FLOAT16:it.UNPACKED_FLOAT16})(t);if(r===st.DOWNLOAD||r===st.PIXELS)return it.PACKED_4X1_UNSIGNED_BYTE;throw new Error("Unknown logical texture type "+r)}function Ji(r,t,e){return r[0]+"_"+r[1]+"_"+t+"_"+e}var yp=function(r,t){this.variableNames=["A"];for(var e=new Array(r.length),n=0;n<e.length;n++)e[n]=r[n]*t[n];this.outputShape=e,this.rank=e.length;var o=we(this.rank),a=(function(i){var s=i.length;if(s>5)throw Error("Tile for rank "+s+" is not yet supported");if(s===1)return"imod(resRC, "+i[0]+")";for(var u=["resRC.x","resRC.y","resRC.z","resRC.w","resRC.u"],c=[],l=0;l<i.length;l++)c.push("imod("+u[l]+", "+i[l]+")");return c.join()})(r);this.userCode=`
      void main() {
        `+o+` resRC = getOutputCoords();
        setOutput(getA(`+a+`));
      }
    `},xp=function(r,t){this.variableNames=["A"];for(var e=new Array(r.length),n=0;n<e.length;n++)e[n]=r[t[n]];this.outputShape=e,this.rank=e.length;var o=we(this.rank),a=(function(i){var s=i.length;if(s>6)throw Error("Transpose for rank "+s+" is not yet supported");for(var u=["resRC.x","resRC.y","resRC.z","resRC.w","resRC.u","resRC.v"],c=new Array(s),l=0;l<i.length;l++)c[i[l]]=u[l];return c.join()})(t);this.userCode=`
    void main() {
      `+o+` resRC = getOutputCoords();
      setOutput(getA(`+a+`));
    }
    `},bp=function(r,t){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!0;for(var e=new Array(r.length),n=0;n<e.length;n++)e[n]=r[t[n]];if(this.outputShape=e,this.rank=e.length,this.rank>6)throw Error("Packed transpose for rank "+this.rank+" is not yet supported.");var o=we(this.rank),a=fu("rc",this.rank),i=new Array(this.rank);for(n=0;n<t.length;n++)i[t[n]]=a[n];var s="vec2("+i.slice(-2).join()+")",u="++"+a[this.rank-1]+" < "+e[this.rank-1],c="getChannel(getA("+i.join()+"), "+s+")";this.userCode=`
    void main() {
      `+o+` rc = getOutputCoords();
      vec4 result = vec4(0.);
      result[0] = `+c+`;
      if(`+u+`) {
        result[1] = `+c+`;
      }
      --`+a[this.rank-1]+`;
      if(++`+a[this.rank-2]+" < "+e[this.rank-2]+`) {
        result[2] = `+c+`;
        if(`+u+`) {
          result[3] = `+c+`;
        }
      }
      setOutput(result);
    }
    `},Oa=1.7580993408473768,Ba=1.0507009873554805,ae=function(r,t){this.variableNames=["A"],this.outputShape=r,this.userCode=`
      float unaryOperation(float x) {
        `+t+`
      }

      void main() {
        float x = getAAtOutCoords();
        float y = unaryOperation(x);

        setOutput(y);
      }
    `},xt="if (isnan(x)) return x;",wp="return x;",Qi="return abs(x);",gu=xt+`
  return (x < 0.0) ? 0.0 : x;
`,yu=xt+`
  return (x < 0.0) ? 0.0 : min(6.0, x);
`,xu="return (x >= 0.0) ? x : (exp(x) - 1.0);",Cp=`
  // Stable and Attracting Fixed Point (0, 1) for Normalized Weights.
  // see: https://arxiv.org/abs/1706.02515
  float scaleAlpha = `+Oa+`;
  float scale = `+Ba+`;
  return (x >= 0.0) ? scale * x : scaleAlpha * (exp(x) - 1.0);
`,Zi="return -x;",es="return ceil(x);",ts="return floor(x);",ns="return exp(x);",rs="return exp(x) - 1.0;",_p=xt+`
  return sin(x);
`,Ep=xt+`
  return cos(x);
`,Ip=xt+`
  if (abs(x) > 1.) {
    return NAN;
  }
  return asin(x);
`,Rp=xt+`
  if (abs(x) > 1.) {
    return NAN;
  }
  return acos(x);
`,kp=xt+`
  return atan(x);
`,Sp=xt+"return log(x + sqrt(x * x + 1.0));",Dp=xt+`
  if (x < 1.0) return NAN;
  return log(x + sqrt(x * x - 1.0));`,Ap=xt+`
  if ((x < -1.0) || (x > 1.0)) return NAN;
  return (log(1.0 + x) - log(1.0 - x)) / 2.0;`,Ir="return x;",Tp="return x;",bu=`
  vec4 result = x * vec4(greaterThanEqual(x, vec4(0.0)));
  bvec4 isNaN = isnan(x);

  result.r = isNaN.r ? x.r : result.r;
  result.g = isNaN.g ? x.g : result.g;
  result.b = isNaN.b ? x.b : result.b;
  result.a = isNaN.a ? x.a : result.a;

  return result;
`,wu=`
  vec4 result = min(x, vec4(6.)) * vec4(greaterThanEqual(x, vec4(0.0)));
  bvec4 isNaN = isnan(x);

  result.r = isNaN.r ? x.r : result.r;
  result.g = isNaN.g ? x.g : result.g;
  result.b = isNaN.b ? x.b : result.b;
  result.a = isNaN.a ? x.a : result.a;

  return result;
`,Cu=`
  vec4 result;

  result.r = (x.r >= 0.0) ? x.r : (exp(x.r) - 1.0);
  result.g = (x.g >= 0.0) ? x.g : (exp(x.g) - 1.0);
  result.b = (x.b >= 0.0) ? x.b : (exp(x.b) - 1.0);
  result.a = (x.a >= 0.0) ? x.a : (exp(x.a) - 1.0);

  return result;
`,Zn=function(r,t){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!0,this.outputShape=r,this.userCode=`
      vec4 unaryOperation(vec4 x) {
        `+t+`
      }

      void main() {
        vec4 x = getAAtOutCoords();
        vec4 y = unaryOperation(x);

        setOutput(y);
      }
    `},Np=function(r){this.variableNames=["A"],this.packedInputs=!0,this.packedOutput=!1,this.outputShape=r;var t=r.length,e=et("rc",t),n=we(t),o=(function(s,u){if(s===1)return"rc";for(var c="",l=0;l<s;l++)c+=u[l],l<s-1&&(c+=",");return c})(t,e),a=e.slice(-2),i=t<=1?"rc":"vec2("+a.join(",")+")";this.userCode=`
      void main() {
        `+n+` rc = getOutputCoords();
        vec4 packedInput = getA(`+o+`);

        setOutput(getChannel(packedInput, `+i+`));
      }
    `},Rr={};function kr(r,t){if(t===void 0&&(t=!1),r==="linear")return t?Tp:wp;if(r==="relu")return t?bu:gu;if(r==="elu")return t?Cu:xu;if(r==="relu6")return t?wu:yu;if(r==="prelu")return t?mu:vu;throw new Error("Activation "+r+" has not been implemented for the WebGL backend.")}var Fp=600,Pp=(function(r){function t(e){var n,o=r.call(this)||this;if(o.pendingRead=new WeakMap,o.pendingDisposal=new WeakSet,o.dataRefCount=new WeakMap,o.numBytesInGPU=0,o.uploadWaitMs=0,o.downloadWaitMs=0,o.warnedAboutMemory=!1,o.pendingDeletes=0,o.disposed=!1,!L().getBool("HAS_WEBGL"))throw new Error("WebGL is not supported on this device");if(e==null){var a=Pt(L().getNumber("WEBGL_VERSION"));o.binaryCache=((n=L().getNumber("WEBGL_VERSION"))in Rr||(Rr[n]={}),Rr[n]),o.gpgpu=new jf(a),o.canvas=a.canvas,o.gpgpuCreatedLocally=!0}else o.gpgpu=e,o.binaryCache={},o.gpgpuCreatedLocally=!1,o.canvas=e.gl.canvas;return o.textureManager=new gp(o.gpgpu),o.numMBBeforeWarning=L().global.screen==null?1024:L().global.screen.height*L().global.screen.width*window.devicePixelRatio*Fp/1024/1024,o.texData=new ru(o,N),o}return yt(t,r),t.prototype.numDataIds=function(){return this.texData.numDataIds()+(this.cpuBackend?this.cpuBackend.numDataIds():0)-this.pendingDeletes},t.prototype.write=function(e,n,o){if(L().getBool("DEBUG")&&this.checkNumericalProblems(e),o==="complex64"&&e!=null)throw new Error("Cannot write to a complex64 dtype. Please use tf.complex(real, imag).");var a={};return this.texData.set(a,{shape:n,dtype:o,values:e,usage:st.UPLOAD}),a},t.prototype.move=function(e,n,o,a){if(L().getBool("DEBUG")&&this.checkNumericalProblems(n),a==="complex64")throw new Error("Cannot write to a complex64 dtype. Please use tf.complex(real, imag).");this.texData.set(e,{shape:o,dtype:a,values:n,usage:st.UPLOAD})},t.prototype.readSync=function(e){var n=this.texData.get(e),o=n.values,a=n.dtype,i=n.complexTensors,s=n.slice,u=n.shape,c=n.isPacked;if(s!=null){var l=void 0;l=c?new Zn(u,Ir):new ae(u,Ir);var h=this.runWebGLProgram(l,[{dataId:e,shape:u,dtype:a}],a),f=this.readSync(h.dataId);return this.disposeData(h.dataId),f}if(o!=null)return this.convertAndCacheOnCPU(e);if(a==="string")return o;var p,d,v=this.activeTimers!=null;return v&&(p=Rt()),a==="complex64"?d=pa(i.real.dataSync(),i.imag.dataSync()):d=this.getValuesFromTexture(e),v&&(this.downloadWaitMs+=Rt()-p),this.convertAndCacheOnCPU(e,d)},t.prototype.read=function(e){return X(this,void 0,void 0,(function(){var n,o,a,i,s,u,c,l,h,f,p,d,v,m,g,x,b,y,w,C,S,k;return $(this,(function(R){switch(R.label){case 0:if(this.pendingRead.has(e))return n=this.pendingRead.get(e),[2,new Promise((function(E){return n.push(E)}))];if(o=this.texData.get(e),a=o.values,i=o.shape,s=o.slice,u=o.dtype,c=o.complexTensors,l=o.isPacked,s!=null)return h=void 0,h=l?new Zn(i,Ir):new ae(i,Ir),f=this.runWebGLProgram(h,[{dataId:e,shape:i,dtype:u}],u),p=this.read(f.dataId),this.disposeData(f.dataId),[2,p];if(a!=null)return[2,this.convertAndCacheOnCPU(e)];if(!L().getBool("WEBGL_DOWNLOAD_FLOAT_ENABLED")&&L().getNumber("WEBGL_VERSION")===2)throw new Error("tensor.data() with WEBGL_DOWNLOAD_FLOAT_ENABLED=false and WEBGL_VERSION=2 not yet supported.");return d=null,u!=="complex64"&&L().get("WEBGL_BUFFER_SUPPORTED")&&(v=this.decode(e),m=this.texData.get(v.dataId),d=(k=this.gpgpu).createBufferFromTexture.apply(k,[m.texture].concat(er(i)))),this.pendingRead.set(e,[]),u==="complex64"?[3,2]:[4,this.gpgpu.createAndWaitForFence()];case 1:R.sent(),R.label=2;case 2:return u!=="complex64"?[3,4]:[4,Promise.all([c.real.data(),c.imag.data()])];case 3:return x=R.sent(),b=x[0],y=x[1],g=pa(b,y),[3,5];case 4:d==null?g=this.getValuesFromTexture(e):(w=Y(i),g=this.gpgpu.downloadFloat32MatrixFromBuffer(d,w)),R.label=5;case 5:return v!=null&&this.disposeData(v.dataId),C=this.convertAndCacheOnCPU(e,g),S=this.pendingRead.get(e),this.pendingRead.delete(e),S.forEach((function(E){return E(C)})),this.pendingDisposal.has(e)&&(this.pendingDisposal.delete(e),this.disposeData(e),this.pendingDeletes--),[2,C]}}))}))},t.prototype.checkNumericalProblems=function(e){if(e!=null)for(var n=0;n<e.length;n++){var o=e[n];if(!wl(o))throw L().getBool("WEBGL_RENDER_FLOAT32_CAPABLE")?Error("The value "+o+" cannot be represented with your current settings. Consider enabling float32 rendering: 'tf.env().set('WEBGL_RENDER_FLOAT32_ENABLED', true);'"):Error("The value "+o+" cannot be represented on this device.")}},t.prototype.getValuesFromTexture=function(e){var n,o=this.texData.get(e),a=o.shape,i=o.dtype,s=o.isPacked,u=Y(a);if(L().getBool("WEBGL_DOWNLOAD_FLOAT_ENABLED")){var c=this.decode(e),l=this.texData.get(c.dataId),h=(n=this.gpgpu).downloadMatrixFromPackedTexture.apply(n,[l.texture].concat(er(a))).subarray(0,u);return this.disposeData(c.dataId),h}var f=L().getBool("WEBGL_PACK")&&s===!0,p=f?Mo(a):a,d=f?new wf(p):new bf(p),v=this.runWebGLProgram(d,[{shape:p,dtype:i,dataId:e}],"float32"),m=this.texData.get(v.dataId),g=this.gpgpu.downloadByteEncodedFloatMatrixFromOutputTexture(m.texture,m.texShape[0],m.texShape[1]).subarray(0,u);return this.disposeData(v.dataId),g},t.prototype.time=function(e){return X(this,void 0,void 0,(function(){var n,o,a,i,s,u,c;return $(this,(function(l){switch(l.label){case 0:return n=this.activeTimers,o=[],a=!1,this.programTimersStack==null?(this.programTimersStack=o,a=!0):this.activeTimers.push(o),this.activeTimers=o,e(),i=Hn(this.activeTimers.map((function(h){return h.query}))).filter((function(h){return h!=null})),s=Hn(this.activeTimers.map((function(h){return h.name}))).filter((function(h){return h!=null})),this.activeTimers=n,a&&(this.programTimersStack=null),u={uploadWaitMs:this.uploadWaitMs,downloadWaitMs:this.downloadWaitMs,kernelMs:null,wallMs:null},L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_RELIABLE")>0?[4,Promise.all(i)]:[3,2];case 1:return c=l.sent(),u.kernelMs=tl(c),u.getExtraProfileInfo=function(){return c.map((function(h,f){return{name:s[f],ms:h}})).map((function(h){return h.name+": "+h.ms})).join(", ")},[3,3];case 2:u.kernelMs={error:"WebGL query timers are not supported in this environment."},l.label=3;case 3:return this.uploadWaitMs=0,this.downloadWaitMs=0,[2,u]}}))}))},t.prototype.memory=function(){return{unreliable:!1,numBytesInGPU:this.numBytesInGPU}},t.prototype.startTimer=function(){return L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_RELIABLE")>0?this.gpgpu.beginQuery():{startMs:Rt(),endMs:null}},t.prototype.endTimer=function(e){return L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_RELIABLE")>0?(this.gpgpu.endQuery(),e):(e.endMs=Rt(),e)},t.prototype.getQueryTime=function(e){return X(this,void 0,void 0,(function(){var n;return $(this,(function(o){return L().getNumber("WEBGL_DISJOINT_QUERY_TIMER_EXTENSION_RELIABLE")>0?[2,this.gpgpu.waitForQueryAndGetTime(e)]:[2,(n=e).endMs-n.startMs]}))}))},t.prototype.disposeData=function(e){if(!this.pendingDisposal.has(e)){if(this.pendingRead.has(e))return this.pendingDisposal.add(e),void this.pendingDeletes++;if(this.texData.has(e)){this.releaseGPUData(e);var n=this.texData.get(e).complexTensors;n!=null&&(n.real.dispose(),n.imag.dispose()),this.texData.delete(e)}}},t.prototype.releaseGPUData=function(e){var n=this.texData.get(e),o=n.texture,a=n.dtype,i=n.texShape,s=n.usage,u=n.isPacked,c=n.slice,l=c&&c.origDataId||e,h=this.dataRefCount.get(l);h>1?this.dataRefCount.set(l,h-1):(this.dataRefCount.delete(l),o!=null&&(this.numBytesInGPU-=this.computeBytes(i,a),this.textureManager.releaseTexture(o,i,s,u)));var f=this.texData.get(e);f.texture=null,f.texShape=null,f.isPacked=!1,f.slice=null},t.prototype.getTexture=function(e){return this.uploadToGPU(e),this.texData.get(e).texture},t.prototype.getDataInfo=function(e){return this.texData.get(e)},t.prototype.getCPUBackend=function(){return L().getBool("WEBGL_CPU_FORWARD")?(this.cpuBackend==null&&(this.cpuBackend=N.findBackend("cpu")),this.cpuBackend):null},t.prototype.shouldExecuteOnCPU=function(e,n){var o=this;return n===void 0&&(n=128),this.getCPUBackend()!=null&&e.every((function(a){return o.texData.get(a.dataId).texture==null&&a.size<n}))},t.prototype.getGPGPUContext=function(){return this.gpgpu},t.prototype.complex=function(e,n){var o=this.makeOutput(e.shape,"complex64");return this.texData.get(o.dataId).complexTensors={real:N.keep(e.clone()),imag:N.keep(n.clone())},o},t.prototype.real=function(e){return this.texData.get(e.dataId).complexTensors.real.clone()},t.prototype.imag=function(e){return this.texData.get(e.dataId).complexTensors.imag.clone()},t.prototype.slice=function(e,n,o){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.slice(e,n,o);if(Y(o)===0)return je([],o,e.dtype);var a=this.texData.get(e.dataId).isPacked,i=tu(e.shape,n,o);if(a||!i){var s=L().getBool("WEBGL_PACK_ARRAY_OPERATIONS")?new vp(o):new dp(o),u=s.getCustomSetupFunc(n);return this.compileAndRun(s,[e],null,u)}return this.uploadToGPU(e.dataId),this.shallowSlice(e,n,o)},t.prototype.shallowSlice=function(e,n,o){var a=this.texData.get(e.dataId),i=this.makeOutput(o,e.dtype),s=this.texData.get(i.dataId);Object.assign(s,a),s.shape=o,s.dtype=e.dtype;var u=nu(n,e.strides);a.slice&&(u+=a.slice.flatOffset),s.slice={flatOffset:u,origDataId:a.slice&&a.slice.origDataId||e.dataId};var c=this.dataRefCount.get(s.slice.origDataId)||1;return this.dataRefCount.set(s.slice.origDataId,c+1),i},t.prototype.stridedSlice=function(e,n,o,a){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.stridedSlice(e,n,o,a);var i=Aa(n,o,a);if(i.some((function(u){return u===0})))return je([],i);var s=new mp(n,a,i);return this.compileAndRun(s,[e])},t.prototype.reverse=function(e,n){var o=L().getBool("WEBGL_PACK_ARRAY_OPERATIONS")?new hp(e.shape,n):new lp(e.shape,n);return this.compileAndRun(o,[e])},t.prototype.concat=function(e,n){if(e[0].dtype==="complex64"){var o=e.map((function(p){return ft(p)})),a=e.map((function(p){return St(p)}));return Ge(this.concat(o,n),this.concat(a,n))}if(this.shouldExecuteOnCPU(e))return this.cpuBackend.concat(e,n);if(e.length===1)return e[0];if(e.length>L().getNumber("WEBGL_MAX_TEXTURES_IN_SHADER")){var i=Math.floor(e.length/2),s=this.concat(e.slice(0,i),n),u=this.concat(e.slice(i),n);return this.concat([s,u],n)}if(L().getBool("WEBGL_PACK_ARRAY_OPERATIONS")&&e[0].rank>1){var c=new af(e.map((function(p){return p.shape})),n);return this.compileAndRun(c,e)}var l=qn(e.map((function(p){return p.shape})),n),h=e.map((function(p){return p.as2D(-1,Y(p.shape.slice(n)))})),f=new of(h.map((function(p){return p.shape})));return this.compileAndRun(f,h).reshape(l)},t.prototype.neg=function(e){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.neg(e);if(L().getBool("WEBGL_PACK_UNARY_OPERATIONS"))return this.packedUnaryOp(e,Zi,e.dtype);var n=new ae(e.shape,Zi);return this.compileAndRun(n,[e])},t.prototype.batchMatMul=function(e,n,o,a){var i=o?e.shape[2]:e.shape[1],s=a?n.shape[1]:n.shape[2],u=o?e.shape[1]:e.shape[2],c=e.shape[0];if((i===1||s===1)&&u>1e3){o&&(e=e.transpose([0,2,1])),a&&(n=n.transpose([0,2,1]));var l=s===1?e:e.as3D(c,u,1),h=s===1?2:1,f=s===1?n.as3D(c,1,u):n;return this.multiply(l,f).sum(h,!0)}var p=He(e.dtype,n.dtype),d=new Wo(e.shape,[c,i,s],o,a);return this.compileAndRun(d,[e,n],p)},t.prototype.fusedBatchMatMul=function(e){var n=e.a,o=e.b,a=e.transposeA,i=e.transposeB,s=e.bias,u=e.activation,c=e.preluActivationWeights,l=a?n.shape[2]:n.shape[1],h=i?o.shape[1]:o.shape[2],f=n.shape[0],p=He(n.dtype,o.dtype),d=s!=null,v=c!=null,m=u?kr(u,!0):null,g=new Wo(n.shape,[f,l,h],a,i,d,m,v),x=[n,o];return s&&x.push(s),c&&x.push(c),this.compileAndRun(g,x,p)},t.prototype.multiply=function(e,n){if(e.dtype==="complex64"){var o=this.texData.get(e.dataId),a=this.texData.get(n.dataId),i=new Vi(Zh,e.shape,n.shape),s=new Vi(ef,e.shape,n.shape),u=[this.makeComplexComponentTensorInfo(e,o.complexTensors.real),this.makeComplexComponentTensorInfo(e,o.complexTensors.imag),this.makeComplexComponentTensorInfo(n,a.complexTensors.real),this.makeComplexComponentTensorInfo(n,a.complexTensors.imag)],c=this.compileAndRun(i,u),l=this.compileAndRun(s,u),h=this.complex(c,l);return c.dispose(),l.dispose(),h}if(this.shouldExecuteOnCPU([e,n]))return this.cpuBackend.multiply(e,n);if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,zi,e.dtype);var f=new De(zi,e.shape,n.shape);return this.compileAndRun(f,[e,n],e.dtype)},t.prototype.batchNormalization=function(e,n,o,a,i,s){var u=[e,n,o],c=null;s!=null&&(c=s.shape,u.push(s));var l=null;if(i!=null&&(l=i.shape,u.push(i)),L().getBool("WEBGL_PACK_NORMALIZATION")){var h=new Qh(e.shape,n.shape,o.shape,c,l,a);return this.compileAndRun(h,u)}var f=new Jh(e.shape,n.shape,o.shape,c,l,a);return this.compileAndRun(f,u)},t.prototype.localResponseNormalization4D=function(e,n,o,a,i){var s=L().getBool("WEBGL_PACK_NORMALIZATION")?new $f(e.shape,n,o,a,i):new Kf(e.shape,n,o,a,i);return this.compileAndRun(s,[e])},t.prototype.LRNGrad=function(e,n,o,a,i,s,u){var c=new Xf(n.shape,a,i,s,u);return this.compileAndRun(c,[n,o,e])},t.prototype.tile=function(e,n){if(e.dtype==="string"){var o=this.readSync(e.dataId).map((function(i){return Br(i)}));return lu(oe(e.shape,e.dtype,o),n)}var a=new yp(e.shape,n);return this.compileAndRun(a,[e])},t.prototype.pad=function(e,n,o){var a=L().getBool("WEBGL_PACK_ARRAY_OPERATIONS")?new np(e.shape,n,o):new tp(e.shape,n,o);return this.compileAndRun(a,[e])},t.prototype.transpose=function(e,n){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.transpose(e,n);var o=L().getBool("WEBGL_PACK_ARRAY_OPERATIONS")?new bp(e.shape,n):new xp(e.shape,n);return this.compileAndRun(o,[e])},t.prototype.gather=function(e,n,o){if(this.shouldExecuteOnCPU([e,n]))return this.cpuBackend.gather(e,n,o);var a=new kf(e.shape,n.size,o);return this.compileAndRun(a,[e,n])},t.prototype.batchToSpaceND=function(e,n,o){I(e.rank<=4,(function(){return"batchToSpaceND for rank > 4 with a WebGL backend not implemented yet"}));var a=n.reduce((function(h,f){return h*f})),i=Gr(e.shape,n,a),s=Hr(i.length,n.length),u=jr(e.shape,n,a),c=Js(o,n.length),l=Qs(u,o,n.length);return e.reshape(i).transpose(s).reshape(u).slice(c,l)},t.prototype.spaceToBatchND=function(e,n,o){I(e.rank<=4,(function(){return"spaceToBatchND for rank > 4 with a WebGL backend not implemented yet"}));var a=n.reduce((function(f,p){return f*p})),i=[[0,0]];i.push.apply(i,o);for(var s=1+n.length;s<e.shape.length;++s)i.push([0,0]);var u=e.pad(i),c=Gr(u.shape,n,a,!1),l=Hr(c.length,n.length,!1),h=jr(u.shape,n,a,!1);return u.reshape(c).transpose(l).reshape(h)},t.prototype.reduce=function(e,n,o){var a=e.shape[0],i=e.shape[1],s=Oo(i),u=new rp({windowSize:s,inSize:i,batchSize:a},n),c=this.compileAndRun(u,[e],o);return c.shape[1]===1?c:this.reduce(c,n,o)},t.prototype.argReduce=function(e,n,o){o===void 0&&(o=null);var a=e.shape[0],i=e.shape[1];o!=null&&(a=o.shape[0],i=o.shape[1]);var s=Oo(i),u=new zh({windowSize:s,inSize:i,batchSize:a},n,o==null),c=[e];o!=null&&c.push(o);var l=this.compileAndRun(u,c,"int32");return l.shape[1]===1?l:this.argReduce(e,n,l)},t.prototype.argReducePacked=function(e,n,o){o===void 0&&(o=null);var a=o!=null?o.shape:e.shape,i=Oo(a[a.length-1]),s=new Xh(a,i,n,o==null),u=o==null?[e]:[e,o],c=this.compileAndRun(s,u,"int32");return c.rank===e.rank?this.argReducePacked(e,n,c):c},t.prototype.sum=function(e,n){at("sum",n,e.rank);var o=qe(e.shape,n),a=o[0],i=Y(o[1]),s=e.as2D(-1,i),u=So(e.dtype);return this.reduce(s,"sum",u).reshape(a)},t.prototype.prod=function(e,n){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.prod(e,n);var o=qe(e.shape,n),a=o[0],i=Y(o[1]),s=e.as2D(-1,i),u=So(e.dtype);return this.reduce(s,"prod",u).reshape(a)},t.prototype.unsortedSegmentSum=function(e,n,o){var a=0,i=Mt([a],e.rank),s=e;i!=null&&(s=e.transpose(i),a=Ot(1,e.rank)[0]);var u=(function(p,d,v){for(var m=[],g=p.length,x=0;x<g;x++)x!==d?m.push(p[x]):m.push(v);return m})(s.shape,a,o),c=Y([s.shape[a]]),l=s.as2D(-1,c),h=So(e.dtype),f=this.segOpCompute(l,"unsortedSegmentSum",n,h,o).reshape(u);return i!=null&&(f=f.transpose(Ra(i))),f},t.prototype.segOpCompute=function(e,n,o,a,i){var s=e.shape[0],u=e.shape[1],c=(function(f,p){var d,v=!1;for(f<=eu?(d=f,v=!0):d=oa(f,Math.floor(Math.sqrt(f)));!v;)d>p||d===f?v=!0:d=oa(f,d+1);return d})(u,i),l=new fp({windowSize:c,inSize:u,batchSize:s,numSegments:i}),h=this.compileAndRun(l,[e,o],a);return h.shape[1]===i?h:(o=zr(0,i).tile([u/c]),this.segOpCompute(h,n,o,a,i))},t.prototype.argMinMaxReduce=function(e,n,o){var a=[n];if(at("arg"+o.charAt(0).toUpperCase()+o.slice(1),a,e.rank),!L().getBool("WEBGL_PACK_REDUCE")||e.rank<=2){var i=qe(e.shape,a),s=i[0],u=Y(i[1]),c=e.as2D(-1,u);return this.argReduce(c,o).reshape(s)}return this.argReducePacked(e,o)},t.prototype.argMin=function(e,n){return this.argMinMaxReduce(e,n,"min")},t.prototype.argMax=function(e,n){return this.argMinMaxReduce(e,n,"max")},t.prototype.cumsum=function(e,n,o,a){if(n!==e.rank-1)throw new Error("WebGL cumsum shader expects an inner-most axis="+(e.rank-1)+" but got axis="+n);var i=new vf(e.shape,o,a);return this.compileAndRun(i,[e])},t.prototype.equal=function(e,n){if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  return vec4(equal(a, b));
`,"bool");var o=new De("return float(a == b);",e.shape,n.shape);return this.compileAndRun(o,[e,n],"bool")},t.prototype.notEqual=function(e,n){if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  return vec4(notEqual(a, b));
`,"bool");var o=new De("return float(a != b);",e.shape,n.shape);return this.compileAndRun(o,[e,n],"bool")},t.prototype.less=function(e,n){if(this.shouldExecuteOnCPU([e,n]))return this.cpuBackend.less(e,n);if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  return vec4(lessThan(a, b));
`,"bool");var o=new De("return float(a < b);",e.shape,n.shape);return this.compileAndRun(o,[e,n],"bool")},t.prototype.lessEqual=function(e,n){if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  return vec4(lessThanEqual(a, b));
`,"bool");var o=new De("return float(a <= b);",e.shape,n.shape);return this.compileAndRun(o,[e,n],"bool")},t.prototype.greater=function(e,n){if(this.shouldExecuteOnCPU([e,n]))return this.cpuBackend.greater(e,n);if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  return vec4(greaterThan(a, b));
`,"bool");var o=new De("return float(a > b);",e.shape,n.shape);return this.compileAndRun(o,[e,n],"bool")},t.prototype.greaterEqual=function(e,n){if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  return vec4(greaterThanEqual(a, b));
`,"bool");var o=new De("return float(a >= b);",e.shape,n.shape);return this.compileAndRun(o,[e,n],"bool")},t.prototype.logicalNot=function(e){var n=new ae(e.shape,"return float(!(x >= 1.0));");return this.compileAndRun(n,[e])},t.prototype.logicalAnd=function(e,n){if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  return vec4(
    vec4(greaterThanEqual(a, vec4(1.0))) *
    vec4(greaterThanEqual(b, vec4(1.0))));
`,"bool");var o=new De("return float(a >= 1.0 && b >= 1.0);",e.shape,n.shape);return this.compileAndRun(o,[e,n],"bool")},t.prototype.logicalOr=function(e,n){if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  return min(
    vec4(greaterThanEqual(a, vec4(1.0))) +
    vec4(greaterThanEqual(b, vec4(1.0))),
    vec4(1.0));
`,"bool");var o=new De("return float(a >= 1.0 || b >= 1.0);",e.shape,n.shape);return this.compileAndRun(o,[e,n],"bool")},t.prototype.select=function(e,n,o){var a=new pp(e.rank,n.shape,n.rank);return this.compileAndRun(a,[e,n,o],He(n.dtype,o.dtype))},t.prototype.where=function(e){Ur("tf.where() in webgl locks the UI thread. Call tf.whereAsync() instead");var n=e.dataSync();return Pa(e.shape,n)},t.prototype.topk=function(e,n,o){return hu(e.dataSync(),e.shape,e.dtype,n)},t.prototype.min=function(e,n){at("min",n,e.rank);var o=qe(e.shape,n),a=o[0],i=Y(o[1]),s=e.as2D(-1,i);return this.reduce(s,"min",s.dtype).reshape(a)},t.prototype.minimum=function(e,n){if(this.shouldExecuteOnCPU([e,n]))return this.cpuBackend.minimum(e,n);var o=L().getBool("WEBGL_PACK_BINARY_OPERATIONS")?new Gt(`
  vec4 result = vec4(min(a, b));
  vec4 isNaN = min(vec4(isnan(a)) + vec4(isnan(b)), vec4(1.0));
  
  result.r = isNaN.r > 0. ? NAN : result.r;
  result.g = isNaN.g > 0. ? NAN : result.g;
  result.b = isNaN.b > 0. ? NAN : result.b;
  result.a = isNaN.a > 0. ? NAN : result.a;

  return result;
`,e.shape,n.shape):new De(`
  if (isnan(a)) return a;
  if (isnan(b)) return b;

  return min(a, b);
`,e.shape,n.shape);return this.compileAndRun(o,[e,n])},t.prototype.mod=function(e,n){var o=L().getBool("WEBGL_PACK_BINARY_OPERATIONS")?new Gt(`
  vec4 result = mod(a, b);
  vec4 isNaN = vec4(equal(b, vec4(0.0)));
  
  result.r = isNaN.r > 0. ? NAN : result.r;
  result.g = isNaN.g > 0. ? NAN : result.g;
  result.b = isNaN.b > 0. ? NAN : result.b;
  result.a = isNaN.a > 0. ? NAN : result.a;

  return result;
`,e.shape,n.shape):new De(`if (b == 0.0) return NAN;
  return mod(a, b);`,e.shape,n.shape);return this.compileAndRun(o,[e,n])},t.prototype.max=function(e,n){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.max(e,n);at("max",n,e.rank);var o=qe(e.shape,n),a=o[0],i=Y(o[1]),s=e.as2D(-1,i);return this.reduce(s,"max",s.dtype).reshape(a)},t.prototype.maximum=function(e,n){if(this.shouldExecuteOnCPU([e,n]))return this.cpuBackend.maximum(e,n);var o=L().getBool("WEBGL_PACK_BINARY_OPERATIONS")?new Gt(`
  vec4 result = vec4(max(a, b));
  vec4 isNaN = min(vec4(isnan(a)) + vec4(isnan(b)), vec4(1.0));
  
  result.r = isNaN.r > 0. ? NAN : result.r;
  result.g = isNaN.g > 0. ? NAN : result.g;
  result.b = isNaN.b > 0. ? NAN : result.b;
  result.a = isNaN.a > 0. ? NAN : result.a;

  return result;
`,e.shape,n.shape):new De(`
  if (isnan(a)) return a;
  if (isnan(b)) return b;

  return max(a, b);
`,e.shape,n.shape);return this.compileAndRun(o,[e,n])},t.prototype.all=function(e,n){at("all",n,e.rank);var o=qe(e.shape,n),a=o[0],i=Y(o[1]),s=e.as2D(-1,i);return this.reduce(s,"all",s.dtype).reshape(a)},t.prototype.any=function(e,n){at("any",n,e.rank);var o=qe(e.shape,n),a=o[0],i=Y(o[1]),s=e.as2D(-1,i);return this.reduce(s,"any",s.dtype).reshape(a)},t.prototype.realDivide=function(e,n){if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  // vec4 one = vec4(equal(a, b));
  // return one + (vec4(1.0) - one) * a / b;
  vec4 result = a / b;
  if(a.x == b.x) {
    result.x = 1.;
  }
  if(a.y == b.y) {
    result.y = 1.;
  }
  if(a.z == b.z) {
    result.z = 1.;
  }
  if(a.w == b.w) {
    result.w = 1.;
  }

  return result;
`,"float32",!0);var o=new De(`
if (a == b) {
  return 1.0;
};
return a / b;`,e.shape,n.shape);return this.compileAndRun(o,[e,n],"float32")},t.prototype.floorDiv=function(e,n){if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,`
  ivec4 ia = round(a);
  ivec4 ib = round(b);
  bvec4 cond = notEqual(ib, ivec4(0));
  ivec4 result = ivec4(0);
  vec4 s = sign(a) * sign(b);

  // Windows (D3D) wants guaranteed non-zero int division at compile-time.
  if (cond[0]) {
    result[0] = idiv(ia[0], ib[0], s[0]);
  }
  if (cond[1]) {
    result[1] = idiv(ia[1], ib[1], s[1]);
  }
  if (cond[2]) {
    result[2] = idiv(ia[2], ib[2], s[2]);
  }
  if (cond[3]) {
    result[3] = idiv(ia[3], ib[3], s[3]);
  }
  return vec4(result);
`,"int32");var o=new De(`
  float s = sign(a) * sign(b);
  int ia = round(a);
  int ib = round(b);
  if (ib != 0) {
    // Windows (D3D) wants guaranteed non-zero int division at compile-time.
    return float(idiv(ia, ib, s));
  } else {
    return NAN;
  }
`,e.shape,n.shape);return this.compileAndRun(o,[e,n],"int32")},t.prototype.add=function(e,n){if(e.dtype==="complex64"&&n.dtype==="complex64")return this.complexSeparableBinaryOp(e,n,Bo);if(this.shouldExecuteOnCPU([e,n]))return this.cpuBackend.add(e,n);var o=He(e.dtype,n.dtype);if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,Bo,o);var a=new De(Bo,e.shape,n.shape);return this.compileAndRun(a,[e,n],o)},t.prototype.packedUnaryOp=function(e,n,o){var a=new Zn(e.shape,n);return this.compileAndRun(a,[e],o)},t.prototype.packedBinaryOp=function(e,n,o,a,i){i===void 0&&(i=!1);var s=new Gt(o,e.shape,n.shape,i);return this.compileAndRun(s,[e,n],a)},t.prototype.complexSeparableBinaryOp=function(e,n,o){var a=this,i=this.texData.get(e.dataId),s=this.texData.get(n.dataId),u=[[i.complexTensors.real,s.complexTensors.real],[i.complexTensors.imag,s.complexTensors.imag]].map((function(f){var p=f[0],d=f[1],v=a.makeComplexComponentTensorInfo(e,p),m=a.makeComplexComponentTensorInfo(n,d),g=new De(o,e.shape,n.shape);return a.compileAndRun(g,[v,m],He(p.dtype,d.dtype))})),c=u[0],l=u[1],h=this.complex(c,l);return c.dispose(),l.dispose(),h},t.prototype.makeComplexComponentTensorInfo=function(e,n){return{dataId:n.dataId,dtype:n.dtype,shape:e.shape}},t.prototype.addN=function(e){if(e.length===1)return e[0];if(e.length>L().get("WEBGL_MAX_TEXTURES_IN_SHADER")){var n=Math.floor(e.length/2),o=this.addN(e.slice(0,n)),a=this.addN(e.slice(n));return this.addN([o,a])}var i=e.map((function(c){return c.dtype})).reduce((function(c,l){return He(c,l)})),s=e.map((function(c){return c.shape})),u=L().getBool("WEBGL_PACK")?new Vh(e[0].shape,s):new Uh(e[0].shape,s);return this.compileAndRun(u,e,i)},t.prototype.subtract=function(e,n){if(e.dtype==="complex64"&&n.dtype==="complex64")return this.complexSeparableBinaryOp(e,n,Lo);if(this.shouldExecuteOnCPU([e,n]))return this.cpuBackend.subtract(e,n);var o=He(e.dtype,n.dtype);if(L().getBool("WEBGL_PACK_BINARY_OPERATIONS"))return this.packedBinaryOp(e,n,Lo,e.dtype);var a=new De(Lo,e.shape,n.shape);return this.compileAndRun(a,[e,n],o)},t.prototype.pow=function(e,n){var o=L().getBool("WEBGL_PACK_BINARY_OPERATIONS")?new Gt(`
  // isModRound1 has 1 for components with round(mod(b, 2.0)) == 1, 0 otherwise.
  vec4 isModRound1 = vec4(equal(round(mod(b, 2.0)), ivec4(1)));
  vec4 multiplier = sign(a) * isModRound1 + (vec4(1.0) - isModRound1);
  vec4 result = multiplier * pow(abs(a), b);

  // Ensure that a^0 = 1, including 0^0 = 1 as this correspond to TF and JS
  bvec4 isExpZero = equal(b, vec4(0.0));
  result.r = isExpZero.r ? 1.0 : result.r;
  result.g = isExpZero.g ? 1.0 : result.g;
  result.b = isExpZero.b ? 1.0 : result.b;
  result.a = isExpZero.a ? 1.0 : result.a;

  vec4 isNaN = vec4(lessThan(a, vec4(0.0))) * vec4(lessThan(floor(b), b));
  
  result.r = isNaN.r > 0. ? NAN : result.r;
  result.g = isNaN.g > 0. ? NAN : result.g;
  result.b = isNaN.b > 0. ? NAN : result.b;
  result.a = isNaN.a > 0. ? NAN : result.a;

  return result;
`,e.shape,n.shape):new De(`
if(a < 0.0 && floor(b) < b){
  return NAN;
}
if (b == 0.0) {
  return 1.0;
}
return (round(mod(b, 2.0)) != 1) ?
    pow(abs(a), b) : sign(a) * pow(abs(a), b);
`,e.shape,n.shape),a=He(e.dtype,n.dtype);return this.compileAndRun(o,[e,n],a)},t.prototype.ceil=function(e){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.ceil(e);if(L().getBool("WEBGL_PACK_UNARY_OPERATIONS"))return this.packedUnaryOp(e,es,e.dtype);var n=new ae(e.shape,es);return this.compileAndRun(n,[e])},t.prototype.floor=function(e){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.floor(e);if(L().getBool("WEBGL_PACK_UNARY_OPERATIONS"))return this.packedUnaryOp(e,ts,e.dtype);var n=new ae(e.shape,ts);return this.compileAndRun(n,[e])},t.prototype.sign=function(e){var n=new ae(e.shape,`
  if (isnan(x)) { return 0.0; }
  return sign(x);
`);return this.compileAndRun(n,[e])},t.prototype.isNaN=function(e){var n=new ae(e.shape,"return float(isnan(x));");return this.compileAndRun(n,[e],"bool")},t.prototype.isInf=function(e){var n=new ae(e.shape,"return float(isinf(x));");return this.compileAndRun(n,[e],"bool")},t.prototype.isFinite=function(e){var n=new ae(e.shape,"return float(!isnan(x) && !isinf(x));");return this.compileAndRun(n,[e],"bool")},t.prototype.round=function(e){var n=new ae(e.shape,`
  // OpenGL ES does not support round function.
  // The algorithm is based on banker's rounding.
  float base = floor(x);
  if ((x - base) < 0.5) {
    return floor(x);
  } else if ((x - base) > 0.5) {
    return ceil(x);
  } else {
    if (mod(base, 2.0) == 0.0) {
      return base;
    } else {
      return base + 1.0;
    }
  }
`);return this.compileAndRun(n,[e])},t.prototype.exp=function(e){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.exp(e);if(L().getBool("WEBGL_PACK_UNARY_OPERATIONS"))return this.packedUnaryOp(e,ns,e.dtype);var n=new ae(e.shape,ns);return this.compileAndRun(n,[e])},t.prototype.expm1=function(e){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.expm1(e);if(L().getBool("WEBGL_PACK_UNARY_OPERATIONS"))return this.packedUnaryOp(e,rs,e.dtype);var n=new ae(e.shape,rs);return this.compileAndRun(n,[e])},t.prototype.softmax=function(e,n){var o=Le([n],e.shape),a=this.max(e,o),i=nt(a.shape,o),s=this.subtract(e,a.reshape(i)),u=this.exp(s),c=this.sum(u,o).reshape(i);return this.realDivide(u,c)},t.prototype.log=function(e){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.log(e);if(L().getBool("WEBGL_PACK_UNARY_OPERATIONS"))return this.packedUnaryOp(e,`
  vec4 result = log(x);
  vec4 isNaN = vec4(lessThan(x, vec4(0.0)));
  result.r = isNaN.r == 1.0 ? NAN : result.r;
  result.g = isNaN.g == 1.0 ? NAN : result.g;
  result.b = isNaN.b == 1.0 ? NAN : result.b;
  result.a = isNaN.a == 1.0 ? NAN : result.a;

  return result;
`,e.dtype);var n=new ae(e.shape,`if (x < 0.0) return NAN;
  return log(x);`);return this.compileAndRun(n,[e])},t.prototype.log1p=function(e){var n=new ae(e.shape,"return log(1.0 + x);");return this.compileAndRun(n,[e])},t.prototype.sqrt=function(e){var n=new ae(e.shape,"return sqrt(x);");return this.compileAndRun(n,[e])},t.prototype.rsqrt=function(e){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.rsqrt(e);var n=new ae(e.shape,"return inversesqrt(x);");return this.compileAndRun(n,[e])},t.prototype.reciprocal=function(e){var n=new ae(e.shape,"return 1.0 / x;");return this.compileAndRun(n,[e])},t.prototype.relu=function(e){var n;return n=L().getBool("WEBGL_PACK")?new Zn(e.shape,bu):new ae(e.shape,gu),this.compileAndRun(n,[e])},t.prototype.relu6=function(e){var n;return n=L().getBool("WEBGL_PACK")?new Zn(e.shape,wu):new ae(e.shape,yu),this.compileAndRun(n,[e])},t.prototype.prelu=function(e,n){var o=L().getBool("WEBGL_PACK_BINARY_OPERATIONS")?new Gt(mu,e.shape,n.shape):new De(vu,e.shape,n.shape);return this.compileAndRun(o,[e,n])},t.prototype.elu=function(e){if(L().getBool("WEBGL_PACK_UNARY_OPERATIONS"))return this.packedUnaryOp(e,Cu,e.dtype);var n=new ae(e.shape,xu);return this.compileAndRun(n,[e])},t.prototype.eluDer=function(e,n){var o=L().getBool("WEBGL_PACK_BINARY_OPERATIONS")?new Gt(`
  vec4 bGTEZero = vec4(greaterThanEqual(b, vec4(0.)));
  return (bGTEZero * a) + ((vec4(1.0) - bGTEZero) * (a * (b + vec4(1.0))));
`,e.shape,n.shape):new De("return (b >= 1.0) ? a : a * (b + 1.0);",e.shape,n.shape);return this.compileAndRun(o,[e,n])},t.prototype.selu=function(e){var n=new ae(e.shape,Cp);return this.compileAndRun(n,[e])},t.prototype.int=function(e){var n=new ae(e.shape,"return float(int(x));");return this.compileAndRun(n,[e],"int32")},t.prototype.clip=function(e,n,o){var a,i=(a=L().getBool("WEBGL_PACK_CLIP")?new nf(e.shape):new tf(e.shape)).getCustomSetupFunc(n,o);return this.compileAndRun(a,[e],null,i)},t.prototype.abs=function(e){if(this.shouldExecuteOnCPU([e]))return this.cpuBackend.abs(e);if(L().getBool("WEBGL_PACK_UNARY_OPERATIONS"))return this.packedUnaryOp(e,Qi,e.dtype);var n=new ae(e.shape,Qi);return this.compileAndRun(n,[e])},t.prototype.complexAbs=function(e){var n=this.texData.get(e.dataId),o=new rf(e.shape),a=[this.makeComplexComponentTensorInfo(e,n.complexTensors.real),this.makeComplexComponentTensorInfo(e,n.complexTensors.imag)];return this.compileAndRun(o,a)},t.prototype.sigmoid=function(e){var n=new ae(e.shape,"return 1.0 / (1.0 + exp(-1.0 * x));");return this.compileAndRun(n,[e])},t.prototype.softplus=function(e){var n=new ae(e.shape,`
  float epsilon = 1.1920928955078125e-7;
  float threshold = log(epsilon) + 2.0;

  bool too_large = x > -threshold;
  bool too_small = x < threshold;

  float result;
  float exp_x = exp(x);

  if (too_large){
    result = x;
  }
  else if (too_small){
    result = exp_x;
  }
  else{
    result = log(exp_x + 1.0);
  }
  return result;
`);return this.compileAndRun(n,[e])},t.prototype.sin=function(e){var n=new ae(e.shape,_p);return this.compileAndRun(n,[e])},t.prototype.cos=function(e){var n=new ae(e.shape,Ep);return this.compileAndRun(n,[e])},t.prototype.tan=function(e){var n=new ae(e.shape,"return tan(x);");return this.compileAndRun(n,[e])},t.prototype.asin=function(e){var n=new ae(e.shape,Ip);return this.compileAndRun(n,[e])},t.prototype.acos=function(e){var n=new ae(e.shape,Rp);return this.compileAndRun(n,[e])},t.prototype.atan=function(e){var n=new ae(e.shape,kp);return this.compileAndRun(n,[e])},t.prototype.atan2=function(e,n){var o=L().getBool("WEBGL_PACK_BINARY_OPERATIONS")?new Gt(`
  vec4 result = atan(a, b);
  vec4 isNaN = min(vec4(isnan(a)) + vec4(isnan(b)), vec4(1.0));
  
  result.r = isNaN.r > 0. ? NAN : result.r;
  result.g = isNaN.g > 0. ? NAN : result.g;
  result.b = isNaN.b > 0. ? NAN : result.b;
  result.a = isNaN.a > 0. ? NAN : result.a;

  return result;
`,e.shape,n.shape):new De(`
  if (isnan(a)) return a;
  if (isnan(b)) return b;

  return atan(a, b);
`,e.shape,n.shape);return this.compileAndRun(o,[e,n])},t.prototype.sinh=function(e){var n=new ae(e.shape,`
  float e2x = exp(x);
  return (e2x - 1.0 / e2x) / 2.0;
`);return this.compileAndRun(n,[e])},t.prototype.cosh=function(e){var n=new ae(e.shape,`
  float e2x = exp(-x);
  return (e2x + 1.0 / e2x) / 2.0;
`);return this.compileAndRun(n,[e])},t.prototype.tanh=function(e){var n=new ae(e.shape,`
  float e2x = exp(-2.0 * abs(x));
  return sign(x) * (1.0 - e2x) / (1.0 + e2x);
`);return this.compileAndRun(n,[e])},t.prototype.asinh=function(e){var n=new ae(e.shape,Sp);return this.compileAndRun(n,[e])},t.prototype.acosh=function(e){var n=new ae(e.shape,Dp);return this.compileAndRun(n,[e])},t.prototype.atanh=function(e){var n=new ae(e.shape,Ap);return this.compileAndRun(n,[e])},t.prototype.erf=function(e){var n=new ae(e.shape,`
  // Error function is calculated approximately with elementary function.
  // See "Handbook of Mathematical Functions with Formulas,
  // Graphs, and Mathematical Tables", Abramowitz and Stegun.
  float p = 0.3275911;
  float a1 = 0.254829592;
  float a2 = -0.284496736;
  float a3 = 1.421413741;
  float a4 = -1.453152027;
  float a5 = 1.061405429;

  float sign = sign(x);
  x = abs(x);
  float t = 1.0 / (1.0 + p * x);
  return sign * (1.0 - (((((a5*t + a4)*t) + a3)*t + a2)*t + a1)*t*exp(-x*x));
`);return this.compileAndRun(n,[e])},t.prototype.step=function(e,n){var o=new ae(e.shape,(function(a){return a===void 0&&(a=0),xt+`
    return x > 0.0 ? 1.0 : float(`+a+`);
  `})(n));return this.compileAndRun(o,[e])},t.prototype.conv2dByMatMul=function(e,n,o,a,i,s){var u=e.shape,c=this.texData.get(e.dataId),l=o.inChannels,h=u[0]*u[1]*u[2],f=o.outChannels,p=o.dataFormat==="channelsLast",d=(h===1||f===1)&&l>1e3,v=u[2]%2!=0&&!!c.isPacked;if(d||!L().getBool("WEBGL_LAZILY_UNPACK")||!L().getBool("WEBGL_PACK_BINARY_OPERATIONS")||!v){var m=p?u[0]*u[1]*u[2]:u[0]*u[2]*u[3],g=this.reshape(e,[1,m,o.inChannels]),x=this.reshape(n,[1,o.inChannels,o.outChannels]);return this.reshape(this.fusedBatchMatMul({a:g,b:x,transposeA:!1,transposeB:!1,bias:a,activation:i,preluActivationWeights:s}),o.outShape)}var b=p?u[0]*u[1]*(u[2]+1):u[0]*u[2]*(u[3]+1),y={dataId:e.dataId,shape:[1,b,o.inChannels],dtype:e.dtype},w=c.shape;c.shape=c.shape.slice(),c.shape[c.shape.length-2]++,I(_r(c.shape,y.shape),(function(){return"packed reshape "+c.shape+" to "+y.shape+" isn't free"}));var C=this.reshape(n,[1,o.inChannels,o.outChannels]),S=this.fusedBatchMatMul({a:y,b:C,transposeA:!1,transposeB:!1,bias:a,activation:i,preluActivationWeights:s}),k=this.texData.get(S.dataId);return I(k.isPacked,(function(){return"batchMatMul result is expected to be packed"})),c.shape=w,k.shape=o.outShape,N.makeTensorFromDataId(S.dataId,o.outShape,S.dtype)},t.prototype.conv2dWithIm2Row=function(e,n,o,a,i,s){var u=o.filterWidth,c=o.filterHeight,l=o.inChannels,h=o.outWidth,f=o.outHeight,p=o.dataFormat==="channelsLast",d=u*c*l,v=f*h,m=[d,v],g=e.squeeze([0]),x=n.reshape([1,d,-1]),b=new qf(m,g.shape,o),y=this.compileAndRun(b,[g]).reshape([1,m[0],m[1]]),w=a!=null,C=s!=null,S=i?kr(i,!0):null,k=new Wo(y.shape,[1,v,o.outChannels],!0,!1,w,S,C),R=[y,x];a&&R.push(a),C&&R.push(s);var E=this.compileAndRun(k,R);return p?E.reshape([1,f,h,o.outChannels]):E.reshape([1,o.outChannels,f,h])},t.prototype.fusedConv2d=function(e){var n=e.input,o=e.filter,a=e.convInfo,i=e.bias,s=e.activation,u=e.preluActivationWeights;if(a.filterHeight===1&&a.filterWidth===1&&a.dilationHeight===1&&a.dilationWidth===1&&a.strideHeight===1&&a.strideWidth===1&&(a.padInfo.type==="SAME"||a.padInfo.type==="VALID"))return this.conv2dByMatMul(n,o,a,i,s,u);if(L().getBool("WEBGL_CONV_IM2COL")&&n.shape[0]===1)return this.conv2dWithIm2Row(n,o,a,i,s,u);var c=i!=null,l=u!=null,h=s?kr(s,!1):null,f=new Gi(a,c,h,l),p=[n,o];return i&&p.push(i),u&&p.push(u),this.compileAndRun(f,p)},t.prototype.conv2d=function(e,n,o){if(o.filterHeight===1&&o.filterWidth===1&&o.dilationHeight===1&&o.dilationWidth===1&&o.strideHeight===1&&o.strideWidth===1&&(o.padInfo.type==="SAME"||o.padInfo.type==="VALID"))return this.conv2dByMatMul(e,n,o);if(L().getBool("WEBGL_CONV_IM2COL")&&e.shape[0]===1)return this.conv2dWithIm2Row(e,n,o);var a=new Gi(o);return this.compileAndRun(a,[e,n])},t.prototype.conv2dDerInput=function(e,n,o){var a=new uf(o);return this.compileAndRun(a,[e,n])},t.prototype.conv2dDerFilter=function(e,n,o){var a=new sf(o);return this.compileAndRun(a,[e,n])},t.prototype.fusedDepthwiseConv2D=function(e){var n,o=e.input,a=e.filter,i=e.convInfo,s=e.bias,u=e.activation,c=e.preluActivationWeights,l=L().getBool("WEBGL_PACK_DEPTHWISECONV")&&i.strideWidth<=2&&i.outChannels/i.inChannels==1,h=u?kr(u,l):null,f=[o,a],p=s!=null,d=c!=null;return p&&f.push(s),d&&f.push(c),l?(n=new ji(i,p,h,d),this.compileAndRun(n,f)):(n=new Hi(i,p,h,d),this.compileAndRun(n,f))},t.prototype.depthwiseConv2D=function(e,n,o){var a;return L().getBool("WEBGL_PACK_DEPTHWISECONV")&&o.strideWidth<=2&&o.outChannels/o.inChannels==1?(a=new ji(o),this.compileAndRun(a,[e,n])):(a=new Hi(o),this.compileAndRun(a,[e,n]))},t.prototype.depthwiseConv2DDerInput=function(e,n,o){var a=new ff(o);return this.compileAndRun(a,[e,n])},t.prototype.depthwiseConv2DDerFilter=function(e,n,o){var a=new hf(o);return this.compileAndRun(a,[e,n])},t.prototype.conv3d=function(e,n,o){var a=new pf(o);return this.compileAndRun(a,[e,n])},t.prototype.conv3dDerInput=function(e,n,o){var a=new lf(o);return this.compileAndRun(a,[e,n])},t.prototype.conv3dDerFilter=function(e,n,o){var a=new cf(o);return this.compileAndRun(a,[e,n])},t.prototype.maxPool=function(e,n){var o=new Uo(n,"max",!1);return this.compileAndRun(o,[e])},t.prototype.avgPool=function(e,n){var o=new Uo(n,"avg",!1);return this.compileAndRun(o,[e],"float32")},t.prototype.maxPoolBackprop=function(e,n,o,a){var i=new Uo(a,"max",!0),s=this.compileAndRun(i,[n]),u=new Yf(a),c=this.compileAndRun(u,[e,s],n.dtype);return s.dispose(),c},t.prototype.avgPoolBackprop=function(e,n,o){var a=new $h(o);return this.compileAndRun(a,[e],n.dtype)},t.prototype.cast=function(e,n){return iu(e,n,this)},t.prototype.unstack=function(e,n){for(var o=e.shape[n],a=new Array(e.rank-1),i=0,s=0;s<e.rank;s++)s!==n&&(a[i++]=e.shape[s]);var u=new Array(e.rank).fill(0),c=e.shape.slice();c[n]=1;var l=new Array(o);for(s=0;s<l.length;s++)u[n]=s,l[s]=this.slice(e,u,c).reshape(a);return l},t.prototype.avgPool3d=function(e,n){var o=new Vo(n,"avg",!1);return this.compileAndRun(o,[e],"float32")},t.prototype.avgPool3dBackprop=function(e,n,o){var a=new Yh(o);return this.compileAndRun(a,[e],n.dtype)},t.prototype.maxPool3d=function(e,n){var o=new Vo(n,"max",!1);return this.compileAndRun(o,[e],"float32")},t.prototype.maxPool3dBackprop=function(e,n,o,a){var i=new Vo(a,"max",!0),s=this.compileAndRun(i,[n]),u=new Jf(a),c=this.compileAndRun(u,[e,s],n.dtype);return s.dispose(),c},t.prototype.reshape=function(e,n){var o=this.texData.get(e.dataId);if(o.isPacked&&!_r(e.shape,n)&&(o.texture===null||!_r(o.shape,n))){var a=this.packedReshape(e,n);return N.makeTensorFromDataId(a.dataId,a.shape,a.dtype)}return fa(e,n)},t.prototype.resizeBilinear=function(e,n,o,a){var i=L().getBool("WEBGL_PACK_IMAGE_OPERATIONS")?new sp(e.shape,n,o,a):new ip(e.shape,n,o,a);return this.compileAndRun(i,[e],"float32")},t.prototype.resizeBilinearBackprop=function(e,n,o){var a=new ap(e,n,o);return this.compileAndRun(a,[e])},t.prototype.resizeNearestNeighbor=function(e,n,o,a){var i=new cp(e.shape,n,o,a);return this.compileAndRun(i,[e])},t.prototype.resizeNearestNeighborBackprop=function(e,n,o){var a=new up(e,n,o);return this.compileAndRun(a,[e])},t.prototype.multinomial=function(e,n,o,a){var i=n?e:qt(e),s=i.shape[0],u=i.shape[1],c=new Qf(s,u,o),l=c.getCustomSetupFunc(a);return this.compileAndRun(c,[i],"int32",l)},t.prototype.oneHot=function(e,n,o,a){var i=new Zf(e.size,n,o,a);return this.compileAndRun(i,[e])},t.prototype.diag=function(e){var n=new xf(e.size);return this.compileAndRun(n,[e])},t.prototype.nonMaxSuppression=function(e,n,o,a,i){return Ur("tf.nonMaxSuppression() in webgl locks the UI thread. Call tf.nonMaxSuppressionAsync() instead"),Na(e.dataSync(),n.dataSync(),o,a,i)},t.prototype.cropAndResize=function(e,n,o,a,i,s){var u=new df(e.shape,n.shape,a,i,s);return this.compileAndRun(u,[e,n,o],"float32")},t.prototype.depthToSpace=function(e,n,o){I(n>1,(function(){return"blockSize should be > 1 for depthToSpace, but was: "+n}));var a=e.shape[0],i=o==="NHWC"?e.shape[1]:e.shape[2],s=o==="NHWC"?e.shape[2]:e.shape[3],u=o==="NHWC"?e.shape[3]:e.shape[1],c=i*n,l=s*n,h=u/(n*n),f=new yf(o==="NHWC"?[a,c,l,h]:[a,h,c,l],n,o);return this.compileAndRun(f,[e])},t.prototype.split=function(e,n,o){return cu(e,n,o)},t.prototype.scatterND=function(e,n,o){var a=qr(0,e,o),i=a.sliceRank,s=a.numUpdates,u=a.sliceSize,c=a.strides,l=a.outputSize,h=[l/u,u],f=e.reshape([s,i]),p=n.reshape([s,u]);if(l===0)return fa(je([]),o);var d=j(0),v=new $i(s,i,f.rank,p.rank,c,h);return this.compileAndRun(v,[p,f,d]).reshape(o)},t.prototype.sparseToDense=function(e,n,o,a){var i=qr(0,e,o),s=i.sliceRank,u=i.numUpdates,c=i.strides,l=i.outputSize,h=new $i(u,s,e.rank,n.rank,c,[l,1]);return this.compileAndRun(h,[n,e,a]).reshape(o)},t.prototype.fft=function(e){return this.fftImpl(e,!1)},t.prototype.ifft=function(e){return this.fftImpl(e,!0)},t.prototype.fftImpl=function(e,n){var o=this.texData.get(e.dataId),a=new Ki(Ef,e.shape,n),i=new Ki(If,e.shape,n),s=[this.makeComplexComponentTensorInfo(e,o.complexTensors.real),this.makeComplexComponentTensorInfo(e,o.complexTensors.imag)],u=this.compileAndRun(a,s),c=this.compileAndRun(i,s),l=this.complex(u,c).as2D(e.shape[0],e.shape[1]);return u.dispose(),c.dispose(),l},t.prototype.gatherND=function(e,n){var o=n.shape,a=o[o.length-1],i=Zs(e,n),s=i[0],u=i[1],c=i[2],l=i[3],h=n.reshape([u,a]),f=e.reshape([e.size/c,c]),p=new Sf(a,l,[u,c]);return this.compileAndRun(p,[f,h]).reshape(s)},t.prototype.fill=function(e,n,o){if((o=o||lr(n))==="string"){var a=Or(o,Y(e));return a.fill(n),N.makeTensor(a,e,o,this)}var i=new Rf(e,n),s=i.getCustomSetupFunc(n);return this.compileAndRun(i,[],o,s)},t.prototype.onesLike=function(e){if(e.dtype==="string")throw new Error("onesLike is not supported under string dtype");return this.fill(e.shape,1,e.dtype)},t.prototype.zerosLike=function(e){return this.fill(e.shape,e.dtype==="string"?"":0,e.dtype)},t.prototype.linspace=function(e,n,o){return su(e,n,o)},t.prototype.makeTensorInfo=function(e,n){var o=this.write(null,e,n);return this.texData.get(o).usage=null,{dataId:o,shape:e,dtype:n}},t.prototype.makeOutput=function(e,n){var o=this.makeTensorInfo(e,n).dataId;return N.makeTensorFromDataId(o,e,n,this)},t.prototype.unpackTensor=function(e){var n=new Np(e.shape);return this.runWebGLProgram(n,[e],e.dtype)},t.prototype.packTensor=function(e){var n=new ep(e.shape);return this.runWebGLProgram(n,[e],e.dtype,null,!0)},t.prototype.packedReshape=function(e,n){var o=[Lr(e.shape)].concat(Wr(e.shape)),a={dtype:e.dtype,shape:o,dataId:e.dataId},i=[Lr(n)].concat(Wr(n)),s=new op(i,o),u=this.runWebGLProgram(s,[a],e.dtype,null,!0);return{dataId:u.dataId,shape:n,dtype:u.dtype}},t.prototype.decode=function(e){var n,o=this.texData.get(e),a=o.isPacked,i=o.shape,s=o.dtype,u=Mo(i);return n=a?new gf(u):new mf(u),{dtype:s,shape:i,dataId:this.runWebGLProgram(n,[{shape:u,dtype:s,dataId:e}],s,null,!0).dataId}},t.prototype.runWebGLProgram=function(e,n,o,a,i){var s=this;i===void 0&&(i=!1);var u=this.makeTensorInfo(e.outputShape,o),c=this.texData.get(u.dataId);if(e.packedOutput&&(c.isPacked=!0),e.outPackingScheme===ar.DENSE){var l=er(e.outputShape);c.texShape=l.map((function(b){return 2*b}))}if(e.outTexUsage!=null&&(c.usage=e.outTexUsage),Y(u.shape)===0)return c.values=rr(u.dtype,0),u;var h=[],f=n.map((function(b){if(b.dtype==="complex64")throw new Error("GPGPUProgram does not support complex64 input. For complex64 dtypes, please separate the program into real and imaginary parts.");var y=s.texData.get(b.dataId);if(y.texture==null){if(!e.packedInputs&&Y(b.shape)<=L().getNumber("WEBGL_SIZE_UPLOAD_UNIFORM"))return{shape:b.shape,texData:null,isUniform:!0,uniformValues:y.values};e.packedInputs&&(y.isPacked=!0,y.shape=b.shape)}else if(!!y.isPacked!=!!e.packedInputs)b=y.isPacked?s.unpackTensor(b):s.packTensor(b),h.push(b),y=s.texData.get(b.dataId);else if(y.isPacked&&!_r(y.shape,b.shape)){var w=b,C=b.shape;b.shape=y.shape,b=s.packedReshape(b,C),h.push(b),y=s.texData.get(b.dataId),w.shape=C}return s.uploadToGPU(b.dataId),{shape:b.shape,texData:y,isUniform:!1}}));this.uploadToGPU(u.dataId);var p,d={shape:u.shape,texData:c,isUniform:!1},v=(function(b,y,w){var C="";y.concat(w).forEach((function(R){var E=R.texData!=null&&R.texData.slice!=null&&R.texData.slice.flatOffset>0,T=R.isUniform?"uniform":R.texData.texShape;C+=R.shape+"_"+T+"_"+E}));var S=b.userCode,k=b.constructor.name;return k+="_"+C+"_"+S})(e,f,d),m=this.getAndSaveBinary(v,(function(){return(function(b,y,w,C){var S=y.userCode,k=w.map((function(U,G){var H={logicalShape:U.shape,texShape:U.isUniform?null:U.texData.texShape,isUniform:U.isUniform,isPacked:!U.isUniform&&U.texData.isPacked,flatOffset:null};return U.texData!=null&&U.texData.slice!=null&&U.texData.slice.flatOffset>0&&(H.flatOffset=U.texData.slice.flatOffset),{name:y.variableNames[G],shapeInfo:H}})),R=k.map((function(U){return U.shapeInfo})),E={logicalShape:C.shape,texShape:C.texData.texShape,isUniform:!1,isPacked:C.texData.isPacked,flatOffset:null},T=Gh(k,E,S,y.packedInputs),A=b.createProgram(T),P=null,O=b.getUniformLocation(A,"NAN",!1);L().getNumber("WEBGL_VERSION")===1&&(P=b.getUniformLocation(A,"INFINITY",!1));for(var B={},V=0;V<y.variableNames.length;V++){var W=y.variableNames[V];B[W]=b.getUniformLocation(A,W,!1),B["offset"+W]=b.getUniformLocation(A,"offset"+W,!1)}return{program:y,source:T,webGLProgram:A,uniformLocations:B,inShapeInfos:R,outShapeInfo:E,infLoc:P,nanLoc:O}})(s.gpgpu,e,f,d)})),g=this.activeTimers!=null;if(g&&(p=this.startTimer()),(function(b,y,w,C,S){Xi(y.inShapeInfos,w),Xi([y.outShapeInfo],[C]);var k=C.texData.texture,R=C.texData.texShape;C.texData.isPacked?b.setOutputPackedMatrixTexture(k,R[0],R[1]):b.setOutputMatrixTexture(k,R[0],R[1]),b.setProgram(y.webGLProgram),L().getNumber("WEBGL_VERSION")===1&&y.infLoc!==null&&b.gl.uniform1f(y.infLoc,1/0),y.nanLoc!==null&&b.gl.uniform1f(y.nanLoc,NaN),w.forEach((function(E,T){var A=y.program.variableNames[T],P=y.uniformLocations[A],O=y.uniformLocations["offset"+A];if(P!=null)if(E.isUniform)if(Y(E.shape)<2)b.gl.uniform1f(P,E.uniformValues[0]);else{var B=E.uniformValues;B instanceof Float32Array||(B=new Float32Array(B)),b.gl.uniform1fv(P,B)}else E.texData.slice!=null&&O!=null&&b.gl.uniform1i(O,E.texData.slice.flatOffset),b.setInputMatrixTexture(E.texData.texture,P,T)})),S!=null&&S(b,y.webGLProgram),b.executeProgram()})(this.gpgpu,m,f,d,a),h.forEach((function(b){return s.disposeData(b.dataId)})),g&&(p=this.endTimer(p),this.activeTimers.push({name:e.constructor.name,query:this.getQueryTime(p)})),!L().getBool("WEBGL_LAZILY_UNPACK")&&c.isPacked&&i===!1){var x=this.unpackTensor(u);return this.disposeData(u.dataId),x}return u},t.prototype.compileAndRun=function(e,n,o,a,i){i===void 0&&(i=!1),o=o||n[0].dtype;var s=this.runWebGLProgram(e,n,o,a,i);return N.makeTensorFromDataId(s.dataId,s.shape,s.dtype)},t.prototype.getAndSaveBinary=function(e,n){return e in this.binaryCache||(this.binaryCache[e]=n()),this.binaryCache[e]},t.prototype.getTextureManager=function(){return this.textureManager},t.prototype.dispose=function(){var e=this;this.disposed||(L().getBool("IS_TEST")||Object.keys(this.binaryCache).forEach((function(n){e.gpgpu.deleteProgram(e.binaryCache[n].webGLProgram),delete e.binaryCache[n]})),this.textureManager.dispose(),this.canvas!=null&&typeof HTMLCanvasElement<"u"&&this.canvas instanceof HTMLCanvasElement?this.canvas.remove():this.canvas=null,this.gpgpuCreatedLocally&&(this.gpgpu.program=null,this.gpgpu.dispose()),this.disposed=!0)},t.prototype.floatPrecision=function(){var e=this;return this.floatPrecisionValue==null&&(this.floatPrecisionValue=K((function(){if(!L().get("WEBGL_RENDER_FLOAT32_ENABLED")){var n=L().getBool("DEBUG");L().set("DEBUG",!1);var o=e.abs(j(1e-8)).dataSync()[0];if(L().set("DEBUG",n),o>0)return 32}return 16}))),this.floatPrecisionValue},t.prototype.epsilon=function(){return this.floatPrecision()===32?1e-7:1e-4},t.prototype.uploadToGPU=function(e){var n,o=this.texData.get(e),a=o.shape,i=o.dtype,s=o.values,u=o.texture,c=o.usage,l=o.isPacked;if(u==null){var h,f=this.activeTimers!=null;f&&(h=Rt());var p=o.texShape;if(p==null&&(p=Wl(a,l),o.texShape=p),s!=null){var d=Mo(a),v=void 0,m=p[1],g=p[0],x=s instanceof Uint8Array;l?(m=(n=fr(p[0],p[1]))[0],g=n[1],v=new _f(d,[g,m],x)):v=new Cf(d,[g,m],x);var b=this.makeTensorInfo([g,m],i);this.texData.get(b.dataId).usage=x?st.PIXELS:st.UPLOAD,this.gpgpu.uploadDenseMatrixToTexture(this.getTexture(b.dataId),m,g,s);var y=this.runWebGLProgram(v,[b],i,null,!0),w=this.texData.get(y.dataId);o.texture=w.texture,o.texShape=w.texShape,o.isPacked=w.isPacked,o.usage=w.usage,this.disposeData(b.dataId),this.texData.delete(y.dataId),o.values=null,f&&(this.uploadWaitMs+=Rt()-h)}else{var C=this.acquireTexture(p,c,i,l);o.texture=C}}},t.prototype.convertAndCacheOnCPU=function(e,n){var o=this.texData.get(e),a=o.dtype;return this.releaseGPUData(e),n!=null&&(o.values=(function(i,s){if(s==="float32"||s==="complex64")return i;if(s==="int32"||s==="bool"){for(var u=s==="int32"?new Int32Array(i.length):new Uint8Array(i.length),c=0;c<u.length;++c)u[c]=Math.round(i[c]);return u}throw new Error("Unknown dtype "+s)})(n,a)),o.values},t.prototype.acquireTexture=function(e,n,o,a){if(this.numBytesInGPU+=this.computeBytes(e,o),!this.warnedAboutMemory&&this.numBytesInGPU>1024*this.numMBBeforeWarning*1024){var i=(this.numBytesInGPU/1024/1024).toFixed(2);this.warnedAboutMemory=!0,console.warn("High memory usage in GPU: "+i+" MB, most likely due to a memory leak")}return this.textureManager.acquireTexture(e,n,a)},t.prototype.computeBytes=function(e,n){return e[0]*e[1]*Ms(n)},t})(ou);zs()&&N.registerBackend("webgl",(function(){return new Pp}),2);var Mp=D({square_:function(r){var t=_(r,"x","square"),e=[t];return N.runKernelFunc((function(n,o){return o([t]),n.square(t)}),{x:t},null,"Square",{},e,[])}}),sr="SquaredDifference",_u=D({squaredDifference_:function(r,t){var e,n=_(r,"a","squaredDifference"),o=_(t,"b","squaredDifference");e=ke(n,o),n=e[0],o=e[1],le(n.shape,o.shape);var a={a:n,b:o},i=[n,o];return N.runKernelFunc((function(s,u){var c=s.squaredDifference(n,o);return u([n,o]),c}),a,(function(s,u){var c=u[0],l=u[1],h=j(2);return{a:function(){return s.mul(c.sub(l).mul(h))},b:function(){return s.mul(l.sub(c).mul(h))}}}),sr,{},i,[])}}),Op=D({abs_:function(r){var t=_(r,"x","abs");return t.dtype==="complex64"?N.runKernelFunc((function(e){return e.complexAbs(t)}),{$x:t}):N.runKernelFunc((function(e,n){var o=e.abs(t);return n([t]),o}),{x:t},(function(e,n){var o=n[0];return{x:function(){return e.mul(o.toFloat().step(-1))}}}),"Abs")}}),Bp=D({acos_:function(r){var t=_(r,"x","acos");return N.runKernelFunc((function(e,n){var o=e.acos(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.divStrict(j(1).sub(o.toFloat().square()).sqrt()).neg()}}}))}}),Lp=D({acosh_:function(r){var t=_(r,"x","acosh");return N.runKernelFunc((function(e,n){var o=e.acosh(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.divStrict(o.toFloat().square().sub(1).sqrt())}}}))}}),Wp=D({asin_:function(r){var t=_(r,"x","asin");return N.runKernelFunc((function(e,n){var o=e.asin(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.divStrict(j(1).sub(o.toFloat().square()).sqrt())}}}))}}),Up=D({asinh_:function(r){var t=_(r,"x","asinh");return N.runKernelFunc((function(e,n){var o=e.asinh(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.divStrict(j(1).add(o.toFloat().square()).sqrt())}}}))}}),Vp=D({atan_:function(r){var t=_(r,"x","atan");return N.runKernelFunc((function(e,n){var o=e.atan(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.div(o.toFloat().square().add(1))}}}))}}),zp=D({atanh_:function(r){var t=_(r,"x","atanh");return N.runKernelFunc((function(e,n){var o=e.atanh(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.div(j(1).sub(o.toFloat().square()))}}}))}}),Gp=D({ceil_:function(r){var t=_(r,"x","ceil");return N.runKernelFunc((function(e){return e.ceil(t)}),{$x:t},(function(e){return{$x:function(){return me(e)}}}))}}),La=D({clipByValue_:function(r,t,e){var n=_(r,"x","clipByValue");I(t<=e,(function(){return"Error in clip: min ("+t+") must be less than or equal to max ("+e+")."}));var o=[n],a={min:t,max:e};return N.runKernelFunc((function(i,s){var u=i.clip(n,t,e);return s([n]),u}),{x:n},(function(i,s){var u=s[0];return{x:function(){return i.where(u.greaterEqual(t).logicalAnd(u.lessEqual(e)),me(i))}}}),"ClipByValue",a,o)}}),Hp=D({cos_:function(r){var t=_(r,"x","cos"),e=[t];return N.runKernelFunc((function(n,o){var a=n.cos(t);return o([t]),a}),{x:t},(function(n,o){var a=o[0];return{x:function(){return a.toFloat().sin().neg().mul(n)}}}),"Cos",{},e)}}),jp=D({cosh_:function(r){var t=_(r,"x","cosh");return N.runKernelFunc((function(e,n){var o=e.cosh(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return o.toFloat().sinh().mulStrict(e)}}}))}}),qp=D({erf_:function(r){var t=_(r,"x","erf");return I(t.dtype==="int32"||t.dtype==="float32",(function(){return"Input dtype must be `int32` or `float32`."})),t.dtype==="int32"&&(t=t.toFloat()),N.runKernelFunc((function(e,n){var o=e.erf(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.mul(o.square().neg().exp().mul(2/Math.sqrt(Math.PI)))}}}))}}),da=D({exp_:function(r){var t=_(r,"x","exp");return N.runKernelFunc((function(e,n){var o=e.exp(t);return n([o]),o}),{x:t},(function(e,n){return{x:function(){return e.mulStrict(n[0])}}}),"Exp",{},[],[!0])}}),Kp=D({expm1_:function(r){var t=_(r,"x","expm1");return N.runKernelFunc((function(e,n){var o=e.expm1(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.mul(o.exp())}}}))}}),Xp=D({floor_:function(r){var t=_(r,"x","floor");return N.runKernelFunc((function(e){return e.floor(t)}),{$x:t},(function(e){return{$x:function(){return me(e)}}}))}}),$p=D({log_:function(r){var t=_(r,"x","log"),e=[t];return N.runKernelFunc((function(n,o){var a=n.log(t);return o([t]),a}),{x:t},(function(n,o){var a=o[0];return{x:function(){return n.div(a.toFloat())}}}),"Log",{},e)}}),Yp=D({log1p_:function(r){var t=_(r,"x","log1p");return N.runKernelFunc((function(e,n){var o=e.log1p(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.div(o.add(1))}}}))}}),Jp=D({logSigmoid_:function(r){var t=_(r,"x","logSigmoid");return N.runKernelFunc((function(e,n){var o=e.softplus(t.neg()).neg();return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.mul(o.neg().sigmoid())}}}))}}),Yr=D({neg_:function(r){var t=_(r,"x","neg"),e=[t];return N.runKernelFunc((function(n){return n.neg(t)}),{x:t},(function(n){return{x:function(){return n.neg()}}}),"Neg",{},e)}}),Qp=D({reciprocal_:function(r){var t=_(r,"x","reciprocal");return N.runKernelFunc((function(e,n){var o=e.reciprocal(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.div(o.square().neg())}}}))}}),Zp=D({round_:function(r){var t=_(r,"x","round");return N.runKernelFunc((function(e){return e.round(t)}),{$x:t},(function(e){return{$x:function(){return me(e)}}}))}}),Eu=D({rsqrt_:function(r){var t=_(r,"x","rsqrt"),e=[t];return N.runKernelFunc((function(n,o){var a=n.rsqrt(t);return o([t]),a}),{x:t},(function(n,o){var a=o[0];return{x:function(){return n.div(a.pow(1.5).mul(2)).neg()}}}),"Rsqrt",{},e)}}),Iu=D({sigmoid_:function(r){var t=_(r,"x","sigmoid");return N.runKernelFunc((function(e,n){var o=e.sigmoid(t);return n([o]),o}),{x:t},(function(e,n){var o=n[0];return{x:function(){return e.mul(o.mul(j(1).sub(o)))}}}),"Sigmoid")}}),ed=D({sign_:function(r){var t=_(r,"x","sign");return N.runKernelFunc((function(e){return e.sign(t)}),{$x:t},(function(e){return{$x:function(){return me(e)}}}))}}),td=D({isNaN_:function(r){var t=_(r,"x","isNaN");return N.runKernelFunc((function(e){return e.isNaN(t)}),{$x:t},(function(e){return{$x:function(){return me(e)}}}))}}),nd=D({isInf_:function(r){var t=_(r,"x","isInf");return N.runKernelFunc((function(e){return e.isInf(t)}),{$x:t},(function(e){return{$x:function(){return me(e)}}}))}}),rd=D({isFinite_:function(r){var t=_(r,"x","isFinite");return N.runKernelFunc((function(e){return e.isFinite(t)}),{$x:t},(function(e){return{$x:function(){return me(e)}}}))}}),od=D({sin_:function(r){var t=_(r,"x","sin"),e=[t];return N.runKernelFunc((function(n,o){var a=n.sin(t);return o([t]),a}),{x:t},(function(n,o){var a=o[0];return{x:function(){return a.toFloat().cos().mul(n)}}}),"Sin",{},e)}}),ad=D({sinh_:function(r){var t=_(r,"x","sinh");return N.runKernelFunc((function(e,n){var o=e.sinh(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return o.toFloat().cosh().mulStrict(e)}}}))}}),id=D({softplus_:function(r){var t=_(r,"x","softplus");return N.runKernelFunc((function(e,n){var o=e.softplus(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.mul(o.sigmoid())}}}))}}),sd=D({sqrt_:function(r){var t=_(r,"x","sqrt");return N.runKernelFunc((function(e,n){var o=e.sqrt(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.div(o.toFloat().sqrt().mul(2))}}}))}}),ud=D({step_:function(r,t){t===void 0&&(t=0);var e=_(r,"x","step");return N.runKernelFunc((function(n){return n.step(e,t)}),{$x:e},(function(n){return{$x:function(){return me(n)}}}))}}),cd=D({tan_:function(r){var t=_(r,"x","tan");return N.runKernelFunc((function(e,n){var o=e.tan(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return e.div(o.cos().square())}}}))}}),ld=D({tanh_:function(r){var t=_(r,"x","tanh");return N.runKernelFunc((function(e,n){var o=e.tanh(t);return n([o]),o}),{x:t},(function(e,n){var o=n[0];return{x:function(){return j(1).sub(o.square()).mulStrict(e)}}}),"Tanh",{},null,[!0])}});function Ru(r,t,e,n,o,a){var i,s,u=_(r,"x","batchNorm"),c=_(t,"mean","batchNorm"),l=_(e,"variance","batchNorm");return o!=null&&(i=_(o,"scale","batchNorm")),n!=null&&(s=_(n,"offset","batchNorm")),I(u.rank===2,(function(){return"Error in batchNorm3D: x must be rank 3 but got rank "+u.rank+"."})),I(c.rank===2||c.rank===1,(function(){return"Error in batchNorm2D: mean must be rank 2 or rank 1 but got rank "+c.rank+"."})),I(l.rank===2||l.rank===1,(function(){return"Error in batchNorm2D: variance must be rank 2 or rank 1 but got rank "+l.rank+"."})),i!=null&&I(i.rank===2||i.rank===1,(function(){return"Error in batchNorm2D: scale must be rank 2 or rank 1 but got rank "+i.rank+"."})),s!=null&&I(s.rank===2||s.rank===1,(function(){return"Error in batchNorm2D: offset must be rank 2 or rank 1 but got rank "+s.rank+"."})),dr(u,c,l,s,i,a)}function ku(r,t,e,n,o,a){var i,s,u=_(r,"x","batchNorm"),c=_(t,"mean","batchNorm"),l=_(e,"variance","batchNorm");return o!=null&&(i=_(o,"scale","batchNorm")),n!=null&&(s=_(n,"offset","batchNorm")),I(u.rank===3,(function(){return"Error in batchNorm3D: x must be rank 3 but got rank "+u.rank+"."})),I(c.rank===3||c.rank===1,(function(){return"Error in batchNorm3D: mean must be rank 3 or rank 1 but got rank "+c.rank+"."})),I(l.rank===3||l.rank===1,(function(){return"Error in batchNorm3D: variance must be rank 3 or rank 1 but got rank "+l.rank+"."})),i!=null&&I(i.rank===3||i.rank===1,(function(){return"Error in batchNorm3D: scale must be rank 3 or rank 1 but got rank "+i.rank+"."})),s!=null&&I(s.rank===3||s.rank===1,(function(){return"Error in batchNorm3D: offset must be rank 3 or rank 1 but got rank "+s.rank+"."})),dr(u,c,l,s,i,a)}function Su(r,t,e,n,o,a){var i,s,u=_(r,"x","batchNorm"),c=_(t,"mean","batchNorm"),l=_(e,"variance","batchNorm");return o!=null&&(i=_(o,"scale","batchNorm")),n!=null&&(s=_(n,"offset","batchNorm")),I(u.rank===4,(function(){return"Error in batchNorm4D: x must be rank 4 but got rank "+u.rank+"."})),I(c.rank===4||c.rank===1,(function(){return"Error in batchNorm4D: mean must be rank 4 or rank 1 but got rank "+c.rank+"."})),I(l.rank===4||l.rank===1,(function(){return"Error in batchNorm4D: variance must be rank 4 or rank 1 but got rank "+l.rank+"."})),i!=null&&I(i.rank===4||i.rank===1,(function(){return"Error in batchNorm4D: scale must be rank 4 or rank 1 but got rank "+i.rank+"."})),s!=null&&I(s.rank===4||s.rank===1,(function(){return"Error in batchNorm4D: offset must be rank 4 or rank 1 but got rank "+s.rank+"."})),dr(u,c,l,s,i,a)}function dr(r,t,e,n,o,a){a==null&&(a=.001);var i,s,u,c=_(r,"x","batchNorm"),l=_(t,"mean","batchNorm"),h=_(e,"variance","batchNorm");o!=null&&(i=_(o,"scale","batchNorm")),n!=null&&(s=_(n,"offset","batchNorm")),I(l.rank===h.rank,(function(){return"Batch normalization gradient requires mean and variance to have equal ranks."})),I(s==null||l.rank===s.rank,(function(){return"Batch normalization gradient requires mean and offset to have equal ranks."})),I(i==null||l.rank===i.rank,(function(){return"Batch normalization gradient requires mean and scale to have equal ranks."})),u=c.rank===0||c.rank===1?c.as4D(1,1,1,c.size):c.rank===2?c.as4D(1,1,c.shape[0],c.shape[1]):c.rank===3?c.as4D(1,c.shape[0],c.shape[1],c.shape[2]):c;var f=[c,l,h,i];return N.runKernelFunc((function(p,d){var v=p.batchNormalization(u,Sr(l),Sr(h),a,Sr(i),Sr(s));return d([c,l,h,i]),v}),{x:c,mean:l,variance:h,scale:i,offset:s},(function(p,d){var v=d,m=v[0],g=v[1],x=v[2],b=v[3],y=b??j(1),w=Oe(g.shape,u.shape),C=[];if(g.rank===1){for(var S=0;S<u.shape.length-1;++S)C.push(u.shape[S]);C.push(1)}var k=m.sub(g),R=p.mul(y),E=Eu(x.add(j(a))),T=E.mul(E).mul(E).mul(j(-.5));return{x:function(){return g.rank===1?p.mul(Bn(E.as4D(1,1,1,g.shape[0]),C)).mul(y).reshape(m.shape):p.mul(E).mul(y).reshape(m.shape)},mean:function(){var A=E.mul(j(-1)).mul(R);return g.rank===1&&(A=A.sum(w)),A.reshape(g.shape)},variance:function(){var A=T.mul(k).mul(R);return g.rank===1&&(A=A.sum(w)),A.reshape(g.shape)},scale:function(){var A=k.mul(E),P=p.mul(A);return g.rank===1&&(P=P.sum(w)),P.reshape(g.shape)},offset:function(){var A=p;return g.rank===1&&(A=A.sum(w)),A.reshape(g.shape)}}}),"BatchNormalization",{varianceEpsilon:a},f).reshape(c.shape)}function Sr(r){return r==null?null:r.rank===0?r.as1D():r.rank===1?r:r.rank===2?r.as4D(1,1,r.shape[0],r.shape[1]):r.rank===3?r.as4D(1,r.shape[0],r.shape[1],r.shape[2]):r}function so(){Gs("tf.batchNormalization() is going away. Use tf.batchNorm() instead, and note the positional argument change of scale, offset, and varianceEpsilon")}var hd=D({batchNormalization2d_:function(r,t,e,n,o,a){return n===void 0&&(n=.001),so(),Ru(r,t,e,a,o,n)}}),fd=D({batchNormalization3d_:function(r,t,e,n,o,a){return n===void 0&&(n=.001),so(),ku(r,t,e,a,o,n)}}),pd=D({batchNormalization4d_:function(r,t,e,n,o,a){return n===void 0&&(n=.001),so(),Su(r,t,e,a,o,n)}}),dd=D({batchNormalization_:function(r,t,e,n,o,a){return n===void 0&&(n=.001),so(),dr(r,t,e,a,o,n)}}),Du=D({batchNorm_:dr}),vd=D({batchNorm2d_:Ru}),md=D({batchNorm3d_:ku}),gd=D({batchNorm4d_:Su}),uo=D({logicalAnd_:function(r,t){var e=_(r,"a","logicalAnd","bool"),n=_(t,"b","logicalAnd","bool");return le(e.shape,n.shape),N.runKernelFunc((function(o){return o.logicalAnd(e,n)}),{a:e,b:n},null,"LogicalAnd")}}),yd=D({logicalNot_:function(r){var t=_(r,"x","logicalNot","bool");return N.runKernelFunc((function(e){return e.logicalNot(t)}),{$x:t})}}),Au=D({logicalOr_:function(r,t){var e=_(r,"a","logicalOr","bool"),n=_(t,"b","logicalOr","bool");return le(e.shape,n.shape),N.runKernelFunc((function(o){return o.logicalOr(e,n)}),{$a:e,$b:n})}}),xd=D({logicalXor_:function(r,t){var e=_(r,"a","logicalXor","bool"),n=_(t,"b","logicalXor","bool");return le(e.shape,n.shape),Au(r,t).logicalAnd(uo(r,t).logicalNot())}}),yn=D({where_:function(r,t,e){var n=_(t,"a","where"),o=_(e,"b","where"),a=_(r,"condition","where","bool");return xe(n.shape,o.shape,"Error in where: "),a.rank===1?I(a.shape[0]===n.shape[0],(function(){return"The first dimension of `a` must match the size of `condition`."})):xe(a.shape,o.shape,"Error in where: "),N.runKernelFunc((function(i,s){var u=i.select(a,n,o);return s([a]),u}),{$condition:a,$a:n,$b:o},(function(i,s){var u=s[0];return{$condition:function(){return me(u).toFloat()},$a:function(){return i.mul(u.cast(i.dtype))},$b:function(){return i.mul(u.logicalNot().cast(i.dtype))}}}))}}),Tu=function(r){return X(this,void 0,void 0,(function(){var t,e,n;return $(this,(function(o){switch(o.label){case 0:return[4,(t=_(r,"condition","whereAsync","bool")).data()];case 1:return e=o.sent(),n=Pa(t.shape,e),r!==t&&t.dispose(),[2,n]}}))}))},ue=D({add_:function(r,t){var e,n=_(r,"a","add"),o=_(t,"b","add");e=ke(n,o),n=e[0],o=e[1];var a=le(n.shape,o.shape);return N.runKernelFunc((function(i){return i.add(n,o)}),{a:n,b:o},(function(i){return{a:function(){var s=i,u=Oe(n.shape,a);return u.length>0&&(s=s.sum(u)),s.reshape(n.shape)},b:function(){var s=i,u=Oe(o.shape,a);return u.length>0&&(s=s.sum(u)),s.reshape(o.shape)}}}),"Add")}}),bd=D({addN_:function(r){I(Array.isArray(r),(function(){return"The argument passed to tf.addN() must be a list of tensors"})),I(r.length>=1,(function(){return"Must pass at least one tensor to tf.addN(), but got "+r.length}));var t=r.map((function(o,a){return _(o,"tensors"+a,"addN")})),e=t[0];t.forEach((function(o){if(o.dtype!==e.dtype)throw new Error("All tensors passed to tf.addN() must have the same dtype")})),t.forEach((function(o){if(!Ue(o.shape,e.shape))throw new Error("All tensors passed to tf.addN() must have the same shape")}));var n=t;return N.runKernelFunc((function(o){return o.addN(t)}),n,(function(o){var a={};return t.forEach((function(i,s){a[s]=function(){return o.clone()}})),a}),"AddN")}}),wd=D({addStrict_:function(r,t){var e=_(r,"a","addStrict"),n=_(t,"b","addStrict");return xe(e.shape,n.shape,"Error in addStrict: "),e.add(n)}}),Cd=D({atan2_:function(r,t){var e,n=_(r,"a","atan2"),o=_(t,"b","atan2");e=ke(n,o),n=e[0],o=e[1];var a=le(n.shape,o.shape);return N.runKernelFunc((function(i,s){var u=i.atan2(n,o);return s([n,o]),u}),{$a:n,$b:o},(function(i,s){var u=s[0],c=s[1];return{$a:function(){var l=ue(u.square(),c.square()),h=i.mul(c.div(l)),f=Oe(u.shape,a);return f.length>0&&(h=h.sum(f)),h.reshape(u.shape)},$b:function(){var l=ue(u.square(),c.square()),h=Yr(i.mul(u.div(l))),f=Oe(c.shape,a);return f.length>0&&(h=h.sum(f)),h.reshape(c.shape)}}}))}}),vt=D({div_:function(r,t){var e,n=_(r,"a","div"),o=_(t,"b","div");if(e=ke(n,o),n=e[0],o=e[1],n.dtype==="int32"&&o.dtype==="int32")return Nu(n,o);var a=le(n.shape,o.shape);return N.runKernelFunc((function(i,s){var u=i.realDivide(n,o);return s([n,o]),u}),{a:n,b:o},(function(i,s){var u=s[0],c=s[1];return{a:function(){var l=i.div(c.toFloat()),h=Oe(u.shape,a);return h.length>0?l.sum(h).reshape(u.shape):l},b:function(){var l=i.mul(u.toFloat()),h=Oe(c.shape,a);h.length>0&&(l=l.sum(h).reshape(c.shape));var f=c.square();return l.div(f.toFloat()).neg()}}}),"Div")}}),_d=D({divNoNan_:function(r,t){var e,n=_(r,"a","div"),o=_(t,"b","div");n=(e=ke(n,o))[0],o=e[1];var a=vt(n,o),i=me(a),s=o.equal(i);return yn(s,i,a)}}),Ed=D({divStrict_:function(r,t){var e=_(r,"a","div"),n=_(t,"b","div");return xe(e.shape,n.shape,"Error in divideStrict: "),e.div(n)}}),Nu=D({floorDiv_:function(r,t){var e,n=_(r,"a","floorDiv"),o=_(t,"b","floorDiv");e=ke(n,o),n=e[0],o=e[1];var a=le(n.shape,o.shape);return N.runKernelFunc((function(i,s){var u=i.floorDiv(n,o);return s([n,o]),u}),{a:n,b:o},(function(i,s){var u=s[0],c=s[1];return{a:function(){var l=i.div(c.toFloat()),h=Oe(u.shape,a);return h.length>0?l.sum(h).reshape(u.shape):l},b:function(){var l=i.mul(u.toFloat()),h=Oe(c.shape,a);h.length>0&&(l=l.sum(h).reshape(c.shape));var f=c.square();return l.div(f.toFloat()).neg()}}}),"FloorDiv")}}),Wa=D({maximum_:function(r,t){var e,n=_(r,"a","maximum"),o=_(t,"b","maximum");return e=ke(n,o),n=e[0],o=e[1],n.dtype==="bool"&&(n=n.toInt(),o=o.toInt()),le(n.shape,o.shape),N.runKernelFunc((function(a,i){var s=a.maximum(n,o);return i([n,o]),s}),{a:n,b:o},(function(a,i){var s=i[0],u=i[1];return{a:function(){return a.mul(s.greaterEqual(u).toFloat())},b:function(){return a.mul(s.less(u).toFloat())}}}),"Maximum")}}),Id=D({maximumStrict_:function(r,t){var e=_(r,"a","maximumStrict"),n=_(t,"b","maximumStrict");return xe(e.shape,n.shape,"Error in maximumStrict: "),e.maximum(n)}}),Fu=D({minimum_:function(r,t){var e,n=_(r,"a","minimum"),o=_(t,"b","minimum");return e=ke(n,o),n=e[0],o=e[1],n.dtype==="bool"&&(n=n.toInt(),o=o.toInt()),le(n.shape,o.shape),N.runKernelFunc((function(a,i){var s=a.minimum(n,o);return i([n,o]),s}),{a:n,b:o},(function(a,i){var s=i[0],u=i[1];return{a:function(){return a.mul(s.lessEqual(u).toFloat())},b:function(){return a.mul(s.greater(u).toFloat())}}}),"Minimum")}}),Rd=D({minimumStrict_:function(r,t){var e=_(r,"a","minimumStrict"),n=_(t,"b","minimumStrict");return xe(e.shape,n.shape,"Error in minimumStrict: "),e.minimum(n)}}),kd=D({mod_:function(r,t){var e,n=_(r,"a","mod"),o=_(t,"b","mod");e=ke(n,o),n=e[0],o=e[1];var a=le(n.shape,o.shape);return N.runKernelFunc((function(i,s){var u=i.mod(n,o);return s([n,o]),u}),{$a:n,$b:o},(function(i,s){var u=s[0],c=s[1];return{$a:function(){var l=Oe(u.shape,a);return l.length>0?i.sum(l).reshape(u.shape):i},$b:function(){var l=i.mul(u.div(c).floor().neg()),h=Oe(c.shape,a);return h.length>0?l.sum(h).reshape(c.shape):l}}}))}}),Sd=D({modStrict_:function(r,t){var e=_(r,"a","modStrict"),n=_(t,"b","modStrict");return xe(e.shape,n.shape,"Error in modStrict: "),e.mod(n)}}),Ye=D({mul_:function(r,t){var e,n=_(r,"a","mul"),o=_(t,"b","mul");e=ke(n,o),n=e[0],o=e[1];var a=le(n.shape,o.shape);return N.runKernelFunc((function(i,s){var u=i.multiply(n,o);return s([n,o]),u}),{a:n,b:o},(function(i,s){var u=s[0],c=s[1];return{a:function(){var l=i.mul(c.toFloat()),h=Oe(u.shape,a);return h.length>0?l.sum(h).reshape(u.shape):l},b:function(){var l=i.mul(u.toFloat()),h=Oe(c.shape,a);return h.length>0?l.sum(h).reshape(c.shape):l}}}),"Mul")}}),Dd=D({mulStrict_:function(r,t){var e=_(r,"a","mul"),n=_(t,"b","mul");return xe(e.shape,n.shape,"Error in multiplyStrict: "),e.mul(n)}}),Jr=D({pow_:function(r,t){var e,n=_(r,"base","pow"),o=_(t,"exp","pow");e=ke(n,o),n=e[0],o=e[1];var a=le(n.shape,o.shape),i=[n,o];return N.runKernelFunc((function(s,u){var c=s.pow(n,o);return u([n,o,c]),c}),{a:n,b:o},(function(s,u){var c=u[0],l=u[1],h=u[2];return{a:function(){var f=l.toFloat(),p=s.mul(f.mul(c.pow(f.sub(j(1))))),d=Oe(c.shape,a);return d.length>0&&(p=p.sum(d)),p.reshape(c.shape)},b:function(){var f=c.greater(0),p=c.log().where(f,me(c)),d=s.mul(h.mul(p)),v=Oe(l.shape,a);return v.length>0&&(d=d.sum(v)),d.reshape(l.shape)}}}),"Pow",{},i,[!0])}}),Ad=D({powStrict_:function(r,t){return xe(r.shape,t.shape,"Error in powStrict: "),r.pow(t)}}),Td=D({squaredDifferenceStrict_:function(r,t){var e=_(r,"a","squaredDifferenceStrict"),n=_(t,"b","squaredDifferenceStrict");return xe(e.shape,n.shape,"Error in squaredDifferenceStrict: "),e.squaredDifference(n)}}),Be=D({sub_:function(r,t){var e,n=_(r,"a","sub"),o=_(t,"b","sub");e=ke(n,o),n=e[0],o=e[1];var a=le(n.shape,o.shape);return N.runKernelFunc((function(i){return i.subtract(n,o)}),{a:n,b:o},(function(i){return{a:function(){var s=i,u=Oe(n.shape,a);return u.length>0&&(s=s.sum(u)),s.reshape(n.shape)},b:function(){var s=i,u=Oe(o.shape,a);return u.length>0&&(s=s.sum(u)),s.neg().reshape(o.shape)}}}),"Sub")}}),Nd=D({subStrict_:function(r,t){var e=_(r,"a","subStrict"),n=_(t,"b","subStrict");return xe(e.shape,n.shape,"Error in subStrict: "),e.sub(n)}}),Pu=D({equal_:function(r,t){var e,n=_(r,"a","equal"),o=_(t,"b","equal");return e=ke(n,o),n=e[0],o=e[1],le(n.shape,o.shape),N.runKernelFunc((function(a){return a.equal(n,o)}),{$a:n,$b:o})}}),Fd=D({equalStrict_:function(r,t){var e=_(r,"a","equalStrict"),n=_(t,"b","equalStrict");return xe(e.shape,n.shape,"Error in equalStrict: "),e.equal(n)}}),Pd=D({greater_:function(r,t){var e,n=_(r,"a","greater"),o=_(t,"b","greater");return e=ke(n,o),n=e[0],o=e[1],le(n.shape,o.shape),N.runKernelFunc((function(a){return a.greater(n,o)}),{a:n,b:o},null,"Greater")}}),Mu=D({greaterEqual_:function(r,t){var e,n=_(r,"a","greaterEqual"),o=_(t,"b","greaterEqual");return e=ke(n,o),n=e[0],o=e[1],le(n.shape,o.shape),N.runKernelFunc((function(a,i){var s=a.greaterEqual(n,o);return i([n,o]),s}),{a:n,b:o},(function(a,i){var s=i[0],u=i[1];return{a:function(){return me(s)},b:function(){return me(u)}}}),"GreaterEqual")}}),Md=D({greaterEqualStrict_:function(r,t){var e=_(r,"a","greaterEqualStrict"),n=_(t,"b","greaterEqualStrict");return xe(e.shape,n.shape,"Error in greaterEqualStrict: "),e.greaterEqual(n)}}),Od=D({greaterStrict_:function(r,t){var e=_(r,"a","greaterStrict"),n=_(t,"b","greaterStrict");return xe(e.shape,n.shape,"Error in greaterStrict: "),e.greater(n)}}),Bd=D({less_:function(r,t){var e,n=_(r,"a","less"),o=_(t,"b","less");return e=ke(n,o),n=e[0],o=e[1],le(n.shape,o.shape),N.runKernelFunc((function(a){return a.less(n,o)}),{a:n,b:o},null,"Less")}}),Ld=D({lessEqual_:function(r,t){var e,n=_(r,"a","lessEqual"),o=_(t,"b","lessEqual");return e=ke(n,o),n=e[0],o=e[1],le(n.shape,o.shape),N.runKernelFunc((function(a,i){var s=a.lessEqual(n,o);return i([n,o]),s}),{a:n,b:o},null,"LessEqual")}}),Wd=D({lessEqualStrict_:function(r,t){var e=_(r,"a","lessEqualStrict"),n=_(t,"b","lessEqualStrict");return xe(e.shape,n.shape,"Error in lessEqualStrict: "),e.lessEqual(n)}}),Ud=D({lessStrict_:function(r,t){var e=_(r,"a","lessStrict"),n=_(t,"b","lessStrict");return xe(e.shape,n.shape,"Error in lessStrict: "),e.less(n)}}),Vd=D({notEqual_:function(r,t){var e,n=_(r,"a","notEqual"),o=_(t,"b","notEqual");return e=ke(n,o),n=e[0],o=e[1],le(n.shape,o.shape),N.runKernelFunc((function(a){return a.notEqual(n,o)}),{a:n,b:o},null,"NotEqual")}}),zd=D({notEqualStrict_:function(r,t){var e=_(r,"a","notEqualStrict"),n=_(t,"b","notEqualStrict");return xe(e.shape,n.shape,"Error in notEqualStrict: "),e.notEqual(n)}});function os(r,t){for(var e=[],n=r;n<t;++n)e.push(n);return e}function as(r){for(var t=[],e=0;e<r.length;++e)for(var n=0;n<r[e].length;++n)t.push(r[e][n]);return t}var Ua=D({gather_:function(r,t,e){e===void 0&&(e=0);var n=_(r,"x","gather"),o=_(t,"indices","gather","int32");e=Le(e,n.shape)[0];var a=(function(i,s,u){for(var c=i.shape[u],l=[],h=1,f=1,p=0;p<u;p++)l.push(i.shape[p]),h*=i.shape[p];for(p=0;p<s.rank;p++)l.push(s.shape[p]);for(p=u+1;p<i.rank;p++)l.push(i.shape[p]),f*=i.shape[p];return{batchSize:h,sliceSize:f,dimSize:c,outputShape:l}})(n,o,e);return N.runKernelFunc((function(i,s){var u=i.gather(n,o.flatten(),e);return s([o]),u}),{x:n,indices:o},(function(i,s){var u=s[0];return{x:function(){var c=n.shape,l=u.size,h=c.slice(0,e),f=h.length,p=c.slice(e,c.length).slice(1),d=p.length,v=os(0,f),m=os(f+1,f+1+d),g=as([h,[l],p]),x=i.reshape(g),b=u.reshape([l]),y=as([[f],v,m]),w=x.transpose(y),C=Ou(w,b,n.shape[e]),S=Ra(y);return C=C.transpose(S)},indices:function(){return u}}}),"Gather",{axis:e}).reshape(a.outputShape)}}),Ou=D({unsortedSegmentSum_:function(r,t,e){var n=_(r,"x","unsortedSegmentSum"),o=_(t,"segmentIds","unsortedSegmentSum","int32");return I(Te(e),(function(){return"numSegments must be of dtype int"})),N.runKernelFunc((function(a,i){var s=a.unsortedSegmentSum(n,o,e);return i([o]),s}),{$x:n},(function(a,i){var s=i[0];return{$x:function(){return(function(u,c){for(var l=Wa(c,me(c)),h=Ua(u,l),f=Mu(c,j(0,"int32")),p=h.rank-f.rank,d=0;d<p;++d)f=ht(f,d+1);f=uo(f,$n(h.shape,"bool"));var v=me(h);return yn(f,h,v)})(a,s)}}}))}}),Gd=function(r,t,e){return X(this,void 0,void 0,(function(){var n,o,a,i,s,u,c,l,h,f,p,d,v;return $(this,(function(m){switch(m.label){case 0:for(n=_(r,"tensor","boolMask"),o=_(t,"mask","boolMask","bool"),a=e??0,i=o.rank,s=n.shape,I(i>0,(function(){return"mask cannot be scalar"})),xe(s.slice(a,a+i),o.shape,"mask's shape must match the first K dimensions of tensor's shape,"),u=1,c=a;c<a+i;c++)u*=s[c];return l=s.slice(0,a).concat([u],s.slice(a+i)),h=n.reshape(l),f=o.reshape([-1]),[4,Tu(f)];case 1:return p=m.sent(),d=p.squeeze([1]),v=Ua(h,d,a),r!==n&&n.dispose(),t!==o&&o.dispose(),d.dispose(),h.dispose(),f.dispose(),p.dispose(),[2,v]}}))}))};function Bu(r,t,e,n,o,a,i){a===void 0&&(a="NHWC"),I(r.length===t.rank,(function(){return"Length of inShape ("+r.length+") and rank of dy ("+t.rank+") must match"}));var s=r,u=t,c=!1;t.rank===3&&(c=!0,u=t.as4D(1,t.shape[0],t.shape[1],t.shape[2]),s=[1,r[0],r[1],r[2]]),I(s.length===4,(function(){return"Error in conv2dDerInput: inShape must be length 4, but got length "+s.length+"."})),I(u.rank===4,(function(){return"Error in conv2dDerInput: dy must be rank 4, but got rank "+u.rank})),I(e.rank===4,(function(){return"Error in conv2dDerInput: filter must be rank 4, but got rank "+e.rank}));var l=a==="NHWC"?s[3]:s[1],h=a==="NHWC"?u.shape[3]:u.shape[1];I(l===e.shape[2],(function(){return"Error in conv2dDerInput: depth of input ("+l+") must match input depth for filter "+e.shape[2]+"."})),I(h===e.shape[3],(function(){return"Error in conv2dDerInput: depth of output ("+h+") must match output depth for filter "+e.shape[3]+"."})),i!=null&&I(Te(o),(function(){return"Error in conv2dDerInput: pad must be an integer when using, dimRoundingMode "+i+" but got pad "+o+"."}));var f=Ta(a),p=Cn(s,e.shape,n,1,o,i,!1,f),d=N.runKernelFunc((function(v,m){var g=v.conv2dDerInput(u,e,p);return m([e,u]),g}),{dy4D:u,filter:e},(function(v,m){var g=m[0],x=m[1];return{dy4D:function(){return dt(v,g,n,o,a,1,i)},filter:function(){return Va(v,x,g.shape,n,o,a,i)}}}));return c?d.as3D(d.shape[1],d.shape[2],d.shape[3]):d}function Go(r){var t=(function(a){return typeof a=="number"?[a,a,a]:a.length===2?[a[0],a[1],1]:a})(r),e=t[0],n=t[1],o=t[2];return e===1&&n===1&&o===1}function Lu(r,t,e,n,o){I(r.length===t.rank,(function(){return"Length of inShape ("+r.length+") and rank of dy ("+t.rank+") must match"}));var a=r,i=t,s=!1;t.rank===4&&(s=!0,i=t.as5D(1,t.shape[0],t.shape[1],t.shape[2],t.shape[3]),a=[1,r[0],r[1],r[2],r[3]]);var u=a[4],c=i.shape[4];I(a.length===5,(function(){return"Error in conv3dDerInput: inShape must be length 5, but got length "+a.length+"."})),I(i.rank===5,(function(){return"Error in conv3dDerInput: dy must be rank 5, but got rank "+i.rank})),I(e.rank===5,(function(){return"Error in conv3dDerInput: filter must be rank 5, but got rank "+e.rank})),I(u===e.shape[3],(function(){return"Error in conv3dDerInput: depth of input ("+u+") must match input depth for filter "+e.shape[3]+"."})),I(c===e.shape[4],(function(){return"Error in conv3dDerInput: depth of output ("+c+") must match output depth for filter "+e.shape[4]+"."}));var l=Xr(a,e.shape,n,1,o),h=N.runKernelFunc((function(f){return f.conv3dDerInput(i,e,l)}),{dy5D:i});return s?h.as4D(h.shape[1],h.shape[2],h.shape[3],h.shape[4]):h}var Hd=D({conv1d_:function(r,t,e,n,o,a,i){o===void 0&&(o="NWC"),a===void 0&&(a=1);var s=_(r,"x","conv1d"),u=_(t,"filter","conv1d"),c=s,l=!1;s.rank===2&&(l=!0,c=s.as3D(1,s.shape[0],s.shape[1])),I(c.rank===3,(function(){return"Error in conv1d: input must be rank 3, but got rank "+c.rank+"."})),I(u.rank===3,(function(){return"Error in conv1d: filter must be rank 3, but got rank "+u.rank+"."})),i!=null&&I(Te(n),(function(){return"Error in conv1d: pad must be an integer when using, dimRoundingMode "+i+" but got pad "+n+"."})),I(c.shape[2]===u.shape[1],(function(){return"Error in conv1d: depth of input ("+c.shape[2]+") must match input depth for filter "+u.shape[1]+"."})),I(rt(e,a),(function(){return"Error in conv1D: Either stride or dilation must be 1. Got stride "+e+" and dilation '"+a+"'"})),I(o==="NWC",(function(){return"Error in conv1d: got dataFormat of "+o+" but only NWC is currently supported."}));var h=u.as4D(1,u.shape[0],u.shape[1],u.shape[2]),f=c.as4D(c.shape[0],1,c.shape[1],c.shape[2]),p=dt(f,h,[1,e],n,"NHWC",[1,a],i);return l?p.as2D(p.shape[2],p.shape[3]):p.as3D(p.shape[0],p.shape[2],p.shape[3])}}),dt=D({conv2d_:function(r,t,e,n,o,a,i){o===void 0&&(o="NHWC"),a===void 0&&(a=[1,1]);var s=_(r,"x","conv2d"),u=_(t,"filter","conv2d"),c=s,l=!1;s.rank===3&&(l=!0,c=s.as4D(1,s.shape[0],s.shape[1],s.shape[2])),I(c.rank===4,(function(){return"Error in conv2d: input must be rank 4, but got rank "+c.rank+"."})),I(u.rank===4,(function(){return"Error in conv2d: filter must be rank 4, but got rank "+u.rank+"."})),i!=null&&I(Te(n),(function(){return"Error in conv2d: pad must be an integer when using, dimRoundingMode "+i+" but got pad "+n+"."}));var h=o==="NHWC"?c.shape[3]:c.shape[1];I(h===u.shape[2],(function(){return"Error in conv2d: depth of input ("+h+") must match input depth for filter "+u.shape[2]+"."})),I(rt(e,a),(function(){return"Error in conv2D: Either strides or dilations must be 1. Got strides "+e+" and dilations '"+a+"'"}));var f=Ta(o),p=Cn(c.shape,u.shape,e,a,n,i,!1,f),d=[u,c],v=N.runKernelFunc((function(m,g){var x=m.conv2d(c,u,p);return g([u,c]),x}),{x:c,filter:u},(function(m,g){var x=g,b=x[0],y=x[1];return I(Kn(a),(function(){return"Error in gradient of conv2D: dilation rates greater than 1 are not yet supported in gradients. Got dilations '"+a+"'"})),{x:function(){return Wu(y.shape,m,b,e,n,o)},filter:function(){return Va(y,m,b.shape,e,n,o)}}}),"Conv2D",p,d);return l?v.as3D(v.shape[1],v.shape[2],v.shape[3]):v}}),jd=D({conv3d_:function(r,t,e,n,o,a){o===void 0&&(o="NDHWC"),a===void 0&&(a=[1,1,1]);var i=_(r,"x","conv3d"),s=_(t,"filter","conv3d"),u=i,c=!1;i.rank===4&&(c=!0,u=i.as5D(1,i.shape[0],i.shape[1],i.shape[2],i.shape[3])),I(u.rank===5,(function(){return"Error in conv3d: input must be rank 5, but got rank "+u.rank+"."})),I(s.rank===5,(function(){return"Error in conv3d: filter must be rank 5, but got rank "+s.rank+"."})),I(u.shape[4]===s.shape[3],(function(){return"Error in conv3d: depth of input ("+u.shape[4]+") must match input depth for filter "+s.shape[3]+"."})),I((function(f,p){return Go(f)||Go(p)})(e,a),(function(){return"Error in conv3D: Either strides or dilations must be 1. Got strides "+e+" and dilations '"+a+"'"})),I(o==="NDHWC",(function(){return"Error in conv3d: got dataFormat of "+o+" but only NDHWC is currently supported."}));var l=Xr(u.shape,s.shape,e,a,n),h=N.runKernelFunc((function(f,p){var d=f.conv3d(u,s,l);return p([u,s]),d}),{x:u,$filter:s},(function(f,p){I(Go(a),(function(){return"Error in gradient of conv3D: dilation rates greater than 1 are not yet supported in gradients. Got dilations '"+a+"'"}));var d=p[0],v=p[1];return{x:function(){return Lu(d.shape,f,v,e,n)},$filter:function(){return(function(m,g,x,b,y){var w=m;m.rank===4&&(w=m.as5D(1,m.shape[0],m.shape[1],m.shape[2],m.shape[3]));var C=g;C.rank===4&&(C=g.as5D(1,g.shape[0],g.shape[1],g.shape[2],g.shape[3])),I(w.rank===5,(function(){return"Error in conv3dDerFilter: input must be rank 5, but got shape "+w.shape+"."})),I(C.rank===5,(function(){return"Error in conv3dDerFilter: dy must be rank 5, but got shape "+C.shape+"."})),I(x.length===5,(function(){return"Error in conv3dDerFilter: filterShape must be length 5, but got "+x+"."})),I(w.shape[4]===x[3],(function(){return"Error in conv3dDerFilter: depth of input "+w.shape[4]+") must match input depth in filter ("+x[3]+"."})),I(C.shape[4]===x[4],(function(){return"Error in conv3dDerFilter: depth of dy ("+C.shape[4]+") must match output depth for filter ("+x[4]+")."}));var S=Xr(w.shape,x,b,1,y);return N.runKernelFunc((function(k){return k.conv3dDerFilter(w,C,S)}),{x5D:w,dy5D:C})})(d,f,v.shape,e,n)}}}));return c?h.as4D(h.shape[1],h.shape[2],h.shape[3],h.shape[4]):h}}),Va=D({conv2dDerFilter_:function(r,t,e,n,o,a,i){a===void 0&&(a="NHWC");var s=r;r.rank===3&&(s=r.as4D(1,r.shape[0],r.shape[1],r.shape[2]));var u=t;u.rank===3&&(u=t.as4D(1,t.shape[0],t.shape[1],t.shape[2])),I(s.rank===4,(function(){return"Error in conv2dDerFilter: input must be rank 4, but got shape "+s.shape+"."})),I(u.rank===4,(function(){return"Error in conv2dDerFilter: dy must be rank 4, but got shape "+u.shape+"."})),I(e.length===4,(function(){return"Error in conv2dDerFilter: filterShape must be length 4, but got "+e+"."}));var c=a==="NHWC"?s.shape[3]:s.shape[1],l=a==="NHWC"?u.shape[3]:u.shape[1];I(c===e[2],(function(){return"Error in conv2dDerFilter: depth of input "+c+") must match input depth in filter ("+e[2]+"."})),I(l===e[3],(function(){return"Error in conv2dDerFilter: depth of dy ("+l+") must match output depth for filter ("+e[3]+")."})),i!=null&&I(Te(o),(function(){return"Error in conv2dDerFilter: pad must be an integer when using, dimRoundingMode "+i+" but got pad "+o+"."}));var h=Ta(a),f=Cn(s.shape,e,n,1,o,i,!1,h);return N.runKernelFunc((function(p){return p.conv2dDerFilter(s,u,f)}),{x4D:s,dy4D:u})}}),Wu=D({conv2dDerInput_:Bu}),co=D({depthwiseConv2d_:function(r,t,e,n,o,a,i){a===void 0&&(a=[1,1]);var s=_(r,"x","depthwiseConv2d"),u=_(t,"filter","depthwiseConv2d"),c=s,l=!1;s.rank===3&&(l=!0,c=s.as4D(1,s.shape[0],s.shape[1],s.shape[2])),I(c.rank===4,(function(){return"Error in depthwiseConv2d: input must be rank 4, but got rank "+c.rank+"."})),I(u.rank===4,(function(){return"Error in depthwiseConv2d: filter must be rank 4, but got rank "+u.rank+"."})),I(c.shape[3]===u.shape[2],(function(){return"Error in depthwiseConv2d: number of input channels ("+c.shape[3]+") must match the inChannels dimension in filter "+u.shape[2]+"."})),a==null&&(a=[1,1]),I(rt(e,a),(function(){return"Error in depthwiseConv2d: Either strides or dilations must be 1. Got strides "+e+" and dilations '"+a+"'"})),i!=null&&I(Te(n),(function(){return"Error in depthwiseConv2d: pad must be an integer when using, dimRoundingMode "+i+" but got pad "+n+"."}));var h=Cn(c.shape,u.shape,e,a,n,i,!0),f=[c,u],p=N.runKernelFunc((function(d,v){var m=d.depthwiseConv2D(c,u,h);return v([c,u]),m}),{x:c,filter:u},(function(d,v){I(Kn(a),(function(){return"Error in gradient of depthwiseConv2d: dilation rates greater than 1 are not yet supported. Got dilations '"+a+"'"}));var m=v[0],g=v[1];return{x:function(){return Uu(m.shape,d,g,h)},filter:function(){return Vu(m,d,g.shape,h)}}}),"DepthwiseConv2dNative",h,f);return l?p.as3D(p.shape[1],p.shape[2],p.shape[3]):p}}),Uu=D({depthwiseConv2dDerInput_:function(r,t,e,n){var o=t,a=!1;t.rank===3&&(a=!0,o=t.as4D(1,t.shape[0],t.shape[1],t.shape[2]));var i=N.runKernelFunc((function(s){return s.depthwiseConv2DDerInput(o,e,n)}),{dy4D:o});return a?i.as3D(i.shape[1],i.shape[2],i.shape[3]):i}}),Vu=D({depthwiseConv2dDerFilter_:function(r,t,e,n){var o=r;r.rank===3&&(o=r.as4D(1,r.shape[0],r.shape[1],r.shape[2]));var a=t;return a.rank===3&&(a=t.as4D(1,t.shape[0],t.shape[1],t.shape[2])),N.runKernelFunc((function(i){return i.depthwiseConv2DDerFilter(o,a,n)}),{x4D:o,dy4D:a})}}),za=D({separableConv2d_:function(r,t,e,n,o,a,i){a===void 0&&(a=[1,1]),i===void 0&&(i="NHWC");var s=_(r,"x","separableConv2d"),u=_(t,"depthwiseFilter","separableConv2d"),c=_(e,"pointwiseFilter","separableConv2d"),l=s,h=!1;if(s.rank===3&&(h=!0,l=s.as4D(1,s.shape[0],s.shape[1],s.shape[2])),i==="NCHW")throw new Error("separableConv2d currently does not support dataFormat NCHW; only NHWC is supported");I(l.rank===4,(function(){return"Error in separableConv2d: input must be rank 4, but got rank "+l.rank+"."})),I(u.rank===4,(function(){return"Error in separableConv2d: depthwise filter must be rank 4, but got rank "+u.rank+"."})),I(c.rank===4,(function(){return"Error in separableConv2d: pointwise filter must be rank 4, but got rank "+u.rank+"."})),I(c.shape[0]===1,(function(){return"Error in separableConv2d: the first dimension of pointwise filter  must be 1, but got "+c.shape[0]+"."})),I(c.shape[1]===1,(function(){return"Error in separableConv2d: the second dimension of pointwise filter must be 1, but got "+c.shape[1]+"."}));var f=u.shape[2],p=u.shape[3];I(c.shape[2]===f*p,(function(){return"Error in separableConv2d: the third dimension of pointwise filter must be "+f*p+", but got "+c.shape[2]+"."}));var d=co(l,u,n,o,i,a),v=dt(d,c,1,"valid",i);return h?v.as3D(v.shape[1],v.shape[2],v.shape[3]):v}}),qd=D({conv2dTranspose_:function(r,t,e,n,o,a){return Bu(e,_(r,"x","conv2dTranspose"),_(t,"filter","conv2dTranspose"),n,o,"NHWC",a)}}),Kd=D({conv3dTranspose_:function(r,t,e,n,o){return Lu(e,_(r,"x","conv3dTranspose"),_(t,"filter","conv3dTranspose"),n,o)}}),lo=D({matMul_:function(r,t,e,n){var o;e===void 0&&(e=!1),n===void 0&&(n=!1);var a=_(r,"a","matMul"),i=_(t,"b","matMul");o=ke(a,i),a=o[0],i=o[1];var s=e?a.shape[a.rank-2]:a.shape[a.rank-1],u=n?i.shape[i.rank-1]:i.shape[i.rank-2],c=e?a.shape[a.rank-1]:a.shape[a.rank-2],l=n?i.shape[i.rank-2]:i.shape[i.rank-1],h=a.shape.slice(0,-2),f=i.shape.slice(0,-2),p=Y(h),d=Y(f);I(a.rank>=2&&i.rank>=2&&a.rank===i.rank,(function(){return"Error in matMul: inputs must have the same rank of at least 2, got ranks "+a.rank+" and "+i.rank+"."})),I(Ue(h,f),(function(){return"Error in matMul: outer dimensions ("+h+") and ("+f+") of Tensors with shapes "+a.shape+" and "+i.shape+" must match."})),I(s===u,(function(){return"Error in matMul: inner shapes ("+s+") and ("+u+") of Tensors with shapes "+a.shape+" and "+i.shape+" and transposeA="+e+" and transposeB="+n+" must match."}));var v=a.shape.slice(0,-2).concat([c,l]),m=e?a.as3D(p,s,c):a.as3D(p,c,s),g=n?i.as3D(d,l,u):i.as3D(d,u,l),x={transposeA:e,transposeB:n};return N.runKernelFunc((function(b,y){var w=b.batchMatMul(m,g,e,n);return y([m,g]),w}),{a:m,b:g},(function(b,y){var w=y,C=w[0],S=w[1];return e||n?!e&&n?{a:function(){return b.matMul(S,!1,!1)},b:function(){return b.matMul(C,!0,!1)}}:e&&!n?{a:function(){return S.matMul(b,!1,!0)},b:function(){return C.matMul(b,!1,!1)}}:{a:function(){return S.matMul(b,!0,!0)},b:function(){return b.matMul(C,!0,!0)}}:{a:function(){return b.matMul(S,!1,!0)},b:function(){return C.matMul(b,!0,!1)}}}),"BatchMatMul",x).reshape(v)}}),Xd=D({dot_:function(r,t){var e=_(r,"t1","dot"),n=_(t,"t2","dot");I(!(e.rank!==1&&e.rank!==2||n.rank!==1&&n.rank!==2),(function(){return"Error in dot: inputs must all be rank 1 or 2, but got ranks "+e.rank+" and "+n.rank+"."}));var o=e.rank===1?e.size:e.shape[1],a=n.rank===1?n.size:n.shape[0];return I(o===a,(function(){return"Error in dot: inner dimensions of inputs must match, but got "+o+" and "+a+"."})),e.rank===1&&n.rank===1?e.as2D(1,-1).matMul(n.as2D(-1,1)).asScalar():e.rank===1&&n.rank===2?e.as2D(1,-1).matMul(n.as2D(n.shape[0],n.shape[1])).as1D():e.rank===2&&n.rank===1?e.matMul(n.as2D(-1,1)).as1D():e.matMul(n.as2D(n.shape[0],n.shape[1]))}}),$d=D({outerProduct_:function(r,t){var e=_(r,"v1","outerProduct"),n=_(t,"v2","outerProduct");return I(e.rank===1&&n.rank===1,(function(){return"Error in outerProduct: inputs must be rank 1, but got ranks "+e.rank+" and "+n.rank+"."})),e.as2D(-1,1).matMul(n.as2D(1,-1))}}),vr=D({reverse_:function(r,t){var e=_(r,"x","reverse");if(e.rank===0)return e.clone();var n=Le(t,e.shape);return N.runKernelFunc((function(o){return o.reverse(e,n)}),{$x:e},(function(o){return{$x:function(){return o.reverse(n)}}})).reshapeAs(e)}}),Yd=D({reverse1d_:function(r){var t=_(r,"x","reverse");return I(t.rank===1,(function(){return"Error in reverse1D: x must be rank 1 but got rank "+t.rank+"."})),vr(t,0)}}),Jd=D({reverse2d_:function(r,t){var e=_(r,"x","reverse");return I(e.rank===2,(function(){return"Error in reverse2D: x must be rank 2 but got rank "+e.rank+"."})),vr(e,t)}}),Qd=D({reverse3d_:function(r,t){var e=_(r,"x","reverse");return I(e.rank===3,(function(){return"Error in reverse3D: x must be rank 3 but got rank "+e.rank+"."})),vr(e,t)}}),Zd=D({reverse4d_:function(r,t){var e=_(r,"x","reverse");return I(e.rank===4,(function(){return"Error in reverse4D: x must be rank 4 but got rank "+e.rank+"."})),vr(e,t)}});function zu(r,t,e,n,o,a){var i=_(r,"x","maxPool"),s=i,u=!1;i.rank===3&&(u=!0,s=i.as4D(1,i.shape[0],i.shape[1],i.shape[2])),I(s.rank===4,(function(){return"Error in maxPool: input must be rank 4 but got rank "+s.rank+"."})),I(rt(e,n),(function(){return"Error in maxPool: Either strides or dilations must be 1. Got strides "+e+" and dilations '"+n+"'"})),a!=null&&I(Te(o),(function(){return"Error in maxPool: pad must be an integer when using, dimRoundingMode "+a+" but got pad "+o+"."}));var c=ir(s.shape,t,e,n,o,a);if(c.filterWidth===1&&c.filterHeight===1&&Ue(c.inShape,c.outShape))return i.clone();var l=[s],h=N.runKernelFunc((function(f,p){var d=f.maxPool(s,c);return p([s,d]),d}),{x:s},(function(f,p){var d=p[0],v=p[1];return{x:function(){return(function(m,g,x,b,y,w,C,S){var k=_(m,"dy","maxPoolBackprop"),R=_(g,"input","maxPoolBackprop"),E=_(x,"output","maxPoolBackprop");I(R.rank===k.rank,(function(){return"Rank of input ("+R.rank+") does not match rank of dy ("+k.rank+")"})),I(rt(y,w),(function(){return"Error in maxPoolBackProp: Either strides or dilations must be 1. Got strides "+y+" and dilations '"+w+"'"})),I(k.rank===4,(function(){return"Error in maxPoolBackprop: dy must be rank 4 but got rank "+k.rank+"."})),I(R.rank===4,(function(){return"Error in maxPoolBackprop: input must be rank 4 but got rank "+R.rank+"."}));var T=ir(R.shape,b,y,w,C,S);return N.runKernelFunc((function(A){return A.maxPoolBackprop(k,R,E,T)}),{$dy:k,$input:R})})(f,d,v,t,e,n,o)}}}),"MaxPool",c,l);return u?h.as3D(h.shape[1],h.shape[2],h.shape[3]):h}function Gu(r,t,e,n,o,a){var i=_(r,"x","avgPool","float32");I(rt(e,n),(function(){return"Error in avgPool: Either strides or dilations must be 1. Got strides "+e+" and dilations '"+n+"'"}));var s=i,u=!1;i.rank===3&&(u=!0,s=i.as4D(1,i.shape[0],i.shape[1],i.shape[2])),I(s.rank===4,(function(){return"Error in avgPool: x must be rank 4 but got rank "+s.rank+"."})),a!=null&&I(Te(o),(function(){return"Error in avgPool: pad must be an integer when using, dimRoundingMode "+a+" but got pad "+o+"."}));var c=ir(s.shape,t,e,n,o,a);if(c.filterWidth===1&&c.filterHeight===1&&Ue(c.inShape,c.outShape))return i.clone();var l=N.runKernelFunc((function(h){return h.avgPool(s,c)}),{x:s},(function(h){return{x:function(){return(function(f,p,d,v,m,g){var x=_(f,"dy","avgPoolBackprop"),b=_(p,"input","avgPoolBackprop");I(b.rank===x.rank,(function(){return"Rank of input ("+b.rank+") does not match rank of dy ("+x.rank+")"})),I(rt(v,m),(function(){return"Error in avgPoolBackprop: Either strides or dilations must be 1. Got strides "+v+" and dilations '"+m+"'"}));var y=b,w=x,C=!1;b.rank===3&&(C=!0,y=b.as4D(1,b.shape[0],b.shape[1],b.shape[2]),w=x.as4D(1,x.shape[0],x.shape[1],x.shape[2])),I(w.rank===4,(function(){return"Error in avgPoolBackprop: dy must be rank 4 but got rank "+w.rank+"."})),I(y.rank===4,(function(){return"Error in avgPoolBackprop: input must be rank 4 but got rank "+y.rank+"."}));var S=ir(y.shape,d,v,m,g),k=N.runKernelFunc((function(R){return R.avgPoolBackprop(w,y,S)}),{dy4D:w,input4D:y});return C?k.as3D(k.shape[1],k.shape[2],k.shape[3]):k})(h,s,t,e,n,o)}}}),"AvgPool",c);return l=l.cast(i.dtype),u?l.as3D(l.shape[1],l.shape[2],l.shape[3]):l}var We=D({maxPool_:function(r,t,e,n,o){return zu(r,t,e,1,n,o)}}),mr=D({avgPool_:function(r,t,e,n,o){return Gu(r,t,e,1,n,o)}}),ev=D({pool_:function(r,t,e,n,o,a){o==null&&(o=[1,1]),a==null&&(a=1),n===0&&(n="valid");var i=_(r,"x","maxPool"),s=i,u=!1;i.rank===3&&(u=!0,s=i.as4D(1,i.shape[0],i.shape[1],i.shape[2])),I(rt(a,o),(function(){return"Error in pool: Either strides or dilations must be 1. Got strides "+a+" and dilations '"+o+"'"}));var c,l=ir(s.shape,t,a,o,n),h=[l.dilationHeight,l.dilationWidth];c=n==="same"?(function(y,w){var C=y.map((function(R,E){return R+(R-1)*(w[E]-1)})).map((function(R){return R-1})),S=C.map((function(R){return Math.floor(R/2)})),k=C.map((function(R,E){return R-S[E]}));return C.map((function(R,E){return[S[E],k[E]]}))})([l.filterHeight,l.filterWidth],h):[[0,0],[0,0]];var f=h[0]===1&&h[1]===1,p=(function(y,w,C){var S=C.map((function(O){return O[0]})),k=C.map((function(O){return O[1]})),R=y.concat(S,k),E=w.map((function(O,B){return(O-R[B]%O)%O})),T=k.map((function(O,B){return O+E[B]})),A=w.map((function(O,B){return[S[B],T[B]]})),P=w.map((function(O,B){return[0,E[B]]}));return[A,P]})([l.inHeight,l.inWidth],h,c),d=p[0],v=p[1],m=f?n:"valid",g=f?s:$s(s,h,d),x=(e==="avg"?function(){return Gu(g,t,a,1,m)}:function(){return zu(g,t,a,1,m)})(),b=f?x:qs(x,h,v);return u?b.as3D(b.shape[1],b.shape[2],b.shape[3]):b}}),tv=D({maxPool3d_:function(r,t,e,n,o,a,i){a===void 0&&(a="NDHWC");var s=_(r,"x","maxPool3d"),u=s,c=!1;s.rank===4&&(c=!0,u=s.as5D(1,s.shape[0],s.shape[1],s.shape[2],s.shape[3])),i==null&&(i=[1,1,1]),I(u.rank===5,(function(){return"Error in maxPool3d: x must be rank 5 but got rank "+u.rank+"."})),I(a==="NDHWC",(function(){return"Error in maxPool3d: Only NDHWC is currently supported, but got dataFormat of "+a})),I(rt(e,i),(function(){return"Error in maxPool3d: Either strides or dilations must be 1. Got strides "+e+" and dilations '"+i+"'"})),o!=null&&I(Te(n),(function(){return"Error in maxPool3d: pad must be an integer when using, dimRoundingMode "+o+" but got pad "+n+"."}));var l=Kr(u.shape,t,e,i,n,o,a),h=N.runKernelFunc((function(f,p){var d=f.maxPool3d(u,l);return p([u,d]),d}),{x:u},(function(f,p){var d=p[0],v=p[1];return{x:function(){return(function(m,g,x,b,y,w,C,S){var k=_(m,"dy","maxPool3dBackprop"),R=_(g,"input","maxPool3dBackprop"),E=_(x,"output","maxPool3dBackprop"),T=k,A=R,P=E,O=!1;R.rank===4&&(O=!0,T=k.as5D(1,k.shape[0],k.shape[1],k.shape[2],k.shape[3]),A=R.as5D(1,R.shape[0],R.shape[1],R.shape[2],R.shape[3]),P=E.as5D(1,E.shape[0],E.shape[1],E.shape[2],E.shape[3])),I(T.rank===5,(function(){return"Error in maxPool3dBackprop: dy must be rank 5 but got rank "+T.rank+"."})),I(A.rank===5,(function(){return"Error in maxPool3dBackprop: input must be rank 5 but got rank "+A.rank+"."})),I(P.rank===5,(function(){return"Error in maxPool3dBackprop: output must be rank 5 but got rank "+P.rank+"."})),w==null&&(w=[1,1,1]),I(rt(y,w),(function(){return"Error in maxPool3dBackprop: Either strides or dilations must be 1. Got strides "+y+" and dilations '"+w+"'"})),S!=null&&I(Te(C),(function(){return"Error in maxPool3dBackprop: pad must be an integer when using, dimRoundingMode "+S+" but got pad "+C+"."}));var B=Kr(A.shape,b,y,w,C,S),V=N.runKernelFunc((function(W){return W.maxPool3dBackprop(T,A,P,B)}),{dy5D:T,input5D:A});return O?V.as4D(V.shape[1],V.shape[2],V.shape[3],V.shape[4]):V})(f,d,v,t,e,i,n,o)}}}));return c?h.as4D(h.shape[1],h.shape[2],h.shape[3],h.shape[4]):h}}),nv=D({avgPool3d_:function(r,t,e,n,o,a,i){a===void 0&&(a="NDHWC");var s=_(r,"x","avgPool3d","float32"),u=s,c=!1;s.rank===4&&(c=!0,u=s.as5D(1,s.shape[0],s.shape[1],s.shape[2],s.shape[3])),i==null&&(i=[1,1,1]),I(u.rank===5,(function(){return"Error in avgPool3d: x must be rank 5 but got rank "+u.rank+"."})),I(a==="NDHWC",(function(){return"Error in avgPool3d: Only NDHWC is currently supported, but got dataFormat of "+a})),I(rt(e,i),(function(){return"Error in avgPool3d: Either strides or dilations must be 1. Got strides "+e+" and dilations '"+i+"'"})),o!=null&&I(Te(n),(function(){return"Error in avgPool3d: pad must be an integer when using, dimRoundingMode "+o+" but got pad "+n+"."}));var l=Kr(u.shape,t,e,i,n,o,a),h=N.runKernelFunc((function(f){return f.avgPool3d(u,l)}),{x:u},(function(f){return{x:function(){return(function(p,d,v,m,g,x,b){var y=_(p,"dy","avgPool3dBackprop"),w=_(d,"input","avgPool3dBackprop"),C=y,S=w,k=!1;w.rank===4&&(k=!0,C=y.as5D(1,y.shape[0],y.shape[1],y.shape[2],y.shape[3]),S=w.as5D(1,w.shape[0],w.shape[1],w.shape[2],w.shape[3])),I(C.rank===5,(function(){return"Error in avgPool3dBackprop: dy must be rank 5 but got rank "+C.rank+"."})),I(S.rank===5,(function(){return"Error in avgPool3dBackprop: input must be rank 5 but got rank "+S.rank+"."})),g==null&&(g=[1,1,1]),I(rt(m,g),(function(){return"Error in avgPool3dBackprop: Either strides or dilations must be 1. Got strides "+m+" and dilations '"+g+"'"})),b!=null&&I(Te(x),(function(){return"Error in maxPool3dBackprop: pad must be an integer when using, dimRoundingMode "+b+" but got pad "+x+"."}));var R=Kr(S.shape,v,m,g,x,b),E=N.runKernelFunc((function(T){return T.avgPool3dBackprop(C,S,R)}),{dy5D:C,input5D:S});return k?E.as4D(E.shape[1],E.shape[2],E.shape[3],E.shape[4]):E})(f,u,t,e,i,n,o)}}}));return h=h.cast(u.dtype),c?h.as4D(h.shape[1],h.shape[2],h.shape[3],h.shape[4]):h}}),Ft=D({slice_:function(r,t,e){var n,o,a=_(r,"x","slice");if(a.rank===0)throw new Error("Slicing scalar is not possible");(n=typeof t=="number"?[t].concat(new Array(a.rank-1).fill(0)):t.length<a.rank?t.concat(new Array(a.rank-t.length).fill(0)):t.slice()).forEach((function(u){I(u!==-1,(function(){return"slice() does not support negative begin indexing."}))})),o=(o=e==null?new Array(a.rank).fill(-1):typeof e=="number"?[e].concat(new Array(a.rank-1).fill(-1)):e.length<a.rank?e.concat(new Array(a.rank-e.length).fill(-1)):e).map((function(u,c){return u>=0?u:(I(u===-1,(function(){return"Negative size values should be exactly -1 but got "+u+" for the slice() size at index "+c+"."})),a.shape[c]-n[c])})),Dh(a,n,o);var i=a.shape,s={begin:n,size:o};return N.runKernelFunc((function(u){return u.slice(a,n,o)}),{x:a},(function(u){for(var c=[],l=0;l<u.rank;l++)c.push([n[l],i[l]-n[l]-o[l]]);return{x:function(){return u.pad(c)}}}),"Slice",s)}}),rv=D({slice1d_:function(r,t,e){var n=_(r,"x","slice1d");return I(n.rank===1,(function(){return"slice1d expects a rank-1 tensor, but got a rank-"+n.rank+" tensor"})),Ft(n,[t],[e])}}),ov=D({slice2d_:function(r,t,e){var n=_(r,"x","slice2d");return I(n.rank===2,(function(){return"slice2d expects a rank-2 tensor, but got a rank-"+n.rank+" tensor"})),Ft(n,t,e)}}),Hu=D({slice3d_:function(r,t,e){var n=_(r,"x","slice3d");return I(n.rank===3,(function(){return"slice3d expects a rank-3 tensor, but got a rank-"+n.rank+" tensor"})),Ft(n,t,e)}}),av=D({slice4d_:function(r,t,e){var n=_(r,"x","slice4d");return I(n.rank===4,(function(){return"slice4d expects a rank-4 tensor, but got a rank-"+n.rank+" tensor"})),Ft(n,t,e)}});function ju(r,t,e,n,o){return t.rank<e.rank&&(t=t.reshape(nt(t.shape,n))),r.rank<e.rank&&(r=r.reshape(nt(r.shape,n))),{x:function(){var a=r.mul(e.equal(t).cast(r.dtype));return o==null?a:a.transpose(o)}}}var iv=D({all_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=_(r,"x","all","bool"),o=Le(t,n.shape),a=o,i=Mt(a,n.rank);i!=null&&(n=n.transpose(i),a=Ot(a.length,n.rank));var s=N.runKernelFunc((function(c){return c.all(n,a)}),{$x:n});if(e){var u=nt(s.shape,o);return s.reshape(u)}return s}}),sv=D({any_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=_(r,"x","any","bool"),o=Le(t,n.shape),a=o,i=Mt(a,n.rank);i!=null&&(n=n.transpose(i),a=Ot(a.length,n.rank));var s=N.runKernelFunc((function(c){return c.any(n,a)}),{$x:n});if(e){var u=nt(s.shape,o);return s.reshape(u)}return s}}),uv=D({argMax_:function(r,t){t===void 0&&(t=0);var e=_(r,"x","argMax");t==null&&(t=0);var n=Le(t,e.shape),o=Mt(n,e.rank);o!=null&&(e=e.transpose(o),n=Ot(n.length,e.rank));var a={axis:n[0]},i=[e];return N.runKernelFunc((function(s,u){var c=s.argMax(e,n[0]);return u([e]),c}),{x:e},(function(s,u){var c=u[0];return{x:function(){return me(c)}}}),"ArgMax",a,i)}}),cv=D({argMin_:function(r,t){t===void 0&&(t=0);var e=_(r,"x","argMin");t==null&&(t=0);var n=Le(t,e.shape),o=Mt(n,e.rank);return o!=null&&(e=e.transpose(o),n=Ot(n.length,e.rank)),N.runKernelFunc((function(a,i){var s=a.argMin(e,n[0]);return i([e]),s}),{$x:e},(function(a,i){var s=i[0];return{$x:function(){return me(s)}}}))}}),lv=D({logSumExp_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=_(r,"x","logSumExp"),o=Le(t,n.shape),a=n.max(o,!0),i=n.sub(a).exp().sum(o).log(),s=a.reshape(i.shape).add(i);if(e){var u=nt(s.shape,o);return s.reshape(u)}return s}}),ho=D({max_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=_(r,"x","max"),o=n,a=Le(t,n.shape),i=a,s=Mt(i,n.rank);s!=null&&(n=n.transpose(s),i=Ot(i.length,n.rank));var u=[n],c=N.runKernelFunc((function(h,f){var p=h.max(n,i);return f([o,p]),p}),{x:n},(function(h,f){return ju(h,f[1],f[0],a,s)}),"Max",{axes:i},u,[!0]);if(e){var l=nt(c.shape,a);c=c.reshape(l)}return c}}),hv=D({mean_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=_(r,"x","mean"),o=Le(t,n.shape),a=Y(qe(n.shape,o)[1]);return io((function(i){var s=j(a);return{value:(s.dtype===i.dtype?i:i.cast(s.dtype)).div(s).sum(t,e),gradFunc:function(u){var c=i.shape.slice();return o.forEach((function(l){c[l]=1})),u.reshape(c).mul($n(i.shape,"float32")).div(a)}}}))(n)}}),fv=D({min_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=_(r,"x","min"),o=n,a=Le(t,n.shape),i=a,s=Mt(i,n.rank);s!=null&&(n=n.transpose(s),i=Ot(i.length,n.rank));var u=[n],c=N.runKernelFunc((function(h,f){var p=h.min(n,i);return f([o,p]),p}),{x:n},(function(h,f){return ju(h,f[1],f[0],a,s)}),"Min",{axes:i},u,[!0]);if(e){var l=nt(c.shape,a);c=c.reshape(l)}return c}}),pv=D({moments_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=Le(t,(r=_(r,"x","moments")).shape),o=r.mean(n,e),a=o.shape;e||(a=nt(o.shape,n));var i=r.toFloat().sub(o.reshape(a)).square();return{mean:o,variance:i.mean(n,e)}}}),qu=D({sum_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=_(r,"x","sum");n.dtype==="bool"&&(n=n.toInt());var o=Le(t,n.shape);return io((function(a){var i=Mt(o,a.rank),s=o,u=a;i!=null&&(u=a.transpose(i),s=Ot(s.length,a.rank));var c=function(p){var d=a.shape.slice();return o.forEach((function(v){d[v]=1})),p.reshape(d).mul($n(a.shape,"float32"))},l={axes:s},h=N.runKernelFunc((function(p){return p.sum(u,s)}),{x:u},(function(p){return{x:function(){return c(p)}}}),"Sum",l);if(e){var f=nt(h.shape,o);h=h.reshape(f)}return{value:h,gradFunc:c}}))(n)}}),dv=D({prod_:function(r,t,e){t===void 0&&(t=null),e===void 0&&(e=!1);var n=_(r,"x","prod");n.dtype==="bool"&&(n=n.toInt());var o=Le(t,n.shape),a=Mt(o,n.rank),i=o,s=n;a!=null&&(s=n.transpose(a),i=Ot(i.length,n.rank));var u=N.runKernelFunc((function(l){return l.prod(s,i)}),{permutedX:s});if(e){var c=nt(u.shape,o);u=u.reshape(c)}return u}}),Ku=D({elu_:function(r){var t=_(r,"x","elu");return N.runKernelFunc((function(e,n){var o=e.elu(t);return n([o]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){return N.runKernelFunc((function(a){return a.eluDer(e,o)}),{dy:e,y:o})}}}))}}),vv=D({leakyRelu_:function(r,t){t===void 0&&(t=.2);var e=_(r,"x","leakyRelu");return Wa(j(t).mul(e),e)}}),Xu=D({prelu_:function(r,t){var e=_(r,"x","prelu"),n=_(t,"alpha","prelu");return N.runKernelFunc((function(o,a){var i=o.prelu(e,n);return a([e,n]),i}),{x:e,alpha:n},(function(o,a){var i=a[0],s=a[1],u=i.greater(0);return{x:function(){return yn(u,o,o.mul(s))},alpha:function(){var c=yn(u,me(o),o.mul(i)),l=Oe(s.shape,o.shape);return l.length>0&&(c=c.sum(l)),c.reshape(s.shape)}}}),"Prelu")}}),Re=D({relu_:function(r){var t=_(r,"x","relu");return t.dtype==="bool"?t.toInt():N.runKernelFunc((function(e,n){var o=e.relu(t);return n([t]),o}),{x:t},(function(e,n){var o=n[0];return{x:function(){return e.mulStrict(o.step().toFloat())}}}),"Relu")}}),$u=D({relu6_:function(r){var t=_(r,"x","relu6");return t.dtype==="bool"?t.toInt():N.runKernelFunc((function(e,n){var o=e.relu6(t);return n([t]),o}),{x:t},(function(e,n){var o=n[0],a=o.lessEqual(6).mul(o.step());return{x:function(){return e.mulStrict(a.toFloat())}}}),"Relu6")}}),mv=D({selu_:function(r){var t=_(r,"x","selu");return N.runKernelFunc((function(e,n){var o=e.selu(t);return n([t]),o}),{$x:t},(function(e,n){var o=n[0];return{$x:function(){var a=o.greater(j(0)),i=j(Oa),s=j(Ba),u=e.mul(s),c=e.mul(i).mul(o.toFloat().exp());return yn(a,u,c)}}}))}}),an=D({transpose_:function(r,t){var e=_(r,"x","transpose");if(t==null&&(t=e.shape.map((function(o,a){return a})).reverse()),I(e.rank===t.length,(function(){return"Error in transpose: rank of input "+e.rank+" must match length of perm "+t+"."})),t.forEach((function(o){I(o>=0&&o<e.rank,(function(){return"All entries in 'perm' must be between 0 and "+(e.rank-1)+" but got "+t}))})),e.rank<=1)return e.clone();var n={perm:t};return N.runKernelFunc((function(o){return o.transpose(e,t)}),{x:e},(function(o){var a=Ra(t);return{x:function(){return o.transpose(a)}}}),"Transpose",n)}}),gv=D({localResponseNormalization_:function(r,t,e,n,o){t===void 0&&(t=5),e===void 0&&(e=1),n===void 0&&(n=1),o===void 0&&(o=.5);var a=_(r,"x","localResponseNormalization");I(a.rank===4||a.rank===3,(function(){return`Error in localResponseNormalization: x must be rank 3 or 4 but got
               rank `+a.rank+"."})),I(Te(t),(function(){return"Error in localResponseNormalization: depthRadius must be an integer but got depthRadius "+t+"."}));var i=a,s=!1;a.rank===3&&(s=!0,i=a.as4D(1,a.shape[0],a.shape[1],a.shape[2]));var u=N.runKernelFunc((function(c,l){var h=c.localResponseNormalization4D(i,t,e,n,o);return l([i,h]),h}),{x4D:i},(function(c,l){var h=l[0],f=l[1];return{x4D:function(){return N.runKernelFunc((function(p){return p.LRNGrad(c,h,f,t,e,n,o)}),{})}}}));return s?u.as3D(u.shape[1],u.shape[2],u.shape[3]):u}}),Yu=D({norm_:function(r,t,e,n){t===void 0&&(t="euclidean"),e===void 0&&(e=null),n===void 0&&(n=!1);var o=(function s(u,c,l){if(l===void 0&&(l=null),u.rank===0)return u.abs();if(u.rank!==1&&l===null)return s(u.reshape([-1]),c,l);if(u.rank===1||typeof l=="number"||Array.isArray(l)&&l.length===1){if(c===1)return u.abs().sum(l);if(c===1/0)return u.abs().max(l);if(c===-1/0)return u.abs().min(l);if(c==="euclidean"||c===2)return u.abs().pow(j(2,"int32")).sum(l).sqrt();throw new Error("Error in norm: invalid ord value: "+c)}if(Array.isArray(l)&&l.length===2){if(c===1)return u.abs().sum(l[0]).max(l[1]-1);if(c===1/0)return u.abs().sum(l[1]).max(l[0]);if(c===-1/0)return u.abs().sum(l[1]).min(l[0]);if(c==="fro"||c==="euclidean")return u.square().sum(l).sqrt();throw new Error("Error in norm: invalid ord value: "+c)}throw new Error("Error in norm: invalid axis: "+l)})(r=_(r,"x","norm"),t,e),a=o.shape;if(n){var i=Le(e,r.shape);a=nt(o.shape,i)}return o.reshape(a)}}),yv=D({basicLSTMCell_:function(r,t,e,n,o,a){var i=_(r,"forgetBias","basicLSTMCell"),s=_(t,"lstmKernel","basicLSTMCell"),u=_(e,"lstmBias","basicLSTMCell"),c=_(n,"data","basicLSTMCell"),l=_(o,"c","basicLSTMCell"),h=_(a,"h","basicLSTMCell"),f=c.concat(h,1).matMul(s).add(u),p=f.shape[0],d=f.shape[1]/4,v=[p,d],m=f.slice([0,0],v),g=f.slice([0,d],v),x=f.slice([0,2*d],v),b=f.slice([0,3*d],v),y=m.sigmoid().mulStrict(g.tanh()).addStrict(l.mulStrict(i.add(x).sigmoid())),w=y.tanh().mulStrict(b.sigmoid());return[y,w]}}),xv=D({multiRNNCell_:function(r,t,e,n){for(var o=_(t,"data","multiRNNCell"),a=Vr(e,"c","multiRNNCell"),i=Vr(n,"h","multiRNNCell"),s=o,u=[],c=0;c<r.length;c++){var l=r[c](s,a[c],i[c]);u.push(l[0]),u.push(l[1]),s=l[1]}var h=[],f=[];for(c=0;c<u.length;c+=2)h.push(u[c]),f.push(u[c+1]);return[h,f]}}),bv=D({movingAverage_:function(r,t,e,n,o){o===void 0&&(o=!0);var a=_(r,"v","movingAverage"),i=_(t,"x","movingAverage"),s=_(e,"decay","movingAverage");ml(a,i),I(Ue(a.shape,i.shape),(function(){return"Shape mismatch in v and x"}));var u=j(1),c=u.sub(s),l=i.sub(a).mul(c);if(o){I(n!=null,(function(){return"When using zeroDebias: true, step is required."}));var h=_(n,"step","movingAverage");l=l.div(u.sub(Jr(s,h)))}return a.add(l)}}),wv=D({stridedSlice_:function(r,t,e,n,o,a,i,s,u){if(o===void 0&&(o=0),a===void 0&&(a=0),i===void 0&&(i=0),s===void 0&&(s=0),u===void 0&&(u=0),n==null&&(n=new Array(t.length)),i!==0)throw new Error("ellipsis mask is not yet supported");var c=_(r,"x","stridedSlice"),l=Li(s),h=c.shape.slice();l.forEach((function(m){t[m]=0,e[m]=1,h.splice(m,0,1)})),c=c.reshape(h);for(var f=0;f<c.rank;f++)t[f]=Ah(o,t,n,c.shape,f),e[f]=Th(a,e,n,c.shape,f),n[f]=n[f]||1;var p=Li(u);p.forEach((function(m){e[m]=t[m]+1,n[m]=1}));var d=Aa(t,e,n),v=d.filter((function(m,g){return p.indexOf(g)===-1}));return n.every((function(m){return m===1}))?Ft(c,t,d).reshape(v):N.runKernelFunc((function(m){return m.stridedSlice(c,t,e,n)}),{$x:c}).reshape(v)}}),Cv=D({topk_:function(r,t,e){t===void 0&&(t=1),e===void 0&&(e=!0);var n=_(r,"x","topk");if(n.rank===0)throw new Error("topk() expects the input to be of rank 1 or higher");var o=n.shape[n.shape.length-1];if(t>o)throw new Error("'k' passed to topk() must be <= the last dimension ("+o+") but got "+t);var a=N.runKernelFunc((function(i){return i.topk(n,t,e)}),{$x:n});return{values:a[0],indices:a[1]}}}),_v=D({scatterND_:function(r,t,e){var n=_(r,"indices","scatterND","int32"),o=_(t,"updates","scatterND");return Sh(o,n,e),N.runKernelFunc((function(a){return a.scatterND(n,o,e)}),{indices:n,updates:o},null,"ScatterNd",{shape:e})}}),Ga=D({fft_:function(r){I(r.dtype==="complex64",(function(){return"The dtype for tf.spectral.fft() must be complex64 but got "+r.dtype+"."}));var t=r.shape[r.shape.length-1],e=r.size/t,n=r.as2D(e,t);return N.runKernelFunc((function(o){return o.fft(n)}),{input:r}).reshape(r.shape)}}),Qr=D({ifft_:function(r){I(r.dtype==="complex64",(function(){return"The dtype for tf.spectral.ifft() must be complex64 but got "+r.dtype+"."}));var t=r.shape[r.shape.length-1],e=r.size/t,n=r.as2D(e,t);return N.runKernelFunc((function(o){return o.ifft(n)}),{input:r}).reshape(r.shape)}}),Ha=D({rfft_:function(r,t){I(r.dtype==="float32",(function(){return"The dtype for rfft() must be real value but got "+r.dtype}));var e,n=r.shape[r.shape.length-1],o=r.size/n;if(t!=null&&t<n){var a=r.shape.map((function(g){return 0})),i=r.shape.map((function(g){return g}));i[r.shape.length-1]=t,e=r.slice(a,i),n=t}else if(t!=null&&t>n){var s=r.shape.map((function(g){return g}));s[r.shape.length-1]=t-n,e=r.concat(Ce(s),r.shape.length-1),n=t}else e=r;var u=e.zerosLike(),c=Ge(e,u).as2D(o,n),l=Ga(c),h=Math.floor(n/2)+1,f=ft(l),p=St(l),d=f.split([h,n-h],f.shape.length-1),v=p.split([h,n-h],p.shape.length-1),m=e.shape.slice();return m[e.shape.length-1]=h,Ge(d[0],v[0]).reshape(m)}}),Ju=D({irfft_:function(r){var t=r.shape[r.shape.length-1],e=r.size/t;if(t<=2){var n=r.as2D(e,t),o=Qr(n);return ft(o)}var a=[e,2*(t-1)],i=ft(r).as2D(e,t),s=St(r).as2D(e,t),u=i.slice([0,1],[e,t-2]).reverse(1),c=s.slice([0,1],[e,t-2]).reverse(1).mul(j(-1)),l=i.concat(u,1),h=s.concat(c,1);return n=Ge(l,h).as2D(a[0],a[1]),o=Qr(n),ft(o)}}),Ev=Object.freeze({fft:Ga,ifft:Qr,rfft:Ha,irfft:Ju}),Iv=D({sparseToDense_:function(r,t,e,n){n===void 0&&(n=0);var o=_(r,"sparseIndices","sparseToDense","int32"),a=_(t,"sparseValues","sparseToDense"),i=_(n,"defaultValue","sparseToDense",a.dtype);return(function(s,u,c,l){if(s.dtype!=="int32")throw new Error("tf.sparseToDense() expects the indices to be int32 type, but the dtype was "+s.dtype+".");if(s.rank>2)throw new Error("sparseIndices should be a scalar, vector, or matrix, but got shape "+s.shape+".");var h=s.rank>0?s.shape[0]:1,f=s.rank>1?s.shape[1]:1;if(c.length!==f)throw new Error("outputShape has incorrect number of elements:, "+c.length+", should be: "+f+".");var p=u.size;if(u.rank!==0&&(u.rank!==1||p!==h))throw new Error("sparseValues has incorrect shape "+u.shape+", should be [] or ["+h+"]");if(u.dtype!==l.dtype)throw new Error("sparseValues.dtype must match defaultValues.dtype")})(o,a,e,i),N.runKernelFunc((function(s){return s.sparseToDense(o,a,e,i)}),{$sparseIndices:o,$sparseValues:a,$defaultValue:i})}}),Rv=D({gatherND_:function(r,t){var e=_(t,"indices","gatherND","int32"),n=_(r,"x","gatherND");return N.runKernelFunc((function(o){return o.gatherND(n,e)}),{x:n,indices:e},null,"GatherNd")}}),kv=D({diag_:function(r){var t=_(r,"x","diag").flatten(),e=r.shape.concat(r.shape);return N.runKernelFunc((function(n){return n.diag(t)}),{$x:t}).reshape(e)}}),Sv=D({dropout_:function(r,t,e,n){var o=_(r,"x","dropout");if(I(o.dtype==="float32",(function(){return"x has to be a floating point tensor since it's going to be scaled, but got a "+o.dtype+" tensor instead."})),I(t>=0&&t<1,(function(){return"rate must be a float in the range [0, 1), but got "+t+"."})),t===0)return r instanceof Ie?o.clone():o;var a=(function(u,c){if(c==null)return u.shape.slice();if(Ue(u.shape,c))return c;if(u.shape.length===c.length){for(var l=[],h=0;h<u.shape.length;h++)c[h]==null&&u.shape[h]!=null?l.push(u.shape[h]):l.push(c[h]);return l}return c})(o,e),i=1-t,s=Xs(a,0,1,"float32",n).add(i).floor().div(i);return o.mul(s)}});function Qu(r,t,e){for(var n=1-r%2,o=new Float32Array(r),a=0;a<r;++a){var i=2*Math.PI*a/(r+n-1);o[a]=t-e*Math.cos(i)}return Ne(o,"float32")}var ja=D({hannWindow_:function(r){return Qu(r,.5,.5)}}),Zu=D({hammingWindow_:function(r){return Qu(r,.54,.46)}}),qa=D({frame_:function(r,t,e,n,o){n===void 0&&(n=!1),o===void 0&&(o=0);for(var a=0,i=[];a+t<=r.size;)i.push(Ft(r,a,t)),a+=e;if(n)for(;a<r.size;){var s=a+t-r.size,u=Pe([Ft(r,a,t-s),Nt([s],o)]);i.push(u),a+=e}return i.length===0?nn([],[0,t]):Pe(i).as2D(i.length,t)}}),ec=D({stft_:function(r,t,e,n,o){var a;o===void 0&&(o=ja),n==null&&(a=t,n=Math.floor(Math.pow(2,Math.ceil(Math.log(a)/Math.log(2)))));for(var i=qa(r,t,e),s=Ye(i,o(t)),u=[],c=0;c<i.shape[0];c++)u.push(Ha(s.slice([c,0],[1,t]),n));return Pe(u)}}),Dv=Object.freeze({hannWindow:ja,hammingWindow:Zu,frame:qa,stft:ec}),$e,Av=function(r,t,e){return e===void 0&&(e=1),X(this,void 0,void 0,(function(){var n,o,a,i,s,u,c,l,h,f,p,d,v,m;return $(this,(function(g){switch(g.label){case 0:return n=_(r,"predictions","inTopK"),o=_(t,"targets","inTopK"),I(n.rank>1,(function(){return"inTopK() expects the predictions to be of rank 2 or higher, but got "+n.rank})),I(n.rank-1===o.rank,(function(){return"predictions rank should be 1 larger than targets rank, but got predictions rank "+n.rank+" and targets rank "+o.rank})),xe(n.shape.slice(0,n.shape.length-1),o.shape,"predictions's shape should be align with the targets' shape, except the last dimension."),a=n.shape[n.shape.length-1],I(e>0&&e<=a,(function(){return"'k' passed to inTopK() must be > 0 && <= the predictions last dimension ("+a+"), but got "+e})),[4,n.data()];case 1:return i=g.sent(),[4,o.data()];case 2:for(s=g.sent(),u=[i.length/a,a],l=u[1],h=rr("bool",c=u[0]),f=0;f<c;f++){for(p=f*l,d=i.subarray(p,p+l),v=[],m=0;m<d.length;m++)v.push({value:d[m],index:m});for(v.sort((function(x,b){return b.value-x.value})),h[f]=0,m=0;m<e;m++)if(v[m].index===s[f]){h[f]=1;break}}return r!==n&&n.dispose(),t!==o&&o.dispose(),[2,je(h,o.shape,"bool")]}}))}))};(function(r){r[r.NONE=0]="NONE",r[r.MEAN=1]="MEAN",r[r.SUM=2]="SUM",r[r.SUM_BY_NONZERO_WEIGHTS=3]="SUM_BY_NONZERO_WEIGHTS"})($e||($e={}));var Tv=D({absoluteDifference_:function(r,t,e,n){n===void 0&&(n=$e.SUM_BY_NONZERO_WEIGHTS);var o=_(r,"labels","absoluteDifference"),a=_(t,"predictions","absoluteDifference"),i=null;e!=null&&(i=_(e,"weights","absoluteDifference")),xe(o.shape,a.shape,"Error in absoluteDifference: ");var s=o.sub(a).abs();return Kt(s,i,n)}}),Kt=D({computeWeightedLoss_:function(r,t,e){e===void 0&&(e=$e.SUM_BY_NONZERO_WEIGHTS);var n=_(r,"losses","computeWeightedLoss"),o=null;t!=null&&(o=_(t,"weights","computeWeightedLoss"));var a=o==null?n:n.mul(o);if(e===$e.NONE)return a;if(e===$e.SUM)return a.sum();if(e===$e.MEAN){if(o==null)return a.mean();var i=n.size/o.size,s=a.sum().div(o.sum());return i>1?s.div(j(i)):s}if(e===$e.SUM_BY_NONZERO_WEIGHTS){if(o==null)return a.sum().div(j(n.size));var u=o.mul($n(n.shape)).notEqual(j(0)).sum().toFloat();return a.sum().div(u)}throw Error("Unknown reduction: "+e)}}),Nv=D({cosineDistance_:function(r,t,e,n,o){o===void 0&&(o=$e.SUM_BY_NONZERO_WEIGHTS);var a=_(r,"labels","cosineDistance"),i=_(t,"predictions","cosineDistance"),s=null;n!=null&&(s=_(n,"weights","cosineDistance")),xe(a.shape,i.shape,"Error in cosineDistance: ");var u=j(1).sub(a.mul(i).sum(e,!0));return Kt(u,s,o)}}),Fv=D({hingeLoss_:function(r,t,e,n){n===void 0&&(n=$e.SUM_BY_NONZERO_WEIGHTS);var o=_(r,"labels","hingeLoss"),a=_(t,"predictions","hingeLoss"),i=null;e!=null&&(i=_(e,"weights","hingeLoss")),xe(o.shape,a.shape,"Error in hingeLoss: ");var s=j(1);o=j(2).mul(o).sub(s);var u=s.sub(o.mul(a)).relu();return Kt(u,i,n)}}),Pv=D({huberLoss_:function(r,t,e,n,o){n===void 0&&(n=1),o===void 0&&(o=$e.SUM_BY_NONZERO_WEIGHTS);var a=_(r,"labels","huberLoss"),i=_(t,"predictions","huberLoss"),s=null;e!=null&&(s=_(e,"weights","huberLoss")),xe(a.shape,i.shape,"Error in huberLoss: ");var u=j(n),c=i.sub(a).abs(),l=Fu(c,u),h=c.sub(l),f=j(.5).mul(l.square()).add(u.mul(h));return Kt(f,s,o)}}),Mv=D({logLoss_:function(r,t,e,n,o){n===void 0&&(n=1e-7),o===void 0&&(o=$e.SUM_BY_NONZERO_WEIGHTS);var a=_(r,"labels","logLoss"),i=_(t,"predictions","logLoss"),s=null;e!=null&&(s=_(e,"weights","logLoss")),xe(a.shape,i.shape,"Error in logLoss: ");var u=j(1),c=j(n),l=a.mul(i.add(c).log()).neg().sub(u.sub(a).mul(u.sub(i).add(c).log()));return Kt(l,s,o)}}),Ov=D({meanSquaredError_:function(r,t,e,n){n===void 0&&(n=$e.SUM_BY_NONZERO_WEIGHTS);var o=_(r,"labels","meanSquaredError"),a=_(t,"predictions","meanSquaredError"),i=null;e!=null&&(i=_(e,"weights","meanSquaredError")),xe(o.shape,a.shape,"Error in meanSquaredError: ");var s=o.squaredDifference(a);return Kt(s,i,n)}}),Bv=D({sigmoidCrossEntropy_:function(r,t,e,n,o){n===void 0&&(n=0),o===void 0&&(o=$e.SUM_BY_NONZERO_WEIGHTS);var a=_(r,"multiClassLabels","sigmoidCrossEntropy"),i=_(t,"logits","sigmoidCrossEntropy"),s=null;if(e!=null&&(s=_(e,"weights","sigmoidCrossEntropy")),xe(a.shape,i.shape,"Error in sigmoidCrossEntropy: "),n>0){var u=j(n),c=j(1),l=j(.5);a=a.mul(c.sub(u)).add(l.mul(u))}var h=(function(f,p){var d=_(f,"labels","sigmoidCrossEntropyWithLogits"),v=_(p,"logits","sigmoidCrossEntropyWithLogits");xe(d.shape,v.shape,"Error in sigmoidCrossEntropyWithLogits: ");var m=v.relu(),g=v.mul(d),x=v.abs().neg().exp().log1p();return m.sub(g).add(x)})(a,i);return Kt(h,s,o)}}),Lv=D({softmaxCrossEntropy_:function(r,t,e,n,o){n===void 0&&(n=0),o===void 0&&(o=$e.SUM_BY_NONZERO_WEIGHTS);var a=_(r,"onehotLabels","softmaxCrossEntropy"),i=_(t,"logits","softmaxCrossEntropy"),s=null;if(e!=null&&(s=_(e,"weights","softmaxCrossEntropy")),xe(a.shape,i.shape,"Error in softmaxCrossEntropy: "),n>0){var u=j(n),c=j(1),l=j(a.shape[1]);a=a.mul(c.sub(u)).add(u.div(l))}var h=(function(f,p,d){if(d===void 0&&(d=-1),d===-1&&(d=p.rank-1),d!==p.rank-1)throw Error("Softmax cross entropy along a non-last dimension is not yet supported. Labels / logits was rank "+p.rank+" and dim was "+d);return io((function(v,m,g){var x=m.logSumExp([d],!0),b=m.toFloat().sub(x);return g([v,b]),{value:b.mul(v).neg().sum([d]),gradFunc:function(y,w){var C=w[0],S=w[1],k=nt(y.shape,[d]);return[y.reshape(k).mul(C.toFloat().sub(S.exp())),y.reshape(k).mul(S.exp().sub(C.toFloat()))]}}}))(f,p)})(a,i);return Kt(h,s,o)}}),Wv=Object.freeze({get Reduction(){return $e},absoluteDifference:Tv,computeWeightedLoss:Kt,cosineDistance:Nv,hingeLoss:Fv,huberLoss:Pv,logLoss:Mv,meanSquaredError:Ov,sigmoidCrossEntropy:Bv,softmaxCrossEntropy:Lv});function is(r,t){return t===void 0&&(t=!1),N.tidy((function(){if(r.shape.length!==2)throw new Error("qr2d() requires a 2D Tensor, but got a "+r.shape.length+"D Tensor.");for(var e=r.shape[0],n=r.shape[1],o=Ks(e),a=r.clone(),i=nn([[1]],[1,1]),s=i.clone(),u=e>=n?n:e,c=function(h){var f,p=a,d=s,v=o;f=N.tidy((function(){var m=a.slice([h,h],[e-h,1]),g=m.norm(),x=a.slice([h,h],[1,1]),b=nn([[-1]]).where(x.greater(0),nn([[1]])),y=x.sub(b.mul(g)),w=m.div(y);s=w.shape[0]===1?i.clone():i.concat(w.slice([1,0],[w.shape[0]-1,w.shape[1]]),0);var C=b.matMul(y).div(g).neg(),S=a.slice([h,0],[e-h,n]),k=C.mul(s);if(h===0)a=S.sub(k.matMul(s.transpose().matMul(S)));else{var R=S.sub(k.matMul(s.transpose().matMul(S)));a=a.slice([0,0],[h,n]).concat(R,0)}var E=o.slice([0,h],[e,o.shape[1]-h]);if(h===0)o=E.sub(E.matMul(s).matMul(k.transpose()));else{var T=E.sub(E.matMul(s).matMul(k.transpose()));o=o.slice([0,0],[e,h]).concat(T,1)}return[s,a,o]})),s=f[0],a=f[1],o=f[2],tt([p,d,v])},l=0;l<u;++l)c(l);return!t&&e>n&&(o=o.slice([0,0],[e,n]),a=a.slice([0,0],[n,n])),[o,a]}))}var Uv=D({bandPart_:function(r,t,e){if(t%1!=0)throw new Error("bandPart(): numLower must be an integer, got "+t+".");if(e%1!=0)throw new Error("bandPart(): numUpper must be an integer, got "+e+".");var n=_(r,"a","bandPart");if(n.rank<2)throw new Error("bandPart(): Rank must be at least 2, got "+n.rank+".");var o=n.shape,a=n.shape.slice(-2),i=a[0],s=a[1];if(!(t<=i))throw new Error("bandPart(): numLower ("+t+") must not be greater than the number of rows ("+i+").");if(!(e<=s))throw new Error("bandPart(): numUpper ("+e+") must not be greater than the number of columns ("+s+").");t<0&&(t=i),e<0&&(e=s);var u=zr(0,i,1,"int32").reshape([-1,1]),c=zr(0,s,1,"int32"),l=Be(u,c),h=uo(l.lessEqual(j(+t,"int32")),l.greaterEqual(j(-e,"int32"))),f=Ce([i,s],n.dtype);return lt(Me(n.reshape([-1,i,s])).map((function(p){return yn(h,p,f)}))).reshape(o)}}),Vv=D({gramSchmidt_:function(r){var t;if(Array.isArray(r)){t=!1,I(r!=null&&r.length>0,(function(){return"Gram-Schmidt process: input must not be null, undefined, or empty"}));for(var e=r[0].shape[0],n=function(u){I(r[u].shape[0]===e,(function(){return"Gram-Schmidt: Non-unique lengths found in the input vectors: ("+r[u].shape[0]+" vs. "+e+")"}))},o=1;o<r.length;++o)n(o)}else t=!0,r=Sa(r,r.shape[0],0).map((function(u){return Ys(u,[0])}));I(r.length<=r[0].shape[0],(function(){return"Gram-Schmidt: Number of vectors ("+r.length+") exceeds number of dimensions ("+r[0].shape[0]+")."}));var a=[],i=r,s=function(u){a.push(N.tidy((function(){var c=i[u];if(u>0)for(var l=0;l<u;++l){var h=qu(a[l].mulStrict(c)).mul(a[l]);c=c.sub(h)}return c.div(Yu(c,"euclidean"))})))};for(o=0;o<r.length;++o)s(o);return t?lt(a,0):a}}),zv=D({qr_:function(r,t){if(t===void 0&&(t=!1),r.rank<2)throw new Error("qr() requires input tensor to have a rank >= 2, but got rank "+r.rank);if(r.rank===2)return is(r,t);var e=r.shape.slice(0,r.shape.length-2).reduce((function(i,s){return i*s})),n=Me(r.reshape([e,r.shape[r.shape.length-2],r.shape[r.shape.length-1]]),0),o=[],a=[];return n.forEach((function(i){var s=is(i,t),u=s[0],c=s[1];o.push(u),a.push(c)})),[lt(o,0).reshape(r.shape),lt(a,0).reshape(r.shape)]}}),Gv=Object.freeze({bandPart:Uv,gramSchmidt:Vv,qr:zv});function fo(r,t,e,n,o,a){n==null&&(n=.5),o==null&&(o=Number.NEGATIVE_INFINITY),a==null&&(a=0);var i=r.shape[0];return e=Math.min(e,i),I(0<=n&&n<=1,(function(){return"iouThreshold must be in [0, 1], but was '"+n+"'"})),I(r.rank===2,(function(){return"boxes must be a 2D tensor, but was of rank '"+r.rank+"'"})),I(r.shape[1]===4,(function(){return"boxes must have 4 columns, but 2nd dimension was "+r.shape[1]})),I(t.rank===1,(function(){return"scores must be a 1D tensor"})),I(t.shape[0]===i,(function(){return"scores has incompatible shape with boxes. Expected "+i+", but was "+t.shape[0]})),I(0<=a&&a<=1,(function(){return"softNmsSigma must be in [0, 1], but was '"+a+"'"})),{maxOutputSize:e,iouThreshold:n,scoreThreshold:o,softNmsSigma:a}}var Hv=D({resizeBilinear_:function(r,t,e){e===void 0&&(e=!1);var n=_(r,"images","resizeBilinear");I(n.rank===3||n.rank===4,(function(){return"Error in resizeBilinear: x must be rank 3 or 4, but got rank "+n.rank+"."})),I(t.length===2,(function(){return"Error in resizeBilinear: new shape must 2D, but got shape "+t+"."}));var o=n,a=!1;n.rank===3&&(a=!0,o=n.as4D(1,n.shape[0],n.shape[1],n.shape[2]));var i=t[0],s=t[1],u=N.runKernelFunc((function(c,l){return l([o]),c.resizeBilinear(o,i,s,e)}),{x:o},(function(c,l){return{x:function(){return N.runKernelFunc((function(h){return h.resizeBilinearBackprop(c,l[0],e)}),{})}}}),"ResizeBilinear",{alignCorners:e,newHeight:i,newWidth:s});return a?u.as3D(u.shape[1],u.shape[2],u.shape[3]):u}}),jv=D({resizeNearestNeighbor_:function(r,t,e){e===void 0&&(e=!1);var n=_(r,"images","resizeNearestNeighbor");I(n.rank===3||n.rank===4,(function(){return"Error in resizeNearestNeighbor: x must be rank 3 or 4, but got rank "+n.rank+"."})),I(t.length===2,(function(){return"Error in resizeNearestNeighbor: new shape must 2D, but got shape "+t+"."})),I(n.dtype==="float32"||n.dtype==="int32",(function(){return"`images` must have `int32` or `float32` as dtype"}));var o=n,a=!1;n.rank===3&&(a=!0,o=n.as4D(1,n.shape[0],n.shape[1],n.shape[2]));var i=t[0],s=t[1],u=N.runKernelFunc((function(c,l){return l([o]),c.resizeNearestNeighbor(o,i,s,e)}),{batchImages:o},(function(c,l){return{batchImages:function(){return N.runKernelFunc((function(h){return h.resizeNearestNeighborBackprop(c,l[0],e)}),{})}}}));return a?u.as3D(u.shape[1],u.shape[2],u.shape[3]):u}}),qv=D({nonMaxSuppression_:function(r,t,e,n,o){n===void 0&&(n=.5),o===void 0&&(o=Number.NEGATIVE_INFINITY);var a=_(r,"boxes","nonMaxSuppression"),i=_(t,"scores","nonMaxSuppression"),s=fo(a,i,e,n,o);e=s.maxOutputSize,n=s.iouThreshold,o=s.scoreThreshold;var u={maxOutputSize:e,iouThreshold:n,scoreThreshold:o};return N.runKernelFunc((function(c){return c.nonMaxSuppression(a,i,e,n,o)}),{boxes:a,scores:i},null,"NonMaxSuppressionV3",u)}}),Kv=function(r,t,e,n,o){return n===void 0&&(n=.5),o===void 0&&(o=Number.NEGATIVE_INFINITY),X(this,void 0,void 0,(function(){var a,i,s,u,c,l,h;return $(this,(function(f){switch(f.label){case 0:return a=_(r,"boxes","nonMaxSuppressionAsync"),i=_(t,"scores","nonMaxSuppressionAsync"),s=fo(a,i,e,n,o),e=s.maxOutputSize,n=s.iouThreshold,o=s.scoreThreshold,[4,Promise.all([a.data(),i.data()])];case 1:return u=f.sent(),c=u[0],l=u[1],h=Na(c,l,e,n,o),a!==r&&a.dispose(),i!==t&&i.dispose(),[2,h]}}))}))},Xv=D({nonMaxSuppressionWithScore_:function(r,t,e,n,o,a){n===void 0&&(n=.5),o===void 0&&(o=Number.NEGATIVE_INFINITY),a===void 0&&(a=0);var i=_(r,"boxes","nonMaxSuppression"),s=_(t,"scores","nonMaxSuppression"),u=fo(i,s,e,n,o,a),c={maxOutputSize:e=u.maxOutputSize,iouThreshold:n=u.iouThreshold,scoreThreshold:o=u.scoreThreshold,softNmsSigma:a=u.softNmsSigma},l=N.runKernel("NonMaxSuppressionV5",{boxes:i,scores:s},c);return{selectedIndices:l[0],selectedScores:l[1]}}}),$v=function(r,t,e,n,o,a){return n===void 0&&(n=.5),o===void 0&&(o=Number.NEGATIVE_INFINITY),a===void 0&&(a=0),X(this,void 0,void 0,(function(){var i,s,u,c,l,h,f;return $(this,(function(p){switch(p.label){case 0:return i=_(r,"boxes","nonMaxSuppressionAsync"),s=_(t,"scores","nonMaxSuppressionAsync"),u=fo(i,s,e,n,o,a),e=u.maxOutputSize,n=u.iouThreshold,o=u.scoreThreshold,a=u.softNmsSigma,[4,Promise.all([i.data(),s.data()])];case 1:return c=p.sent(),l=c[0],h=c[1],f=Fa(l,h,e,n,o,a),i!==r&&i.dispose(),s!==t&&s.dispose(),[2,f]}}))}))},Yv=D({cropAndResize_:function(r,t,e,n,o,a){var i=_(r,"image","cropAndResize"),s=_(t,"boxes","cropAndResize","float32"),u=_(e,"boxInd","cropAndResize","int32");o=o||"bilinear",a=a||0;var c=s.shape[0];return I(i.rank===4,(function(){return"Error in cropAndResize: image must be rank 4,but got rank "+i.rank+"."})),I(s.rank===2&&s.shape[1]===4,(function(){return"Error in cropAndResize: boxes must be have size ["+c+",4] but had shape "+s.shape+"."})),I(u.rank===1&&u.shape[0]===c,(function(){return"Error in cropAndResize: boxInd must be have size ["+c+"] but had shape "+s.shape+"."})),I(n.length===2,(function(){return"Error in cropAndResize: cropSize must be of length 2, but got length "+n.length+"."})),I(n[0]>=1&&n[1]>=1,(function(){return"cropSize must be atleast [1,1], but was "+n})),I(o==="bilinear"||o==="nearest",(function(){return"method must be bilinear or nearest, but was "+o})),N.runKernelFunc((function(l,h){return l.cropAndResize(i,s,u,n,o,a)}),{images:i,boxes:s,boxInd:u},null,"CropAndResize",{method:o,extrapolationValue:a,cropSize:n})}}),Ka=Object.freeze({resizeBilinear:Hv,resizeNearestNeighbor:jv,nonMaxSuppression:qv,nonMaxSuppressionAsync:Kv,nonMaxSuppressionWithScore:Xv,nonMaxSuppressionWithScoreAsync:$v,cropAndResize:Yv}),Xa=function(r,t){return!(r>0)||t==="linear"},$a=function(r,t,e){if(e==null||e==="linear")return r;if(e==="relu")return r.mul(t.step());throw new Error("Gradient for activation "+e+" has not been implemented yet.")},Ya=function(r,t){var e=t,n=Oe(r.shape,t.shape);return n.length>0&&(e=e.sum(n)),e.reshape(r.shape)},Ja=function(r,t,e){if(t==="linear")return r;if(t==="relu")return Re(r);if(t==="elu")return Ku(r);if(t==="relu6")return $u(r);if(t==="prelu")return Xu(r,e);throw new Error("Unknown fused activation "+t+".")},Jv=D({fusedMatMul_:function(r){var t,e=r.a,n=r.b,o=r.transposeA,a=o!==void 0&&o,i=r.transposeB,s=i!==void 0&&i,u=r.bias,c=r.activation,l=c===void 0?"linear":c,h=r.preluActivationWeights;if(Xa(N.state.gradientDepth,l)===!1){var f=lo(e,n,a,s);return u!=null&&(f=ue(f,u)),Ja(f,l,h)}var p=_(e,"a","fused matMul"),d=_(n,"b","fused matMul");t=ke(p,d),p=t[0],d=t[1];var v=a?p.shape[p.rank-2]:p.shape[p.rank-1],m=s?d.shape[d.rank-1]:d.shape[d.rank-2],g=a?p.shape[p.rank-1]:p.shape[p.rank-2],x=s?d.shape[d.rank-2]:d.shape[d.rank-1],b=p.shape.slice(0,-2),y=d.shape.slice(0,-2),w=Y(b),C=Y(y);I(p.rank>=2&&d.rank>=2&&p.rank===d.rank,(function(){return"Error in fused matMul: inputs must have the same rank of at least 2, got ranks "+p.rank+" and "+d.rank+"."})),I(Ue(b,y),(function(){return"Error in fused matMul: outer dimensions ("+b+") and ("+y+") of Tensors with shapes "+p.shape+" and "+d.shape+" must match."})),I(v===m,(function(){return"Error in fused matMul: inner shapes ("+v+") and ("+m+") of Tensors with shapes "+p.shape+" and "+d.shape+" and transposeA="+a+" and transposeB="+s+" must match."}));var S,k,R=p.shape.slice(0,-2).concat([g,x]),E=a?p.as3D(w,v,g):p.as3D(w,g,v),T=s?d.as3D(C,x,m):d.as3D(C,m,x);u!=null&&le(R,(S=ke(S=_(u,"bias","fused matMul"),p)[0]).shape),h!=null&&(k=_(h,"prelu weights","fused matMul"));var A={a:E,b:T};u!=null&&(A.bias=S),h!=null&&(A.preluActivationWeights=k);var P=[E,T];return N.runKernelFunc((function(O,B){var V=O.fusedBatchMatMul({a:E,b:T,transposeA:a,transposeB:s,bias:S,activation:l,preluActivationWeights:k});return B([E,T,V]),V}),A,(function(O,B){var V=B[0],W=B[1],U=B[2],G=$a(O,U,l),H={};return u!=null&&(H={bias:function(){return Ya(S,G)}}),Object.assign(a||s?!a&&s?{a:function(){return G.matMul(W,!1,!1)},b:function(){return G.matMul(V,!0,!1)}}:a&&!s?{a:function(){return W.matMul(G,!1,!0)},b:function(){return V.matMul(G,!1,!1)}}:{a:function(){return W.matMul(G,!0,!0)},b:function(){return G.matMul(V,!0,!0)}}:{a:function(){return G.matMul(W,!1,!0)},b:function(){return V.matMul(G,!0,!1)}},H)}),"_FusedMatMul",{transposeA:a,transposeB:s,activation:l},P,[!0]).reshape(R)}}),Qv=D({fusedConv2d_:function(r){var t=r.x,e=r.filter,n=r.strides,o=r.pad,a=r.dataFormat,i=a===void 0?"NHWC":a,s=r.dilations,u=s===void 0?[1,1]:s,c=r.dimRoundingMode,l=r.bias,h=r.activation,f=h===void 0?"linear":h,p=r.preluActivationWeights;if(f=f||"linear",Xa(N.state.gradientDepth,f)===!1){var d=dt(t,e,n,o,i,u,c);return l!=null&&(d=ue(d,l)),Ja(d,f,p)}var v=_(t,"x","conv2d"),m=_(e,"filter","conv2d"),g=v,x=!1;v.rank===3&&(x=!0,g=v.as4D(1,v.shape[0],v.shape[1],v.shape[2])),I(g.rank===4,(function(){return"Error in fused conv2d: input must be rank 4, but got rank "+g.rank+"."})),I(m.rank===4,(function(){return"Error in fused conv2d: filter must be rank 4, but got rank "+m.rank+"."})),c!=null&&I(Te(o),(function(){return"Error in fused conv2d: pad must be an integer when using, dimRoundingMode "+c+" but got pad "+o+"."})),I(g.shape[3]===m.shape[2],(function(){return"Error in conv2d: depth of input ("+g.shape[3]+") must match input depth for filter "+m.shape[2]+"."})),I(rt(n,u),(function(){return"Error in conv2D: Either strides or dilations must be 1. Got strides "+n+" and dilations '"+u+"'"})),I(i==="NHWC",(function(){return"Error in conv2d: got dataFormat of "+i+" but only NHWC is currently supported."}));var b,y,w=Cn(g.shape,m.shape,n,u,o,c);l!=null&&(b=ke(b=_(l,"bias","fused conv2d"),v)[0],le(w.outShape,b.shape)),p!=null&&(y=_(p,"prelu weights","fused conv2d"));var C={x:g,filter:m};l!=null&&(C.bias=b),p!=null&&(C.preluActivationWeights=y);var S=[m,g],k=N.runKernelFunc((function(R,E){var T=R.fusedConv2d({input:g,filter:m,convInfo:w,bias:b,activation:f,preluActivationWeights:y});return E([m,g,T]),T}),C,(function(R,E){var T=E,A=T[0],P=T[1],O=T[2],B=$a(R,O,f);I(Kn(u),(function(){return"Error in gradient of fused conv2D: dilation rates greater than 1 are not yet supported in gradients. Got dilations '"+u+"'"}));var V={};return l!=null&&(V={bias:function(){return Ya(b,B)}}),Object.assign({x:function(){return Wu(P.shape,B,A,n,o)},filter:function(){return Va(P,B,A.shape,n,o)}},V)}),"FusedConv2D",{convInfo:w,activation:f},S,[!0]);return x?k.as3D(k.shape[1],k.shape[2],k.shape[3]):k}}),Zv=D({fusedDepthwiseConv2d_:function(r){var t=r.x,e=r.filter,n=r.strides,o=r.pad,a=r.dataFormat,i=a===void 0?"NHWC":a,s=r.dilations,u=s===void 0?[1,1]:s,c=r.dimRoundingMode,l=r.bias,h=r.activation,f=h===void 0?"linear":h,p=r.preluActivationWeights;if(Xa(N.state.gradientDepth,f)===!1){var d=co(t,e,n,o,i,u,c);return l!=null&&(d=ue(d,l)),Ja(d,f,p)}var v=_(t,"x","depthwiseConv2d"),m=_(e,"filter","depthwiseConv2d"),g=v,x=!1;v.rank===3&&(x=!0,g=v.as4D(1,v.shape[0],v.shape[1],v.shape[2])),I(g.rank===4,(function(){return"Error in fused depthwiseConv2d: input must be rank 4, but got rank "+g.rank+"."})),I(m.rank===4,(function(){return"Error in fused depthwiseConv2d: filter must be rank 4, but got rank "+m.rank+"."})),I(g.shape[3]===m.shape[2],(function(){return"Error in fused depthwiseConv2d: number of input channels ("+g.shape[3]+") must match the inChannels dimension in filter "+m.shape[2]+"."})),u==null&&(u=[1,1]),I(rt(n,u),(function(){return"Error in fused depthwiseConv2d: Either strides or dilations must be 1. Got strides "+n+" and dilations '"+u+"'"})),c!=null&&I(Te(o),(function(){return"Error in fused depthwiseConv2d: pad must be an integer when using dimRoundingMode "+c+" but got pad "+o+"."}));var b,y,w=Cn(g.shape,m.shape,n,u,o,c,!0);l!=null&&(b=ke(b=_(l,"bias","fused conv2d"),v)[0],le(w.outShape,b.shape)),p!=null&&(y=_(p,"prelu weights","fused depthwiseConv2d"));var C={x:g,filter:m};l!=null&&(C.bias=b),p!=null&&(C.preluActivationWeights=y);var S=[m,g],k=N.runKernelFunc((function(R,E){var T=R.fusedDepthwiseConv2D({input:g,filter:m,convInfo:w,bias:b,activation:f,preluActivationWeights:y});return E([m,g,T]),T}),C,(function(R,E){I(Kn(u),(function(){return"Error in gradient of fused depthwiseConv2d: dilation rates greater than 1 are not yet supported. Got dilations '"+u+"'"}));var T=E[0],A=E[1],P=E[2],O=$a(R,P,f),B={};return l!=null&&(B={bias:function(){return Ya(b,O)}}),Object.assign({x:function(){return Uu(A.shape,O,T,w)},filter:function(){return Vu(A,O,T.shape,w)}},B)}),"FusedDepthwiseConv2D",{convInfo:w,activation:f},S,[!0]);return x?k.as3D(k.shape[1],k.shape[2],k.shape[3]):k}}),em=Object.freeze({matMul:Jv,conv2d:Qv,depthwiseConv2d:Zv}),tm=Object.freeze({image:Ka,linalg:Gv,losses:Wv,spectral:Ev,fused:em,signal:Dv,square:Mp,squaredDifference:_u,conv1d:Hd,conv2d:dt,conv3d:jd,depthwiseConv2d:co,separableConv2d:za,conv2dTranspose:qd,conv3dTranspose:Kd,op:D,batchNormalization2d:hd,batchNormalization3d:fd,batchNormalization4d:pd,batchNormalization:dd,batchNorm:Du,batchNorm2d:vd,batchNorm3d:md,batchNorm4d:gd,booleanMaskAsync:Gd,complex:Ge,real:ft,imag:St,concat:Pe,concat1d:Zl,concat2d:eh,concat3d:th,concat4d:nh,split:Sa,matMul:lo,dot:Xd,outerProduct:$d,reverse:vr,reverse1d:Yd,reverse2d:Jd,reverse3d:Qd,reverse4d:Zd,maxPool:We,avgPool:mr,pool:ev,maxPool3d:tv,avgPool3d:nv,slice:Ft,slice1d:rv,slice2d:ov,slice3d:Hu,slice4d:av,abs:Op,acos:Bp,acosh:Lp,asin:Wp,asinh:Up,atan:Vp,atanh:zp,ceil:Gp,clipByValue:La,cos:Hp,cosh:jp,erf:qp,exp:da,expm1:Kp,floor:Xp,log:$p,log1p:Yp,logSigmoid:Jp,neg:Yr,reciprocal:Qp,round:Zp,rsqrt:Eu,sigmoid:Iu,sign:ed,isNaN:td,isInf:nd,isFinite:rd,sin:od,sinh:ad,softplus:id,sqrt:sd,step:ud,tan:cd,tanh:ld,all:iv,any:sv,argMax:uv,argMin:cv,logSumExp:lv,max:ho,mean:hv,min:fv,moments:pv,sum:qu,prod:dv,equal:Pu,equalStrict:Fd,greater:Pd,greaterEqual:Mu,greaterEqualStrict:Md,greaterStrict:Od,less:Bd,lessEqual:Ld,lessEqualStrict:Wd,lessStrict:Ud,notEqual:Vd,notEqualStrict:zd,add:ue,addN:bd,addStrict:wd,atan2:Cd,div:vt,divNoNan:_d,divStrict:Ed,floorDiv:Nu,maximum:Wa,maximumStrict:Id,minimum:Fu,minimumStrict:Rd,mod:kd,modStrict:Sd,mul:Ye,mulStrict:Dd,pow:Jr,powStrict:Ad,squaredDifferenceStrict:Td,sub:Be,subStrict:Nd,elu:Ku,leakyRelu:vv,prelu:Xu,relu:Re,relu6:$u,selu:mv,logicalAnd:uo,logicalNot:yd,logicalOr:Au,logicalXor:xd,where:yn,whereAsync:Tu,buffer:oe,print:hh,batchToSpaceND:qs,broadcastTo:fh,cast:ph,clone:dh,cumsum:vh,depthToSpace:mh,expandDims:ht,eye:Ks,multinomial:gh,oneHot:la,pad:wn,pad1d:yh,pad2d:xh,pad3d:bh,pad4d:wh,rand:Ch,randomNormal:_h,randomGamma:Eh,randomUniform:Xs,reshape:mt,spaceToBatchND:$s,squeeze:Ys,stack:lt,tile:Bn,truncatedNormal:Ih,unstack:Me,setdiff1dAsync:Rh,fill:Nt,linspace:Ql,ones:$n,range:zr,scalar:j,tensor:je,tensor1d:Ne,tensor2d:nn,tensor3d:ka,tensor4d:Ze,tensor5d:$l,tensor6d:Yl,variable:Jl,zeros:Ce,onesLike:js,zerosLike:me,transpose:an,softmax:qt,logSoftmax:Fh,localResponseNormalization:gv,norm:Yu,gather:Ua,unsortedSegmentSum:Ou,basicLSTMCell:yv,multiRNNCell:xv,movingAverage:bv,stridedSlice:wv,topk:Cv,scatterND:_v,fft:Ga,ifft:Qr,rfft:Ha,irfft:Ju,sparseToDense:Iv,gatherND:Rv,diag:kv,dropout:Sv,hannWindow:ja,hammingWindow:Zu,frame:qa,stft:ec,inTopKAsync:Av});function z(r,t){Array.isArray(r)||(r=[r]),r.forEach((function(e){e!=null&&I(e.dtype!=="complex64",(function(){return t+" does not support complex64 tensors."}))}))}function Ho(r,t,e,n){if(e==="linear")return r.linear(t);if(e==="relu")return r.relu(t);if(e==="elu")return r.elu(t);if(e==="relu6")return r.relu6(t);if(e==="prelu")return r.prelu(t,n);throw new Error("Activation "+e+" has not been implemented for the CPU backend.")}var nm=(function(r){function t(){var e=r.call(this)||this;return e.blockSize=48,e.firstUse=!0,e.data=new ru(e,N),e}return yt(t,r),t.prototype.write=function(e,n,o){this.firstUse&&(this.firstUse=!1,L().get("IS_NODE")&&Ur(`
============================
Hi there 👋. Looks like you are running TensorFlow.js in Node.js. To speed things up dramatically, install our node backend, which binds to TensorFlow C++, by running npm i @tensorflow/tfjs-node, or npm i @tensorflow/tfjs-node-gpu if you have CUDA. Then call require('@tensorflow/tfjs-node'); (-gpu suffix for CUDA) at the start of your program. Visit https://github.com/tensorflow/tfjs-node for more details.
============================`));var a={};return this.data.set(a,{values:e,dtype:o}),a},t.prototype.move=function(e,n,o,a){this.data.set(e,{values:n,dtype:a})},t.prototype.numDataIds=function(){return this.data.numDataIds()},t.prototype.read=function(e){return X(this,void 0,void 0,(function(){return $(this,(function(n){return[2,this.readSync(e)]}))}))},t.prototype.readSync=function(e){var n=this.data.get(e),o=n.dtype,a=n.complexTensors;return o==="complex64"?pa(this.readSync(a.real.dataId),this.readSync(a.imag.dataId)):this.data.get(e).values},t.prototype.bufferSync=function(e){var n=this.readSync(e.dataId),o=n;if(e.dtype==="string")try{o=n.map((function(a){return Br(a)}))}catch{throw new Error("Failed to decode encoded string bytes into utf-8")}return oe(e.shape,e.dtype,o)},t.prototype.makeOutput=function(e,n,o){var a=this.write(e,n,o);return N.makeTensorFromDataId(a,n,o,this)},t.prototype.disposeData=function(e){if(this.data.has(e)){var n=this.data.get(e).complexTensors;n!=null&&(n.real.dispose(),n.imag.dispose()),this.data.delete(e)}},t.prototype.time=function(e){return X(this,void 0,void 0,(function(){var n;return $(this,(function(o){return n=Rt(),e(),[2,{kernelMs:Rt()-n}]}))}))},t.prototype.memory=function(){return{unreliable:!0,reasons:["The reported memory is an upper bound. Due to automatic garbage collection, the true allocated memory may be less."]}},t.prototype.complex=function(e,n){var o=this.makeOutput(null,e.shape,"complex64");return this.data.get(o.dataId).complexTensors={real:N.keep(e.clone()),imag:N.keep(n.clone())},o},t.prototype.real=function(e){return this.data.get(e.dataId).complexTensors.real.clone()},t.prototype.imag=function(e){return this.data.get(e.dataId).complexTensors.imag.clone()},t.prototype.slice=function(e,n,o){if(z(e,"slice"),tu(e.shape,n,o)){var a=nu(n,e.strides),i=Y(o);return je(this.readSync(e.dataId).subarray(a,a+i),o,e.dtype)}for(var s=oe(o,e.dtype),u=this.bufferSync(e),c=0;c<s.size;++c){var l=s.indexToLoc(c).map((function(h,f){return h+n[f]}));s.values[c]=u.get.apply(u,l)}return s.toTensor()},t.prototype.stridedSlice=function(e,n,o,a){z(e,"stridedSlice");var i=Aa(n,o,a);if(i.some((function(p){return p===0})))return je([],i);for(var s=oe(i,e.dtype),u=this.bufferSync(e),c=0;c<s.size;c++){for(var l=s.indexToLoc(c),h=new Array(l.length),f=0;f<h.length;f++)h[f]=l[f]*a[f]+n[f];s.set.apply(s,[u.get.apply(u,h)].concat(l))}return s.toTensor()},t.prototype.diag=function(e){for(var n=this.readSync(e.dataId),o=oe([e.size,e.size],e.dtype),a=o.values,i=0;i<n.length;i++)a[i*e.size+i]=n[i];return o.toTensor()},t.prototype.unstack=function(e,n){for(var o=e.shape[n],a=new Array(e.rank-1),i=0,s=0;s<e.rank;s++)s!==n&&(a[i++]=e.shape[s]);var u=new Array(e.rank).fill(0),c=e.shape.slice();c[n]=1;var l=new Array(o);for(s=0;s<l.length;s++)u[n]=s,l[s]=this.slice(e,u,c).reshape(a);return l},t.prototype.reverse=function(e,n){z(e,"reverse");for(var o=oe(e.shape,e.dtype),a=this.bufferSync(e),i=function(u){var c=o.indexToLoc(u),l=c.slice();n.forEach((function(h){return l[h]=e.shape[h]-1-l[h]})),o.set.apply(o,[a.get.apply(a,l)].concat(c))},s=0;s<o.size;s++)i(s);return o.toTensor()},t.prototype.concat=function(e,n){var o=this;if(e[0].dtype==="complex64"){var a=e.map((function(p){return ft(p)})),i=e.map((function(p){return St(p)}));return Ge(this.concat(a,n),this.concat(i,n))}var s=e.map((function(p){var d=Y(p.shape.slice(n));return p.as2D(-1,d)})),u=qn(s.map((function(p){return p.shape})),1),c=oe(u,e[0].dtype).values;if(s[0].shape[0]===1){var l=0;s.forEach((function(p){c.set(o.readSync(p.dataId),l),l+=p.size}))}else{var h=0;s.forEach((function(p){for(var d=o.readSync(p.dataId),v=0,m=0;m<p.shape[0];++m)for(var g=m*u[1]+h,x=0;x<p.shape[1];++x)c[g+x]=d[v++];h+=p.shape[1]}))}var f=qn(e.map((function(p){return p.shape})),n);return je(c,f,e[0].dtype)},t.prototype.neg=function(e){return z(e,"neg"),this.multiply(j(-1),e)},t.prototype.add=function(e,n){return e.dtype==="complex64"||n.dtype==="complex64"?this.broadcastedBinaryComplexOp(e.cast("complex64"),n.cast("complex64"),(function(o,a,i,s){return{real:o+i,imag:a+s}})):this.broadcastedBinaryOp(e,n,He(e.dtype,n.dtype),(function(o,a){return o+a}))},t.prototype.addN=function(e){var n=this;z(e,"addN");for(var o=e.map((function(l){return n.readSync(l.dataId)})),a=oe(e[0].shape,e[0].dtype),i=a.values,s=0;s<e.length;s++)for(var u=o[s],c=0;c<i.length;c++)i[c]+=u[c];return a.toTensor()},t.prototype.softmax=function(e,n){var o=Le([n],e.shape),a=this.max(e,o),i=nt(a.shape,o),s=this.subtract(e,a.reshape(i)),u=this.exp(s),c=this.sum(u,o).reshape(i);return this.realDivide(u,c)},t.prototype.subtract=function(e,n){return e.dtype==="complex64"||n.dtype==="complex64"?this.broadcastedBinaryComplexOp(e.cast("complex64"),n.cast("complex64"),(function(o,a,i,s){return{real:o-i,imag:a-s}})):this.broadcastedBinaryOp(e,n,He(e.dtype,n.dtype),(function(o,a){return o-a}))},t.prototype.pow=function(e,n){return z([e,n],"pow"),this.broadcastedBinaryOp(e,n,e.dtype,(function(o,a){return Math.pow(o,a)}))},t.prototype.batchMatMul=function(e,n,o,a){z([e,n],"matMul");for(var i=o?e.shape[1]:e.shape[2],s=o?e.shape[2]:e.shape[1],u=a?n.shape[1]:n.shape[2],c=e.shape[0],l=this.readSync(e.dataId),h=this.readSync(n.dataId),f=o?[e.strides[0],1,e.strides[1]]:[e.strides[0],e.strides[1],1],p=f[0],d=f[1],v=f[2],m=a?[1,n.strides[1],n.strides[0]]:[n.strides[1],1,n.strides[0]],g=m[0],x=m[1],b=m[2],y=s*u,w=oe([c,s,u],e.dtype),C=w.values,S=this.blockSize,k=0;k<c;k++)for(var R=0;R<s;R+=S)for(var E=0;E<u;E+=S)for(var T=0;T<i;T+=S)for(var A=Math.min(R+S,s),P=Math.min(E+S,u),O=Math.min(T+S,i),B=R;B<A;B++)for(var V=E;V<P;V++){for(var W=0,U=T;U<O;U++)W+=l[k*p+B*d+U*v]*h[U*g+V*x+k*b];C[k*y+(B*u+V)]+=W}return w.toTensor()},t.prototype.fusedBatchMatMul=function(e){var n=e.a,o=e.b,a=e.transposeA,i=e.transposeB,s=e.bias,u=e.activation,c=e.preluActivationWeights,l=this.batchMatMul(n,o,a,i);return s&&(l=this.add(l,s)),u&&(l=Ho(this,l,u,c)),l},t.prototype.multiply=function(e,n){return e.dtype==="complex64"||n.dtype==="complex64"?this.broadcastedBinaryComplexOp(e.cast("complex64"),n.cast("complex64"),(function(o,a,i,s){return{real:o*i-a*s,imag:o*s+a*i}})):this.broadcastedBinaryOp(e,n,He(e.dtype,n.dtype),(function(o,a){return o*a}))},t.prototype.realDivide=function(e,n){return z([e,n],"realDivide"),this.broadcastedBinaryOp(e,n,"float32",(function(o,a){return o/a}))},t.prototype.floorDiv=function(e,n){return z([e,n],"floorDiv"),this.broadcastedBinaryOp(e,n,"int32",(function(o,a){return Math.floor(o/a)}))},t.prototype.sum=function(e,n){z(e,"sum"),at("sum",n,e.rank);for(var o=qe(e.shape,n),a=o[0],i=o[1],s=Ce(a,He(e.dtype,"int32")),u=Y(i),c=this.readSync(s.dataId),l=this.readSync(e.dataId),h=0;h<c.length;++h){for(var f=h*u,p=0,d=0;d<u;++d)p+=l[f+d];c[h]=p}return s},t.prototype.prod=function(e,n){z(e,"sum");for(var o=qe(e.shape,n),a=o[0],i=o[1],s=Ce(a,He(e.dtype,"int32")),u=Y(i),c=this.readSync(s.dataId),l=this.readSync(e.dataId),h=0;h<c.length;++h){for(var f=h*u,p=1,d=0;d<u;++d)p*=l[f+d];c[h]=p}return s},t.prototype.unsortedSegmentSum=function(e,n,o){z(e,"unsortedSegmentSum");for(var a=[],i=e.rank-n.rank,s=0;s<i;++s)n=n.expandDims(s+1);for(s=0;s<o;++s){var u=j(s,"int32"),c=Pu(u,n).asType("float32").mul(e).sum(0);a.push(c)}return lt(a)},t.prototype.argMin=function(e,n){z(e,"argMin");var o=[n];at("argMin",o,e.rank);for(var a=qe(e.shape,o),i=a[0],s=a[1],u=Ce(i,"int32"),c=Y(s),l=this.readSync(u.dataId),h=this.readSync(e.dataId),f=0;f<l.length;++f){for(var p=f*c,d=h[p],v=0,m=0;m<c;++m){var g=h[p+m];g<d&&(d=g,v=m)}l[f]=v}return u},t.prototype.argMax=function(e,n){z(e,"argMax");var o=[n];at("argMax",o,e.rank);for(var a=qe(e.shape,o),i=a[0],s=a[1],u=Ce(i,"int32"),c=Y(s),l=this.readSync(u.dataId),h=this.readSync(e.dataId),f=0;f<l.length;++f){for(var p=f*c,d=h[p],v=0,m=0;m<c;++m){var g=h[p+m];g>d&&(d=g,v=m)}l[f]=v}return u},t.prototype.cumsum=function(e,n,o,a){if(z(e,"cumsum"),n!==e.rank-1)throw new Error("backend.cumsum in CPU expects an inner-most axis="+(e.rank-1)+" but got axis="+n);for(var i=He(e.dtype,"int32"),s=Ce(e.shape,i),u=this.readSync(s.dataId),c=this.readSync(e.dataId),l=e.shape[e.rank-1],h=a?function(m,g){return m+l-g-1}:function(m,g){return m+g},f=0;f<c.length;f+=l)for(var p=0;p<l;p++){var d=h(f,p);if(p===0)u[d]=o?0:c[d];else{var v=h(f,p-1);u[d]=o?c[v]+u[v]:c[d]+u[v]}}return s},t.prototype.equal=function(e,n){return z([e,n],"equal"),this.broadcastedBinaryOp(e,n,"bool",(function(o,a){return o===a?1:0}))},t.prototype.notEqual=function(e,n){return z([e,n],"notEqual"),this.broadcastedBinaryOp(e,n,"bool",(function(o,a){return o!==a?1:0}))},t.prototype.less=function(e,n){return z([e,n],"less"),this.broadcastedBinaryOp(e,n,"bool",(function(o,a){return o<a?1:0}))},t.prototype.lessEqual=function(e,n){return z([e,n],"lessEqual"),this.broadcastedBinaryOp(e,n,"bool",(function(o,a){return o<=a?1:0}))},t.prototype.greater=function(e,n){return z([e,n],"greater"),this.broadcastedBinaryOp(e,n,"bool",(function(o,a){return o>a?1:0}))},t.prototype.greaterEqual=function(e,n){return z([e,n],"greaterEqual"),this.broadcastedBinaryOp(e,n,"bool",(function(o,a){return o>=a?1:0}))},t.prototype.logicalNot=function(e){z(e,"logicalNot");for(var n=this.readSync(e.dataId),o=new Uint8Array(n.length),a=0;a<n.length;++a)o[a]=n[a]?0:1;return this.makeOutput(o,e.shape,"bool")},t.prototype.logicalAnd=function(e,n){return z([e,n],"logicalAnd"),this.broadcastedBinaryOp(e,n,"bool",(function(o,a){return o&&a}))},t.prototype.logicalOr=function(e,n){return z([e,n],"logicalOr"),this.broadcastedBinaryOp(e,n,"bool",(function(o,a){return o||a}))},t.prototype.select=function(e,n,o){z([e,n,o],"select");for(var a=this.readSync(e.dataId),i=this.readSync(n.dataId),s=this.readSync(o.dataId),u=Ce(n.shape,He(n.dtype,o.dtype)),c=this.readSync(u.dataId),l=0,h=e.rank===0||e.rank>1||n.rank===1?1:Y(n.shape.slice(1)),f=0;f<a.length;f++)for(var p=0;p<h;p++)a[f]===1?c[l++]=i[f]:c[l++]=s[f];return u},t.prototype.where=function(e){z([e],"where");var n=this.readSync(e.dataId);return Pa(e.shape,n)},t.prototype.topk=function(e,n,o){return z(e,"topk"),hu(this.readSync(e.dataId),e.shape,e.dtype,n)},t.prototype.min=function(e,n){z(e,"min"),at("min",n,e.rank);for(var o=qe(e.shape,n),a=o[0],i=o[1],s=Ce(a,e.dtype),u=Y(i),c=this.readSync(s.dataId),l=this.readSync(e.dataId),h=0;h<c.length;++h){for(var f=h*u,p=l[f],d=0;d<u;++d){var v=l[f+d];v<p&&(p=v)}c[h]=p}return s},t.prototype.minimum=function(e,n){return z([e,n],"minimum"),this.broadcastedBinaryOp(e,n,e.dtype,(function(o,a){return Math.min(o,a)}))},t.prototype.mod=function(e,n){return z([e,n],"mod"),this.broadcastedBinaryOp(e,n,e.dtype,(function(o,a){var i=o%a;return o<0&&a<0||o>=0&&a>=0?i:(i+a)%a}))},t.prototype.max=function(e,n){z(e,"max"),at("max",n,e.rank);for(var o=qe(e.shape,n),a=o[0],i=o[1],s=Ce(a,e.dtype),u=Y(i),c=this.readSync(s.dataId),l=this.readSync(e.dataId),h=0;h<c.length;++h){for(var f=h*u,p=l[f],d=0;d<u;++d){var v=l[f+d];v>p&&(p=v)}c[h]=p}return s},t.prototype.maximum=function(e,n){return z([e,n],"maximum"),this.broadcastedBinaryOp(e,n,e.dtype,(function(o,a){return Math.max(o,a)}))},t.prototype.all=function(e,n){z(e,"all"),at("all",n,e.rank);for(var o=qe(e.shape,n),a=o[0],i=o[1],s=Ce(a,e.dtype),u=Y(i),c=this.readSync(s.dataId),l=this.readSync(e.dataId),h=0;h<c.length;++h){for(var f=h*u,p=l[f],d=0;d<u;++d){var v=l[f+d];p=p&&v}c[h]=p}return s},t.prototype.any=function(e,n){z(e,"any"),at("any",n,e.rank);for(var o=qe(e.shape,n),a=o[0],i=o[1],s=Ce(a,e.dtype),u=Y(i),c=this.readSync(s.dataId),l=this.readSync(e.dataId),h=0;h<c.length;++h){for(var f=h*u,p=l[f],d=0;d<u;++d){var v=l[f+d];p=p||v}c[h]=p}return s},t.prototype.squaredDifference=function(e,n){return z([e,n],"squaredDifference"),this.broadcastedBinaryOp(e,n,e.dtype,(function(o,a){var i=o-a;return i*i}))},t.prototype.ceil=function(e){z(e,"ceil");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a)o[a]=Math.ceil(n[a]);return this.makeOutput(o,e.shape,"float32")},t.prototype.floor=function(e){z(e,"floor");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a)o[a]=Math.floor(n[a]);return this.makeOutput(o,e.shape,"float32")},t.prototype.sign=function(e){z(e,"x");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a)n[a]<0?o[a]=-1:n[a]>0?o[a]=1:o[a]=0;return this.makeOutput(o,e.shape,"float32")},t.prototype.isNaN=function(e){z(e,"x");for(var n=this.readSync(e.dataId),o=new Uint8Array(n.length),a=0;a<n.length;++a)Number.isNaN(n[a])&&(o[a]=1);return this.makeOutput(o,e.shape,"bool")},t.prototype.isInf=function(e){z(e,"x");for(var n=this.readSync(e.dataId),o=new Uint8Array(n.length),a=0;a<n.length;++a)Math.abs(n[a])===1/0&&(o[a]=1);return this.makeOutput(o,e.shape,"bool")},t.prototype.isFinite=function(e){z(e,"x");for(var n=this.readSync(e.dataId),o=new Uint8Array(n.length),a=0;a<n.length;++a)Number.isFinite(n[a])&&(o[a]=1);return this.makeOutput(o,e.shape,"bool")},t.prototype.round=function(e){z(e,"round");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a){var i=Math.floor(n[a]);n[a]-i<.5?o[a]=Math.floor(n[a]):n[a]-i>.5?o[a]=Math.ceil(n[a]):o[a]=i%2==0?i:i+1}return this.makeOutput(o,e.shape,"float32")},t.prototype.exp=function(e){z(e,"exp");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a)o[a]=Math.exp(n[a]);return this.makeOutput(o,e.shape,"float32")},t.prototype.expm1=function(e){z(e,"expm1");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a)o[a]=Math.expm1(n[a]);return this.makeOutput(o,e.shape,"float32")},t.prototype.log=function(e){z(e,"log");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a){var i=n[a];o[a]=Math.log(i)}return this.makeOutput(o,e.shape,"float32")},t.prototype.log1p=function(e){z(e,"log1p");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a){var i=n[a];o[a]=Math.log1p(i)}return this.makeOutput(o,e.shape,"float32")},t.prototype.sqrt=function(e){z(e,"sqrt");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a){var i=n[a];o[a]=Math.sqrt(i)}return this.makeOutput(o,e.shape,"float32")},t.prototype.rsqrt=function(e){z(e,"rsqrt");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a){var i=n[a];o[a]=1/Math.sqrt(i)}return this.makeOutput(o,e.shape,"float32")},t.prototype.reciprocal=function(e){z(e,"reciprocal");for(var n=this.readSync(e.dataId),o=new Float32Array(n.length),a=0;a<n.length;++a)o[a]=1/n[a];return this.makeOutput(o,e.shape,"float32")},t.prototype.linear=function(e){return e},t.prototype.relu=function(e){z(e,"relu");for(var n=Ce(e.shape,e.dtype),o=this.readSync(n.dataId),a=this.readSync(e.dataId),i=0;i<a.length;++i)o[i]=Math.max(0,a[i]);return n},t.prototype.relu6=function(e){z(e,"relu");for(var n=Ce(e.shape,e.dtype),o=this.readSync(n.dataId),a=this.readSync(e.dataId),i=0;i<a.length;++i)o[i]=Math.min(Math.max(0,a[i]),6);return n},t.prototype.prelu=function(e,n){return z([e,n],"prelu"),this.broadcastedBinaryOp(e,n,e.dtype,(function(o,a){return o<0?a*o:o}))},t.prototype.elu=function(e){z(e,"elu");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a){var i=o[a];n[a]=i>=0?i:Math.exp(i)-1}return this.makeOutput(n,e.shape,"float32")},t.prototype.eluDer=function(e,n){z([e,n],"eluDer");for(var o=new Float32Array(n.size),a=this.readSync(n.dataId),i=this.readSync(e.dataId),s=0;s<a.length;++s){var u=a[s];o[s]=u>=1?i[s]:i[s]*(u+1)}return this.makeOutput(o,n.shape,"float32")},t.prototype.selu=function(e){z(e,"selu");for(var n=Oa,o=Ba,a=new Float32Array(e.size),i=this.readSync(e.dataId),s=0;s<i.length;++s){var u=i[s];a[s]=u>=0?o*u:n*(Math.exp(u)-1)}return this.makeOutput(a,e.shape,"float32")},t.prototype.clip=function(e,n,o){z(e,"clip");for(var a=new Float32Array(e.size),i=this.readSync(e.dataId),s=0;s<i.length;++s){var u=i[s];a[s]=u>o?o:u<n?n:u}return this.makeOutput(a,e.shape,"float32")},t.prototype.abs=function(e){for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.abs(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.complexAbs=function(e){for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<e.size;++a){var i=o[2*a],s=o[2*a+1];n[a]=Math.hypot(i,s)}return this.makeOutput(n,e.shape,"float32")},t.prototype.int=function(e){z(e,"int");for(var n=new Int32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=o[a];return this.makeOutput(n,e.shape,"int32")},t.prototype.sigmoid=function(e){z(e,"sigmoid");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=1/(1+Math.exp(-o[a]));return this.makeOutput(n,e.shape,"float32")},t.prototype.softplus=function(e){z(e,"softplus");for(var n=Math.log(11920928955078125e-23)+2,o=new Float32Array(e.size),a=this.readSync(e.dataId),i=0;i<a.length;++i){var s=a[i]>-n,u=a[i]<n,c=Math.exp(a[i]),l=void 0;l=u?c:s?a[i]:Math.log(1+c),o[i]=l}return this.makeOutput(o,e.shape,"float32")},t.prototype.sin=function(e){z(e,"sin");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.sin(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.cos=function(e){z(e,"cos");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.cos(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.tan=function(e){z(e,"tan");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.tan(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.asin=function(e){z(e,"asin");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.asin(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.acos=function(e){z(e,"acos");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.acos(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.atan=function(e){z(e,"atan");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.atan(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.atan2=function(e,n){return z([e,n],"atan2"),this.broadcastedBinaryOp(e,n,e.dtype,(function(o,a){return Math.atan2(o,a)}))},t.prototype.sinh=function(e){z(e,"sinh");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.sinh(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.cosh=function(e){z(e,"cosh");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.cosh(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.tanh=function(e){z(e,"tanh");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=nl(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.asinh=function(e){z(e,"asinh");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.asinh(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.acosh=function(e){z(e,"acosh");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.acosh(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.atanh=function(e){z(e,"atanh");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a)n[a]=Math.atanh(o[a]);return this.makeOutput(n,e.shape,"float32")},t.prototype.erf=function(e){z(e,"erf");for(var n=new Float32Array(e.size),o=this.readSync(e.dataId),a=0;a<o.length;++a){var i=Math.sign(o[a]),s=Math.abs(o[a]),u=1/(1+.3275911*s);n[a]=i*(1-((((1.061405429*u-1.453152027)*u+1.421413741)*u-.284496736)*u+.254829592)*u*Math.exp(-s*s))}return this.makeOutput(n,e.shape,"float32")},t.prototype.step=function(e,n){n===void 0&&(n=0),z(e,"step");for(var o=new Float32Array(e.size),a=this.readSync(e.dataId),i=0;i<a.length;++i){var s=a[i];isNaN(s)?o[i]=NaN:o[i]=s>0?1:n}return this.makeOutput(o,e.shape,"float32")},t.prototype.fusedConv2d=function(e){var n=e.input,o=e.filter,a=e.convInfo,i=e.bias,s=e.activation,u=e.preluActivationWeights,c=this.conv2d(n,o,a);return i&&(c=this.add(c,i)),s&&(c=Ho(this,c,s,u)),c},t.prototype.conv2d=function(e,n,o){z([e,n],"conv2d");for(var a=o.filterHeight,i=o.filterWidth,s=o.dilationHeight,u=o.dilationWidth,c=o.padInfo.left,l=o.padInfo.top,h=o.dataFormat==="channelsLast",f=oe(o.outShape,e.dtype),p=e.strides[0],d=h?e.strides[1]:e.strides[2],v=h?e.strides[2]:1,m=h?1:e.strides[1],g=f.strides[0],x=h?f.strides[1]:f.strides[2],b=h?f.strides[2]:1,y=h?1:f.strides[1],w=this.readSync(e.dataId),C=this.readSync(n.dataId),S=f.values,k=0;k<o.batchSize;++k)for(var R=k*p,E=k*g,T=0;T<o.outHeight;++T)for(var A=E+T*x,P=T*o.strideHeight-l,O=0;O<a;O++){var B=P+O*s;if(!(B<0||B>=o.inHeight))for(var V=O*n.strides[0],W=R+B*d,U=0;U<o.outWidth;++U)for(var G=A+U*b,H=U*o.strideWidth-c,q=0;q<i;q++){var ee=H+q*u;if(!(ee<0||ee>=o.inWidth))for(var te=W+ee*v,ie=V+q*n.strides[1],se=0;se<o.inChannels;++se){for(var ce=w[te+se*m],pe=0;pe<o.outChannels;++pe)S[G+pe*y]+=ce*C[ie+pe];ie+=o.outChannels}}}return f.toTensor()},t.prototype.conv3d=function(e,n,o){for(var a=o.filterDepth,i=o.filterHeight,s=o.filterWidth,u=o.dilationDepth,c=o.dilationHeight,l=o.dilationWidth,h=o.padInfo.front,f=o.padInfo.left,p=o.padInfo.top,d=oe(o.outShape,e.dtype),v=this.readSync(e.dataId),m=this.readSync(n.dataId),g=d.values,x=0;x<o.batchSize;++x)for(var b=x*e.strides[0],y=x*d.strides[0],w=0;w<o.outDepth;++w)for(var C=y+w*d.strides[1],S=w*o.strideDepth-h,k=0;k<a;k++){var R=S+k*u;if(!(R<0||R>=o.inDepth))for(var E=k*n.strides[0],T=b+R*e.strides[1],A=0;A<o.outHeight;++A)for(var P=C+A*d.strides[2],O=A*o.strideHeight-p,B=0;B<i;B++){var V=O+B*c;if(!(V<0||V>=o.inHeight))for(var W=E+B*n.strides[1],U=T+V*e.strides[2],G=0;G<o.outWidth;++G)for(var H=P+G*o.outChannels,q=G*o.strideWidth-f,ee=0;ee<s;ee++){var te=q+ee*l;if(!(te<0||te>=o.inWidth))for(var ie=W+ee*n.strides[2],se=U+te*o.inChannels,ce=ie,pe=0;pe<o.inChannels;++pe){for(var he=v[se+pe],de=0;de<o.outChannels;++de)g[H+de]+=he*m[ce+de];ce+=o.outChannels}}}}return d.toTensor()},t.prototype.conv2dDerInput=function(e,n,o){z([e,n],"conv2dDerInput");for(var a=oe(o.inShape,"float32"),i=a.values,s=this.readSync(e.dataId),u=this.readSync(n.dataId),c=n.strides,l=c[0],h=c[1],f=c[2],p=o.batchSize,d=o.filterHeight,v=o.filterWidth,m=o.inChannels,g=o.inHeight,x=o.inWidth,b=o.outChannels,y=o.outHeight,w=o.outWidth,C=o.strideHeight,S=o.strideWidth,k=o.dataFormat,R=d-1-o.padInfo.top,E=v-1-o.padInfo.left,T=k==="channelsLast",A=a.strides[0],P=T?a.strides[1]:a.strides[2],O=T?a.strides[2]:1,B=T?1:a.strides[1],V=e.strides[0],W=T?e.strides[1]:e.strides[2],U=T?e.strides[2]:1,G=T?1:e.strides[1],H=0;H<p;++H)for(var q=0;q<m;++q)for(var ee=0;ee<g;++ee)for(var te=ee-R,ie=Math.max(0,Math.ceil(te/C)),se=Math.min(y,(d+te)/C),ce=0;ce<x;++ce){for(var pe=ce-E,he=Math.max(0,Math.ceil(pe/S)),de=Math.min(w,(v+pe)/S),Ae=0,fe=ie;fe<se;++fe)for(var be=fe*C-te,ge=he;ge<de;++ge)for(var Se=V*H+W*fe+U*ge,_e=l*(d-1-be)+h*(v-1-(ge*S-pe))+f*q,Ee=0;Ee<b;++Ee)Ae+=s[Se+G*Ee]*u[_e+Ee];i[A*H+P*ee+O*ce+B*q]=Ae}return a.toTensor()},t.prototype.conv3dDerInput=function(e,n,o){for(var a=oe(o.inShape,"float32"),i=a.values,s=a.strides,u=s[0],c=s[1],l=s[2],h=s[3],f=this.readSync(e.dataId),p=e.strides,d=p[0],v=p[1],m=p[2],g=p[3],x=this.readSync(n.dataId),b=n.strides,y=b[0],w=b[1],C=b[2],S=b[3],k=o.batchSize,R=o.filterDepth,E=o.filterHeight,T=o.filterWidth,A=o.inChannels,P=o.inDepth,O=o.inHeight,B=o.inWidth,V=o.outChannels,W=o.outDepth,U=o.outHeight,G=o.outWidth,H=o.strideDepth,q=o.strideHeight,ee=o.strideWidth,te=R-1-o.padInfo.front,ie=E-1-o.padInfo.top,se=T-1-o.padInfo.left,ce=0;ce<k;++ce)for(var pe=0;pe<A;++pe)for(var he=0;he<P;++he)for(var de=he-te,Ae=Math.max(0,Math.ceil(de/H)),fe=Math.min(W,(R+de)/H),be=0;be<O;++be)for(var ge=be-ie,Se=Math.max(0,Math.ceil(ge/q)),_e=Math.min(U,(E+ge)/q),Ee=0;Ee<B;++Ee){for(var bt=Ee-se,wt=Math.max(0,Math.ceil(bt/ee)),ot=Math.min(G,(T+bt)/ee),In=0,Lt=Ae;Lt<fe;++Lt)for(var Jt=Lt*H-de,Wt=Se;Wt<_e;++Wt)for(var Rn=Wt*q-ge,Ut=wt;Ut<ot;++Ut)for(var wo=d*ce+v*Lt+m*Wt+g*Ut,kn=y*(R-1-Jt)+w*(E-1-Rn)+C*(T-1-(Ut*ee-bt))+S*pe,Ct=0;Ct<V;++Ct)In+=f[wo+Ct]*x[kn+Ct];i[u*ce+c*he+l*be+h*Ee+pe]=In}return a.toTensor()},t.prototype.conv2dDerFilter=function(e,n,o){z([e,n],"conv2dDerFilter");for(var a=o.strideHeight,i=o.strideWidth,s=o.filterHeight,u=o.filterWidth,c=o.dataFormat==="channelsLast",l=oe(o.filterShape,"float32"),h=o.padInfo.left,f=o.padInfo.top,p=this.bufferSync(e),d=this.bufferSync(n),v=0;v<s;++v)for(var m=Math.max(0,Math.ceil((f-v)/a)),g=Math.min(o.outHeight,(o.inHeight+f-v)/a),x=0;x<u;++x)for(var b=Math.max(0,Math.ceil((h-x)/i)),y=Math.min(o.outWidth,(o.inWidth+h-x)/i),w=0;w<o.inChannels;++w)for(var C=0;C<o.outChannels;++C){for(var S=0,k=0;k<o.batchSize;++k)for(var R=m;R<g;++R)for(var E=v+R*a-f,T=b;T<y;++T){var A=x+T*i-h;S+=c?p.get(k,E,A,w)*d.get(k,R,T,C):p.get(k,w,E,A)*d.get(k,C,R,T)}l.set(S,v,x,w,C)}return l.toTensor()},t.prototype.conv3dDerFilter=function(e,n,o){for(var a=o.strideDepth,i=o.strideHeight,s=o.strideWidth,u=o.filterDepth,c=o.filterHeight,l=o.filterWidth,h=oe(o.filterShape,"float32"),f=h.values,p=h.strides,d=p[0],v=p[1],m=p[2],g=p[3],x=this.readSync(n.dataId),b=n.strides,y=b[0],w=b[1],C=b[2],S=b[3],k=this.readSync(e.dataId),R=e.strides,E=R[0],T=R[1],A=R[2],P=R[3],O=o.padInfo.front,B=o.padInfo.left,V=o.padInfo.top,W=0;W<u;++W)for(var U=Math.max(0,Math.ceil((O-W)/a)),G=Math.min(o.outDepth,(o.inDepth+O-W)/a),H=W*d,q=0;q<c;++q)for(var ee=Math.max(0,Math.ceil((V-q)/i)),te=Math.min(o.outHeight,(o.inHeight+V-q)/i),ie=q*v+H,se=0;se<l;++se)for(var ce=Math.max(0,Math.ceil((B-se)/s)),pe=Math.min(o.outWidth,(o.inWidth+B-se)/s),he=se*m+ie,de=0;de<o.inChannels;++de)for(var Ae=de*g+he,fe=0;fe<o.outChannels;++fe){for(var be=0,ge=0;ge<o.batchSize;++ge)for(var Se=ge*E,_e=ge*y,Ee=U;Ee<G;++Ee)for(var bt=(W+Ee*a-O)*T+Se,wt=Ee*w+_e,ot=ee;ot<te;++ot)for(var In=(q+ot*i-V)*A+bt,Lt=ot*C+wt,Jt=ce;Jt<pe;++Jt){var Wt=Jt*S+Lt;be+=k[(se+Jt*s-B)*P+In+de]*x[Wt+fe]}f[Ae+fe]=be}return h.toTensor()},t.prototype.fusedDepthwiseConv2D=function(e){var n=e.input,o=e.filter,a=e.convInfo,i=e.bias,s=e.activation,u=e.preluActivationWeights,c=this.depthwiseConv2D(n,o,a);return i&&(c=this.add(c,i)),s&&(c=Ho(this,c,s,u)),c},t.prototype.depthwiseConv2D=function(e,n,o){z([e,n],"depthwiseConv2D");for(var a=o.filterHeight,i=o.filterWidth,s=o.dilationHeight,u=o.dilationWidth,c=o.padInfo.left,l=o.padInfo.top,h=o.outChannels/o.inChannels,f=oe(o.outShape,e.dtype),p=this.readSync(e.dataId),d=this.readSync(n.dataId),v=f.values,m=0;m<o.batchSize;++m)for(var g=m*e.strides[0],x=m*f.strides[0],b=0;b<o.outHeight;++b)for(var y=x+b*f.strides[1],w=b*o.strideHeight-c,C=0;C<a;++C){var S=w+C*s;if(!(S<0||S>=o.inHeight))for(var k=C*n.strides[0],R=g+S*e.strides[1],E=0;E<o.outWidth;++E)for(var T=y+E*f.strides[2],A=E*o.strideWidth-l,P=0;P<i;++P){var O=A+P*u;if(!(O<0||O>=o.inWidth))for(var B=k+P*n.strides[1],V=R+O*o.inChannels,W=T,U=B,G=0;G<o.inChannels;++G){for(var H=p[V+G],q=0;q<h;++q)v[W+q]+=H*d[U+q];W+=h,U+=h}}}return f.toTensor()},t.prototype.depthwiseConv2DDerInput=function(e,n,o){z([e,n],"depthwiseConv2DDerInput");for(var a=oe(o.inShape,"float32"),i=a.values,s=a.strides,u=s[0],c=s[1],l=s[2],h=this.readSync(e.dataId),f=e.strides,p=f[0],d=f[1],v=f[2],m=this.readSync(n.dataId),g=n.strides,x=g[0],b=g[1],y=g[2],w=o.batchSize,C=o.filterHeight,S=o.filterWidth,k=o.inChannels,R=o.inHeight,E=o.inWidth,T=o.outChannels,A=o.outHeight,P=o.outWidth,O=o.strideHeight,B=o.strideWidth,V=C-1-o.padInfo.top,W=S-1-o.padInfo.left,U=T/k,G=0;G<w;++G)for(var H=0;H<k;++H)for(var q=0;q<R;++q)for(var ee=q-V,te=Math.max(0,Math.ceil(ee/O)),ie=Math.min(A,(C+ee)/O),se=0;se<E;++se){for(var ce=se-W,pe=Math.max(0,Math.ceil(ce/B)),he=Math.min(P,(S+ce)/B),de=0,Ae=te;Ae<ie;++Ae)for(var fe=Ae*O-ee,be=pe;be<he;++be)for(var ge=p*G+d*Ae+v*be,Se=x*(C-1-fe)+b*(S-1-(be*B-ce))+y*H,_e=0;_e<U;++_e)de+=h[ge+(H*U+_e)]*m[Se+_e];i[u*G+c*q+l*se+H]=de}return a.toTensor()},t.prototype.depthwiseConv2DDerFilter=function(e,n,o){z([e,n],"depthwiseConv2DDerFilter");for(var a=o.strideHeight,i=o.strideWidth,s=o.filterHeight,u=o.filterWidth,c=oe(o.filterShape,"float32"),l=o.padInfo.left,h=o.padInfo.top,f=o.outChannels/o.inChannels,p=this.bufferSync(e),d=this.bufferSync(n),v=0;v<s;++v)for(var m=Math.max(0,Math.ceil((h-v)/a)),g=Math.min(o.outHeight,(o.inHeight+h-v)/a),x=0;x<u;++x)for(var b=Math.max(0,Math.ceil((l-x)/i)),y=Math.min(o.outWidth,(o.inWidth+l-x)/i),w=0;w<o.outChannels;++w){for(var C=Math.trunc(w/f),S=w%f,k=0,R=0;R<o.batchSize;++R)for(var E=m;E<g;++E)for(var T=v+E*a-h,A=b;A<y;++A){var P=x+A*i-l;k+=p.get(R,T,P,C)*d.get(R,E,A,w)}c.set(k,v,x,C,S)}return c.toTensor()},t.prototype.tile=function(e,n){return z(e,"tile"),lu(this.bufferSync(e),n)},t.prototype.pad=function(e,n,o){z(e,"pad");var a=n.map((function(f,p){return f[0]+e.shape[p]+f[1]})),i=n.map((function(f){return f[0]})),s=this.bufferSync(e),u=oe(a,e.dtype);o!==0&&u.values.fill(o);for(var c=0;c<e.size;c++){var l=s.indexToLoc(c),h=l.map((function(f,p){return f+i[p]}));u.set.apply(u,[s.get.apply(s,l)].concat(h))}return u.toTensor()},t.prototype.transpose=function(e,n){z(e,"transpose");for(var o=new Array(e.rank),a=0;a<o.length;a++)o[a]=e.shape[n[a]];var i=this.readSync(e.dataId),s=oe(o,e.dtype),u=this.bufferSync(e);for(a=0;a<e.size;++a){for(var c=u.indexToLoc(a),l=new Array(c.length),h=0;h<l.length;h++)l[h]=c[n[h]];var f=s.locToIndex(l);s.values[f]=i[a]}return s.toTensor()},t.prototype.gather=function(e,n,o){z([e,n],"gather");var a=e.shape.slice(),i=this.readSync(n.dataId);a[o]=i.length;for(var s=oe(a,e.dtype),u=this.bufferSync(e),c=0;c<s.size;++c){var l=s.indexToLoc(c),h=l.slice();h[o]=i[l[o]];var f=u.locToIndex(h);s.values[c]=u.values[f]}return s.toTensor()},t.prototype.batchToSpaceND=function(e,n,o){z([e],"batchToSpaceND");var a=n.reduce((function(h,f){return h*f})),i=Gr(e.shape,n,a),s=Hr(i.length,n.length),u=jr(e.shape,n,a),c=Js(o,n.length),l=Qs(u,o,n.length);return e.reshape(i).transpose(s).reshape(u).slice(c,l)},t.prototype.spaceToBatchND=function(e,n,o){z([e],"spaceToBatchND");var a=n.reduce((function(f,p){return f*p})),i=[[0,0]];i.push.apply(i,o);for(var s=1+n.length;s<e.shape.length;++s)i.push([0,0]);var u=e.pad(i),c=Gr(u.shape,n,a,!1),l=Hr(c.length,n.length,!1),h=jr(u.shape,n,a,!1);return u.reshape(c).transpose(l).reshape(h)},t.prototype.pool=function(e,n,o){z(e,"pool");for(var a=n.strideHeight,i=n.strideWidth,s=n.dilationHeight,u=n.dilationWidth,c=n.effectiveFilterHeight,l=n.effectiveFilterWidth,h=n.padInfo.top,f=n.padInfo.left,p=o==="max"?Number.NEGATIVE_INFINITY:Number.POSITIVE_INFINITY,d=this.readSync(e.dataId),v=oe(n.outShape,e.dtype),m=v.values,g=n.outShape[1]*n.outShape[2]*n.outShape[3],x=n.outShape[2]*n.outShape[3],b=n.outShape[3],y=0;y<n.batchSize;++y)for(var w=y*g,C=y*e.strides[0],S=0;S<n.inChannels;++S)for(var k=0;k<n.outHeight;++k)for(var R=k*a-h,E=Math.max(0,R),T=Math.min(n.inHeight,c+R),A=w+k*x,P=0;P<n.outWidth;++P){for(var O=P*i-f,B=Math.max(0,O),V=Math.min(n.inWidth,l+O),W=p,U=0,G=0,H=E;H<T;H+=s){for(var q=C+H*e.strides[1],ee=B;ee<V;ee+=u){var te=d[q+ee*e.strides[2]+S];o==="max"&&te>W?W=te:o==="avg"&&(U+=te,G++)}if(isNaN(W))break}m[A+P*b+S]=o==="avg"?U/G:W}return v.toTensor()},t.prototype.maxPool=function(e,n){return this.pool(e,n,"max")},t.prototype.maxPoolPositions=function(e,n){for(var o=oe(n.outShape,"int32"),a=n.strideHeight,i=n.strideWidth,s=n.dilationHeight,u=n.dilationWidth,c=n.effectiveFilterHeight,l=n.effectiveFilterWidth,h=n.padInfo.top,f=n.padInfo.left,p=this.bufferSync(e),d=0;d<n.batchSize;++d)for(var v=0;v<n.inChannels;++v)for(var m=0;m<n.outHeight;++m){for(var g=m*a-h,x=g;x<0;)x+=s;for(var b=Math.min(n.inHeight,c+g),y=0;y<n.outWidth;++y){for(var w=y*i-f,C=w;C<0;)C+=u;for(var S=Math.min(n.inWidth,l+w),k=Number.NEGATIVE_INFINITY,R=-1,E=x;E<b;E+=s)for(var T=E-g,A=C;A<S;A+=u){var P=A-w,O=p.get(d,E,A,v);O>k&&(k=O,R=T*l+P)}o.set(R,d,m,y,v)}}return o.toTensor()},t.prototype.maxPoolBackprop=function(e,n,o,a){z([n,o],"maxPoolBackprop");for(var i=this.maxPoolPositions(n,a),s=a.strideHeight,u=a.strideWidth,c=a.dilationHeight,l=a.dilationWidth,h=a.effectiveFilterHeight,f=a.effectiveFilterWidth,p=f-1-a.padInfo.left,d=h-1-a.padInfo.top,v=oe(n.shape,"float32"),m=this.bufferSync(i),g=this.bufferSync(e),x=0;x<a.batchSize;++x)for(var b=0;b<a.inChannels;++b)for(var y=0;y<a.inHeight;++y)for(var w=0;w<a.inWidth;++w){for(var C=y-d,S=w-p,k=0,R=0;R<h;R+=c){var E=(C+R)/s;if(!(E<0||E>=a.outHeight||Math.floor(E)!==E))for(var T=0;T<f;T+=l){var A=(S+T)/u;if(!(A<0||A>=a.outWidth||Math.floor(A)!==A)){var P=h*f-1-m.get(x,E,A,b)===R*f+T?1:0;P!==0&&(k+=g.get(x,E,A,b)*P)}}}v.set(k,x,y,w,b)}return v.toTensor()},t.prototype.avgPoolBackprop=function(e,n,o){z([e,n],"avgPoolBackprop");for(var a=o.strideHeight,i=o.strideWidth,s=o.filterHeight,u=o.filterWidth,c=o.dilationHeight,l=o.dilationWidth,h=o.effectiveFilterHeight,f=o.effectiveFilterWidth,p=f-1-o.padInfo.left,d=h-1-o.padInfo.top,v=oe(n.shape,"float32"),m=1/(s*u),g=this.bufferSync(e),x=0;x<o.batchSize;++x)for(var b=0;b<o.inChannels;++b)for(var y=0;y<o.inHeight;++y)for(var w=0;w<o.inWidth;++w){for(var C=y-d,S=w-p,k=0,R=0;R<h;R+=c){var E=(C+R)/a;if(!(E<0||E>=o.outHeight||Math.floor(E)!==E))for(var T=0;T<f;T+=l){var A=(S+T)/i;A<0||A>=o.outWidth||Math.floor(A)!==A||(k+=g.get(x,E,A,b))}}v.set(k*m,x,y,w,b)}return v.toTensor()},t.prototype.pool3d=function(e,n,o){z(e,"pool3d");for(var a=n.strideDepth,i=n.strideHeight,s=n.strideWidth,u=n.dilationDepth,c=n.dilationHeight,l=n.dilationWidth,h=n.effectiveFilterDepth,f=n.effectiveFilterHeight,p=n.effectiveFilterWidth,d=n.padInfo.front,v=n.padInfo.top,m=n.padInfo.left,g=o==="max"?Number.NEGATIVE_INFINITY:Number.POSITIVE_INFINITY,x=this.readSync(e.dataId),b=oe(n.outShape,e.dtype),y=b.values,w=n.outShape[1]*n.outShape[2]*n.outShape[3]*n.outShape[4],C=n.outShape[2]*n.outShape[3]*n.outShape[4],S=n.outShape[3]*n.outShape[4],k=n.outShape[4],R=0;R<n.batchSize;++R)for(var E=R*w,T=R*e.strides[0],A=0;A<n.inChannels;++A)for(var P=0;P<n.outDepth;++P){for(var O=P*a-d,B=O;B<0;)B+=u;for(var V=Math.min(n.inDepth,h+O),W=E+P*C,U=0;U<n.outHeight;++U){for(var G=U*i-v,H=G;H<0;)H+=c;for(var q=Math.min(n.inHeight,f+G),ee=W+U*S,te=0;te<n.outWidth;++te){for(var ie=te*s-m,se=ie;se<0;)se+=l;for(var ce=Math.min(n.inWidth,p+ie),pe=ee+te*k,he=g,de=0,Ae=0,fe=B;fe<V;fe+=u){for(var be=T+fe*e.strides[1],ge=H;ge<q;ge+=c){for(var Se=be+ge*e.strides[2],_e=se;_e<ce;_e+=l){var Ee=x[Se+_e*e.strides[3]+A];if(o==="max"&&Ee>he?he=Ee:o==="avg"&&(de+=Ee,Ae++),isNaN(he))break}if(isNaN(he))break}if(isNaN(he))break}y[pe+A]=o==="avg"?de/Ae:he}}}return b.toTensor()},t.prototype.avgPool3d=function(e,n){return z(e,"avgPool3d"),this.pool3d(e,n,"avg").toFloat()},t.prototype.avgPool3dBackprop=function(e,n,o){z([e,n],"avgPool3dBackprop");for(var a=o.strideDepth,i=o.strideHeight,s=o.strideWidth,u=o.filterDepth,c=o.filterHeight,l=o.filterWidth,h=o.dilationDepth,f=o.dilationHeight,p=o.dilationWidth,d=o.effectiveFilterDepth,v=o.effectiveFilterHeight,m=o.effectiveFilterWidth,g=d-1-o.padInfo.front,x=m-1-o.padInfo.left,b=v-1-o.padInfo.top,y=oe(n.shape,"float32"),w=1/(u*c*l),C=this.bufferSync(e),S=0;S<o.batchSize;++S)for(var k=0;k<o.inChannels;++k)for(var R=0;R<o.inDepth;++R)for(var E=0;E<o.inHeight;++E)for(var T=0;T<o.inWidth;++T){for(var A=R-g,P=E-b,O=T-x,B=0,V=0;V<d;V+=h){var W=(A+V)/a;if(!(W<0||W>=o.outDepth||Math.floor(W)!==W))for(var U=0;U<v;U+=f){var G=(P+U)/i;if(!(G<0||G>=o.outHeight||Math.floor(G)!==G))for(var H=0;H<m;H+=p){var q=(O+H)/s;q<0||q>=o.outWidth||Math.floor(q)!==q||(B+=C.get(S,W,G,q,k))}}}y.set(B*w,S,R,E,T,k)}return y.toTensor()},t.prototype.maxPool3d=function(e,n){return z(e,"maxPool3d"),this.pool3d(e,n,"max").toFloat()},t.prototype.maxPool3dPositions=function(e,n){for(var o=oe(n.outShape,"int32"),a=n.strideDepth,i=n.strideHeight,s=n.strideWidth,u=n.dilationDepth,c=n.dilationHeight,l=n.dilationWidth,h=n.effectiveFilterDepth,f=n.effectiveFilterHeight,p=n.effectiveFilterWidth,d=n.padInfo.front,v=n.padInfo.top,m=n.padInfo.left,g=this.bufferSync(e),x=0;x<n.batchSize;++x)for(var b=0;b<n.inChannels;++b)for(var y=0;y<n.outDepth;++y){for(var w=y*a-d,C=w;C<0;)C+=u;for(var S=Math.min(n.inDepth,h+w),k=0;k<n.outHeight;++k){for(var R=k*i-v,E=R;E<0;)E+=c;for(var T=Math.min(n.inHeight,f+R),A=0;A<n.outWidth;++A){for(var P=A*s-m,O=P;O<0;)O+=l;for(var B=Math.min(n.inWidth,p+P),V=Number.NEGATIVE_INFINITY,W=-1,U=C;U<S;U+=u)for(var G=U-w,H=E;H<T;H+=c)for(var q=H-R,ee=O;ee<B;ee+=l){var te=ee-P,ie=g.get(x,U,H,ee,b);ie>=V&&(V=ie,W=G*f*p+q*f+te)}o.set(W,x,y,k,A,b)}}}return o.toTensor()},t.prototype.maxPool3dBackprop=function(e,n,o,a){z([n,o],"maxPool3dBackprop");for(var i=this.maxPool3dPositions(n,a),s=a.strideDepth,u=a.strideHeight,c=a.strideWidth,l=a.dilationDepth,h=a.dilationHeight,f=a.dilationWidth,p=a.effectiveFilterDepth,d=a.effectiveFilterHeight,v=a.effectiveFilterWidth,m=p-1-a.padInfo.front,g=v-1-a.padInfo.left,x=d-1-a.padInfo.top,b=oe(n.shape,"float32"),y=this.bufferSync(i),w=this.bufferSync(e),C=0;C<a.batchSize;++C)for(var S=0;S<a.inChannels;++S)for(var k=0;k<a.inDepth;++k)for(var R=0;R<a.inHeight;++R)for(var E=0;E<a.inWidth;++E){for(var T=k-m,A=R-x,P=E-g,O=0,B=0;B<p;B+=l){var V=(T+B)/s;if(!(V<0||V>=a.outDepth||Math.floor(V)!==V))for(var W=0;W<d;W+=h){var U=(A+W)/u;if(!(U<0||U>=a.outHeight||Math.floor(U)!==U))for(var G=0;G<v;G+=f){var H=(P+G)/c;if(!(H<0||H>=a.outWidth||Math.floor(H)!==H)){var q=p*d*v-1-y.get(C,V,U,H,S)===B*d*v+W*v+G?1:0;q!==0&&(O+=w.get(C,V,U,H,S)*q)}}}}b.set(O,C,k,R,E,S)}return b.toTensor()},t.prototype.cast=function(e,n){return iu(e,n,this)},t.prototype.reshape=function(e,n){return fa(e,n)},t.prototype.avgPool=function(e,n){return z(e,"avgPool"),this.pool(e,n,"avg").toFloat()},t.prototype.resizeBilinear=function(e,n,o,a){z(e,"resizeBilinear");for(var i=e.shape,s=i[0],u=i[1],c=i[2],l=i[3],h=this.readSync(e.dataId),f=new Float32Array(Y([s,n,o,l])),p=[a&&n>1?u-1:u,a&&o>1?c-1:c],d=[a&&n>1?n-1:n,a&&o>1?o-1:o],v=0,m=p[0]/d[0],g=p[1]/d[1],x=0;x<s;x++)for(var b=0;b<n;b++)for(var y=m*b,w=Math.floor(y),C=y-w,S=Math.min(u-1,Math.ceil(y)),k=x*e.strides[0]+w*e.strides[1],R=x*e.strides[0]+S*e.strides[1],E=0;E<o;E++)for(var T=g*E,A=Math.floor(T),P=T-A,O=Math.min(c-1,Math.ceil(T)),B=k+A*e.strides[2],V=R+A*e.strides[2],W=k+O*e.strides[2],U=R+O*e.strides[2],G=0;G<l;G++){var H=h[B+G],q=h[V+G],ee=H+(h[W+G]-H)*P,te=ee+(q+(h[U+G]-q)*P-ee)*C;f[v++]=te}return je(f,[s,n,o,l])},t.prototype.resizeBilinearBackprop=function(e,n,o){z([e,n],"resizeBilinearBackprop");for(var a=n.shape,i=a[0],s=a[1],u=a[2],c=a[3],l=e.shape,h=l[1],f=l[2],p=new Float32Array(i*s*u*c),d=[o&&h>1?s-1:s,o&&f>1?u-1:u],v=[o&&h>1?h-1:h,o&&f>1?f-1:f],m=d[0]/v[0],g=d[1]/v[1],x=this.readSync(e.dataId),b=0,y=0;y<i;y++)for(var w=y*n.strides[0],C=0;C<h;C++)for(var S=C*m,k=Math.floor(S),R=Math.min(Math.ceil(S),s-1),E=w+k*n.strides[1],T=w+R*n.strides[1],A=S-k,P=1-A,O=0;O<f;O++)for(var B=O*g,V=Math.floor(B),W=Math.min(Math.ceil(B),u-1),U=B-V,G=1-U,H=E+V*n.strides[2],q=E+W*n.strides[2],ee=T+V*n.strides[2],te=T+W*n.strides[2],ie=P*G,se=P*U,ce=A*G,pe=A*U,he=0;he<c;he++){var de=x[b++];p[H+he]+=de*ie,p[q+he]+=de*se,p[ee+he]+=de*ce,p[te+he]+=de*pe}return Ze(p,[i,u,s,c],n.dtype)},t.prototype.resizeNearestNeighbor=function(e,n,o,a){z(e,"resizeNearestNeighbor");for(var i=e.shape,s=i[0],u=i[1],c=i[2],l=i[3],h=this.readSync(e.dataId),f=new Float32Array(s*n*o*l),p=[a&&n>1?u-1:u,a&&o>1?c-1:c],d=[a&&n>1?n-1:n,a&&o>1?o-1:o],v=p[0]/d[0],m=p[1]/d[1],g=0,x=0;x<s;x++)for(var b=x*e.strides[0],y=0;y<n;y++)for(var w=v*y,C=b+Math.min(u-1,a?Math.round(w):Math.floor(w))*e.strides[1],S=0;S<o;S++)for(var k=m*S,R=C+Math.min(c-1,a?Math.round(k):Math.floor(k))*e.strides[2],E=0;E<l;E++){var T=h[R+E];f[g++]=T}return je(f,[s,n,o,l],e.dtype)},t.prototype.resizeNearestNeighborBackprop=function(e,n,o){z([e,n],"resizeNearestNeighborBackprop");for(var a=n.shape,i=a[0],s=a[1],u=a[2],c=a[3],l=e.shape,h=l[1],f=l[2],p=new Float32Array(i*s*u*c),d=this.readSync(e.dataId),v=[o&&h>1?s-1:s,o&&f>1?u-1:u],m=[o&&h>1?h-1:h,o&&f>1?f-1:f],g=v[0]/m[0],x=v[1]/m[1],b=1/g,y=1/x,w=2*Math.ceil(b)+2,C=2*Math.ceil(y)+2,S=0;S<i;S++)for(var k=S*n.strides[0],R=0;R<s;R++)for(var E=k+R*n.strides[1],T=Math.floor(R*b),A=Math.floor(T-w/2),P=0;P<u;P++)for(var O=E+P*n.strides[2],B=Math.floor(P*y),V=Math.floor(B-C/2),W=0;W<c;W++){for(var U=0,G=0;G<w;G++){var H=G+A;if(!(H<0||H>=h)){var q=k+H*e.strides[1],ee=H*g;if(R===Math.min(s-1,o?Math.round(ee):Math.floor(ee)))for(var te=0;te<C;te++){var ie=te+V;if(!(ie<0||ie>=f)){var se=q+ie*e.strides[2],ce=ie*x;P===Math.min(u-1,o?Math.round(ce):Math.floor(ce))&&(U+=d[se+W])}}}}p[O+W]=U}return Ze(p,n.shape,n.dtype)},t.prototype.batchNormalization=function(e,n,o,a,i,s){z([e,n,o,i,s],"batchNorm");for(var u=this.readSync(e.dataId),c=this.readSync(n.dataId),l=this.readSync(o.dataId),h=i?this.readSync(i.dataId):new Float32Array([1]),f=s?this.readSync(s.dataId):new Float32Array([0]),p=new Float32Array(u.length),d=f.length,v=h.length,m=l.length,g=c.length,x=0,b=0,y=0,w=0,C=0;C<u.length;++C)p[C]=f[x++]+(u[C]-c[b++])*h[y++]/Math.sqrt(l[w++]+a),x>=d&&(x=0),b>=g&&(b=0),y>=v&&(y=0),w>=m&&(w=0);return Ze(p,e.shape)},t.prototype.localResponseNormalization4D=function(e,n,o,a,i){z(e,"localResponseNormalization4D");var s=e.shape[3],u=s-1,c=this.readSync(e.dataId),l=e.size,h=new Float32Array(l);function f(m){for(var g=m%s,x=m-g+Math.max(0,g-n),b=m-g+Math.min(g+n,u),y=0;x<=b;x++){var w=c[x];y+=w*w}return y}for(var p=0;p<l;p++){var d=f(p),v=c[p]*Math.pow(o+a*d,-i);h[p]=v}return Ze(h,e.shape)},t.prototype.LRNGrad=function(e,n,o,a,i,s,u){z(e,"LRNGrad");for(var c=e.shape[3],l=this.readSync(e.dataId),h=this.readSync(n.dataId),f=this.readSync(o.dataId),p=new Float32Array(e.size),d=e.size,v=0;v<d;v++){for(var m=v%c,g=v-m+Math.max(0,m-a),x=v-m+Math.min(c,m+a+1),b=0,y=g;y<x;y++)b+=Math.pow(h[y],2);for(b=s*b+i,y=g;y<x;y++){var w=-2*s*u*h[y]*f[v]/b;v===y&&(w+=Math.pow(b,-u)),w*=l[v],p[y]+=w}}return Ze(p,e.shape)},t.prototype.multinomial=function(e,n,o,a){z(e,"multinomial");for(var i=n?e:qt(e),s=i.shape[0],u=i.shape[1],c=Ce([s,o],"int32"),l=this.readSync(c.dataId),h=this.readSync(i.dataId),f=0;f<s;++f){var p=f*u,d=new Float32Array(u-1);d[0]=h[p];for(var v=1;v<d.length;++v)d[v]=d[v-1]+h[p+v];for(var m=ao(a.toString()),g=f*o,x=0;x<o;++x){var b=m();l[g+x]=d.length;for(var y=0;y<d.length;y++)if(b<d[y]){l[g+x]=y;break}}}return c},t.prototype.oneHot=function(e,n,o,a){z(e,"oneHot");var i=new Float32Array(e.size*n);i.fill(a);for(var s=this.readSync(e.dataId),u=0;u<e.size;++u)s[u]>=0&&s[u]<n&&(i[u*n+s[u]]=o);return nn(i,[e.size,n],"int32")},t.prototype.nonMaxSuppression=function(e,n,o,a,i){return z(e,"nonMaxSuppression"),Na(this.readSync(e.dataId),this.readSync(n.dataId),o,a,i)},t.prototype.fft=function(e){return this.fftBatch(e,!1)},t.prototype.ifft=function(e){return this.fftBatch(e,!0)},t.prototype.fftBatch=function(e,n){for(var o=e.shape[0],a=e.shape[1],i=oe(e.shape,"float32"),s=oe(e.shape,"float32"),u=ft(e).as2D(o,a),c=St(e).as2D(o,a),l=0;l<o;l++)for(var h=u.slice([l,0],[1,a]),f=c.slice([l,0],[1,a]),p=Ge(h,f),d=this.readSync(this.fftImpl(p,n).dataId),v=0;v<a;v++){var m=Wi(d,v);i.values[l*a+v]=m.real,s.values[l*a+v]=m.imag}return Ge(i.toTensor(),s.toTensor()).as2D(o,a)},t.prototype.fftImpl=function(e,n){var o=e.as1D(),a=o.size;if(this.isExponentOf2(a)){var i=this.fftRadix2(o,a,n).as2D(e.shape[0],e.shape[1]);return n&&(i=Ge(ft(i).div(j(a)),St(i).div(j(a)))),i}var s=this.readSync(e.dataId),u=(function(c){for(var l=new Float32Array(c.length/2),h=new Float32Array(c.length/2),f=0;f<c.length;f+=2)l[f/2]=c[f],h[f/2]=c[f+1];return{real:l,imag:h}})(this.fourierTransformByMatmul(s,a,n));return Ge(u.real,u.imag).as2D(e.shape[0],e.shape[1])},t.prototype.isExponentOf2=function(e){return(e&e-1)==0},t.prototype.fftRadix2=function(e,n,o){if(n===1)return e;var a=this.readSync(e.dataId),i=n/2,s=(function(g){for(var x=Math.ceil(g.length/4),b=new Float32Array(x),y=new Float32Array(x),w=0;w<g.length;w+=4)b[Math.floor(w/4)]=g[w],y[Math.floor(w/4)]=g[w+1];return{real:b,imag:y}})(a),u=Ge(s.real,s.imag).as1D(),c=(function(g){for(var x=Math.floor(g.length/4),b=new Float32Array(x),y=new Float32Array(x),w=2;w<g.length;w+=4)b[Math.floor(w/4)]=g[w],y[Math.floor(w/4)]=g[w+1];return{real:b,imag:y}})(a),l=Ge(c.real,c.imag).as1D();u=this.fftRadix2(u,i,o),l=this.fftRadix2(l,i,o);var h=(function(g,x){for(var b=new Float32Array(g/2),y=new Float32Array(g/2),w=0;w<Math.ceil(g/2);w++){var C=(x?2:-2)*Math.PI*(w/g);b[w]=Math.cos(C),y[w]=Math.sin(C)}return{real:b,imag:y}})(n,o),f=Ge(h.real,h.imag).mul(l),p=u.add(f),d=u.sub(f),v=ft(p).concat(ft(d)),m=St(p).concat(St(d));return Ge(v,m).as1D()},t.prototype.fourierTransformByMatmul=function(e,n,o){for(var a=new Float32Array(2*n),i=0;i<n;i++){for(var s=0,u=0,c=0;c<n;c++){var l=Mh(i*c,n,o),h=Wi(e,c);s+=h.real*l.real-h.imag*l.imag,u+=h.real*l.imag+h.imag*l.real}o&&(s/=n,u/=n),Ph(a,s,u,i)}return a},t.prototype.depthToSpace=function(e,n,o){I(o==="NHWC",(function(){return"Only NHWC dataFormat supported on CPU for depthToSpace. Got "+o})),I(n>1,(function(){return"blockSize should be > 1 for depthToSpace, but was: "+n}));for(var a=e.shape[0],i=e.shape[1],s=e.shape[2],u=e.shape[3],c=i*n,l=s*n,h=u/(n*n),f=this.readSync(e.dataId),p=new Float32Array(a*c*l*h),d=0,v=0;v<a;++v)for(var m=0;m<c;++m)for(var g=Math.floor(m/n),x=m%n,b=0;b<l;++b)for(var y=Math.floor(b/n),w=(x*n+b%n)*h,C=0;C<h;++C){var S=C+w+u*(y+s*(g+i*v));p[d++]=f[S]}return Ze(p,[a,c,l,h])},t.prototype.broadcastedBinaryOp=function(e,n,o,a){var i=le(e.shape,n.shape),s=oe(i,o),u=this.readSync(e.dataId),c=this.readSync(n.dataId),l=en(e.shape,i),h=en(n.shape,i),f=s.values;if(l.length+h.length===0)for(var p=0;p<f.length;++p)f[p]=a(u[p%u.length],c[p%c.length]);else{var d=this.bufferSync(e),v=this.bufferSync(n),m=function(g){var x=s.indexToLoc(g),b=x.slice(-e.rank);l.forEach((function(S){return b[S]=0}));var y=d.locToIndex(b),w=x.slice(-n.rank);h.forEach((function(S){return w[S]=0}));var C=v.locToIndex(w);f[g]=a(u[y],c[C])};for(p=0;p<f.length;++p)m(p)}return s.toTensor()},t.prototype.broadcastedBinaryComplexOp=function(e,n,o){var a=le(e.shape,n.shape),i=oe(a,"float32"),s=oe(a,"float32"),u=this.readSync(e.dataId),c=this.readSync(n.dataId),l=en(e.shape,a),h=en(n.shape,a),f=i.values,p=s.values;if(l.length+h.length===0)for(var d=0;d<f.length;d++){var v=d%u.length,m=d%c.length,g=o(u[2*v],u[2*v+1],c[2*m],c[2*m+1]);f[d]=g.real,p[d]=g.imag}else{var x=this.bufferSync(this.data.get(e.dataId).complexTensors.real),b=this.bufferSync(this.data.get(n.dataId).complexTensors.real),y=function(w){var C=i.indexToLoc(w),S=C.slice(-e.rank);l.forEach((function(A){return S[A]=0}));var k=x.locToIndex(S),R=C.slice(-n.rank);h.forEach((function(A){return R[A]=0}));var E=b.locToIndex(R),T=o(u[2*k],u[2*k+1],c[2*E],c[2*E+1]);f[w]=T.real,p[w]=T.imag};for(d=0;d<f.length;d++)y(d)}return this.complex(i.toTensor(),s.toTensor())},t.prototype.split=function(e,n,o){return cu(e,n,o)},t.prototype.dispose=function(){},t.prototype.floatPrecision=function(){return 32},t.prototype.epsilon=function(){return 1e-7},t.prototype.cropAndResize=function(e,n,o,a,i,s){for(var u=e.shape,c=u[0],l=u[1],h=u[2],f=u[3],p=n.shape[0],d=a[0],v=a[1],m=oe([p,d,v,f],"float32"),g=this.readSync(n.dataId),x=this.readSync(o.dataId),b=this.readSync(e.dataId),y=e.strides,w=m.strides,C=0;C<p;C++){var S=4*C,k=g[S],R=g[S+1],E=g[S+2],T=g[S+3],A=x[C];if(!(A>=c))for(var P=d>1?(E-k)*(l-1)/(d-1):0,O=v>1?(T-R)*(h-1)/(v-1):0,B=0;B<d;B++){var V=d>1?k*(l-1)+B*P:.5*(k+E)*(l-1);if(V<0||V>l-1)for(var W=0;W<v;W++)for(var U=0;U<f;U++){var G=U+W*w[2]+B*w[1]+C*w[0];m.values[G]=s}else if(i==="bilinear"){var H=Math.floor(V),q=Math.ceil(V),ee=V-H;for(W=0;W<v;W++)if((fe=v>1?R*(h-1)+W*O:.5*(R+T)*(h-1))<0||fe>h-1)for(U=0;U<f;U++)G=U+W*w[2]+B*w[1]+C*w[0],m.values[G]=s;else{var te=Math.floor(fe),ie=Math.ceil(fe),se=fe-te;for(U=0;U<f;U++){var ce=b[G=U+te*y[2]+H*y[1]+A*y[0]],pe=b[G=U+ie*y[2]+H*y[1]+A*y[0]],he=b[G=U+te*y[2]+q*y[1]+A*y[0]],de=ce+(pe-ce)*se,Ae=he+(b[G=U+ie*y[2]+q*y[1]+A*y[0]]-he)*se;G=U+W*w[2]+B*w[1]+C*w[0],m.values[G]=de+(Ae-de)*ee}}}else for(W=0;W<v;++W){var fe;if((fe=v>1?R*(h-1)+W*O:.5*(R+T)*(h-1))<0||fe>h-1)for(U=0;U<f;U++)G=U+W*w[2]+B*w[1]+C*w[0],m.values[G]=s;else{var be=Math.round(fe),ge=Math.round(V);for(U=0;U<f;U++){var Se=U+be*y[2]+ge*y[1]+A*y[0],_e=U+W*w[2]+B*w[1]+C*w[0];m.values[_e]=b[Se]}}}}}return m.toTensor()},t.prototype.sparseToDense=function(e,n,o,a){var i=qr(0,e,o),s=i.sliceRank,u=i.numUpdates,c=i.sliceSize,l=i.strides,h=i.outputSize;return this.scatter(e,n,o,h,c,u,s,l,a,!1)},t.prototype.gatherND=function(e,n){var o=n.shape,a=o[o.length-1],i=Zs(e,n),s=i[0],u=i[1],c=i[2],l=i[3];if(u===0)return je([],s,e.dtype);for(var h=new or([u,c],e.dtype),f=this.readSync(n.dataId),p=this.readSync(e.dataId),d=0;d<u;d++){for(var v=[],m=0,g=0;g<a;g++){var x=f[d*a+g];m+=x*l[g],v.push(x)}if(m<0||m>=e.size/c)throw new Error("Invalid indices: "+v+" does not index into "+e.shape);for(var b=0;b<c;b++)h.values[d*c+b]=p[m*c+b]}return h.toTensor().reshape(s)},t.prototype.scatterND=function(e,n,o){var a=qr(0,e,o),i=a.sliceRank,s=a.numUpdates,u=a.sliceSize,c=a.strides,l=a.outputSize,h=j(0);return this.scatter(e,n,o,l,u,s,i,c,h,!0)},t.prototype.fill=function(e,n,o){var a=Or(o=o||lr(n),Y(e));return a.fill(n),N.makeTensor(a,e,o,this)},t.prototype.onesLike=function(e){if(e.dtype==="string")throw new Error("onesLike is not supported for string tensors");return this.fill(e.shape,1,e.dtype)},t.prototype.zerosLike=function(e){var n=Or(e.dtype,Y(e.shape));return this.makeOutput(n,e.shape,e.dtype)},t.prototype.linspace=function(e,n,o){return su(e,n,o)},t.prototype.scatter=function(e,n,o,a,i,s,u,c,l,h){var f=[a/i,i],p=this.readSync(e.dataId),d=this.readSync(n.dataId);if(a===0)return je([],o,n.dtype);var v=new or(f,n.dtype);v.values.fill(this.readSync(l.dataId)[0]);for(var m=0;m<s;m++){for(var g=[],x=0,b=0;b<u;b++){var y=p[m*u+b];g.push(y),x+=y*c[b]}if(x<0||x>=a/i)throw new Error("Invalid indices: "+g+" does not index into "+o);for(var w=0;w<i;w++)h?v.values[x*i+w]+=d[m*i+w]:v.values[x*i+w]=n.rank===0?d[0]:d[m*i+w]}return v.toTensor().reshape(o)},t})(ou);N.registerBackend("cpu",(function(){return new nm}),1);for(var jo=0,ss=[{kernelName:"NonMaxSuppressionV5",backendName:"cpu",kernelFunc:function(r){var t=r.inputs,e=r.backend,n=r.attrs,o=t,a=o.boxes,i=o.scores,s=n,u=s.maxOutputSize,c=s.iouThreshold,l=s.scoreThreshold,h=s.softNmsSigma,f=e;z(a,"NonMaxSuppressionWithScore");var p=Fa(f.data.get(a.dataId).values,f.data.get(i.dataId).values,u,c,l,h);return[p.selectedIndices,p.selectedScores]}},{kernelName:"Square",backendName:"cpu",kernelFunc:function(r){var t=r.inputs,e=r.backend,n=t.x,o=e;z(n,"square");for(var a=o.data.get(n.dataId).values,i=new Float32Array(a.length),s=0;s<a.length;++s){var u=a[s];i[s]=u*u}return{dataId:o.write(i,n.shape,n.dtype),shape:n.shape,dtype:n.dtype}}},{kernelName:sr,backendName:"cpu",kernelFunc:function(r){var t=r.inputs,e=r.backend,n=t,o=n.a,a=n.b,i=e;z([o,a],sr);var s=i.data.get(o.dataId).values,u=i.data.get(a.dataId).values,c=(function(f,p,d,v,m,g){var x=le(f,p),b=x.length,y=Tt(x),w=rr(m,Y(x)),C=f.length,S=p.length,k=Tt(f),R=Tt(p),E=en(f,x),T=en(p,x);if(E.length+T.length===0)for(var A=0;A<w.length;++A)w[A]=g(d[A%d.length],v[A%v.length]);else{var P=function(O){var B=hl(O,b,y),V=B.slice(-C);E.forEach((function(H){return V[H]=0}));var W=Ai(V,C,k),U=B.slice(-S);T.forEach((function(H){return U[H]=0}));var G=Ai(U,S,R);w[O]=g(d[W],v[G])};for(A=0;A<w.length;++A)P(A)}return[w,x]})(o.shape,a.shape,s,u,o.dtype,(function(f,p){var d=f-p;return d*d})),l=c[0],h=c[1];return{dataId:i.write(l,h,o.dtype),shape:h,dtype:o.dtype}}}];jo<ss.length;jo++)Ns(ss[jo]);var Dn,rm=function(r){this.variableNames=["A"];var t=Xe(),e=r[0],n=r[1];this.outputShape=r,this.userCode=`
      void main() {
        ivec3 coords = getOutputCoords();
        int texR = coords[0];
        int texC = coords[1];
        int depth = coords[2];
        vec2 uv = (vec2(texC, texR) + halfCR) / vec2(`+n+".0, "+e+`.0);

        vec4 values = `+t.texture2D+`(A, uv);
        float value;
        if (depth == 0) {
          value = values.r;
        } else if (depth == 1) {
          value = values.g;
        } else if (depth == 2) {
          value = values.b;
        } else if (depth == 3) {
          value = values.a;
        }

        setOutput(floor(value * 255.0 + 0.5));
      }
    `},om=function(r){this.variableNames=["A"],this.packedInputs=!1,this.packedOutput=!0;var t=Xe(),e=r[0],n=r[1];this.outputShape=r,this.userCode=`
      void main() {
        ivec3 coords = getOutputCoords();
        int texR = coords[0];
        int texC = coords[1];
        int depth = coords[2];

        vec4 result = vec4(0.);

        for(int row=0; row<=1; row++) {
          for(int col=0; col<=1; col++) {
            texC = coords[1] + row;
            depth = coords[2] + col;

            vec2 uv = (vec2(texC, texR) + halfCR) /
                       vec2(`+n+".0, "+e+`.0);
            vec4 values = `+t.texture2D+`(A, uv);
            float value;
            if (depth == 0) {
              value = values.r;
            } else if (depth == 1) {
              value = values.g;
            } else if (depth == 2) {
              value = values.b;
            } else if (depth == 3) {
              value = values.a;
            }

            result[row * 2 + col] = floor(value * 255.0 + 0.5);
          }
        }

        `+t.output+` = result;
      }
    `};for(var qo=0,us=[{kernelName:"FromPixels",backendName:"webgl",kernelFunc:function(r){var t=r.inputs,e=r.backend,n=r.attrs,o=t.pixels,a=n.numChannels,i=typeof HTMLVideoElement<"u"&&o instanceof HTMLVideoElement,s=typeof HTMLImageElement<"u"&&o instanceof HTMLImageElement,u=i?[o.videoWidth,o.videoHeight]:[o.width,o.height],c=u[0],l=u[1],h=[l,c],f=[l,c,a];(s||i)&&(Dn==null&&(Dn=document.createElement("canvas").getContext("2d")),Dn.canvas.width=c,Dn.canvas.height=l,Dn.drawImage(o,0,0,c,l),o=Dn.canvas);var p=e.makeTensorInfo(h,"int32");e.texData.get(p.dataId).usage=st.PIXELS,e.gpgpu.uploadPixelDataToTexture(e.getTexture(p.dataId),o);var d=L().getBool("WEBGL_PACK")?new om(f):new rm(f),v=e.runWebGLProgram(d,[p],"int32");return e.disposeData(p.dataId),v}},{kernelName:"NonMaxSuppressionV5",backendName:"webgl",kernelFunc:function(r){var t=r.inputs,e=r.backend,n=r.attrs;Ur("tf.nonMaxSuppression() in webgl locks the UI thread. Call tf.nonMaxSuppressionAsync() instead");var o=t,a=o.boxes,i=o.scores,s=n,u=s.maxOutputSize,c=s.iouThreshold,l=s.scoreThreshold,h=s.softNmsSigma,f=e,p=Fa(f.readSync(a.dataId),f.readSync(i.dataId),u,c,l,h);return[p.selectedIndices,p.selectedScores]}},{kernelName:"Square",backendName:"webgl",kernelFunc:function(r){var t=r.inputs,e=r.backend,n=t.x,o=e,a=new ae(n.shape,"return x * x;");return o.runWebGLProgram(a,[n],n.dtype)}},{kernelName:sr,backendName:"webgl",kernelFunc:function(r){var t=r.inputs,e=r.backend,n=t,o=n.a,a=n.b,i=e,s=L().getBool("WEBGL_PACK_BINARY_OPERATIONS")?new Gt("return (a - b) * (a - b);",o.shape,a.shape):new De("return (a - b) * (a - b);",o.shape,a.shape);return i.compileAndRun(s,[o,a])}}];qo<us.length;qo++)Ns(us[qo]);for(var Ko=0,cs=[{kernelName:"Square",gradFunc:function(r,t){var e=t[0];return{x:function(){return r.mul(e.toFloat().mul(2))}}}},{kernelName:sr,gradFunc:function(r,t){var e=t[0],n=t[1],o=j(2);return{a:function(){return Ye(r,Ye(o,Be(e,n)))},b:function(){return Ye(r,Ye(o,Be(n,e)))}}}}];Ko<cs.length;Ko++)el(cs[Ko]);var am=(function(){function r(){}return r.prototype.fetch=function(t,e){return fetch(t,e)},r.prototype.now=function(){return performance.now()},r.prototype.encode=function(t,e){if(e!=="utf-8"&&e!=="utf8")throw new Error("Browser's encoder only supports utf-8, but got "+e);return this.textEncoder==null&&(this.textEncoder=new TextEncoder),this.textEncoder.encode(t)},r.prototype.decode=function(t,e){return new TextDecoder(e).decode(t)},r})();L().get("IS_BROWSER")&&L().setPlatform("browser",new am);var Xo,im=function(){return require("node-fetch")},sm=(function(){function r(){this.util=require("util"),this.textEncoder=new this.util.TextEncoder}return r.prototype.fetch=function(t,e){return L().global.fetch!=null?L().global.fetch(t,e):(Xo==null&&(Xo=im()),Xo(t,e))},r.prototype.now=function(){var t=process.hrtime();return 1e3*t[0]+t[1]/1e6},r.prototype.encode=function(t,e){if(e!=="utf-8"&&e!=="utf8")throw new Error("Node built-in encoder only supports utf-8, but got "+e);return this.textEncoder.encode(t)},r.prototype.decode=function(t,e){return t.length===0?"":new this.util.TextDecoder(e).decode(t)},r})();L().get("IS_NODE")&&L().setPlatform("node",new sm);var va={float32:4,int32:4,uint16:2,uint8:1,bool:1},Zr=4;function tc(r,t){for(var e={},n=0,o=function(s){var u=s.name,c=s.dtype,l=s.shape,h=Y(l),f=void 0;if("quantization"in s){var p=s.quantization;if(p.dtype!=="uint8"&&p.dtype!=="uint16")throw new Error("Weight "+s.name+" has unknown quantization dtype "+p.dtype+". Supported quantization dtypes are: 'uint8' and 'uint16'.");var d=va[p.dtype],v=r.slice(n,n+h*d),m=p.dtype==="uint8"?new Uint8Array(v):new Uint16Array(v);if(c==="float32")f=Float32Array.from(m,(function(C){return C*p.scale+p.min}));else{if(c!=="int32")throw new Error("Unsupported dtype in weight '"+u+"': "+c);f=Int32Array.from(m,(function(C){return Math.round(C*p.scale+p.min)}))}n+=h*d}else if(c==="string"){var g=Y(s.shape);f=[];for(var x=0;x<g;x++){var b=new Uint32Array(r.slice(n,n+Zr))[0];n+=Zr;var y=new Uint8Array(r.slice(n,n+b));f.push(y),n+=b}}else{var w=va[c];if(v=r.slice(n,n+h*w),c==="float32")f=new Float32Array(v);else if(c==="int32")f=new Int32Array(v);else{if(c!=="bool")throw new Error("Unsupported dtype in weight '"+u+"': "+c);f=new Uint8Array(v)}n+=h*w}e[u]=je(f,l,c)},a=0,i=t;a<i.length;a++)o(i[a]);return e}function um(r){if(r===null)throw new Error("Invalid input value: "+JSON.stringify(r));var t=0,e=[];r.forEach((function(a){if(t+=a.byteLength,e.push(a.byteLength===a.buffer.byteLength?a:new a.constructor(a)),!(a instanceof Float32Array||a instanceof Int32Array||a instanceof Uint8Array))throw new Error("Unsupported TypedArray subtype: "+a.constructor.name)}));var n=new Uint8Array(t),o=0;return e.forEach((function(a){n.set(new Uint8Array(a.buffer),o),o+=a.byteLength})),n.buffer}var ma=typeof Buffer<"u"&&(typeof Blob>"u"||typeof atob>"u"||typeof btoa>"u");function ls(r){return ma?Buffer.byteLength(r):new Blob([r]).size}function Qa(r){var t=0;r.forEach((function(o){t+=o.byteLength}));var e=new Uint8Array(t),n=0;return r.forEach((function(o){e.set(new Uint8Array(o),n),n+=o.byteLength})),e.buffer}function hs(r){for(r=r.trim();r.endsWith("/");)r=r.slice(0,r.length-1);var t=r.split("/");return t[t.length-1]}function gr(r){if(r.modelTopology instanceof ArrayBuffer)throw new Error("Expected JSON model topology, received ArrayBuffer.");return{dateSaved:new Date,modelTopologyType:"JSON",modelTopologyBytes:r.modelTopology==null?0:ls(JSON.stringify(r.modelTopology)),weightSpecsBytes:r.weightSpecs==null?0:ls(JSON.stringify(r.weightSpecs)),weightDataBytes:r.weightData==null?0:r.weightData.byteLength}}var ut=(function(){function r(){this.saveRouters=[],this.loadRouters=[]}return r.getInstance=function(){return r.instance==null&&(r.instance=new r),r.instance},r.registerSaveRouter=function(t){r.getInstance().saveRouters.push(t)},r.registerLoadRouter=function(t){r.getInstance().loadRouters.push(t)},r.getSaveHandlers=function(t){return r.getHandlers(t,"save")},r.getLoadHandlers=function(t,e){return r.getHandlers(t,"load",e)},r.getHandlers=function(t,e,n){var o=[];return(e==="load"?r.getInstance().loadRouters:r.getInstance().saveRouters).forEach((function(a){var i=a(t,n);i!==null&&o.push(i)})),o},r})(),Wn="://",rn=(function(){function r(){this.managers={}}return r.getInstance=function(){return r.instance==null&&(r.instance=new r),r.instance},r.registerManager=function(t,e){I(t!=null,(function(){return"scheme must not be undefined or null."})),t.endsWith(Wn)&&(t=t.slice(0,t.indexOf(Wn))),I(t.length>0,(function(){return"scheme must not be an empty string."}));var n=r.getInstance();I(n.managers[t]==null,(function(){return"A model store manager is already registered for scheme '"+t+"'."})),n.managers[t]=e},r.getManager=function(t){var e=this.getInstance().managers[t];if(e==null)throw new Error("Cannot find model manager for scheme '"+t+"'");return e},r.getSchemes=function(){return Object.keys(this.getInstance().managers)},r})();function Pr(r){if(r.indexOf(Wn)===-1)throw new Error("The url string provided does not contain a scheme. Supported schemes are: "+rn.getSchemes().join(","));return{scheme:r.split(Wn)[0],path:r.split(Wn)[1]}}function fs(r,t,e){return e===void 0&&(e=!1),X(this,void 0,void 0,(function(){var n,o,a,i,s,u,c,l,h;return $(this,(function(f){switch(f.label){case 0:return I(r!==t,(function(){return"Old path and new path are the same: '"+r+"'"})),I((n=ut.getLoadHandlers(r)).length>0,(function(){return"Copying failed because no load handler is found for source URL "+r+"."})),I(n.length<2,(function(){return"Copying failed because more than one ("+n.length+") load handlers for source URL "+r+"."})),o=n[0],I((a=ut.getSaveHandlers(t)).length>0,(function(){return"Copying failed because no save handler is found for destination URL "+t+"."})),I(a.length<2,(function(){return"Copying failed because more than one ("+n.length+") save handlers for destination URL "+t+"."})),i=a[0],s=Pr(r).scheme,u=Pr(r).path,c=s===Pr(r).scheme,[4,o.load()];case 1:return l=f.sent(),e&&c?[4,rn.getManager(s).removeModel(u)]:[3,3];case 2:f.sent(),f.label=3;case 3:return[4,i.save(l)];case 4:return h=f.sent(),!e||c?[3,6]:[4,rn.getManager(s).removeModel(u)];case 5:f.sent(),f.label=6;case 6:return[2,h.modelArtifactsInfo]}}))}))}var mn="models_store",tn="model_info_store";function nc(){if(!L().getBool("IS_BROWSER"))throw new Error("Failed to obtain IndexedDB factory because the current environmentis not a web browser.");var r=window||self,t=r.indexedDB||r.mozIndexedDB||r.webkitIndexedDB||r.msIndexedDB||r.shimIndexedDB;if(t==null)throw new Error("The current browser does not appear to support IndexedDB.");return t}function ga(r){var t=r.result;t.createObjectStore(mn,{keyPath:"modelPath"}),t.createObjectStore(tn,{keyPath:"modelPath"})}var Un=(function(){function r(t){if(this.indexedDB=nc(),t==null||!t)throw new Error("For IndexedDB, modelPath must not be null, undefined or empty.");this.modelPath=t}return r.prototype.save=function(t){return X(this,void 0,void 0,(function(){return $(this,(function(e){if(t.modelTopology instanceof ArrayBuffer)throw new Error("BrowserLocalStorage.save() does not support saving model topology in binary formats yet.");return[2,this.databaseAction(this.modelPath,t)]}))}))},r.prototype.load=function(){return X(this,void 0,void 0,(function(){return $(this,(function(t){return[2,this.databaseAction(this.modelPath)]}))}))},r.prototype.databaseAction=function(t,e){var n=this;return new Promise((function(o,a){var i=n.indexedDB.open("tensorflowjs",1);i.onupgradeneeded=function(){return ga(i)},i.onsuccess=function(){var s=i.result;if(e==null){var u=s.transaction(mn,"readonly"),c=u.objectStore(mn).get(n.modelPath);c.onsuccess=function(){if(c.result==null)return s.close(),a(new Error("Cannot find model with path '"+n.modelPath+"' in IndexedDB."));o(c.result.modelArtifacts)},c.onerror=function(v){return s.close(),a(c.error)},u.oncomplete=function(){return s.close()}}else{var l,h=gr(e),f=s.transaction(tn,"readwrite"),p=f.objectStore(tn),d=p.put({modelPath:n.modelPath,modelArtifactsInfo:h});d.onsuccess=function(){var v=(l=s.transaction(mn,"readwrite")).objectStore(mn).put({modelPath:n.modelPath,modelArtifacts:e,modelArtifactsInfo:h});v.onsuccess=function(){return o({modelArtifactsInfo:h})},v.onerror=function(m){var g=(p=f.objectStore(tn)).delete(n.modelPath);g.onsuccess=function(){return s.close(),a(v.error)},g.onerror=function(x){return s.close(),a(v.error)}}},d.onerror=function(v){return s.close(),a(d.error)},f.oncomplete=function(){l==null?s.close():l.oncomplete=function(){return s.close()}}}},i.onerror=function(s){return a(i.error)}}))},r.URL_SCHEME="indexeddb://",r})(),ps=function(r){return L().getBool("IS_BROWSER")&&!Array.isArray(r)&&r.startsWith(Un.URL_SCHEME)?(t=r.slice(Un.URL_SCHEME.length),new Un(t)):null;var t};ut.registerSaveRouter(ps),ut.registerLoadRouter(ps);var cm=(function(){function r(){this.indexedDB=nc()}return r.prototype.listModels=function(){return X(this,void 0,void 0,(function(){var t=this;return $(this,(function(e){return[2,new Promise((function(n,o){var a=t.indexedDB.open("tensorflowjs",1);a.onupgradeneeded=function(){return ga(a)},a.onsuccess=function(){var i=a.result,s=i.transaction(tn,"readonly"),u=s.objectStore(tn).getAll();u.onsuccess=function(){for(var c={},l=0,h=u.result;l<h.length;l++){var f=h[l];c[f.modelPath]=f.modelArtifactsInfo}n(c)},u.onerror=function(c){return i.close(),o(u.error)},s.oncomplete=function(){return i.close()}},a.onerror=function(i){return o(a.error)}}))]}))}))},r.prototype.removeModel=function(t){return X(this,void 0,void 0,(function(){var e=this;return $(this,(function(n){var o;return t=(o=t).startsWith(Un.URL_SCHEME)?o.slice(Un.URL_SCHEME.length):o,[2,new Promise((function(a,i){var s=e.indexedDB.open("tensorflowjs",1);s.onupgradeneeded=function(){return ga(s)},s.onsuccess=function(){var u,c=s.result,l=c.transaction(tn,"readwrite"),h=l.objectStore(tn),f=h.get(t);f.onsuccess=function(){if(f.result==null)return c.close(),i(new Error("Cannot find model with path '"+t+"' in IndexedDB."));var p=h.delete(t),d=function(){var v=(u=c.transaction(mn,"readwrite")).objectStore(mn).delete(t);v.onsuccess=function(){return a(f.result.modelArtifactsInfo)},v.onerror=function(m){return i(f.error)}};p.onsuccess=d,p.onerror=function(v){return d(),c.close(),i(f.error)}},f.onerror=function(p){return c.close(),i(f.error)},l.oncomplete=function(){u==null?c.close():u.oncomplete=function(){return c.close()}}},s.onerror=function(u){return i(s.error)}}))]}))}))},r})();if(L().getBool("IS_BROWSER"))try{rn.registerManager(Un.URL_SCHEME,new cm)}catch{}var Ht="/",Mn="tensorflowjs_models",rc="info",lm="model_topology",hm="weight_specs",fm="weight_data",pm="model_metadata";function oc(r){return{info:[Mn,r,rc].join(Ht),topology:[Mn,r,lm].join(Ht),weightSpecs:[Mn,r,hm].join(Ht),weightData:[Mn,r,fm].join(Ht),modelMetadata:[Mn,r,pm].join(Ht)}}function dm(r){var t=r.split(Ht);if(t.length<3)throw new Error("Invalid key format: "+r);return t.slice(1,t.length-1).join(Ht)}var Vn=(function(){function r(t){if(!L().getBool("IS_BROWSER")||typeof window>"u"||window.localStorage===void 0)throw new Error("The current environment does not support local storage.");if(this.LS=window.localStorage,t==null||!t)throw new Error("For local storage, modelPath must not be null, undefined or empty.");this.modelPath=t,this.keys=oc(this.modelPath)}return r.prototype.save=function(t){return X(this,void 0,void 0,(function(){var e,n,o;return $(this,(function(a){if(t.modelTopology instanceof ArrayBuffer)throw new Error("BrowserLocalStorage.save() does not support saving model topology in binary formats yet.");e=JSON.stringify(t.modelTopology),n=JSON.stringify(t.weightSpecs),o=gr(t);try{return this.LS.setItem(this.keys.info,JSON.stringify(o)),this.LS.setItem(this.keys.topology,e),this.LS.setItem(this.keys.weightSpecs,n),this.LS.setItem(this.keys.weightData,(function(i){if(ma)return Buffer.from(i).toString("base64");for(var s=new Uint8Array(i),u="",c=0,l=s.length;c<l;c++)u+=String.fromCharCode(s[c]);return btoa(u)})(t.weightData)),this.LS.setItem(this.keys.modelMetadata,JSON.stringify({format:t.format,generatedBy:t.generatedBy,convertedBy:t.convertedBy,userDefinedMetadata:t.userDefinedMetadata})),[2,{modelArtifactsInfo:o}]}catch{throw this.LS.removeItem(this.keys.info),this.LS.removeItem(this.keys.topology),this.LS.removeItem(this.keys.weightSpecs),this.LS.removeItem(this.keys.weightData),this.LS.removeItem(this.keys.modelMetadata),new Error("Failed to save model '"+this.modelPath+"' to local storage: size quota being exceeded is a possible cause of this failure: modelTopologyBytes="+o.modelTopologyBytes+", weightSpecsBytes="+o.weightSpecsBytes+", weightDataBytes="+o.weightDataBytes+".")}return[2]}))}))},r.prototype.load=function(){return X(this,void 0,void 0,(function(){var t,e,n,o,a,i,s;return $(this,(function(u){if((t=JSON.parse(this.LS.getItem(this.keys.info)))==null)throw new Error("In local storage, there is no model with name '"+this.modelPath+"'");if(t.modelTopologyType!=="JSON")throw new Error("BrowserLocalStorage does not support loading non-JSON model topology yet.");if(e={},(n=JSON.parse(this.LS.getItem(this.keys.topology)))==null)throw new Error("In local storage, the topology of model '"+this.modelPath+"' is missing.");if(e.modelTopology=n,(o=JSON.parse(this.LS.getItem(this.keys.weightSpecs)))==null)throw new Error("In local storage, the weight specs of model '"+this.modelPath+"' are missing.");if(e.weightSpecs=o,(a=this.LS.getItem(this.keys.modelMetadata))!=null&&(i=JSON.parse(a),e.format=i.format,e.generatedBy=i.generatedBy,e.convertedBy=i.convertedBy,e.userDefinedMetadata=i.userDefinedMetadata),(s=this.LS.getItem(this.keys.weightData))==null)throw new Error("In local storage, the binary weight values of model '"+this.modelPath+"' are missing.");return e.weightData=(function(c){if(ma){var l=Buffer.from(c,"base64");return l.buffer.slice(l.byteOffset,l.byteOffset+l.byteLength)}for(var h=atob(c),f=new Uint8Array(h.length),p=0;p<h.length;++p)f.set([h.charCodeAt(p)],p);return f.buffer})(s),[2,e]}))}))},r.URL_SCHEME="localstorage://",r})(),ds=function(r){return L().getBool("IS_BROWSER")&&!Array.isArray(r)&&r.startsWith(Vn.URL_SCHEME)?(t=r.slice(Vn.URL_SCHEME.length),new Vn(t)):null;var t};ut.registerSaveRouter(ds),ut.registerLoadRouter(ds);var vm=(function(){function r(){I(L().getBool("IS_BROWSER"),(function(){return"Current environment is not a web browser"})),I(typeof window>"u"||window.localStorage!==void 0,(function(){return"Current browser does not appear to support localStorage"})),this.LS=window.localStorage}return r.prototype.listModels=function(){return X(this,void 0,void 0,(function(){var t,e,n,o,a,i;return $(this,(function(s){for(t={},e=Mn+Ht,n=Ht+rc,o=0;o<this.LS.length;++o)(a=this.LS.key(o)).startsWith(e)&&a.endsWith(n)&&(i=dm(a),t[i]=JSON.parse(this.LS.getItem(a)));return[2,t]}))}))},r.prototype.removeModel=function(t){return X(this,void 0,void 0,(function(){var e,n;return $(this,(function(o){var a;if(t=(a=t).startsWith(Vn.URL_SCHEME)?a.slice(Vn.URL_SCHEME.length):a,e=oc(t),this.LS.getItem(e.info)==null)throw new Error("Cannot find model at path '"+t+"'");return n=JSON.parse(this.LS.getItem(e.info)),this.LS.removeItem(e.info),this.LS.removeItem(e.topology),this.LS.removeItem(e.weightSpecs),this.LS.removeItem(e.weightData),[2,n]}))}))},r})();if(L().getBool("IS_BROWSER"))try{rn.registerManager(Vn.URL_SCHEME,new vm)}catch{}var mm="model",gm=".json",ym=".weights.bin";function vs(r){return new Promise((function(t){return setTimeout(t)})).then(r)}var $o=(function(){function r(t){if(!L().getBool("IS_BROWSER"))throw new Error("browserDownloads() cannot proceed because the current environment is not a browser.");t.startsWith(r.URL_SCHEME)&&(t=t.slice(r.URL_SCHEME.length)),t!=null&&t.length!==0||(t=mm),this.modelTopologyFileName=t+gm,this.weightDataFileName=t+ym}return r.prototype.save=function(t){return X(this,void 0,void 0,(function(){var e,n,o,a,i,s;return $(this,(function(u){switch(u.label){case 0:if(typeof document>"u")throw new Error("Browser downloads are not supported in this environment since `document` is not present");if(e=window.URL.createObjectURL(new Blob([t.weightData],{type:"application/octet-stream"})),!(t.modelTopology instanceof ArrayBuffer))return[3,1];throw new Error("BrowserDownloads.save() does not support saving model topology in binary formats yet.");case 1:return n=[{paths:["./"+this.weightDataFileName],weights:t.weightSpecs}],o={modelTopology:t.modelTopology,format:t.format,generatedBy:t.generatedBy,convertedBy:t.convertedBy,weightsManifest:n},a=window.URL.createObjectURL(new Blob([JSON.stringify(o)],{type:"application/json"})),(i=this.jsonAnchor==null?document.createElement("a"):this.jsonAnchor).download=this.modelTopologyFileName,i.href=a,[4,vs((function(){return i.dispatchEvent(new MouseEvent("click"))}))];case 2:return u.sent(),t.weightData==null?[3,4]:((s=this.weightDataAnchor==null?document.createElement("a"):this.weightDataAnchor).download=this.weightDataFileName,s.href=e,[4,vs((function(){return s.dispatchEvent(new MouseEvent("click"))}))]);case 3:u.sent(),u.label=4;case 4:return[2,{modelArtifactsInfo:gr(t)}]}}))}))},r.URL_SCHEME="downloads://",r})(),xm=(function(){function r(t){if(t==null||t.length<1)throw new Error("When calling browserFiles, at least 1 file is required, but received "+t);this.files=t}return r.prototype.load=function(){return X(this,void 0,void 0,(function(){var t,e,n=this;return $(this,(function(o){return t=this.files[0],e=this.files.slice(1),[2,new Promise((function(a,i){var s=new FileReader;s.onload=function(u){var c=JSON.parse(u.target.result),l=c.modelTopology;if(l!=null){e.length===0&&a({modelTopology:l});var h=c.weightsManifest;if(h!=null){var f;try{f=n.checkManifestAndWeightFiles(h,e)}catch(m){return void i(m)}var p=[],d=[],v=[];h.forEach((function(m){m.paths.forEach((function(g){d.push(g),v.push(null)})),p.push.apply(p,m.weights)})),h.forEach((function(m){m.paths.forEach((function(g){var x=new FileReader;x.onload=function(b){var y=b.target.result,w=d.indexOf(g);v[w]=y,v.indexOf(null)===-1&&a({modelTopology:l,weightSpecs:p,weightData:Qa(v),format:c.format,generatedBy:c.generatedBy,convertedBy:c.convertedBy,userDefinedMetadata:c.userDefinedMetadata})},x.onerror=function(b){return i("Failed to weights data from file of path '"+g+"'.")},x.readAsArrayBuffer(f[g])}))}))}else i(new Error("weightManifest field is missing from file "+t.name))}else i(new Error("modelTopology field is missing from file "+t.name))},s.onerror=function(u){return i("Failed to read model topology and weights manifest JSON from file '"+t.name+"'. BrowserFiles supports loading Keras-style tf.Model artifacts only.")},s.readAsText(t)}))]}))}))},r.prototype.checkManifestAndWeightFiles=function(t,e){for(var n=[],o=e.map((function(u){return hs(u.name)})),a={},i=0,s=t;i<s.length;i++)s[i].paths.forEach((function(u){var c=hs(u);if(n.indexOf(c)!==-1)throw new Error("Duplicate file basename found in weights manifest: '"+c+"'");if(n.push(c),o.indexOf(c)===-1)throw new Error("Weight file with basename '"+c+"' is not provided.");a[u]=e[o.indexOf(c)]}));if(n.length!==e.length)throw new Error("Mismatch in the number of files in weights manifest ("+n.length+") and the number of weight files provided ("+e.length+").");return a},r})();function ms(r,t,e,n){(function(a){I(a!=null&&Array.isArray(a)&&a.length>0,(function(){return"promises must be a none empty array"}))})(r),(function(a,i){I(a>=0&&a<=1,(function(){return"Progress fraction must be in range [0, 1], but got startFraction "+a})),I(i>=0&&i<=1,(function(){return"Progress fraction must be in range [0, 1], but got endFraction "+i})),I(i>=a,(function(){return"startFraction must be no more than endFraction, but got startFraction "+a+" and endFraction "+i}))})(e=e??0,n=n??1);var o=0;return Promise.all(r.map((function(a){return a.then((function(i){var s=e+ ++o/r.length*(n-e);return t(s),i})),a})))}function ac(r,t){return X(this,void 0,void 0,(function(){var e,n,o,a,i,s,u,c,l;return $(this,(function(h){switch(h.label){case 0:return t==null&&(t={}),e=t.fetchFunc==null?L().platform.fetch:t.fetchFunc,n=r.map((function(f){return e(f,t.requestInit,{isBinary:!0})})),o=0,a=.5,t.onProgress!=null?[3,2]:[4,Promise.all(n)];case 1:return i=h.sent(),[3,4];case 2:return[4,ms(n,t.onProgress,o,a)];case 3:i=h.sent(),h.label=4;case 4:return s=i.map((function(f){return f.arrayBuffer()})),u=.5,c=1,t.onProgress!=null?[3,6]:[4,Promise.all(s)];case 5:return l=h.sent(),[3,8];case 6:return[4,ms(s,t.onProgress,u,c)];case 7:l=h.sent(),h.label=8;case 8:return[2,l]}}))}))}function gs(r){var t=this;return function(e,n,o){return n===void 0&&(n=""),X(t,void 0,void 0,(function(){var a,i,s,u,c,l,h,f,p,d;return $(this,(function(v){switch(v.label){case 0:if(a=e.map((function(){return!1})),i={},s=o!=null?o.map((function(){return!1})):[],u=[],e.forEach((function(m,g){var x=0;m.weights.forEach((function(b){var y="quantization"in b?b.quantization.dtype:b.dtype,w=va[y]*Y(b.shape),C=function(){a[g]=!0,i[g]==null&&(i[g]=[]),i[g].push({manifestEntry:b,groupOffset:x,sizeBytes:w})};o!=null?o.forEach((function(S,k){S===b.name&&(C(),s[k]=!0)})):C(),u.push(b.name),x+=w}))})),!s.every((function(m){return m})))throw c=o.filter((function(m,g){return!s[g]})),new Error("Could not find weights in manifest with names: "+c.join(", ")+`. 
Manifest JSON has weights with names: `+u.join(", ")+".");return l=a.reduce((function(m,g,x){return g&&m.push(x),m}),[]),h=[],l.forEach((function(m){e[m].paths.forEach((function(g){var x=n+(n.endsWith("/")?"":"/")+g;h.push(x)}))})),[4,r(h)];case 1:return f=v.sent(),p={},d=0,l.forEach((function(m){for(var g=e[m].paths.length,x=0,b=0;b<g;b++)x+=f[d+b].byteLength;for(var y=new ArrayBuffer(x),w=new Uint8Array(y),C=0,S=0;S<g;S++){var k=new Uint8Array(f[d+S]);w.set(k,C),C+=k.byteLength}i[m].forEach((function(R){var E=tc(y.slice(R.groupOffset,R.groupOffset+R.sizeBytes),[R.manifestEntry]);for(var T in E)p[T]=E[T]})),d+=g})),[2,p]}}))}))}}ut.registerSaveRouter((function(r){return L().getBool("IS_BROWSER")&&!Array.isArray(r)&&r.startsWith($o.URL_SCHEME)?(function(t){return t===void 0&&(t="model"),new $o(t)})(r.slice($o.URL_SCHEME.length)):null}));var ic=(function(){function r(t,e){if(this.DEFAULT_METHOD="POST",e==null&&(e={}),this.weightPathPrefix=e.weightPathPrefix,this.onProgress=e.onProgress,e.fetchFunc!=null?(I(typeof e.fetchFunc=="function",(function(){return"Must pass a function that matches the signature of `fetch` (see https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)"})),this.fetch=e.fetchFunc):this.fetch=L().platform.fetch,I(t!=null&&t.length>0,(function(){return"URL path for http must not be null, undefined or empty."})),Array.isArray(t)&&I(t.length===2,(function(){return"URL paths for http must have a length of 2, (actual length is "+t.length+")."})),this.path=t,e.requestInit!=null&&e.requestInit.body!=null)throw new Error("requestInit is expected to have no pre-existing body, but has one.");this.requestInit=e.requestInit||{}}return r.prototype.save=function(t){return X(this,void 0,void 0,(function(){var e,n,o,a;return $(this,(function(i){switch(i.label){case 0:if(t.modelTopology instanceof ArrayBuffer)throw new Error("BrowserHTTPRequest.save() does not support saving model topology in binary formats yet.");return(e=Object.assign({method:this.DEFAULT_METHOD},this.requestInit)).body=new FormData,n=[{paths:["./model.weights.bin"],weights:t.weightSpecs}],o={modelTopology:t.modelTopology,format:t.format,generatedBy:t.generatedBy,convertedBy:t.convertedBy,userDefinedMetadata:t.userDefinedMetadata,weightsManifest:n},e.body.append("model.json",new Blob([JSON.stringify(o)],{type:"application/json"}),"model.json"),t.weightData!=null&&e.body.append("model.weights.bin",new Blob([t.weightData],{type:"application/octet-stream"}),"model.weights.bin"),[4,this.fetch(this.path,e)];case 1:if((a=i.sent()).ok)return[2,{modelArtifactsInfo:gr(t),responses:[a]}];throw new Error("BrowserHTTPRequest.save() failed due to HTTP response status "+a.status+".")}}))}))},r.prototype.load=function(){return X(this,void 0,void 0,(function(){var t,e,n,o,a,i,s,u,c,l,h,f;return $(this,(function(p){switch(p.label){case 0:return[4,this.fetch(this.path,this.requestInit)];case 1:if(!(t=p.sent()).ok)throw new Error("Request to "+this.path+" failed with status code "+t.status+". Please verify this URL points to the model JSON of the model to load.");p.label=2;case 2:return p.trys.push([2,4,,5]),[4,t.json()];case 3:return e=p.sent(),[3,5];case 4:throw p.sent(),n="Failed to parse model JSON of response from "+this.path+".",this.path.endsWith(".pb")?n+=" Your path contains a .pb file extension. Support for .pb models have been removed in TensorFlow.js 1.0 in favor of .json models. You can re-convert your Python TensorFlow model using the TensorFlow.js 1.0 conversion scripts or you can convert your.pb models with the 'pb2json'NPM script in the tensorflow/tfjs-converter repository.":n+=" Please make sure the server is serving valid JSON for this request.",new Error(n);case 5:if(o=e.modelTopology,a=e.weightsManifest,i=e.generatedBy,s=e.convertedBy,u=e.format,c=e.userDefinedMetadata,o==null&&a==null)throw new Error("The JSON from HTTP path "+this.path+" contains neither model topology or manifest for weights.");return a==null?[3,7]:[4,this.loadWeights(a)];case 6:f=p.sent(),l=f[0],h=f[1],p.label=7;case 7:return[2,{modelTopology:o,weightSpecs:l,weightData:h,userDefinedMetadata:c,generatedBy:i,convertedBy:s,format:u}]}}))}))},r.prototype.loadWeights=function(t){return X(this,void 0,void 0,(function(){var e,n,o,a,i,s,u,c,l,h,f;return $(this,(function(p){switch(p.label){case 0:for(e=Array.isArray(this.path)?this.path[1]:this.path,n=(function(d){var v=d.lastIndexOf("/"),m=d.lastIndexOf("?"),g=d.substring(0,v),x=m>v?d.substring(m):"";return[g+"/",x]})(e),o=n[0],a=n[1],i=this.weightPathPrefix||o,s=[],u=0,c=t;u<c.length;u++)l=c[u],s.push.apply(s,l.weights);return h=[],t.forEach((function(d){d.paths.forEach((function(v){h.push(i+v+a)}))})),[4,ac(h,{requestInit:this.requestInit,fetchFunc:this.fetch,onProgress:this.onProgress})];case 1:return f=p.sent(),[2,[s,Qa(f)]]}}))}))},r.URL_SCHEME_REGEX=/^https?:\/\//,r})();function ya(r){return r.match(ic.URL_SCHEME_REGEX)!=null}var ys=function(r,t){return typeof fetch>"u"?null:(Array.isArray(r)?r.every((function(e){return ya(e)})):ya(r))?xa(r,{onProgress:t}):null};function xa(r,t){return new ic(r,t)}ut.registerSaveRouter(ys),ut.registerLoadRouter(ys);var Yo=(function(){function r(t){this.modelArtifacts=t}return r.prototype.load=function(){return X(this,void 0,void 0,(function(){return $(this,(function(t){return[2,this.modelArtifacts]}))}))},r})(),bm=(function(){function r(t){this.saveHandler=t}return r.prototype.save=function(t){return X(this,void 0,void 0,(function(){return $(this,(function(e){return[2,this.saveHandler(t)]}))}))},r})(),sc=Object.freeze({browserFiles:function(r){return new xm(r)},browserHTTPRequest:function(r,t){return xa(r,t)},concatenateArrayBuffers:Qa,decodeWeights:tc,encodeWeights:function(r,t){return X(this,void 0,void 0,(function(){var e,n,o,a,i,s=this;return $(this,(function(u){switch(u.label){case 0:for(e=[],n=[],o=Array.isArray(r)?r.map((function(c){return c.name})):Object.keys(r),a=function(c){var l=o[c],h=Array.isArray(r)?r[c].tensor:r[l];if(h.dtype!=="float32"&&h.dtype!=="int32"&&h.dtype!=="bool"&&h.dtype!=="string")throw new Error("Unsupported dtype in weight '"+l+"': "+h.dtype);var f={name:l,shape:h.shape,dtype:h.dtype};if(h.dtype==="string"){var p=new Promise((function(d){return X(s,void 0,void 0,(function(){var v,m,g,x,b,y,w;return $(this,(function(C){switch(C.label){case 0:return[4,h.bytes()];case 1:for(v=C.sent(),m=v.reduce((function(S,k){return S+k.length}),0)+Zr*v.length,g=new Uint8Array(m),x=0,b=0;b<v.length;b++)y=v[b],w=new Uint8Array(new Uint32Array([y.length]).buffer),g.set(w,x),x+=Zr,g.set(y,x),x+=y.length;return d(g),[2]}}))}))}));n.push(p)}else n.push(h.data());t!=null&&(f.group=t),e.push(f)},i=0;i<o.length;++i)a(i);return[4,Promise.all(n)];case 1:return[2,{data:um(u.sent()),specs:e}]}}))}))},fromMemory:function(r,t,e,n){return arguments.length===1?r.modelTopology!=null||r.weightSpecs!=null?new Yo(r):(console.warn("Please call tf.io.fromMemory() with only one argument. The argument should be of type ModelArtifacts. The multi-argument signature of tf.io.fromMemory() has been deprecated and will be removed in a future release."),new Yo({modelTopology:r})):(console.warn("Please call tf.io.fromMemory() with only one argument. The argument should be of type ModelArtifacts. The multi-argument signature of tf.io.fromMemory() has been deprecated and will be removed in a future release."),new Yo({modelTopology:r,weightSpecs:t,weightData:e,trainingConfig:n}))},getLoadHandlers:function(r,t){return ut.getLoadHandlers(r,t)},getModelArtifactsInfoForJSON:gr,getSaveHandlers:function(r){return ut.getSaveHandlers(r)},http:xa,isHTTPScheme:ya,loadWeights:function(r,t,e,n){return t===void 0&&(t=""),X(this,void 0,void 0,(function(){return $(this,(function(o){return[2,gs((function(a){return ac(a,{requestInit:n})}))(r,t,e)]}))}))},registerLoadRouter:function(r){return ut.registerLoadRouter(r)},registerSaveRouter:function(r){return ut.registerSaveRouter(r)},weightsLoaderFactory:gs,withSaveHandler:function(r){return new bm(r)},copyModel:function(r,t){return X(this,void 0,void 0,(function(){return $(this,(function(e){return[2,fs(r,t,!1)]}))}))},listModels:function(){return X(this,void 0,void 0,(function(){var r,t,e,n,o,a,i;return $(this,(function(s){switch(s.label){case 0:r=rn.getSchemes(),t={},e=0,n=r,s.label=1;case 1:return e<n.length?(o=n[e],[4,rn.getManager(o).listModels()]):[3,4];case 2:for(i in a=s.sent())t[o+Wn+i]=a[i];s.label=3;case 3:return e++,[3,1];case 4:return[2,t]}}))}))},moveModel:function(r,t){return X(this,void 0,void 0,(function(){return $(this,(function(e){return[2,fs(r,t,!0)]}))}))},removeModel:function(r){return X(this,void 0,void 0,(function(){var t;return $(this,(function(e){return t=Pr(r),[2,rn.getManager(t.scheme).removeModel(t.path)]}))}))}}),An;D({confusionMatrix_:function(r,t,e){var n=_(r,"labels","confusionMatrix"),o=_(t,"predictions","confusionMatrix");I(e==null||e>0&&Number.isInteger(e),(function(){return"If provided, numClasses must be a positive integer, but got "+e})),I(n.rank===1,(function(){return"Expected the rank of labels to be 1, but got "+n.rank})),I(o.rank===1,(function(){return"Expected the rank of predictions to be 1, but got "+o.rank})),I(n.shape[0]===o.shape[0],(function(){return"Mismatch in the number of examples: "+n.shape[0]+" vs. "+o.shape[0]+". Labels and predictions should have the same number of elements."})),I(e>0&&Number.isInteger(e),(function(){return"numClasses is required to be a positive integer, but got "+e}));var a=la(n.asType("int32"),e),i=la(o.asType("int32"),e);return a.transpose().matMul(i).asType("int32")}});var wm=D({fromPixels_:function(r,t){if(t===void 0&&(t=3),t>4)throw new Error("Cannot construct Tensor with more than 4 channels from pixels.");if(r==null)throw new Error("pixels passed to tf.browser.fromPixels() can not be null");var e=!1,n=!1,o=!1,a=!1,i=!1;if(r.data instanceof Uint8Array)e=!0;else if(typeof ImageData<"u"&&r instanceof ImageData)n=!0;else if(typeof HTMLVideoElement<"u"&&r instanceof HTMLVideoElement)o=!0;else if(typeof HTMLImageElement<"u"&&r instanceof HTMLImageElement)a=!0;else{if(r.getContext==null)throw new Error("pixels passed to tf.browser.fromPixels() must be either an HTMLVideoElement, HTMLImageElement, HTMLCanvasElement, ImageData in browser, or OffscreenCanvas, ImageData in webworker or {data: Uint32Array, width: number, height: number}, but was "+r.constructor.name);i=!0}if(o&&o&&r.readyState<2)throw new Error("The video element has not loaded data yet. Please wait for `loadeddata` event on the <video> element.");if(Ts("FromPixels",N.backendName)!=null)return N.runKernel("FromPixels",{pixels:r},{numChannels:t});var s,u,c=o?[r.videoWidth,r.videoHeight]:[r.width,r.height],l=c[0],h=c[1];if(i?s=r.getContext("2d").getImageData(0,0,l,h).data:n||e?s=r.data:(a||o)&&(An==null&&(An=document.createElement("canvas").getContext("2d")),An.canvas.width=l,An.canvas.height=h,An.drawImage(r,0,0,l,h),s=An.getImageData(0,0,l,h).data),t===4)u=new Int32Array(s);else{var f=l*h;u=new Int32Array(f*t);for(var p=0;p<f;p++)for(var d=0;d<t;++d)u[p*t+d]=s[4*p+d]}return ka(u,[h,l,t],"int32")}}),Za=Object.freeze({toPixels:function(r,t){return X(this,void 0,void 0,(function(){var e,n,o,a,i,s,u,c,l,h,f,p,d,v,m,g,x,b,y,w,C,S,k;return $(this,(function(R){switch(R.label){case 0:if(e=_(r,"img","toPixels"),r instanceof Ie||(e=e.toInt()),e.rank!==2&&e.rank!==3)throw new Error("toPixels only supports rank 2 or 3 tensors, got rank "+e.rank+".");if(n=e.shape.slice(0,2),o=n[0],a=n[1],(i=e.rank===2?1:e.shape[2])>4||i===2)throw new Error("toPixels only supports depth of size 1, 3 or 4 but got "+i);return[4,e.data()];case 1:return s=R.sent(),u=e.min(),c=e.max(),[4,Promise.all([u.data(),c.data()])];case 2:if(l=R.sent(),h=l[0],f=l[1],p=h[0],d=f[0],u.dispose(),c.dispose(),e.dtype==="float32"){if(p<0||d>1)throw new Error("Tensor values for a float32 Tensor must be in the range [0 - 1] but got range ["+p+" - "+d+"].")}else{if(e.dtype!=="int32")throw new Error("Unsupported type for toPixels: "+e.dtype+". Please use float32 or int32 tensors.");if(p<0||d>255)throw new Error("Tensor values for a int32 Tensor must be in the range [0 - 255] but got range ["+p+" - "+d+"].")}for(v=e.dtype==="float32"?255:1,m=new Uint8ClampedArray(a*o*4),g=0;g<o*a;++g)x=void 0,b=void 0,y=void 0,w=void 0,i===1?(x=s[g]*v,b=s[g]*v,y=s[g]*v,w=255):i===3?(x=s[3*g]*v,b=s[3*g+1]*v,y=s[3*g+2]*v,w=255):i===4&&(x=s[4*g]*v,b=s[4*g+1]*v,y=s[4*g+2]*v,w=s[4*g+3]*v),m[(C=4*g)+0]=Math.round(x),m[C+1]=Math.round(b),m[C+2]=Math.round(y),m[C+3]=Math.round(w);return t!=null&&(t.width=a,t.height=o,S=t.getContext("2d"),k=new ImageData(m,a,o),S.putImageData(k,0,0)),e!==r&&e.dispose(),[2,m]}}))}))},fromPixels:wm}),Cm=(function(){function r(){}return r.prototype.getClassName=function(){return this.constructor.className},r.fromConfig=function(t,e){return new t(e)},r})(),_m=(function(){function r(){this.classNameMap={}}return r.getMap=function(){return r.instance==null&&(r.instance=new r),r.instance},r.register=function(t){r.getMap().classNameMap[t.className]=[t,t.fromConfig]},r})();function _n(r){I(r.className!=null,(function(){return"Class being registered does not have the static className property defined."})),I(typeof r.className=="string",(function(){return"className is required to be a string, but got type "+typeof r.className})),I(r.className.length>0,(function(){return"Class being registered has an empty-string as its className, which is disallowed."})),_m.register(r)}var En=(function(r){function t(){return r!==null&&r.apply(this,arguments)||this}return yt(t,r),t.prototype.minimize=function(e,n,o){n===void 0&&(n=!1);var a=this.computeGradients(e,o),i=a.value,s=a.grads;if(o!=null){var u=o.map((function(c){return{name:c.name,tensor:s[c.name]}}));this.applyGradients(u)}else this.applyGradients(s);return tt(s),n?i:(i.dispose(),null)},Object.defineProperty(t.prototype,"iterations",{get:function(){return this.iterations_==null&&(this.iterations_=0),this.iterations_},enumerable:!0,configurable:!0}),t.prototype.incrementIterations=function(){this.iterations_=this.iterations+1},t.prototype.computeGradients=function(e,n){return Nh(e,n)},t.prototype.dispose=function(){this.iterations_!=null&&tt(this.iterations_)},t.prototype.saveIterations=function(){return X(this,void 0,void 0,(function(){return $(this,(function(e){return this.iterations_==null&&(this.iterations_=0),[2,{name:"iter",tensor:j(this.iterations_,"int32")}]}))}))},t.prototype.getWeights=function(){return X(this,void 0,void 0,(function(){return $(this,(function(e){throw new Error("getWeights() is not implemented for this optimizer yet.")}))}))},t.prototype.setWeights=function(e){return X(this,void 0,void 0,(function(){return $(this,(function(n){throw new Error("setWeights() is not implemented for this optimizer class "+this.getClassName())}))}))},t.prototype.extractIterations=function(e){return X(this,void 0,void 0,(function(){var n;return $(this,(function(o){switch(o.label){case 0:return n=this,[4,e[0].tensor.data()];case 1:return n.iterations_=o.sent()[0],[2,e.slice(1)]}}))}))},t})(Cm);Object.defineProperty(En,Symbol.hasInstance,{value:function(r){return r.minimize!=null&&r.computeGradients!=null&&r.applyGradients!=null}});var Em=(function(r){function t(e,n,o){o===void 0&&(o=null);var a=r.call(this)||this;return a.learningRate=e,a.rho=n,a.epsilon=o,a.accumulatedGrads=[],a.accumulatedUpdates=[],o==null&&(a.epsilon=N.backend.epsilon()),a}return yt(t,r),t.prototype.applyGradients=function(e){var n=this;(Array.isArray(e)?e.map((function(o){return o.name})):Object.keys(e)).forEach((function(o,a){var i=N.registeredVariables[o];n.accumulatedGrads[a]==null&&(n.accumulatedGrads[a]={originalName:o+"/accum_grad",variable:K((function(){return me(i).variable(!1)}))}),n.accumulatedUpdates[a]==null&&(n.accumulatedUpdates[a]={originalName:o+"/accum_var",variable:K((function(){return me(i).variable(!1)}))});var s=Array.isArray(e)?e[a].tensor:e[o];if(s!=null){var u=n.accumulatedGrads[a].variable,c=n.accumulatedUpdates[a].variable;K((function(){var l=u.mul(n.rho).add(s.square().mul(1-n.rho)),h=c.add(n.epsilon).sqrt().div(u.add(n.epsilon).sqrt()).mul(s),f=c.mul(n.rho).add(h.square().mul(1-n.rho));u.assign(l),c.assign(f);var p=h.mul(-n.learningRate).add(i);i.assign(p)}))}})),this.incrementIterations()},t.prototype.dispose=function(){this.accumulatedUpdates!=null&&(tt(this.accumulatedGrads.map((function(e){return e.variable}))),tt(this.accumulatedUpdates.map((function(e){return e.variable}))))},t.prototype.getWeights=function(){return X(this,void 0,void 0,(function(){var e;return $(this,(function(n){switch(n.label){case 0:return e=this.accumulatedGrads.concat(this.accumulatedUpdates),[4,this.saveIterations()];case 1:return[2,[n.sent()].concat(e.map((function(o){return{name:o.originalName,tensor:o.variable}})))]}}))}))},t.prototype.setWeights=function(e){return X(this,void 0,void 0,(function(){var n;return $(this,(function(o){switch(o.label){case 0:return[4,this.extractIterations(e)];case 1:return e=o.sent(),n=e.length/2,this.accumulatedGrads=e.slice(0,n).map((function(a){return{originalName:a.name,variable:a.tensor.variable(!1)}})),this.accumulatedUpdates=e.slice(n,2*n).map((function(a){return{originalName:a.name,variable:a.tensor.variable(!1)}})),[2]}}))}))},t.prototype.getConfig=function(){return{learningRate:this.learningRate,rho:this.rho,epsilon:this.epsilon}},t.fromConfig=function(e,n){return new e(n.learningRate,n.rho,n.epsilon)},t.className="Adadelta",t})(En);_n(Em);var Im=(function(r){function t(e,n){n===void 0&&(n=.1);var o=r.call(this)||this;return o.learningRate=e,o.initialAccumulatorValue=n,o.accumulatedGrads=[],o}return yt(t,r),t.prototype.applyGradients=function(e){var n=this;(Array.isArray(e)?e.map((function(o){return o.name})):Object.keys(e)).forEach((function(o,a){var i=N.registeredVariables[o];n.accumulatedGrads[a]==null&&(n.accumulatedGrads[a]={originalName:o+"/accumulator",variable:K((function(){return Nt(i.shape,n.initialAccumulatorValue).variable(!1)}))});var s=Array.isArray(e)?e[a].tensor:e[o];if(s!=null){var u=n.accumulatedGrads[a].variable;K((function(){var c=u.add(s.square());u.assign(c);var l=s.div(c.add(N.backend.epsilon()).sqrt()).mul(-n.learningRate).add(i);i.assign(l)}))}})),this.incrementIterations()},t.prototype.dispose=function(){this.accumulatedGrads!=null&&tt(this.accumulatedGrads.map((function(e){return e.variable})))},t.prototype.getWeights=function(){return X(this,void 0,void 0,(function(){return $(this,(function(e){switch(e.label){case 0:return[4,this.saveIterations()];case 1:return[2,[e.sent()].concat(this.accumulatedGrads.map((function(n){return{name:n.originalName,tensor:n.variable}})))]}}))}))},t.prototype.setWeights=function(e){return X(this,void 0,void 0,(function(){return $(this,(function(n){switch(n.label){case 0:return[4,this.extractIterations(e)];case 1:return e=n.sent(),this.accumulatedGrads=e.map((function(o){return{originalName:o.name,variable:o.tensor.variable(!1)}})),[2]}}))}))},t.prototype.getConfig=function(){return{learningRate:this.learningRate,initialAccumulatorValue:this.initialAccumulatorValue}},t.fromConfig=function(e,n){return new e(n.learningRate,n.initialAccumulatorValue)},t.className="Adagrad",t})(En);_n(Im);var Rm=(function(r){function t(e,n,o,a){a===void 0&&(a=null);var i=r.call(this)||this;return i.learningRate=e,i.beta1=n,i.beta2=o,i.epsilon=a,i.accumulatedFirstMoment=[],i.accumulatedSecondMoment=[],K((function(){i.accBeta1=j(n).variable(),i.accBeta2=j(o).variable()})),a==null&&(i.epsilon=N.backend.epsilon()),i}return yt(t,r),t.prototype.applyGradients=function(e){var n=this,o=Array.isArray(e)?e.map((function(a){return a.name})):Object.keys(e);K((function(){var a=Be(1,n.accBeta1),i=Be(1,n.accBeta2);o.forEach((function(s,u){var c=N.registeredVariables[s];n.accumulatedFirstMoment[u]==null&&(n.accumulatedFirstMoment[u]={originalName:s+"/m",variable:K((function(){return me(c).variable(!1)}))}),n.accumulatedSecondMoment[u]==null&&(n.accumulatedSecondMoment[u]={originalName:s+"/v",variable:K((function(){return me(c).variable(!1)}))});var l=Array.isArray(e)?e[u].tensor:e[s];if(l!=null){var h=n.accumulatedFirstMoment[u].variable,f=n.accumulatedSecondMoment[u].variable,p=h.mul(n.beta1).add(l.mul(1-n.beta1)),d=f.mul(n.beta2).add(l.square().mul(1-n.beta2)),v=p.div(a),m=d.div(i);h.assign(p),f.assign(d);var g=v.div(m.sqrt().add(n.epsilon)).mul(-n.learningRate).add(c);c.assign(g)}})),n.accBeta1.assign(n.accBeta1.mul(n.beta1)),n.accBeta2.assign(n.accBeta2.mul(n.beta2))})),this.incrementIterations()},t.prototype.dispose=function(){this.accBeta1.dispose(),this.accBeta2.dispose(),this.accumulatedFirstMoment!=null&&tt(this.accumulatedFirstMoment.map((function(e){return e.variable}))),this.accumulatedSecondMoment!=null&&tt(this.accumulatedSecondMoment.map((function(e){return e.variable})))},t.prototype.getWeights=function(){return X(this,void 0,void 0,(function(){var e;return $(this,(function(n){switch(n.label){case 0:return e=this.accumulatedFirstMoment.concat(this.accumulatedSecondMoment),[4,this.saveIterations()];case 1:return[2,[n.sent()].concat(e.map((function(o){return{name:o.originalName,tensor:o.variable}})))]}}))}))},t.prototype.setWeights=function(e){return X(this,void 0,void 0,(function(){var n,o=this;return $(this,(function(a){switch(a.label){case 0:return[4,this.extractIterations(e)];case 1:return e=a.sent(),K((function(){o.accBeta1.assign(Jr(o.beta1,o.iterations_+1)),o.accBeta2.assign(Jr(o.beta2,o.iterations_+1))})),n=e.length/2,this.accumulatedFirstMoment=e.slice(0,n).map((function(i){return{originalName:i.name,variable:i.tensor.variable(!1)}})),this.accumulatedSecondMoment=e.slice(n,2*n).map((function(i){return{originalName:i.name,variable:i.tensor.variable(!1)}})),[2]}}))}))},t.prototype.getConfig=function(){return{learningRate:this.learningRate,beta1:this.beta1,beta2:this.beta2,epsilon:this.epsilon}},t.fromConfig=function(e,n){return new e(n.learningRate,n.beta1,n.beta2,n.epsilon)},t.className="Adam",t})(En);_n(Rm);var km=(function(r){function t(e,n,o,a,i){a===void 0&&(a=null),i===void 0&&(i=0);var s=r.call(this)||this;return s.learningRate=e,s.beta1=n,s.beta2=o,s.epsilon=a,s.decay=i,s.accumulatedFirstMoment=[],s.accumulatedWeightedInfNorm=[],K((function(){s.iteration=j(0).variable(),s.accBeta1=j(n).variable()})),a==null&&(s.epsilon=N.backend.epsilon()),s}return yt(t,r),t.prototype.applyGradients=function(e){var n=this,o=Array.isArray(e)?e.map((function(a){return a.name})):Object.keys(e);K((function(){var a=Be(1,n.accBeta1),i=vt(-n.learningRate,n.iteration.mul(n.decay).add(1));o.forEach((function(s,u){var c=N.registeredVariables[s];n.accumulatedFirstMoment[u]==null&&(n.accumulatedFirstMoment[u]={originalName:s+"/m",variable:me(c).variable(!1)}),n.accumulatedWeightedInfNorm[u]==null&&(n.accumulatedWeightedInfNorm[u]={originalName:s+"/v",variable:me(c).variable(!1)});var l=Array.isArray(e)?e[u].tensor:e[s];if(l!=null){var h=n.accumulatedFirstMoment[u].variable,f=n.accumulatedWeightedInfNorm[u].variable,p=h.mul(n.beta1).add(l.mul(1-n.beta1)),d=f.mul(n.beta2),v=l.abs(),m=d.maximum(v);h.assign(p),f.assign(m);var g=i.div(a).mul(p.div(m.add(n.epsilon))).add(c);c.assign(g)}})),n.iteration.assign(n.iteration.add(1)),n.accBeta1.assign(n.accBeta1.mul(n.beta1))})),this.incrementIterations()},t.prototype.dispose=function(){this.accBeta1.dispose(),this.iteration.dispose(),this.accumulatedFirstMoment!=null&&tt(this.accumulatedFirstMoment.map((function(e){return e.variable}))),this.accumulatedWeightedInfNorm!=null&&tt(this.accumulatedWeightedInfNorm.map((function(e){return e.variable})))},t.prototype.getWeights=function(){return X(this,void 0,void 0,(function(){return $(this,(function(e){throw new Error("getWeights() is not implemented for Adamax yet.")}))}))},t.prototype.setWeights=function(e){return X(this,void 0,void 0,(function(){return $(this,(function(n){throw new Error("setWeights() is not implemented for Adamax yet.")}))}))},t.prototype.getConfig=function(){return{learningRate:this.learningRate,beta1:this.beta1,beta2:this.beta2,epsilon:this.epsilon,decay:this.decay}},t.fromConfig=function(e,n){return new e(n.learningRate,n.beta1,n.beta2,n.epsilon,n.decay)},t.className="Adamax",t})(En);_n(km);var uc=(function(r){function t(e){var n=r.call(this)||this;return n.learningRate=e,n.setLearningRate(e),n}return yt(t,r),t.prototype.applyGradients=function(e){var n=this;(Array.isArray(e)?e.map((function(o){return o.name})):Object.keys(e)).forEach((function(o,a){var i=Array.isArray(e)?e[a].tensor:e[o];if(i!=null){var s=N.registeredVariables[o];K((function(){var u=n.c.mul(i).add(s);s.assign(u)}))}})),this.incrementIterations()},t.prototype.setLearningRate=function(e){this.learningRate=e,this.c!=null&&this.c.dispose(),this.c=ql(j(-e))},t.prototype.dispose=function(){this.c.dispose()},t.prototype.getWeights=function(){return X(this,void 0,void 0,(function(){return $(this,(function(e){switch(e.label){case 0:return[4,this.saveIterations()];case 1:return[2,[e.sent()]]}}))}))},t.prototype.setWeights=function(e){return X(this,void 0,void 0,(function(){return $(this,(function(n){switch(n.label){case 0:return[4,this.extractIterations(e)];case 1:if((e=n.sent()).length!==0)throw new Error("SGD optimizer does not have settable weights.");return[2]}}))}))},t.prototype.getConfig=function(){return{learningRate:this.learningRate}},t.fromConfig=function(e,n){return new e(n.learningRate)},t.className="SGD",t})(En);_n(uc);var Sm=(function(r){function t(e,n,o){o===void 0&&(o=!1);var a=r.call(this,e)||this;return a.learningRate=e,a.momentum=n,a.useNesterov=o,a.accumulations=[],a.m=j(a.momentum),a}return yt(t,r),t.prototype.applyGradients=function(e){var n=this;(Array.isArray(e)?e.map((function(o){return o.name})):Object.keys(e)).forEach((function(o,a){var i=N.registeredVariables[o];n.accumulations[a]==null&&(n.accumulations[a]={originalName:o+"/momentum",variable:K((function(){return me(i).variable(!1)}))});var s=n.accumulations[a].variable,u=Array.isArray(e)?e[a].tensor:e[o];u!=null&&K((function(){var c,l=n.m.mul(s).add(u);c=n.useNesterov?n.c.mul(u.add(l.mul(n.m))).add(i):n.c.mul(l).add(i),s.assign(l),i.assign(c)}))})),this.incrementIterations()},t.prototype.dispose=function(){this.m.dispose(),this.accumulations!=null&&tt(this.accumulations.map((function(e){return e.variable})))},t.prototype.setMomentum=function(e){this.momentum=e},t.prototype.getWeights=function(){return X(this,void 0,void 0,(function(){return $(this,(function(e){switch(e.label){case 0:return[4,this.saveIterations()];case 1:return[2,[e.sent()].concat(this.accumulations.map((function(n){return{name:n.originalName,tensor:n.variable}})))]}}))}))},t.prototype.setWeights=function(e){return X(this,void 0,void 0,(function(){return $(this,(function(n){switch(n.label){case 0:return[4,this.extractIterations(e)];case 1:return e=n.sent(),this.accumulations=e.map((function(o){return{originalName:o.name,variable:o.tensor.variable(!1)}})),[2]}}))}))},t.prototype.getConfig=function(){return{learningRate:this.learningRate,momentum:this.momentum,useNesterov:this.useNesterov}},t.fromConfig=function(e,n){return new e(n.learningRate,n.momentum,n.useNesterov)},t.className="Momentum",t})(uc);_n(Sm);var Dm=(function(r){function t(e,n,o,a,i){n===void 0&&(n=.9),o===void 0&&(o=0),a===void 0&&(a=null),i===void 0&&(i=!1);var s=r.call(this)||this;if(s.learningRate=e,s.decay=n,s.momentum=o,s.epsilon=a,s.accumulatedMeanSquares=[],s.accumulatedMoments=[],s.accumulatedMeanGrads=[],s.centered=i,a==null&&(s.epsilon=N.backend.epsilon()),e==null)throw new Error("learningRate for RMSPropOptimizer must be defined.");return s}return yt(t,r),t.prototype.applyGradients=function(e){var n=this;(Array.isArray(e)?e.map((function(o){return o.name})):Object.keys(e)).forEach((function(o,a){var i=N.registeredVariables[o];n.accumulatedMeanSquares[a]==null&&(n.accumulatedMeanSquares[a]={originalName:o+"/rms",variable:K((function(){return me(i).variable(!1)}))}),n.accumulatedMoments[a]==null&&(n.accumulatedMoments[a]={originalName:o+"/momentum",variable:K((function(){return me(i).variable(!1)}))}),n.accumulatedMeanGrads[a]==null&&n.centered&&(n.accumulatedMeanGrads[a]={originalName:o+"/mg",variable:K((function(){return me(i).variable(!1)}))});var s=Array.isArray(e)?e[a].tensor:e[o];if(s!=null){var u=n.accumulatedMeanSquares[a].variable,c=n.accumulatedMoments[a].variable;K((function(){var l=u.mul(n.decay).add(s.square().mul(1-n.decay));if(n.centered){var h=n.accumulatedMeanGrads[a].variable,f=h.mul(n.decay).add(s.mul(1-n.decay)),p=c.mul(n.momentum).add(s.mul(n.learningRate).div(l.sub(f.square().add(n.epsilon)).sqrt()));u.assign(l),h.assign(f),c.assign(p);var d=i.sub(p);i.assign(d)}else{var v=u.mul(n.decay).add(s.square().mul(1-n.decay));p=c.mul(n.momentum).add(s.mul(n.learningRate).div(v.add(n.epsilon).sqrt())),u.assign(v),c.assign(p),d=i.sub(p),i.assign(d)}}))}})),this.incrementIterations()},t.prototype.dispose=function(){this.accumulatedMeanSquares!=null&&tt(this.accumulatedMeanSquares.map((function(e){return e.variable}))),this.accumulatedMeanGrads!=null&&this.centered&&tt(this.accumulatedMeanGrads.map((function(e){return e.variable}))),this.accumulatedMoments!=null&&tt(this.accumulatedMoments.map((function(e){return e.variable})))},t.prototype.getWeights=function(){return X(this,void 0,void 0,(function(){var e;return $(this,(function(n){switch(n.label){case 0:return e=this.accumulatedMeanSquares.concat(this.accumulatedMoments),this.centered&&e.push.apply(e,this.accumulatedMeanGrads),[4,this.saveIterations()];case 1:return[2,[n.sent()].concat(e.map((function(o){return{name:o.originalName,tensor:o.variable}})))]}}))}))},t.prototype.setWeights=function(e){return X(this,void 0,void 0,(function(){var n;return $(this,(function(o){switch(o.label){case 0:return[4,this.extractIterations(e)];case 1:return e=o.sent(),n=this.centered?e.length/3:e.length/2,this.accumulatedMeanSquares=e.slice(0,n).map((function(a){return{originalName:a.name,variable:a.tensor.variable(!1)}})),this.accumulatedMoments=e.slice(n,2*n).map((function(a){return{originalName:a.name,variable:a.tensor.variable(!1)}})),this.centered&&(this.accumulatedMeanGrads=e.slice(2*n,3*n).map((function(a){return{originalName:a.name,variable:a.tensor.variable(!1)}}))),[2]}}))}))},t.prototype.getConfig=function(){return{learningRate:this.learningRate,decay:this.decay,momentum:this.momentum,epsilon:this.epsilon,centered:this.centered}},t.fromConfig=function(e,n){return new e(n.learningRate,n.decay,n.momentum,n.epsilon,n.centered)},t.className="RMSProp",t})(En);_n(Dm);Ie.prototype.squaredDifference=function(r){return _u(this,r)},M=tm;/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */var ba=function(r,t){return ba=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,n){e.__proto__=n}||function(e,n){for(var o in n)n.hasOwnProperty(o)&&(e[o]=n[o])},ba(r,t)};function re(r,t){ba(r,t);function e(){this.constructor=r}r.prototype=t===null?Object.create(t):(e.prototype=t.prototype,new e)}var Ke=function(){return Ke=Object.assign||function(t){for(var e,n=1,o=arguments.length;n<o;n++){e=arguments[n];for(var a in e)Object.prototype.hasOwnProperty.call(e,a)&&(t[a]=e[a])}return t},Ke.apply(this,arguments)};function Q(r,t,e,n){function o(a){return a instanceof e?a:new e(function(i){i(a)})}return new(e||(e=Promise))(function(a,i){function s(l){try{c(n.next(l))}catch(h){i(h)}}function u(l){try{c(n.throw(l))}catch(h){i(h)}}function c(l){l.done?a(l.value):o(l.value).then(s,u)}c((n=n.apply(r,[])).next())})}function Z(r,t){var e={label:0,sent:function(){if(a[0]&1)throw a[1];return a[1]},trys:[],ops:[]},n,o,a,i;return i={next:s(0),throw:s(1),return:s(2)},typeof Symbol=="function"&&(i[Symbol.iterator]=function(){return this}),i;function s(c){return function(l){return u([c,l])}}function u(c){if(n)throw new TypeError("Generator is already executing.");for(;e;)try{if(n=1,o&&(a=c[0]&2?o.return:c[0]?o.throw||((a=o.return)&&a.call(o),0):o.next)&&!(a=a.call(o,c[1])).done)return a;switch(o=0,a&&(c=[c[0]&2,a.value]),c[0]){case 0:case 1:a=c;break;case 4:return e.label++,{value:c[1],done:!1};case 5:e.label++,o=c[1],c=[0];continue;case 7:c=e.ops.pop(),e.trys.pop();continue;default:if(a=e.trys,!(a=a.length>0&&a[a.length-1])&&(c[0]===6||c[0]===2)){e=0;continue}if(c[0]===3&&(!a||c[1]>a[0]&&c[1]<a[3])){e.label=c[1];break}if(c[0]===6&&e.label<a[1]){e.label=a[1],a=c;break}if(a&&e.label<a[2]){e.label=a[2],e.ops.push(c);break}a[2]&&e.ops.pop(),e.trys.pop();continue}c=t.call(r,e)}catch(l){c=[6,l],o=0}finally{n=a=0}if(c[0]&5)throw c[1];return{value:c[0]?c[1]:void 0,done:!0}}}function nr(){for(var r=0,t=0,e=arguments.length;t<e;t++)r+=arguments[t].length;for(var n=Array(r),o=0,t=0;t<e;t++)for(var a=arguments[t],i=0,s=a.length;i<s;i++,o++)n[o]=a[i];return n}var zn=(function(){function r(t,e){if(!gn(t)||!gn(e))throw new Error("Dimensions.constructor - expected width and height to be valid numbers, instead have "+JSON.stringify({width:t,height:e}));this._width=t,this._height=e}return Object.defineProperty(r.prototype,"width",{get:function(){return this._width},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"height",{get:function(){return this._height},enumerable:!0,configurable:!0}),r.prototype.reverse=function(){return new r(1/this.width,1/this.height)},r})();function po(r,t){return r instanceof Ie&&r.shape.length===t}function Am(r){return po(r,2)}function vo(r){return po(r,3)}function on(r){return po(r,4)}function Tm(r){return r%1!==0}function xs(r){return r%2===0}function Nm(r,t){t===void 0&&(t=2);var e=Math.pow(10,t);return Math.floor(r*e)/e}function bs(r){return r&&r.width&&r.height}function Fm(r,t){var e=r.width,n=r.height,o=t/Math.max(n,e);return new zn(Math.round(e*o),Math.round(n*o))}function ei(r){return r.reduce(function(t,e){return t.add(e)},new ye(0,0)).div(new ye(r.length,r.length))}function ur(r,t,e){return Array(r).fill(0).map(function(n,o){return t+o*e})}function gn(r){return!!r&&r!==1/0&&r!==-1/0&&!isNaN(r)||r===0}function ws(r){return gn(r)&&0<=r&&r<=1}var ye=(function(){function r(t,e){this._x=t,this._y=e}return Object.defineProperty(r.prototype,"x",{get:function(){return this._x},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"y",{get:function(){return this._y},enumerable:!0,configurable:!0}),r.prototype.add=function(t){return new r(this.x+t.x,this.y+t.y)},r.prototype.sub=function(t){return new r(this.x-t.x,this.y-t.y)},r.prototype.mul=function(t){return new r(this.x*t.x,this.y*t.y)},r.prototype.div=function(t){return new r(this.x/t.x,this.y/t.y)},r.prototype.abs=function(){return new r(Math.abs(this.x),Math.abs(this.y))},r.prototype.magnitude=function(){return Math.sqrt(Math.pow(this.x,2)+Math.pow(this.y,2))},r.prototype.floor=function(){return new r(Math.floor(this.x),Math.floor(this.y))},r})(),sn=(function(){function r(t,e){e===void 0&&(e=!0);var n=t||{},o=[n.left,n.top,n.right,n.bottom].every(gn),a=[n.x,n.y,n.width,n.height].every(gn);if(!a&&!o)throw new Error("Box.constructor - expected box to be IBoundingBox | IRect, instead have "+JSON.stringify(n));var i=a?[n.x,n.y,n.width,n.height]:[n.left,n.top,n.right-n.left,n.bottom-n.top],s=i[0],u=i[1],c=i[2],l=i[3];r.assertIsValidBox({x:s,y:u,width:c,height:l},"Box.constructor",e),this._x=s,this._y=u,this._width=c,this._height=l}return r.isRect=function(t){return!!t&&[t.x,t.y,t.width,t.height].every(gn)},r.assertIsValidBox=function(t,e,n){if(n===void 0&&(n=!1),!r.isRect(t))throw new Error(e+" - invalid box: "+JSON.stringify(t)+", expected object with properties x, y, width, height");if(!n&&(t.width<0||t.height<0))throw new Error(e+" - width ("+t.width+") and height ("+t.height+") must be positive numbers")},Object.defineProperty(r.prototype,"x",{get:function(){return this._x},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"y",{get:function(){return this._y},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"width",{get:function(){return this._width},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"height",{get:function(){return this._height},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"left",{get:function(){return this.x},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"top",{get:function(){return this.y},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"right",{get:function(){return this.x+this.width},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"bottom",{get:function(){return this.y+this.height},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"area",{get:function(){return this.width*this.height},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"topLeft",{get:function(){return new ye(this.left,this.top)},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"topRight",{get:function(){return new ye(this.right,this.top)},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"bottomLeft",{get:function(){return new ye(this.left,this.bottom)},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"bottomRight",{get:function(){return new ye(this.right,this.bottom)},enumerable:!0,configurable:!0}),r.prototype.round=function(){var t=[this.x,this.y,this.width,this.height].map(function(i){return Math.round(i)}),e=t[0],n=t[1],o=t[2],a=t[3];return new r({x:e,y:n,width:o,height:a})},r.prototype.floor=function(){var t=[this.x,this.y,this.width,this.height].map(function(i){return Math.floor(i)}),e=t[0],n=t[1],o=t[2],a=t[3];return new r({x:e,y:n,width:o,height:a})},r.prototype.toSquare=function(){var t=this,e=t.x,n=t.y,o=t.width,a=t.height,i=Math.abs(o-a);return o<a&&(e-=i/2,o+=i),a<o&&(n-=i/2,a+=i),new r({x:e,y:n,width:o,height:a})},r.prototype.rescale=function(t){var e=bs(t)?t.width:t,n=bs(t)?t.height:t;return new r({x:this.x*e,y:this.y*n,width:this.width*e,height:this.height*n})},r.prototype.pad=function(t,e){var n=[this.x-t/2,this.y-e/2,this.width+t,this.height+e],o=n[0],a=n[1],i=n[2],s=n[3];return new r({x:o,y:a,width:i,height:s})},r.prototype.clipAtImageBorders=function(t,e){var n=this,o=n.x,a=n.y,i=n.right,s=n.bottom,u=Math.max(o,0),c=Math.max(a,0),l=i-u,h=s-c,f=Math.min(l,t-u),p=Math.min(h,e-c);return new r({x:u,y:c,width:f,height:p}).floor()},r.prototype.shift=function(t,e){var n=this,o=n.width,a=n.height,i=this.x+t,s=this.y+e;return new r({x:i,y:s,width:o,height:a})},r.prototype.padAtBorders=function(t,e){var n=this.width+1,o=this.height+1,a=1,i=1,s=n,u=o,c=this.left,l=this.top,h=this.right,f=this.bottom;return h>e&&(s=-h+e+n,h=e),f>t&&(u=-f+t+o,f=t),c<1&&(u=2-c,c=1),l<1&&(u=2-l,l=1),{dy:i,edy:u,dx:a,edx:s,y:l,ey:f,x:c,ex:h,w:n,h:o}},r.prototype.calibrate=function(t){return new r({left:this.left+t.left*this.width,top:this.top+t.top*this.height,right:this.right+t.right*this.width,bottom:this.bottom+t.bottom*this.height}).toSquare().round()},r})(),mo=(function(r){re(t,r);function t(e,n,o,a,i){return i===void 0&&(i=!1),r.call(this,{left:e,top:n,right:o,bottom:a},i)||this}return t})(sn),cc=(function(){function r(t,e,n,o,a){this._imageDims=new zn(a.width,a.height),this._score=t,this._classScore=e,this._className=n,this._box=new sn(o).rescale(this._imageDims)}return Object.defineProperty(r.prototype,"score",{get:function(){return this._score},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"classScore",{get:function(){return this._classScore},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"className",{get:function(){return this._className},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"box",{get:function(){return this._box},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"imageDims",{get:function(){return this._imageDims},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"imageWidth",{get:function(){return this.imageDims.width},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"imageHeight",{get:function(){return this.imageDims.height},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"relativeBox",{get:function(){return new sn(this._box).rescale(this.imageDims.reverse())},enumerable:!0,configurable:!0}),r.prototype.forSize=function(t,e){return new r(this.score,this.classScore,this.className,this.relativeBox,{width:t,height:e})},r})(),Bt=(function(r){re(t,r);function t(e,n,o){return r.call(this,e,e,"",n,o)||this}return t.prototype.forSize=function(e,n){var o=r.prototype.forSize.call(this,e,n),a=o.score,i=o.relativeBox,s=o.imageDims;return new t(a,i,s)},t})(cc);function Pm(r,t,e){e===void 0&&(e=!0);var n=Math.max(0,Math.min(r.right,t.right)-Math.max(r.left,t.left)),o=Math.max(0,Math.min(r.bottom,t.bottom)-Math.max(r.top,t.top)),a=n*o;return e?a/(r.area+t.area-a):a/Math.min(r.area,t.area)}function Mm(r){var t=r.map(function(s){return s.x}),e=r.map(function(s){return s.y}),n=t.reduce(function(s,u){return u<s?u:s},1/0),o=e.reduce(function(s,u){return u<s?u:s},1/0),a=t.reduce(function(s,u){return s<u?u:s},0),i=e.reduce(function(s,u){return s<u?u:s},0);return new mo(n,o,a,i)}function cr(r,t,e,n){n===void 0&&(n=!0);for(var o=t.map(function(s,u){return{score:s,boxIndex:u}}).sort(function(s,u){return s.score-u.score}).map(function(s){return s.boxIndex}),a=[],i=function(){var s=o.pop();a.push(s);for(var u=o,c=[],l=0;l<u.length;l++){var h=u[l],f=r[s],p=r[h];c.push(Pm(f,p,n))}o=o.filter(function(d,v){return c[v]<=e})};o.length>0;)i();return a}function yr(r,t){return K(function(){var e=t[0],n=t[1],o=t[2],a=Nt(nr(r.shape.slice(0,3),[1]),e),i=Nt(nr(r.shape.slice(0,3),[1]),n),s=Nt(nr(r.shape.slice(0,3),[1]),o),u=Pe([a,i,s],3);return Be(r,u)})}function Om(r,t){return t===void 0&&(t=!1),K(function(){var e=r.shape.slice(1),n=e[0],o=e[1];if(n===o)return r;var a=Math.abs(n-o),i=Math.round(a*(t?.5:1)),s=n>o?2:1,u=function(p){var d=r.shape.slice();return d[s]=p,Nt(d,0)},c=u(i),l=a-c.shape[s],h=t&&l?u(l):null,f=[h,r,c].filter(function(p){return!!p}).map(function(p){return p.toFloat()});return Pe(f,s)})}function Jo(r){return 1/(1+Math.exp(-r))}var ti=(function(r){re(t,r);function t(e,n,o,a,i){return i===void 0&&(i=!1),r.call(this,{x:e,y:n,width:o,height:a},i)||this}return t})(sn),Bm=.5,Lm=.43,Wm=.45,eo=(function(){function r(t,e,n){n===void 0&&(n=new ye(0,0));var o=e.width,a=e.height;this._imgDims=new zn(o,a),this._shift=n,this._positions=t.map(function(i){return i.mul(new ye(o,a)).add(n)})}return Object.defineProperty(r.prototype,"shift",{get:function(){return new ye(this._shift.x,this._shift.y)},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"imageWidth",{get:function(){return this._imgDims.width},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"imageHeight",{get:function(){return this._imgDims.height},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"positions",{get:function(){return this._positions},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"relativePositions",{get:function(){var t=this;return this._positions.map(function(e){return e.sub(t._shift).div(new ye(t.imageWidth,t.imageHeight))})},enumerable:!0,configurable:!0}),r.prototype.forSize=function(t,e){return new this.constructor(this.relativePositions,{width:t,height:e})},r.prototype.shiftBy=function(t,e){return new this.constructor(this.relativePositions,this._imgDims,new ye(t,e))},r.prototype.shiftByPoint=function(t){return this.shiftBy(t.x,t.y)},r.prototype.align=function(t,e){if(e===void 0&&(e={}),t){var n=t instanceof Bt?t.box.floor():new sn(t);return this.shiftBy(n.x,n.y).align(null,e)}var o=Object.assign({},{useDlibAlignment:!1,minBoxPadding:.2},e),a=o.useDlibAlignment,i=o.minBoxPadding;return a?this.alignDlib():this.alignMinBbox(i)},r.prototype.alignDlib=function(){var t=this.getRefPointsForAlignment(),e=t[0],n=t[1],o=t[2],a=function(h){return o.sub(h).magnitude()},i=(a(e)+a(n))/2,s=Math.floor(i/Wm),u=ei(t),c=Math.floor(Math.max(0,u.x-Bm*s)),l=Math.floor(Math.max(0,u.y-Lm*s));return new ti(c,l,Math.min(s,this.imageWidth+c),Math.min(s,this.imageHeight+l))},r.prototype.alignMinBbox=function(t){var e=Mm(this.positions);return e.pad(e.width*t,e.height*t)},r.prototype.getRefPointsForAlignment=function(){throw new Error("getRefPointsForAlignment not implemented by base class")},r})(),Um=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.getRefPointsForAlignment=function(){var e=this.positions;return[e[0],e[1],ei([e[3],e[4]])]},t})(eo),Vm=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.getJawOutline=function(){return this.positions.slice(0,17)},t.prototype.getLeftEyeBrow=function(){return this.positions.slice(17,22)},t.prototype.getRightEyeBrow=function(){return this.positions.slice(22,27)},t.prototype.getNose=function(){return this.positions.slice(27,36)},t.prototype.getLeftEye=function(){return this.positions.slice(36,42)},t.prototype.getRightEye=function(){return this.positions.slice(42,48)},t.prototype.getMouth=function(){return this.positions.slice(48,68)},t.prototype.getRefPointsForAlignment=function(){return[this.getLeftEye(),this.getRightEye(),this.getMouth()].map(ei)},t})(eo),Cs=(function(){function r(t,e){this._label=t,this._distance=e}return Object.defineProperty(r.prototype,"label",{get:function(){return this._label},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"distance",{get:function(){return this._distance},enumerable:!0,configurable:!0}),r.prototype.toString=function(t){return t===void 0&&(t=!0),""+this.label+(t?" ("+Nm(this.distance)+")":"")},r})(),_s=(function(r){re(t,r);function t(e,n){var o=r.call(this,e)||this;return o._label=n,o}return t.assertIsValidLabeledBox=function(e,n){if(sn.assertIsValidBox(e,n),!gn(e.label))throw new Error(n+" - expected property label ("+e.label+") to be a number")},Object.defineProperty(t.prototype,"label",{get:function(){return this._label},enumerable:!0,configurable:!0}),t})(sn),Dr=(function(){function r(t,e){if(typeof t!="string")throw new Error("LabeledFaceDescriptors - constructor expected label to be a string");if(!Array.isArray(e)||e.some(function(n){return!(n instanceof Float32Array)}))throw new Error("LabeledFaceDescriptors - constructor expected descriptors to be an array of Float32Array");this._label=t,this._descriptors=e}return Object.defineProperty(r.prototype,"label",{get:function(){return this._label},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"descriptors",{get:function(){return this._descriptors},enumerable:!0,configurable:!0}),r.prototype.toJSON=function(){return{label:this.label,descriptors:this.descriptors.map(function(t){return Array.from(t)})}},r.fromJSON=function(t){var e=t.descriptors.map(function(n){return new Float32Array(n)});return new r(t.label,e)},r})();(function(r){re(t,r);function t(e,n,o,a){var i=r.call(this,e,n)||this;return i._score=o,i._classScore=a,i}return t.assertIsValidPredictedBox=function(e,n){if(_s.assertIsValidLabeledBox(e,n),!ws(e.score)||!ws(e.classScore))throw new Error(n+" - expected properties score ("+e.score+") and ("+e.classScore+") to be a number between [0, 1]")},Object.defineProperty(t.prototype,"score",{get:function(){return this._score},enumerable:!0,configurable:!0}),Object.defineProperty(t.prototype,"classScore",{get:function(){return this._classScore},enumerable:!0,configurable:!0}),t})(_s);function zm(r){return r.detection instanceof Bt}function ni(r,t){var e={detection:t};return Object.assign({},r,e)}function lc(){var r=window.fetch||function(){throw new Error("fetch - missing fetch implementation for browser environment")},t=function(){throw new Error("readFile - filesystem not available for browser environment")};return{Canvas:HTMLCanvasElement,CanvasRenderingContext2D,Image:HTMLImageElement,ImageData,Video:HTMLVideoElement,createCanvasElement:function(){return document.createElement("canvas")},createImageElement:function(){return document.createElement("img")},fetch:r,readFile:t}}function hc(r){var t="";if(!r)try{r=require("fs")}catch(n){t=n.toString()}var e=r?function(n){return new Promise(function(o,a){r.readFile(n,function(i,s){return i?a(i):o(s)})})}:function(){throw new Error("readFile - failed to require fs in nodejs environment with error: "+t)};return{readFile:e}}function fc(){var r=global.Canvas||global.HTMLCanvasElement,t=global.Image||global.HTMLImageElement,e=function(){if(r)return new r;throw new Error("createCanvasElement - missing Canvas implementation for nodejs environment")},n=function(){if(t)return new t;throw new Error("createImageElement - missing Image implementation for nodejs environment")},o=global.fetch||function(){throw new Error("fetch - missing fetch implementation for nodejs environment")},a=hc();return Ke({Canvas:r||(function(){function i(){}return i})(),CanvasRenderingContext2D:global.CanvasRenderingContext2D||(function(){function i(){}return i})(),Image:t||(function(){function i(){}return i})(),ImageData:global.ImageData||(function(){function i(){}return i})(),Video:global.HTMLVideoElement||(function(){function i(){}return i})(),createCanvasElement:e,createImageElement:n,fetch:o},a)}function pc(){return typeof window=="object"&&typeof document<"u"&&typeof HTMLImageElement<"u"&&typeof HTMLCanvasElement<"u"&&typeof HTMLVideoElement<"u"&&typeof ImageData<"u"&&typeof CanvasRenderingContext2D<"u"}function dc(){return typeof global=="object"&&typeof require=="function"&&typeof module<"u"&&typeof process<"u"&&!!process.version}var Fe;function Gm(){if(!Fe)throw new Error("getEnv - environment is not defined, check isNodejs() and isBrowser()");return Fe}function wa(r){Fe=r}function ri(){pc()&&wa(lc()),dc()&&wa(fc())}function Hm(r){if(Fe||ri(),!Fe)throw new Error("monkeyPatch - environment is not defined, check isNodejs() and isBrowser()");var t=r.Canvas,e=t===void 0?Fe.Canvas:t,n=r.Image,o=n===void 0?Fe.Image:n;Fe.Canvas=e,Fe.Image=o,Fe.createCanvasElement=r.createCanvasElement||(function(){return new e}),Fe.createImageElement=r.createImageElement||(function(){return new o}),Fe.ImageData=r.ImageData||Fe.ImageData,Fe.Video=r.Video||Fe.Video,Fe.fetch=r.fetch||Fe.fetch,Fe.readFile=r.readFile||Fe.readFile}var Je={getEnv:Gm,setEnv:wa,initialize:ri,createBrowserEnv:lc,createFileSystem:hc,createNodejsEnv:fc,monkeyPatch:Hm,isBrowser:pc,isNodejs:dc};ri();function vc(r){return!Je.isNodejs()&&typeof r=="string"?document.getElementById(r):r}function xn(r){var t=Je.getEnv(),e=t.Canvas,n=t.CanvasRenderingContext2D;if(r instanceof n)return r;var o=vc(r);if(!(o instanceof e))throw new Error("resolveContext2d - expected canvas to be of instance of Canvas");var a=o.getContext("2d");if(!a)throw new Error("resolveContext2d - canvas 2d context is null");return a}var Es;(function(r){r.TOP_LEFT="TOP_LEFT",r.TOP_RIGHT="TOP_RIGHT",r.BOTTOM_LEFT="BOTTOM_LEFT",r.BOTTOM_RIGHT="BOTTOM_RIGHT"})(Es||(Es={}));function mc(r){var t=Je.getEnv(),e=t.Image,n=t.Video;return r instanceof e&&r.complete||r instanceof n&&r.readyState>=3}function jm(r){return new Promise(function(t,e){if(r instanceof Je.getEnv().Canvas||mc(r))return t();function n(a){a.currentTarget&&(a.currentTarget.removeEventListener("load",n),a.currentTarget.removeEventListener("error",o),t(a))}function o(a){a.currentTarget&&(a.currentTarget.removeEventListener("load",n),a.currentTarget.removeEventListener("error",o),e(a))}r.addEventListener("load",n),r.addEventListener("error",o)})}function gc(r){var t=Je.getEnv(),e=t.Image,n=t.Video;return r instanceof e?new zn(r.naturalWidth,r.naturalHeight):r instanceof n?new zn(r.videoWidth,r.videoHeight):new zn(r.width,r.height)}function go(r){var t=r.width,e=r.height,n=Je.getEnv().createCanvasElement,o=n();return o.width=t,o.height=e,o}function oi(r,t){var e=Je.getEnv().ImageData;if(!(r instanceof e)&&!mc(r))throw new Error("createCanvasFromMedia - media has not finished loading yet");var n=gc(r),o=n.width,a=n.height,i=go({width:o,height:a});return r instanceof e?xn(i).putImageData(r,0,0):xn(i).drawImage(r,0,0,o,a),i}function qm(r,t){return Q(this,void 0,void 0,function(){var e,n,o,a,i,s;return Z(this,function(u){switch(u.label){case 0:return e=Je.getEnv().createCanvasElement(),n=r.shape.slice(on(r)?1:0),o=n[0],a=n[1],i=n[2],s=K(function(){return r.as3D(o,a,i).toInt()}),[4,Za.toPixels(s,e)];case 1:return u.sent(),s.dispose(),[2,e]}})})}function Is(r){var t=Je.getEnv(),e=t.Image,n=t.Canvas,o=t.Video;return r instanceof e||r instanceof n||r instanceof o}function Km(r,t,e){e===void 0&&(e=!1);var n=Je.getEnv(),o=n.Image,a=n.Canvas;if(!(r instanceof o||r instanceof a))throw new Error("imageToSquare - expected arg0 to be HTMLImageElement | HTMLCanvasElement");var i=gc(r),s=t/Math.max(i.height,i.width),u=s*i.width,c=s*i.height,l=go({width:t,height:t}),h=r instanceof a?r:oi(r),f=Math.abs(u-c)/2,p=e&&u<c?f:0,d=e&&c<u?f:0;return xn(l).drawImage(h,p,d,u,c),l}var to=(function(){function r(t,e){var n=this;if(e===void 0&&(e=!1),this._imageTensors=[],this._canvases=[],this._treatAsBatchInput=!1,this._inputDimensions=[],!Array.isArray(t))throw new Error("NetInput.constructor - expected inputs to be an Array of TResolvedNetInput or to be instanceof tf.Tensor4D, instead have "+t);this._treatAsBatchInput=e,this._batchSize=t.length,t.forEach(function(o,a){if(vo(o)){n._imageTensors[a]=o,n._inputDimensions[a]=o.shape;return}if(on(o)){var i=o.shape[0];if(i!==1)throw new Error("NetInput - tf.Tensor4D with batchSize "+i+" passed, but not supported in input array");n._imageTensors[a]=o,n._inputDimensions[a]=o.shape.slice(1);return}var s=o instanceof Je.getEnv().Canvas?o:oi(o);n._canvases[a]=s,n._inputDimensions[a]=[s.height,s.width,3]})}return Object.defineProperty(r.prototype,"imageTensors",{get:function(){return this._imageTensors},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"canvases",{get:function(){return this._canvases},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"isBatchInput",{get:function(){return this.batchSize>1||this._treatAsBatchInput},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"batchSize",{get:function(){return this._batchSize},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"inputDimensions",{get:function(){return this._inputDimensions},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"inputSize",{get:function(){return this._inputSize},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"reshapedInputDimensions",{get:function(){var t=this;return ur(this.batchSize,0,1).map(function(e,n){return t.getReshapedInputDimensions(n)})},enumerable:!0,configurable:!0}),r.prototype.getInput=function(t){return this.canvases[t]||this.imageTensors[t]},r.prototype.getInputDimensions=function(t){return this._inputDimensions[t]},r.prototype.getInputHeight=function(t){return this._inputDimensions[t][0]},r.prototype.getInputWidth=function(t){return this._inputDimensions[t][1]},r.prototype.getReshapedInputDimensions=function(t){if(typeof this.inputSize!="number")throw new Error("getReshapedInputDimensions - inputSize not set, toBatchTensor has not been called yet");var e=this.getInputWidth(t),n=this.getInputHeight(t);return Fm({width:e,height:n},this.inputSize)},r.prototype.toBatchTensor=function(t,e){var n=this;return e===void 0&&(e=!0),this._inputSize=t,K(function(){var o=ur(n.batchSize,0,1).map(function(i){var s=n.getInput(i);if(s instanceof Ie){var u=on(s)?s:s.expandDims();return u=Om(u,e),(u.shape[1]!==t||u.shape[2]!==t)&&(u=Ka.resizeBilinear(u,[t,t])),u.as3D(t,t,3)}if(s instanceof Je.getEnv().Canvas)return Za.fromPixels(Km(s,t,e));throw new Error("toBatchTensor - at batchIdx "+i+", expected input to be instanceof tf.Tensor or instanceof HTMLCanvasElement, instead have "+s)}),a=lt(o.map(function(i){return i.toFloat()})).as4D(n.batchSize,t,t,3);return a})},r})();function Ve(r){return Q(this,void 0,void 0,function(){var t,e,n;return Z(this,function(o){switch(o.label){case 0:if(r instanceof to)return[2,r];if(t=Array.isArray(r)?r:[r],!t.length)throw new Error("toNetInput - empty array passed as input");return e=function(a){return Array.isArray(r)?" at input index "+a+":":""},n=t.map(vc),n.forEach(function(a,i){if(!Is(a)&&!vo(a)&&!on(a))throw typeof t[i]=="string"?new Error("toNetInput -"+e(i)+" string passed, but could not resolve HTMLElement for element id "+t[i]):new Error("toNetInput -"+e(i)+" expected media to be of type HTMLImageElement | HTMLVideoElement | HTMLCanvasElement | tf.Tensor3D, or to be an element id");if(on(a)){var s=a.shape[0];if(s!==1)throw new Error("toNetInput -"+e(i)+" tf.Tensor4D with batchSize "+s+" passed, but not supported in input array")}}),[4,Promise.all(n.map(function(a){return Is(a)&&jm(a)}))];case 1:return o.sent(),[2,new to(n,Array.isArray(r))]}})})}function ai(r,t){return Q(this,void 0,void 0,function(){var e,n,o,a,i,s,u;return Z(this,function(c){switch(c.label){case 0:return e=Je.getEnv().Canvas,n=r,r instanceof e?[3,5]:[4,Ve(r)];case 1:if(o=c.sent(),o.batchSize>1)throw new Error("extractFaces - batchSize > 1 not supported");return a=o.getInput(0),a instanceof e?(i=a,[3,4]):[3,2];case 2:return[4,qm(a)];case 3:i=c.sent(),c.label=4;case 4:n=i,c.label=5;case 5:return s=xn(n),u=t.map(function(l){return l instanceof Bt?l.forSize(n.width,n.height).box.floor():l}).map(function(l){return l.clipAtImageBorders(n.width,n.height)}),[2,u.map(function(l){var h=l.x,f=l.y,p=l.width,d=l.height,v=go({width:p,height:d});return xn(v).putImageData(s.getImageData(h,f,p,d),0,0),v})]}})})}function ii(r,t){return Q(this,void 0,void 0,function(){return Z(this,function(e){if(!vo(r)&&!on(r))throw new Error("extractFaceTensors - expected image tensor to be 3D or 4D");if(on(r)&&r.shape[0]>1)throw new Error("extractFaceTensors - batchSize > 1 not supported");return[2,K(function(){var n=r.shape.slice(on(r)?1:0),o=n[0],a=n[1],i=n[2],s=t.map(function(c){return c instanceof Bt?c.forSize(a,o).box:c}).map(function(c){return c.clipAtImageBorders(a,o)}),u=s.map(function(c){var l=c.x,h=c.y,f=c.width,p=c.height;return Hu(r.as3D(o,a,i),[h,l,0],[p,f,i])});return u})]})})}function Xm(r,t){return Q(this,void 0,void 0,function(){var e,n;return Z(this,function(o){switch(o.label){case 0:return e=Je.getEnv().fetch,[4,e(r,t)];case 1:if(n=o.sent(),!(n.status<400))throw new Error("failed to fetch: ("+n.status+") "+n.statusText+", from url: "+n.url);return[2,n]}})})}function $m(r){return Q(this,void 0,void 0,function(){return Z(this,function(t){switch(t.label){case 0:return[4,Xm(r)];case 1:return[2,t.sent().json()]}})})}function yc(r,t){var e=t+"-weights_manifest.json";if(!r)return{modelBaseUri:"",manifestUri:e};if(r==="/")return{modelBaseUri:"/",manifestUri:"/"+e};var n=r.startsWith("http://")?"http://":r.startsWith("https://")?"https://":"";r=r.replace(n,"");var o=r.split("/").filter(function(s){return s}),a=r.endsWith(".json")?o[o.length-1]:e,i=n+(r.endsWith(".json")?o.slice(0,o.length-1):o).join("/");return i=r.startsWith("/")?"/"+i:i,{modelBaseUri:i,manifestUri:i==="/"?"/"+a:i+"/"+a}}function Ym(r,t){return Q(this,void 0,void 0,function(){var e,n,o,a;return Z(this,function(i){switch(i.label){case 0:return e=yc(r,t),n=e.manifestUri,o=e.modelBaseUri,[4,$m(n)];case 1:return a=i.sent(),[2,sc.loadWeights(a,o)]}})})}var Xt=(function(){function r(t){this._name=t,this._params=void 0,this._paramMappings=[]}return Object.defineProperty(r.prototype,"params",{get:function(){return this._params},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"paramMappings",{get:function(){return this._paramMappings},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"isLoaded",{get:function(){return!!this.params},enumerable:!0,configurable:!0}),r.prototype.getParamFromPath=function(t){var e=this.traversePropertyPath(t),n=e.obj,o=e.objProp;return n[o]},r.prototype.reassignParamFromPath=function(t,e){var n=this.traversePropertyPath(t),o=n.obj,a=n.objProp;o[a].dispose(),o[a]=e},r.prototype.getParamList=function(){var t=this;return this._paramMappings.map(function(e){var n=e.paramPath;return{path:n,tensor:t.getParamFromPath(n)}})},r.prototype.getTrainableParams=function(){return this.getParamList().filter(function(t){return t.tensor instanceof jn})},r.prototype.getFrozenParams=function(){return this.getParamList().filter(function(t){return!(t.tensor instanceof jn)})},r.prototype.variable=function(){var t=this;this.getFrozenParams().forEach(function(e){var n=e.path,o=e.tensor;t.reassignParamFromPath(n,o.variable())})},r.prototype.freeze=function(){var t=this;this.getTrainableParams().forEach(function(e){var n=e.path,o=e.tensor,a=je(o.dataSync());o.dispose(),t.reassignParamFromPath(n,a)})},r.prototype.dispose=function(t){t===void 0&&(t=!0),this.getParamList().forEach(function(e){if(t&&e.tensor.isDisposed)throw new Error("param tensor has already been disposed for path "+e.path);e.tensor.dispose()}),this._params=void 0},r.prototype.serializeParams=function(){return new Float32Array(this.getParamList().map(function(t){var e=t.tensor;return Array.from(e.dataSync())}).reduce(function(t,e){return t.concat(e)}))},r.prototype.load=function(t){return Q(this,void 0,void 0,function(){return Z(this,function(e){switch(e.label){case 0:return t instanceof Float32Array?(this.extractWeights(t),[2]):[4,this.loadFromUri(t)];case 1:return e.sent(),[2]}})})},r.prototype.loadFromUri=function(t){return Q(this,void 0,void 0,function(){var e;return Z(this,function(n){switch(n.label){case 0:if(t&&typeof t!="string")throw new Error(this._name+".loadFromUri - expected model uri");return[4,Ym(t,this.getDefaultModelName())];case 1:return e=n.sent(),this.loadFromWeightMap(e),[2]}})})},r.prototype.loadFromDisk=function(t){return Q(this,void 0,void 0,function(){var e,n,o,a,i,s,u,c,l,h;return Z(this,function(f){switch(f.label){case 0:if(t&&typeof t!="string")throw new Error(this._name+".loadFromDisk - expected model file path");return e=Je.getEnv().readFile,n=yc(t,this.getDefaultModelName()),o=n.manifestUri,a=n.modelBaseUri,i=function(p){return Promise.all(p.map(function(d){return e(d).then(function(v){return v.buffer})}))},s=sc.weightsLoaderFactory(i),l=(c=JSON).parse,[4,e(o)];case 1:return u=l.apply(c,[f.sent().toString()]),[4,s(u,a)];case 2:return h=f.sent(),this.loadFromWeightMap(h),[2]}})})},r.prototype.loadFromWeightMap=function(t){var e=this.extractParamsFromWeigthMap(t),n=e.paramMappings,o=e.params;this._paramMappings=n,this._params=o},r.prototype.extractWeights=function(t){var e=this.extractParams(t),n=e.paramMappings,o=e.params;this._paramMappings=n,this._params=o},r.prototype.traversePropertyPath=function(t){if(!this.params)throw new Error("traversePropertyPath - model has no loaded params");var e=t.split("/").reduce(function(a,i){if(!a.nextObj.hasOwnProperty(i))throw new Error("traversePropertyPath - object does not have property "+i+", for path "+t);return{obj:a.nextObj,objProp:i,nextObj:a.nextObj[i]}},{nextObj:this.params}),n=e.obj,o=e.objProp;if(!n||!o||!(n[o]instanceof Ie))throw new Error("traversePropertyPath - parameter is not a tensor, for path "+t);return{obj:n,objProp:o}},r})();function ct(r,t,e){return K(function(){var n=za(r,t.depthwise_filter,t.pointwise_filter,e,"same");return n=ue(n,t.bias),n})}function Qo(r,t,e){return e===void 0&&(e=!1),K(function(){var n=Re(e?ue(dt(r,t.conv0.filters,[2,2],"same"),t.conv0.bias):ct(r,t.conv0,[2,2])),o=ct(n,t.conv1,[1,1]),a=Re(ue(n,o)),i=ct(a,t.conv2,[1,1]);return Re(ue(n,ue(o,i)))})}function Ar(r,t,e,n){return e===void 0&&(e=!1),n===void 0&&(n=!0),K(function(){var o=Re(e?ue(dt(r,t.conv0.filters,n?[2,2]:[1,1],"same"),t.conv0.bias):ct(r,t.conv0,n?[2,2]:[1,1])),a=ct(o,t.conv1,[1,1]),i=Re(ue(o,a)),s=ct(i,t.conv2,[1,1]),u=Re(ue(o,ue(a,s))),c=ct(u,t.conv3,[1,1]);return Re(ue(o,ue(a,ue(s,c))))})}function gt(r,t,e,n){return e===void 0&&(e="same"),n===void 0&&(n=!1),K(function(){var o=ue(dt(r,t.filters,[1,1],e),t.bias);return n?Re(o):o})}function $t(r,t){Object.keys(r).forEach(function(e){t.some(function(n){return n.originalPath===e})||r[e].dispose()})}function yo(r,t){return function(e,n,o,a){var i=Ze(r(e*n*o*o),[o,o,e,n]),s=Ne(r(n));return t.push({paramPath:a+"/filters"},{paramPath:a+"/bias"}),{filters:i,bias:s}}}function si(r,t){return function(e,n,o){var a=nn(r(e*n),[e,n]),i=Ne(r(n));return t.push({paramPath:o+"/weights"},{paramPath:o+"/bias"}),{weights:a,bias:i}}}var xc=(function(){function r(t,e,n){this.depthwise_filter=t,this.pointwise_filter=e,this.bias=n}return r})();function ui(r,t){return function(e,n,o){var a=Ze(r(9*e),[3,3,e,1]),i=Ze(r(e*n),[1,1,e,n]),s=Ne(r(n));return t.push({paramPath:o+"/depthwise_filter"},{paramPath:o+"/pointwise_filter"},{paramPath:o+"/bias"}),new xc(a,i,s)}}function ci(r){return function(t){var e=r(t+"/depthwise_filter",4),n=r(t+"/pointwise_filter",4),o=r(t+"/bias",1);return new xc(e,n,o)}}function ln(r,t){return function(e,n,o){var a=r[e];if(!po(a,n))throw new Error("expected weightMap["+e+"] to be a Tensor"+n+"D, instead have "+a);return t.push({originalPath:e,paramPath:o||e}),a}}function Yt(r){var t=r;function e(o){var a=t.slice(0,o);return t=t.slice(o),a}function n(){return t}return{extractWeights:e,getRemainingWeights:n}}function bc(r,t){var e=yo(r,t),n=ui(r,t);function o(i,s,u,c){c===void 0&&(c=!1);var l=c?e(i,s,3,u+"/conv0"):n(i,s,u+"/conv0"),h=n(s,s,u+"/conv1"),f=n(s,s,u+"/conv2");return{conv0:l,conv1:h,conv2:f}}function a(i,s,u,c){c===void 0&&(c=!1);var l=o(i,s,u,c),h=l.conv0,f=l.conv1,p=l.conv2,d=n(s,s,u+"/conv3");return{conv0:h,conv1:f,conv2:p,conv3:d}}return{extractDenseBlock3Params:o,extractDenseBlock4Params:a}}function Jm(r){var t=[],e=Yt(r),n=e.extractWeights,o=e.getRemainingWeights,a=bc(n,t).extractDenseBlock4Params,i=a(3,32,"dense0",!0),s=a(32,64,"dense1"),u=a(64,128,"dense2"),c=a(128,256,"dense3");if(o().length!==0)throw new Error("weights remaing after extract: "+o().length);return{paramMappings:t,params:{dense0:i,dense1:s,dense2:u,dense3:c}}}function wc(r){return function(t){var e=r(t+"/filters",4),n=r(t+"/bias",1);return{filters:e,bias:n}}}function Cc(r,t){var e=ln(r,t),n=wc(e),o=ci(e);function a(s,u){u===void 0&&(u=!1);var c=u?n(s+"/conv0"):o(s+"/conv0"),l=o(s+"/conv1"),h=o(s+"/conv2");return{conv0:c,conv1:l,conv2:h}}function i(s,u){u===void 0&&(u=!1);var c=u?n(s+"/conv0"):o(s+"/conv0"),l=o(s+"/conv1"),h=o(s+"/conv2"),f=o(s+"/conv3");return{conv0:c,conv1:l,conv2:h,conv3:f}}return{extractDenseBlock3Params:a,extractDenseBlock4Params:i}}function Qm(r){var t=[],e=Cc(r,t).extractDenseBlock4Params,n={dense0:e("dense0",!0),dense1:e("dense1"),dense2:e("dense2"),dense3:e("dense3")};return $t(r,t),{params:n,paramMappings:t}}var _c=(function(r){re(t,r);function t(){return r.call(this,"FaceFeatureExtractor")||this}return t.prototype.forwardInput=function(e){var n=this.params;if(!n)throw new Error("FaceFeatureExtractor - load model before inference");return K(function(){var o=e.toBatchTensor(112,!0),a=[122.782,117.001,104.298],i=yr(o,a).div(j(255)),s=Ar(i,n.dense0,!0);return s=Ar(s,n.dense1),s=Ar(s,n.dense2),s=Ar(s,n.dense3),s=mr(s,[7,7],[2,2],"valid"),s})},t.prototype.forward=function(e){return Q(this,void 0,void 0,function(){var n;return Z(this,function(o){switch(o.label){case 0:return n=this.forwardInput,[4,Ve(e)];case 1:return[2,n.apply(this,[o.sent()])]}})})},t.prototype.getDefaultModelName=function(){return"face_feature_extractor_model"},t.prototype.extractParamsFromWeigthMap=function(e){return Qm(e)},t.prototype.extractParams=function(e){return Jm(e)},t})(Xt);function Dt(r,t){return K(function(){return ue(lo(r,t.weights),t.bias)})}function Zm(r,t,e){var n=[],o=Yt(r),a=o.extractWeights,i=o.getRemainingWeights,s=si(a,n),u=s(t,e,"fc");if(i().length!==0)throw new Error("weights remaing after extract: "+i().length);return{paramMappings:n,params:{fc:u}}}function eg(r){var t=[],e=ln(r,t);function n(a){var i=e(a+"/weights",2),s=e(a+"/bias",1);return{weights:i,bias:s}}var o={fc:n("fc")};return $t(r,t),{params:o,paramMappings:t}}function Ec(r){var t={},e={};return Object.keys(r).forEach(function(n){var o=n.startsWith("fc")?e:t;o[n]=r[n]}),{featureExtractorMap:t,classifierMap:e}}var Ic=(function(r){re(t,r);function t(e,n){var o=r.call(this,e)||this;return o._faceFeatureExtractor=n,o}return Object.defineProperty(t.prototype,"faceFeatureExtractor",{get:function(){return this._faceFeatureExtractor},enumerable:!0,configurable:!0}),t.prototype.runNet=function(e){var n=this,o=this.params;if(!o)throw new Error(this._name+" - load model before inference");return K(function(){var a=e instanceof to?n.faceFeatureExtractor.forwardInput(e):e;return Dt(a.as2D(a.shape[0],-1),o.fc)})},t.prototype.dispose=function(e){e===void 0&&(e=!0),this.faceFeatureExtractor.dispose(e),r.prototype.dispose.call(this,e)},t.prototype.loadClassifierParams=function(e){var n=this.extractClassifierParams(e),o=n.params,a=n.paramMappings;this._params=o,this._paramMappings=a},t.prototype.extractClassifierParams=function(e){return Zm(e,this.getClassifierChannelsIn(),this.getClassifierChannelsOut())},t.prototype.extractParamsFromWeigthMap=function(e){var n=Ec(e),o=n.featureExtractorMap,a=n.classifierMap;return this.faceFeatureExtractor.loadFromWeightMap(o),eg(a)},t.prototype.extractParams=function(e){var n=this.getClassifierChannelsIn(),o=this.getClassifierChannelsOut(),a=o*n+o,i=e.slice(0,e.length-a),s=e.slice(e.length-a);return this.faceFeatureExtractor.extractWeights(i),this.extractClassifierParams(s)},t})(Xt),Rs=["neutral","happy","sad","angry","fearful","disgusted","surprised"],tg=(function(){function r(t){var e=this;if(t.length!==7)throw new Error("FaceExpressions.constructor - expected probabilities.length to be 7, have: "+t.length);Rs.forEach(function(n,o){e[n]=t[o]})}return r.prototype.asSortedArray=function(){var t=this;return Rs.map(function(e){return{expression:e,probability:t[e]}}).sort(function(e,n){return n.probability-e.probability})},r})(),ng=(function(r){re(t,r);function t(e){return e===void 0&&(e=new _c),r.call(this,"FaceExpressionNet",e)||this}return t.prototype.forwardInput=function(e){var n=this;return K(function(){return qt(n.runNet(e))})},t.prototype.forward=function(e){return Q(this,void 0,void 0,function(){var n;return Z(this,function(o){switch(o.label){case 0:return n=this.forwardInput,[4,Ve(e)];case 1:return[2,n.apply(this,[o.sent()])]}})})},t.prototype.predictExpressions=function(e){return Q(this,void 0,void 0,function(){var n,o,a,i,s=this;return Z(this,function(u){switch(u.label){case 0:return[4,Ve(e)];case 1:return n=u.sent(),[4,this.forwardInput(n)];case 2:return o=u.sent(),[4,Promise.all(Me(o).map(function(c){return Q(s,void 0,void 0,function(){var l;return Z(this,function(h){switch(h.label){case 0:return[4,c.data()];case 1:return l=h.sent(),c.dispose(),[2,l]}})})}))];case 3:return a=u.sent(),o.dispose(),i=a.map(function(c){return new tg(c)}),[2,n.isBatchInput?i:i[0]]}})})},t.prototype.getDefaultModelName=function(){return"face_expression_model"},t.prototype.getClassifierChannelsIn=function(){return 256},t.prototype.getClassifierChannelsOut=function(){return 7},t})(Ic);function Rc(r,t){var e={expressions:t};return Object.assign({},r,e)}function rg(r){return zm(r)&&r.landmarks instanceof eo&&r.unshiftedLandmarks instanceof eo&&r.alignedRect instanceof Bt}function li(r,t){var e=r.detection.box,n=t.shiftBy(e.x,e.y),o=n.align(),a=r.detection.imageDims,i=new Bt(r.detection.score,o.rescale(a.reverse()),a),s={landmarks:n,unshiftedLandmarks:t,alignedRect:i};return Object.assign({},r,s)}function og(r,t){var e=yo(r,t),n=ui(r,t);function o(i,s,u){var c=n(i,s,u+"/separable_conv0"),l=n(s,s,u+"/separable_conv1"),h=e(i,s,1,u+"/expansion_conv");return{separable_conv0:c,separable_conv1:l,expansion_conv:h}}function a(i,s){var u=n(i,i,s+"/separable_conv0"),c=n(i,i,s+"/separable_conv1"),l=n(i,i,s+"/separable_conv2");return{separable_conv0:u,separable_conv1:c,separable_conv2:l}}return{extractConvParams:e,extractSeparableConvParams:n,extractReductionBlockParams:o,extractMainBlockParams:a}}function ag(r,t){var e=[],n=Yt(r),o=n.extractWeights,a=n.getRemainingWeights,i=og(o,e),s=i.extractConvParams,u=i.extractSeparableConvParams,c=i.extractReductionBlockParams,l=i.extractMainBlockParams,h=s(3,32,3,"entry_flow/conv_in"),f=c(32,64,"entry_flow/reduction_block_0"),p=c(64,128,"entry_flow/reduction_block_1"),d={conv_in:h,reduction_block_0:f,reduction_block_1:p},v={};ur(t,0,1).forEach(function(b){v["main_block_"+b]=l(128,"middle_flow/main_block_"+b)});var m=c(128,256,"exit_flow/reduction_block"),g=u(256,512,"exit_flow/separable_conv"),x={reduction_block:m,separable_conv:g};if(a().length!==0)throw new Error("weights remaing after extract: "+a().length);return{paramMappings:e,params:{entry_flow:d,middle_flow:v,exit_flow:x}}}function ig(r,t){var e=ln(r,t),n=wc(e),o=ci(e);function a(s){var u=o(s+"/separable_conv0"),c=o(s+"/separable_conv1"),l=n(s+"/expansion_conv");return{separable_conv0:u,separable_conv1:c,expansion_conv:l}}function i(s){var u=o(s+"/separable_conv0"),c=o(s+"/separable_conv1"),l=o(s+"/separable_conv2");return{separable_conv0:u,separable_conv1:c,separable_conv2:l}}return{extractConvParams:n,extractSeparableConvParams:o,extractReductionBlockParams:a,extractMainBlockParams:i}}function sg(r,t){var e=[],n=ig(r,e),o=n.extractConvParams,a=n.extractSeparableConvParams,i=n.extractReductionBlockParams,s=n.extractMainBlockParams,u=o("entry_flow/conv_in"),c=i("entry_flow/reduction_block_0"),l=i("entry_flow/reduction_block_1"),h={conv_in:u,reduction_block_0:c,reduction_block_1:l},f={};ur(t,0,1).forEach(function(m){f["main_block_"+m]=s("middle_flow/main_block_"+m)});var p=i("exit_flow/reduction_block"),d=a("exit_flow/separable_conv"),v={reduction_block:p,separable_conv:d};return $t(r,e),{params:{entry_flow:h,middle_flow:f,exit_flow:v},paramMappings:e}}function kc(r,t,e){return ue(dt(r,t.filters,e,"same"),t.bias)}function Zo(r,t,e){e===void 0&&(e=!0);var n=e?Re(r):r;return n=ct(n,t.separable_conv0,[1,1]),n=ct(Re(n),t.separable_conv1,[1,1]),n=We(n,[3,3],[2,2],"same"),n=ue(n,kc(r,t.expansion_conv,[2,2])),n}function ug(r,t){var e=ct(Re(r),t.separable_conv0,[1,1]);return e=ct(Re(e),t.separable_conv1,[1,1]),e=ct(Re(e),t.separable_conv2,[1,1]),e=ue(e,r),e}var cg=(function(r){re(t,r);function t(e){var n=r.call(this,"TinyXception")||this;return n._numMainBlocks=e,n}return t.prototype.forwardInput=function(e){var n=this,o=this.params;if(!o)throw new Error("TinyXception - load model before inference");return K(function(){var a=e.toBatchTensor(112,!0),i=[122.782,117.001,104.298],s=yr(a,i).div(j(256)),u=Re(kc(s,o.entry_flow.conv_in,[2,2]));return u=Zo(u,o.entry_flow.reduction_block_0,!1),u=Zo(u,o.entry_flow.reduction_block_1),ur(n._numMainBlocks,0,1).forEach(function(c){u=ug(u,o.middle_flow["main_block_"+c])}),u=Zo(u,o.exit_flow.reduction_block),u=Re(ct(u,o.exit_flow.separable_conv,[1,1])),u})},t.prototype.forward=function(e){return Q(this,void 0,void 0,function(){var n;return Z(this,function(o){switch(o.label){case 0:return n=this.forwardInput,[4,Ve(e)];case 1:return[2,n.apply(this,[o.sent()])]}})})},t.prototype.getDefaultModelName=function(){return"tiny_xception_model"},t.prototype.extractParamsFromWeigthMap=function(e){return sg(e,this._numMainBlocks)},t.prototype.extractParams=function(e){return ag(e,this._numMainBlocks)},t})(Xt);function lg(r){var t=[],e=Yt(r),n=e.extractWeights,o=e.getRemainingWeights,a=si(n,t),i=a(512,1,"fc/age"),s=a(512,2,"fc/gender");if(o().length!==0)throw new Error("weights remaing after extract: "+o().length);return{paramMappings:t,params:{fc:{age:i,gender:s}}}}function hg(r){var t=[],e=ln(r,t);function n(a){var i=e(a+"/weights",2),s=e(a+"/bias",1);return{weights:i,bias:s}}var o={fc:{age:n("fc/age"),gender:n("fc/gender")}};return $t(r,t),{params:o,paramMappings:t}}var no;(function(r){r.FEMALE="female",r.MALE="male"})(no||(no={}));var fg=(function(r){re(t,r);function t(e){e===void 0&&(e=new cg(2));var n=r.call(this,"AgeGenderNet")||this;return n._faceFeatureExtractor=e,n}return Object.defineProperty(t.prototype,"faceFeatureExtractor",{get:function(){return this._faceFeatureExtractor},enumerable:!0,configurable:!0}),t.prototype.runNet=function(e){var n=this,o=this.params;if(!o)throw new Error(this._name+" - load model before inference");return K(function(){var a=e instanceof to?n.faceFeatureExtractor.forwardInput(e):e,i=mr(a,[7,7],[2,2],"valid").as2D(a.shape[0],-1),s=Dt(i,o.fc.age).as1D(),u=Dt(i,o.fc.gender);return{age:s,gender:u}})},t.prototype.forwardInput=function(e){var n=this;return K(function(){var o=n.runNet(e),a=o.age,i=o.gender;return{age:a,gender:qt(i)}})},t.prototype.forward=function(e){return Q(this,void 0,void 0,function(){var n;return Z(this,function(o){switch(o.label){case 0:return n=this.forwardInput,[4,Ve(e)];case 1:return[2,n.apply(this,[o.sent()])]}})})},t.prototype.predictAgeAndGender=function(e){return Q(this,void 0,void 0,function(){var n,o,a,i,s,u,c=this;return Z(this,function(l){switch(l.label){case 0:return[4,Ve(e)];case 1:return n=l.sent(),[4,this.forwardInput(n)];case 2:return o=l.sent(),a=Me(o.age),i=Me(o.gender),s=a.map(function(h,f){return{ageTensor:h,genderTensor:i[f]}}),[4,Promise.all(s.map(function(h){var f=h.ageTensor,p=h.genderTensor;return Q(c,void 0,void 0,function(){var d,v,m,g,x;return Z(this,function(b){switch(b.label){case 0:return[4,f.data()];case 1:return d=b.sent()[0],[4,p.data()];case 2:return v=b.sent()[0],m=v>.5,g=m?no.MALE:no.FEMALE,x=m?v:1-v,f.dispose(),p.dispose(),[2,{age:d,gender:g,genderProbability:x}]}})})}))];case 3:return u=l.sent(),o.age.dispose(),o.gender.dispose(),[2,n.isBatchInput?u:u[0]]}})})},t.prototype.getDefaultModelName=function(){return"age_gender_model"},t.prototype.dispose=function(e){e===void 0&&(e=!0),this.faceFeatureExtractor.dispose(e),r.prototype.dispose.call(this,e)},t.prototype.loadClassifierParams=function(e){var n=this.extractClassifierParams(e),o=n.params,a=n.paramMappings;this._params=o,this._paramMappings=a},t.prototype.extractClassifierParams=function(e){return lg(e)},t.prototype.extractParamsFromWeigthMap=function(e){var n=Ec(e),o=n.featureExtractorMap,a=n.classifierMap;return this.faceFeatureExtractor.loadFromWeightMap(o),hg(a)},t.prototype.extractParams=function(e){var n=1539,o=e.slice(0,e.length-n),a=e.slice(e.length-n);return this.faceFeatureExtractor.extractWeights(o),this.extractClassifierParams(a)},t})(Xt),Sc=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.postProcess=function(e,n,o){var a=o.map(function(s){var u=s.width,c=s.height,l=n/Math.max(c,u);return{width:u*l,height:c*l}}),i=a.length;return K(function(){var s=function(f,p){return lt([Nt([68],f),Nt([68],p)],1).as2D(1,136).as1D()},u=function(f,p){var d=a[f],v=d.width,m=d.height;return p(v,m)?Math.abs(v-m)/2:0},c=function(f){return u(f,function(p,d){return p<d})},l=function(f){return u(f,function(p,d){return d<p})},h=e.mul(Nt([i,136],n)).sub(lt(Array.from(Array(i),function(f,p){return s(c(p),l(p))}))).div(lt(Array.from(Array(i),function(f,p){return s(a[p].width,a[p].height)})));return h})},t.prototype.forwardInput=function(e){var n=this;return K(function(){var o=n.runNet(e);return n.postProcess(o,e.inputSize,e.inputDimensions.map(function(a){var i=a[0],s=a[1];return{height:i,width:s}}))})},t.prototype.forward=function(e){return Q(this,void 0,void 0,function(){var n;return Z(this,function(o){switch(o.label){case 0:return n=this.forwardInput,[4,Ve(e)];case 1:return[2,n.apply(this,[o.sent()])]}})})},t.prototype.detectLandmarks=function(e){return Q(this,void 0,void 0,function(){var n,o,a,i=this;return Z(this,function(s){switch(s.label){case 0:return[4,Ve(e)];case 1:return n=s.sent(),o=K(function(){return Me(i.forwardInput(n))}),[4,Promise.all(o.map(function(u,c){return Q(i,void 0,void 0,function(){var l,h,f,p,d;return Z(this,function(v){switch(v.label){case 0:return f=(h=Array).from,[4,u.data()];case 1:return l=f.apply(h,[v.sent()]),p=l.filter(function(m,g){return xs(g)}),d=l.filter(function(m,g){return!xs(g)}),[2,new Vm(Array(68).fill(0).map(function(m,g){return new ye(p[g],d[g])}),{height:n.getInputHeight(c),width:n.getInputWidth(c)})]}})})}))];case 2:return a=s.sent(),o.forEach(function(u){return u.dispose()}),[2,n.isBatchInput?a:a[0]]}})})},t.prototype.getClassifierChannelsOut=function(){return 136},t})(Ic),Dc=(function(r){re(t,r);function t(e){return e===void 0&&(e=new _c),r.call(this,"FaceLandmark68Net",e)||this}return t.prototype.getDefaultModelName=function(){return"face_landmark_68_model"},t.prototype.getClassifierChannelsIn=function(){return 256},t})(Sc);function pg(r){var t=[],e=Cc(r,t).extractDenseBlock3Params,n={dense0:e("dense0",!0),dense1:e("dense1"),dense2:e("dense2")};return $t(r,t),{params:n,paramMappings:t}}function dg(r){var t=[],e=Yt(r),n=e.extractWeights,o=e.getRemainingWeights,a=bc(n,t).extractDenseBlock3Params,i=a(3,32,"dense0",!0),s=a(32,64,"dense1"),u=a(64,128,"dense2");if(o().length!==0)throw new Error("weights remaing after extract: "+o().length);return{paramMappings:t,params:{dense0:i,dense1:s,dense2:u}}}var vg=(function(r){re(t,r);function t(){return r.call(this,"TinyFaceFeatureExtractor")||this}return t.prototype.forwardInput=function(e){var n=this.params;if(!n)throw new Error("TinyFaceFeatureExtractor - load model before inference");return K(function(){var o=e.toBatchTensor(112,!0),a=[122.782,117.001,104.298],i=yr(o,a).div(j(255)),s=Qo(i,n.dense0,!0);return s=Qo(s,n.dense1),s=Qo(s,n.dense2),s=mr(s,[14,14],[2,2],"valid"),s})},t.prototype.forward=function(e){return Q(this,void 0,void 0,function(){var n;return Z(this,function(o){switch(o.label){case 0:return n=this.forwardInput,[4,Ve(e)];case 1:return[2,n.apply(this,[o.sent()])]}})})},t.prototype.getDefaultModelName=function(){return"face_feature_extractor_tiny_model"},t.prototype.extractParamsFromWeigthMap=function(e){return pg(e)},t.prototype.extractParams=function(e){return dg(e)},t})(Xt),mg=(function(r){re(t,r);function t(e){return e===void 0&&(e=new vg),r.call(this,"FaceLandmark68TinyNet",e)||this}return t.prototype.getDefaultModelName=function(){return"face_landmark_68_tiny_model"},t.prototype.getClassifierChannelsIn=function(){return 128},t})(Sc);(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t})(Dc);function gg(r,t){return ue(Ye(r,t.weights),t.biases)}function hi(r,t,e,n,o){o===void 0&&(o="same");var a=t.conv,i=a.filters,s=a.bias,u=dt(r,i,e,o);return u=ue(u,s),u=gg(u,t.scale),n?Re(u):u}function yg(r,t){return hi(r,t,[1,1],!0)}function Ac(r,t){return hi(r,t,[1,1],!1)}function Tc(r,t){return hi(r,t,[2,2],!0,"valid")}function xg(r,t){function e(s,u,c){var l=r(s),h=l.length/(u*c*c);if(Tm(h))throw new Error("depth has to be an integer: "+h+", weights.length: "+l.length+", numFilters: "+u+", filterSize: "+c);return K(function(){return an(Ze(l,[u,h,c,c]),[2,3,1,0])})}function n(s,u,c,l){var h=e(s,u,c),f=Ne(r(u));return t.push({paramPath:l+"/filters"},{paramPath:l+"/bias"}),{filters:h,bias:f}}function o(s,u){var c=Ne(r(s)),l=Ne(r(s));return t.push({paramPath:u+"/weights"},{paramPath:u+"/biases"}),{weights:c,biases:l}}function a(s,u,c,l){var h=n(s,u,c,l+"/conv"),f=o(u,l+"/scale");return{conv:h,scale:f}}function i(s,u,c,l,h){h===void 0&&(h=!1);var f=a((h?.5:1)*s,u,c,l+"/conv1"),p=a(s,u,c,l+"/conv2");return{conv1:f,conv2:p}}return{extractConvLayerParams:a,extractResidualLayerParams:i}}function bg(r){var t=Yt(r),e=t.extractWeights,n=t.getRemainingWeights,o=[],a=xg(e,o),i=a.extractConvLayerParams,s=a.extractResidualLayerParams,u=i(4704,32,7,"conv32_down"),c=s(9216,32,3,"conv32_1"),l=s(9216,32,3,"conv32_2"),h=s(9216,32,3,"conv32_3"),f=s(36864,64,3,"conv64_down",!0),p=s(36864,64,3,"conv64_1"),d=s(36864,64,3,"conv64_2"),v=s(36864,64,3,"conv64_3"),m=s(147456,128,3,"conv128_down",!0),g=s(147456,128,3,"conv128_1"),x=s(147456,128,3,"conv128_2"),b=s(589824,256,3,"conv256_down",!0),y=s(589824,256,3,"conv256_1"),w=s(589824,256,3,"conv256_2"),C=s(589824,256,3,"conv256_down_out"),S=K(function(){return an(nn(e(256*128),[128,256]),[1,0])});if(o.push({paramPath:"fc"}),n().length!==0)throw new Error("weights remaing after extract: "+n().length);var k={conv32_down:u,conv32_1:c,conv32_2:l,conv32_3:h,conv64_down:f,conv64_1:p,conv64_2:d,conv64_3:v,conv128_down:m,conv128_1:g,conv128_2:x,conv256_down:b,conv256_1:y,conv256_2:w,conv256_down_out:C,fc:S};return{params:k,paramMappings:o}}function wg(r,t){var e=ln(r,t);function n(i){var s=e(i+"/scale/weights",1),u=e(i+"/scale/biases",1);return{weights:s,biases:u}}function o(i){var s=e(i+"/conv/filters",4),u=e(i+"/conv/bias",1),c=n(i);return{conv:{filters:s,bias:u},scale:c}}function a(i){return{conv1:o(i+"/conv1"),conv2:o(i+"/conv2")}}return{extractConvLayerParams:o,extractResidualLayerParams:a}}function Cg(r){var t=[],e=wg(r,t),n=e.extractConvLayerParams,o=e.extractResidualLayerParams,a=n("conv32_down"),i=o("conv32_1"),s=o("conv32_2"),u=o("conv32_3"),c=o("conv64_down"),l=o("conv64_1"),h=o("conv64_2"),f=o("conv64_3"),p=o("conv128_down"),d=o("conv128_1"),v=o("conv128_2"),m=o("conv256_down"),g=o("conv256_1"),x=o("conv256_2"),b=o("conv256_down_out"),y=r.fc;if(t.push({originalPath:"fc",paramPath:"fc"}),!Am(y))throw new Error("expected weightMap[fc] to be a Tensor2D, instead have "+y);var w={conv32_down:a,conv32_1:i,conv32_2:s,conv32_3:u,conv64_down:c,conv64_1:l,conv64_2:h,conv64_3:f,conv128_down:p,conv128_1:d,conv128_2:v,conv256_down:m,conv256_1:g,conv256_2:x,conv256_down_out:b,fc:y};return $t(r,t),{params:w,paramMappings:t}}function Et(r,t){var e=yg(r,t.conv1);return e=Ac(e,t.conv2),e=ue(e,r),e=Re(e),e}function Tr(r,t){var e=Tc(r,t.conv1);e=Ac(e,t.conv2);var n=mr(r,2,2,"valid"),o=Ce(n.shape),a=n.shape[3]!==e.shape[3],i=n.shape[1]!==e.shape[1]||n.shape[2]!==e.shape[2];if(i){var s=nr(e.shape);s[1]=1;var u=Ce(s);e=Pe([e,u],1);var c=nr(e.shape);c[2]=1;var l=Ce(c);e=Pe([e,l],2)}return n=a?Pe([n,o],3):n,e=ue(n,e),e=Re(e),e}var _g=(function(r){re(t,r);function t(){return r.call(this,"FaceRecognitionNet")||this}return t.prototype.forwardInput=function(e){var n=this.params;if(!n)throw new Error("FaceRecognitionNet - load model before inference");return K(function(){var o=e.toBatchTensor(150,!0).toFloat(),a=[122.782,117.001,104.298],i=yr(o,a).div(j(256)),s=Tc(i,n.conv32_down);s=We(s,3,2,"valid"),s=Et(s,n.conv32_1),s=Et(s,n.conv32_2),s=Et(s,n.conv32_3),s=Tr(s,n.conv64_down),s=Et(s,n.conv64_1),s=Et(s,n.conv64_2),s=Et(s,n.conv64_3),s=Tr(s,n.conv128_down),s=Et(s,n.conv128_1),s=Et(s,n.conv128_2),s=Tr(s,n.conv256_down),s=Et(s,n.conv256_1),s=Et(s,n.conv256_2),s=Tr(s,n.conv256_down_out);var u=s.mean([1,2]),c=lo(u,n.fc);return c})},t.prototype.forward=function(e){return Q(this,void 0,void 0,function(){var n;return Z(this,function(o){switch(o.label){case 0:return n=this.forwardInput,[4,Ve(e)];case 1:return[2,n.apply(this,[o.sent()])]}})})},t.prototype.computeFaceDescriptor=function(e){return Q(this,void 0,void 0,function(){var n,o,a,i=this;return Z(this,function(s){switch(s.label){case 0:return[4,Ve(e)];case 1:return n=s.sent(),o=K(function(){return Me(i.forwardInput(n))}),[4,Promise.all(o.map(function(u){return u.data()}))];case 2:return a=s.sent(),o.forEach(function(u){return u.dispose()}),[2,n.isBatchInput?a:a[0]]}})})},t.prototype.getDefaultModelName=function(){return"face_recognition_model"},t.prototype.extractParamsFromWeigthMap=function(e){return Cg(e)},t.prototype.extractParams=function(e){return bg(e)},t})(Xt);function Nc(r,t){var e={descriptor:t};return Object.assign({},r,e)}function Fc(r,t){var e={age:t};return Object.assign({},r,e)}function Pc(r,t,e){var n={gender:t,genderProbability:e};return Object.assign({},r,n)}var Mc=(function(){function r(t){var e=t===void 0?{}:t,n=e.minFaceSize,o=e.scaleFactor,a=e.maxNumScales,i=e.scoreThresholds,s=e.scaleSteps;if(this._name="MtcnnOptions",this._minFaceSize=n||20,this._scaleFactor=o||.709,this._maxNumScales=a||10,this._scoreThresholds=i||[.6,.7,.7],this._scaleSteps=s,typeof this._minFaceSize!="number"||this._minFaceSize<0)throw new Error(this._name+" - expected minFaceSize to be a number > 0");if(typeof this._scaleFactor!="number"||this._scaleFactor<=0||this._scaleFactor>=1)throw new Error(this._name+" - expected scaleFactor to be a number between 0 and 1");if(typeof this._maxNumScales!="number"||this._maxNumScales<0)throw new Error(this._name+" - expected maxNumScales to be a number > 0");if(!Array.isArray(this._scoreThresholds)||this._scoreThresholds.length!==3||this._scoreThresholds.some(function(u){return typeof u!="number"}))throw new Error(this._name+" - expected scoreThresholds to be an array of numbers of length 3");if(this._scaleSteps&&(!Array.isArray(this._scaleSteps)||this._scaleSteps.some(function(u){return typeof u!="number"})))throw new Error(this._name+" - expected scaleSteps to be an array of numbers")}return Object.defineProperty(r.prototype,"minFaceSize",{get:function(){return this._minFaceSize},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"scaleFactor",{get:function(){return this._scaleFactor},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"maxNumScales",{get:function(){return this._maxNumScales},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"scoreThresholds",{get:function(){return this._scoreThresholds},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"scaleSteps",{get:function(){return this._scaleSteps},enumerable:!0,configurable:!0}),r})();function Eg(r,t){function e(u,c){var l=Ze(r(9*u),[3,3,u,1]),h=Ne(r(u)),f=Ne(r(u)),p=Ne(r(u)),d=Ne(r(u));return t.push({paramPath:c+"/filters"},{paramPath:c+"/batch_norm_scale"},{paramPath:c+"/batch_norm_offset"},{paramPath:c+"/batch_norm_mean"},{paramPath:c+"/batch_norm_variance"}),{filters:l,batch_norm_scale:h,batch_norm_offset:f,batch_norm_mean:p,batch_norm_variance:d}}function n(u,c,l,h,f){var p=Ze(r(u*c*l*l),[l,l,u,c]),d=Ne(r(c));return t.push({paramPath:h+"/filters"},{paramPath:h+"/"+(f?"batch_norm_offset":"bias")}),{filters:p,bias:d}}function o(u,c,l,h){var f=n(u,c,l,h,!0),p=f.filters,d=f.bias;return{filters:p,batch_norm_offset:d}}function a(u,c,l){var h=e(u,l+"/depthwise_conv"),f=o(u,c,1,l+"/pointwise_conv");return{depthwise_conv:h,pointwise_conv:f}}function i(){var u=o(3,32,3,"mobilenetv1/conv_0"),c=a(32,64,"mobilenetv1/conv_1"),l=a(64,128,"mobilenetv1/conv_2"),h=a(128,128,"mobilenetv1/conv_3"),f=a(128,256,"mobilenetv1/conv_4"),p=a(256,256,"mobilenetv1/conv_5"),d=a(256,512,"mobilenetv1/conv_6"),v=a(512,512,"mobilenetv1/conv_7"),m=a(512,512,"mobilenetv1/conv_8"),g=a(512,512,"mobilenetv1/conv_9"),x=a(512,512,"mobilenetv1/conv_10"),b=a(512,512,"mobilenetv1/conv_11"),y=a(512,1024,"mobilenetv1/conv_12"),w=a(1024,1024,"mobilenetv1/conv_13");return{conv_0:u,conv_1:c,conv_2:l,conv_3:h,conv_4:f,conv_5:p,conv_6:d,conv_7:v,conv_8:m,conv_9:g,conv_10:x,conv_11:b,conv_12:y,conv_13:w}}function s(){var u=o(1024,256,1,"prediction_layer/conv_0"),c=o(256,512,3,"prediction_layer/conv_1"),l=o(512,128,1,"prediction_layer/conv_2"),h=o(128,256,3,"prediction_layer/conv_3"),f=o(256,128,1,"prediction_layer/conv_4"),p=o(128,256,3,"prediction_layer/conv_5"),d=o(256,64,1,"prediction_layer/conv_6"),v=o(64,128,3,"prediction_layer/conv_7"),m=n(512,12,1,"prediction_layer/box_predictor_0/box_encoding_predictor"),g=n(512,9,1,"prediction_layer/box_predictor_0/class_predictor"),x=n(1024,24,1,"prediction_layer/box_predictor_1/box_encoding_predictor"),b=n(1024,18,1,"prediction_layer/box_predictor_1/class_predictor"),y=n(512,24,1,"prediction_layer/box_predictor_2/box_encoding_predictor"),w=n(512,18,1,"prediction_layer/box_predictor_2/class_predictor"),C=n(256,24,1,"prediction_layer/box_predictor_3/box_encoding_predictor"),S=n(256,18,1,"prediction_layer/box_predictor_3/class_predictor"),k=n(256,24,1,"prediction_layer/box_predictor_4/box_encoding_predictor"),R=n(256,18,1,"prediction_layer/box_predictor_4/class_predictor"),E=n(128,24,1,"prediction_layer/box_predictor_5/box_encoding_predictor"),T=n(128,18,1,"prediction_layer/box_predictor_5/class_predictor"),A={box_encoding_predictor:m,class_predictor:g},P={box_encoding_predictor:x,class_predictor:b},O={box_encoding_predictor:y,class_predictor:w},B={box_encoding_predictor:C,class_predictor:S},V={box_encoding_predictor:k,class_predictor:R},W={box_encoding_predictor:E,class_predictor:T};return{conv_0:u,conv_1:c,conv_2:l,conv_3:h,conv_4:f,conv_5:p,conv_6:d,conv_7:v,box_predictor_0:A,box_predictor_1:P,box_predictor_2:O,box_predictor_3:B,box_predictor_4:V,box_predictor_5:W}}return{extractMobilenetV1Params:i,extractPredictionLayerParams:s}}function Ig(r){var t=[],e=Yt(r),n=e.extractWeights,o=e.getRemainingWeights,a=Eg(n,t),i=a.extractMobilenetV1Params,s=a.extractPredictionLayerParams,u=i(),c=s(),l=ka(n(5118*4),[1,5118,4]),h={extra_dim:l};if(t.push({paramPath:"output_layer/extra_dim"}),o().length!==0)throw new Error("weights remaing after extract: "+o().length);return{params:{mobilenetv1:u,prediction_layer:c,output_layer:h},paramMappings:t}}function Rg(r,t){var e=ln(r,t);function n(c,l,h){var f=e(c+"/Conv2d_"+l+"_pointwise/weights",4,h+"/filters"),p=e(c+"/Conv2d_"+l+"_pointwise/convolution_bn_offset",1,h+"/batch_norm_offset");return{filters:f,batch_norm_offset:p}}function o(c){var l="mobilenetv1/conv_"+c,h="MobilenetV1/Conv2d_"+c+"_depthwise",f=l+"/depthwise_conv",p=l+"/pointwise_conv",d=e(h+"/depthwise_weights",4,f+"/filters"),v=e(h+"/BatchNorm/gamma",1,f+"/batch_norm_scale"),m=e(h+"/BatchNorm/beta",1,f+"/batch_norm_offset"),g=e(h+"/BatchNorm/moving_mean",1,f+"/batch_norm_mean"),x=e(h+"/BatchNorm/moving_variance",1,f+"/batch_norm_variance");return{depthwise_conv:{filters:d,batch_norm_scale:v,batch_norm_offset:m,batch_norm_mean:g,batch_norm_variance:x},pointwise_conv:n("MobilenetV1",c,p)}}function a(){return{conv_0:n("MobilenetV1",0,"mobilenetv1/conv_0"),conv_1:o(1),conv_2:o(2),conv_3:o(3),conv_4:o(4),conv_5:o(5),conv_6:o(6),conv_7:o(7),conv_8:o(8),conv_9:o(9),conv_10:o(10),conv_11:o(11),conv_12:o(12),conv_13:o(13)}}function i(c,l){var h=e(c+"/weights",4,l+"/filters"),f=e(c+"/biases",1,l+"/bias");return{filters:h,bias:f}}function s(c){var l=i("Prediction/BoxPredictor_"+c+"/BoxEncodingPredictor","prediction_layer/box_predictor_"+c+"/box_encoding_predictor"),h=i("Prediction/BoxPredictor_"+c+"/ClassPredictor","prediction_layer/box_predictor_"+c+"/class_predictor");return{box_encoding_predictor:l,class_predictor:h}}function u(){return{conv_0:n("Prediction",0,"prediction_layer/conv_0"),conv_1:n("Prediction",1,"prediction_layer/conv_1"),conv_2:n("Prediction",2,"prediction_layer/conv_2"),conv_3:n("Prediction",3,"prediction_layer/conv_3"),conv_4:n("Prediction",4,"prediction_layer/conv_4"),conv_5:n("Prediction",5,"prediction_layer/conv_5"),conv_6:n("Prediction",6,"prediction_layer/conv_6"),conv_7:n("Prediction",7,"prediction_layer/conv_7"),box_predictor_0:s(0),box_predictor_1:s(1),box_predictor_2:s(2),box_predictor_3:s(3),box_predictor_4:s(4),box_predictor_5:s(5)}}return{extractMobilenetV1Params:a,extractPredictionLayerParams:u}}function kg(r){var t=[],e=Rg(r,t),n=e.extractMobilenetV1Params,o=e.extractPredictionLayerParams,a=r["Output/extra_dim"];if(t.push({originalPath:"Output/extra_dim",paramPath:"output_layer/extra_dim"}),!vo(a))throw new Error("expected weightMap['Output/extra_dim'] to be a Tensor3D, instead have "+a);var i={mobilenetv1:n(),prediction_layer:o(),output_layer:{extra_dim:a}};return $t(r,t),{params:i,paramMappings:t}}function It(r,t,e){return K(function(){var n=dt(r,t.filters,e,"same");return n=ue(n,t.batch_norm_offset),La(n,0,6)})}var Sg=.0010000000474974513;function Dg(r,t,e){return K(function(){var n=co(r,t.filters,e,"same");return n=Du(n,t.batch_norm_mean,t.batch_norm_variance,t.batch_norm_offset,t.batch_norm_scale,Sg),La(n,0,6)})}function Ag(r){return[2,4,6,12].some(function(t){return t===r})?[2,2]:[1,1]}function Tg(r,t){return K(function(){var e=null,n=It(r,t.conv_0,[2,2]),o=[t.conv_1,t.conv_2,t.conv_3,t.conv_4,t.conv_5,t.conv_6,t.conv_7,t.conv_8,t.conv_9,t.conv_10,t.conv_11,t.conv_12,t.conv_13];if(o.forEach(function(a,i){var s=i+1,u=Ag(s);n=Dg(n,a.depthwise_conv,u),n=It(n,a.pointwise_conv,[1,1]),s===11&&(e=n)}),e===null)throw new Error("mobileNetV1 - output of conv layer 11 is null");return{out:n,conv11:e}})}function Ng(r,t,e,n,o){var a=r.shape[0],i=Math.min(e,a),s=t.map(function(l,h){return{score:l,boxIndex:h}}).filter(function(l){return l.score>o}).sort(function(l,h){return h.score-l.score}),u=function(l){return l<=n?1:0},c=[];return s.forEach(function(l){if(!(c.length>=i)){for(var h=l.score,f=c.length-1;f>=0;--f){var p=Fg(r,l.boxIndex,c[f]);if(p!==0&&(l.score*=u(p),l.score<=o))break}h===l.score&&c.push(l.boxIndex)}}),c}function Fg(r,t,e){var n=r.arraySync(),o=Math.min(n[t][0],n[t][2]),a=Math.min(n[t][1],n[t][3]),i=Math.max(n[t][0],n[t][2]),s=Math.max(n[t][1],n[t][3]),u=Math.min(n[e][0],n[e][2]),c=Math.min(n[e][1],n[e][3]),l=Math.max(n[e][0],n[e][2]),h=Math.max(n[e][1],n[e][3]),f=(i-o)*(s-a),p=(l-u)*(h-c);if(f<=0||p<=0)return 0;var d=Math.max(o,u),v=Math.max(a,c),m=Math.min(i,l),g=Math.min(s,h),x=Math.max(m-d,0)*Math.max(g-v,0);return x/(f+p-x)}function Pg(r){var t=Me(an(r,[1,0])),e=[Be(t[2],t[0]),Be(t[3],t[1])],n=[ue(t[0],vt(e[0],j(2))),ue(t[1],vt(e[1],j(2)))];return{sizes:e,centers:n}}function Mg(r,t){var e=Pg(r),n=e.sizes,o=e.centers,a=Me(an(t,[1,0])),i=vt(Ye(da(vt(a[2],j(5))),n[0]),j(2)),s=ue(Ye(vt(a[0],j(10)),n[0]),o[0]),u=vt(Ye(da(vt(a[3],j(5))),n[1]),j(2)),c=ue(Ye(vt(a[1],j(10)),n[1]),o[1]);return an(lt([Be(s,i),Be(c,u),ue(s,i),ue(c,u)]),[1,0])}function Og(r,t,e){return K(function(){var n=r.shape[0],o=Mg(mt(Bn(e.extra_dim,[n,1,1]),[-1,4]),mt(r,[-1,4]));o=mt(o,[n,o.shape[0]/n,4]);var a=Iu(Ft(t,[0,0,1],[-1,-1,-1])),i=Ft(a,[0,0,0],[-1,-1,1]);i=mt(i,[n,i.shape[1]]);var s=Me(o),u=Me(i);return{boxes:s,scores:u}})}function Tn(r,t){return K(function(){var e=r.shape[0],n=mt(gt(r,t.box_encoding_predictor),[e,-1,1,4]),o=mt(gt(r,t.class_predictor),[e,-1,3]);return{boxPredictionEncoding:n,classPrediction:o}})}function Bg(r,t,e){return K(function(){var n=It(r,e.conv_0,[1,1]),o=It(n,e.conv_1,[2,2]),a=It(o,e.conv_2,[1,1]),i=It(a,e.conv_3,[2,2]),s=It(i,e.conv_4,[1,1]),u=It(s,e.conv_5,[2,2]),c=It(u,e.conv_6,[1,1]),l=It(c,e.conv_7,[2,2]),h=Tn(t,e.box_predictor_0),f=Tn(r,e.box_predictor_1),p=Tn(o,e.box_predictor_2),d=Tn(i,e.box_predictor_3),v=Tn(u,e.box_predictor_4),m=Tn(l,e.box_predictor_5),g=Pe([h.boxPredictionEncoding,f.boxPredictionEncoding,p.boxPredictionEncoding,d.boxPredictionEncoding,v.boxPredictionEncoding,m.boxPredictionEncoding],1),x=Pe([h.classPrediction,f.classPrediction,p.classPrediction,d.classPrediction,v.classPrediction,m.classPrediction],1);return{boxPredictions:g,classPredictions:x}})}var xo=(function(){function r(t){var e=t===void 0?{}:t,n=e.minConfidence,o=e.maxResults;if(this._name="SsdMobilenetv1Options",this._minConfidence=n||.5,this._maxResults=o||100,typeof this._minConfidence!="number"||this._minConfidence<=0||this._minConfidence>=1)throw new Error(this._name+" - expected minConfidence to be a number between 0 and 1");if(typeof this._maxResults!="number")throw new Error(this._name+" - expected maxResults to be a number")}return Object.defineProperty(r.prototype,"minConfidence",{get:function(){return this._minConfidence},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"maxResults",{get:function(){return this._maxResults},enumerable:!0,configurable:!0}),r})(),Oc=(function(r){re(t,r);function t(){return r.call(this,"SsdMobilenetv1")||this}return t.prototype.forwardInput=function(e){var n=this.params;if(!n)throw new Error("SsdMobilenetv1 - load model before inference");return K(function(){var o=e.toBatchTensor(512,!1).toFloat(),a=Be(Ye(o,j(.007843137718737125)),j(1)),i=Tg(a,n.mobilenetv1),s=Bg(i.out,i.conv11,n.prediction_layer),u=s.boxPredictions,c=s.classPredictions;return Og(u,c,n.output_layer)})},t.prototype.forward=function(e){return Q(this,void 0,void 0,function(){var n;return Z(this,function(o){switch(o.label){case 0:return n=this.forwardInput,[4,Ve(e)];case 1:return[2,n.apply(this,[o.sent()])]}})})},t.prototype.locateFaces=function(e,n){return n===void 0&&(n={}),Q(this,void 0,void 0,function(){var o,a,i,s,u,c,l,h,f,p,d,v,m,g,x,b,y,w,C,S,k;return Z(this,function(R){switch(R.label){case 0:return o=new xo(n),a=o.maxResults,i=o.minConfidence,[4,Ve(e)];case 1:for(s=R.sent(),u=this.forwardInput(s),c=u.boxes,l=u.scores,h=c[0],f=l[0],p=1;p<c.length;p++)c[p].dispose(),l[p].dispose();return m=(v=Array).from,[4,f.data()];case 2:return d=m.apply(v,[R.sent()]),g=.5,x=Ng(h,d,a,g,i),b=s.getReshapedInputDimensions(0),y=s.inputSize,w=y/b.width,C=y/b.height,S=h.arraySync(),k=x.map(function(E){var T=[Math.max(0,S[E][0]),Math.min(1,S[E][2])].map(function(W){return W*C}),A=T[0],P=T[1],O=[Math.max(0,S[E][1]),Math.min(1,S[E][3])].map(function(W){return W*w}),B=O[0],V=O[1];return new Bt(d[E],new ti(B,A,V-B,P-A),{height:s.getInputHeight(0),width:s.getInputWidth(0)})}),h.dispose(),f.dispose(),[2,k]}})})},t.prototype.getDefaultModelName=function(){return"ssd_mobilenetv1_model"},t.prototype.extractParamsFromWeigthMap=function(e){return kg(e)},t.prototype.extractParams=function(e){return Ig(e)},t})(Xt);(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t})(Oc);var Lg=.4,Wg=[new ye(.738768,.874946),new ye(2.42204,2.65704),new ye(4.30971,7.04493),new ye(10.246,4.59428),new ye(12.6868,11.8741)],Ug=[new ye(1.603231,2.094468),new ye(6.041143,7.080126),new ye(2.882459,3.518061),new ye(4.266906,5.178857),new ye(9.041765,10.66308)],Vg=[117.001,114.697,97.404],zg="tiny_yolov2_model",Gg="tiny_yolov2_separable_conv_model",Nr=function(r){return typeof r=="number"};function Hg(r){if(!r)throw new Error("invalid config: "+r);if(typeof r.withSeparableConvs!="boolean")throw new Error("config.withSeparableConvs has to be a boolean, have: "+r.withSeparableConvs);if(!Nr(r.iouThreshold)||r.iouThreshold<0||r.iouThreshold>1)throw new Error("config.iouThreshold has to be a number between [0, 1], have: "+r.iouThreshold);if(!Array.isArray(r.classes)||!r.classes.length||!r.classes.every(function(t){return typeof t=="string"}))throw new Error("config.classes has to be an array class names: string[], have: "+JSON.stringify(r.classes));if(!Array.isArray(r.anchors)||!r.anchors.length||!r.anchors.map(function(t){return t||{}}).every(function(t){return Nr(t.x)&&Nr(t.y)}))throw new Error("config.anchors has to be an array of { x: number, y: number }, have: "+JSON.stringify(r.anchors));if(r.meanRgb&&(!Array.isArray(r.meanRgb)||r.meanRgb.length!==3||!r.meanRgb.every(Nr)))throw new Error("config.meanRgb has to be an array of shape [number, number, number], have: "+JSON.stringify(r.meanRgb))}function fi(r){return K(function(){var t=Ye(r,j(.10000000149011612));return ue(Re(Be(r,t)),t)})}function Qt(r,t){return K(function(){var e=wn(r,[[0,0],[1,1],[1,1],[0,0]]);return e=dt(e,t.conv.filters,[1,1],"valid"),e=Be(e,t.bn.sub),e=Ye(e,t.bn.truediv),e=ue(e,t.conv.bias),fi(e)})}function Zt(r,t){return K(function(){var e=wn(r,[[0,0],[1,1],[1,1],[0,0]]);return e=za(e,t.depthwise_filter,t.pointwise_filter,[1,1],"valid"),e=ue(e,t.bias),fi(e)})}function jg(r,t){var e=yo(r,t);function n(i,s){var u=Ne(r(i)),c=Ne(r(i));return t.push({paramPath:s+"/sub"},{paramPath:s+"/truediv"}),{sub:u,truediv:c}}function o(i,s,u){var c=e(i,s,3,u+"/conv"),l=n(s,u+"/bn");return{conv:c,bn:l}}var a=ui(r,t);return{extractConvParams:e,extractConvWithBatchNormParams:o,extractSeparableConvParams:a}}function qg(r,t,e,n){var o=Yt(r),a=o.extractWeights,i=o.getRemainingWeights,s=[],u=jg(a,s),c=u.extractConvParams,l=u.extractConvWithBatchNormParams,h=u.extractSeparableConvParams,f;if(t.withSeparableConvs){var p=n[0],d=n[1],v=n[2],m=n[3],g=n[4],x=n[5],b=n[6],y=n[7],w=n[8],C=t.isFirstLayerConv2d?c(p,d,3,"conv0"):h(p,d,"conv0"),S=h(d,v,"conv1"),k=h(v,m,"conv2"),R=h(m,g,"conv3"),E=h(g,x,"conv4"),T=h(x,b,"conv5"),A=y?h(b,y,"conv6"):void 0,P=w?h(y,w,"conv7"):void 0,O=c(w||y||b,5*e,1,"conv8");f={conv0:C,conv1:S,conv2:k,conv3:R,conv4:E,conv5:T,conv6:A,conv7:P,conv8:O}}else{var p=n[0],d=n[1],v=n[2],m=n[3],g=n[4],x=n[5],b=n[6],y=n[7],w=n[8],C=l(p,d,"conv0"),S=l(d,v,"conv1"),k=l(v,m,"conv2"),R=l(m,g,"conv3"),E=l(g,x,"conv4"),T=l(x,b,"conv5"),A=l(b,y,"conv6"),P=l(y,w,"conv7"),O=c(w,5*e,1,"conv8");f={conv0:C,conv1:S,conv2:k,conv3:R,conv4:E,conv5:T,conv6:A,conv7:P,conv8:O}}if(i().length!==0)throw new Error("weights remaing after extract: "+i().length);return{params:f,paramMappings:s}}function Kg(r,t){var e=ln(r,t);function n(s){var u=e(s+"/sub",1),c=e(s+"/truediv",1);return{sub:u,truediv:c}}function o(s){var u=e(s+"/filters",4),c=e(s+"/bias",1);return{filters:u,bias:c}}function a(s){var u=o(s+"/conv"),c=n(s+"/bn");return{conv:u,bn:c}}var i=ci(e);return{extractConvParams:o,extractConvWithBatchNormParams:a,extractSeparableConvParams:i}}function Xg(r,t){var e=[],n=Kg(r,e),o=n.extractConvParams,a=n.extractConvWithBatchNormParams,i=n.extractSeparableConvParams,s;if(t.withSeparableConvs){var u=t.filterSizes&&t.filterSizes.length||9;s={conv0:t.isFirstLayerConv2d?o("conv0"):i("conv0"),conv1:i("conv1"),conv2:i("conv2"),conv3:i("conv3"),conv4:i("conv4"),conv5:i("conv5"),conv6:u>7?i("conv6"):void 0,conv7:u>8?i("conv7"):void 0,conv8:o("conv8")}}else s={conv0:a("conv0"),conv1:a("conv1"),conv2:a("conv2"),conv3:a("conv3"),conv4:a("conv4"),conv5:a("conv5"),conv6:a("conv6"),conv7:a("conv7"),conv8:o("conv8")};return $t(r,e),{params:s,paramMappings:e}}var ks;(function(r){r[r.XS=224]="XS",r[r.SM=320]="SM",r[r.MD=416]="MD",r[r.LG=608]="LG"})(ks||(ks={}));var pi=(function(){function r(t){var e=t===void 0?{}:t,n=e.inputSize,o=e.scoreThreshold;if(this._name="TinyYolov2Options",this._inputSize=n||416,this._scoreThreshold=o||.5,typeof this._inputSize!="number"||this._inputSize%32!==0)throw new Error(this._name+" - expected inputSize to be a number divisible by 32");if(typeof this._scoreThreshold!="number"||this._scoreThreshold<=0||this._scoreThreshold>=1)throw new Error(this._name+" - expected scoreThreshold to be a number between 0 and 1")}return Object.defineProperty(r.prototype,"inputSize",{get:function(){return this._inputSize},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"scoreThreshold",{get:function(){return this._scoreThreshold},enumerable:!0,configurable:!0}),r})(),Bc=(function(r){re(t,r);function t(e){var n=r.call(this,"TinyYolov2")||this;return Hg(e),n._config=e,n}return Object.defineProperty(t.prototype,"config",{get:function(){return this._config},enumerable:!0,configurable:!0}),Object.defineProperty(t.prototype,"withClassScores",{get:function(){return this.config.withClassScores||this.config.classes.length>1},enumerable:!0,configurable:!0}),Object.defineProperty(t.prototype,"boxEncodingSize",{get:function(){return 5+(this.withClassScores?this.config.classes.length:0)},enumerable:!0,configurable:!0}),t.prototype.runTinyYolov2=function(e,n){var o=Qt(e,n.conv0);return o=We(o,[2,2],[2,2],"same"),o=Qt(o,n.conv1),o=We(o,[2,2],[2,2],"same"),o=Qt(o,n.conv2),o=We(o,[2,2],[2,2],"same"),o=Qt(o,n.conv3),o=We(o,[2,2],[2,2],"same"),o=Qt(o,n.conv4),o=We(o,[2,2],[2,2],"same"),o=Qt(o,n.conv5),o=We(o,[2,2],[1,1],"same"),o=Qt(o,n.conv6),o=Qt(o,n.conv7),gt(o,n.conv8,"valid",!1)},t.prototype.runMobilenet=function(e,n){var o=this.config.isFirstLayerConv2d?fi(gt(e,n.conv0,"valid",!1)):Zt(e,n.conv0);return o=We(o,[2,2],[2,2],"same"),o=Zt(o,n.conv1),o=We(o,[2,2],[2,2],"same"),o=Zt(o,n.conv2),o=We(o,[2,2],[2,2],"same"),o=Zt(o,n.conv3),o=We(o,[2,2],[2,2],"same"),o=Zt(o,n.conv4),o=We(o,[2,2],[2,2],"same"),o=Zt(o,n.conv5),o=We(o,[2,2],[1,1],"same"),o=n.conv6?Zt(o,n.conv6):o,o=n.conv7?Zt(o,n.conv7):o,gt(o,n.conv8,"valid",!1)},t.prototype.forwardInput=function(e,n){var o=this,a=this.params;if(!a)throw new Error("TinyYolov2 - load model before inference");return K(function(){var i=e.toBatchTensor(n,!1).toFloat();return i=o.config.meanRgb?yr(i,o.config.meanRgb):i,i=i.div(j(256)),o.config.withSeparableConvs?o.runMobilenet(i,a):o.runTinyYolov2(i,a)})},t.prototype.forward=function(e,n){return Q(this,void 0,void 0,function(){var o;return Z(this,function(a){switch(a.label){case 0:return o=this.forwardInput,[4,Ve(e)];case 1:return[4,o.apply(this,[a.sent(),n])];case 2:return[2,a.sent()]}})})},t.prototype.detect=function(e,n){return n===void 0&&(n={}),Q(this,void 0,void 0,function(){var o,a,i,s,u,c,l,h,f,p,d,v,m,g,x=this;return Z(this,function(b){switch(b.label){case 0:return o=new pi(n),a=o.inputSize,i=o.scoreThreshold,[4,Ve(e)];case 1:return s=b.sent(),[4,this.forwardInput(s,a)];case 2:return u=b.sent(),c=K(function(){return Me(u)[0].expandDims()}),l={width:s.getInputWidth(0),height:s.getInputHeight(0)},[4,this.extractBoxes(c,s.getReshapedInputDimensions(0),i)];case 3:return h=b.sent(),u.dispose(),c.dispose(),f=h.map(function(y){return y.box}),p=h.map(function(y){return y.score}),d=h.map(function(y){return y.classScore}),v=h.map(function(y){return x.config.classes[y.label]}),m=cr(f.map(function(y){return y.rescale(a)}),p,this.config.iouThreshold,!0),g=m.map(function(y){return new cc(p[y],d[y],v[y],f[y],l)}),[2,g]}})})},t.prototype.getDefaultModelName=function(){return""},t.prototype.extractParamsFromWeigthMap=function(e){return Xg(e,this.config)},t.prototype.extractParams=function(e){var n=this.config.filterSizes||t.DEFAULT_FILTER_SIZES,o=n?n.length:void 0;if(o!==7&&o!==8&&o!==9)throw new Error("TinyYolov2 - expected 7 | 8 | 9 convolutional filters, but found "+o+" filterSizes in config");return qg(e,this.config,this.boxEncodingSize,n)},t.prototype.extractBoxes=function(e,n,o){return Q(this,void 0,void 0,function(){var a,i,s,u,c,l,h,f,p,d,v,m,g,x,b,y,w,C,S,k,R,E,T,A,P,O,B,V,W,U=this;return Z(this,function(G){switch(G.label){case 0:return a=n.width,i=n.height,s=Math.max(a,i),u=s/a,c=s/i,l=e.shape[1],h=this.config.anchors.length,f=K(function(){var H=e.reshape([l,l,h,U.boxEncodingSize]),q=H.slice([0,0,0,0],[l,l,h,4]),ee=H.slice([0,0,0,4],[l,l,h,1]),te=U.withClassScores?qt(H.slice([0,0,0,5],[l,l,h,U.config.classes.length]),3):j(0);return[q,ee,te]}),p=f[0],d=f[1],v=f[2],m=[],[4,d.array()];case 1:return g=G.sent(),[4,p.array()];case 2:x=G.sent(),b=0,G.label=3;case 3:if(!(b<l))return[3,12];y=0,G.label=4;case 4:if(!(y<l))return[3,11];w=0,G.label=5;case 5:return w<h?(C=Jo(g[b][y][w][0]),!o||C>o?(S=(y+Jo(x[b][y][w][0]))/l*u,k=(b+Jo(x[b][y][w][1]))/l*c,R=Math.exp(x[b][y][w][2])*this.config.anchors[w].x/l*u,E=Math.exp(x[b][y][w][3])*this.config.anchors[w].y/l*c,T=S-R/2,A=k-E/2,P={row:b,col:y,anchor:w},this.withClassScores?[4,this.extractPredictedClass(v,P)]:[3,7]):[3,9]):[3,10];case 6:return W=G.sent(),[3,8];case 7:W={classScore:1,label:0},G.label=8;case 8:O=W,B=O.classScore,V=O.label,m.push(Ke({box:new mo(T,A,T+R,A+E),score:C,classScore:C*B,label:V},P)),G.label=9;case 9:return w++,[3,5];case 10:return y++,[3,4];case 11:return b++,[3,3];case 12:return p.dispose(),d.dispose(),v.dispose(),[2,m]}})})},t.prototype.extractPredictedClass=function(e,n){return Q(this,void 0,void 0,function(){var o,a,i,s;return Z(this,function(u){switch(u.label){case 0:return o=n.row,a=n.col,i=n.anchor,[4,e.array()];case 1:return s=u.sent(),[2,Array(this.config.classes.length).fill(0).map(function(c,l){return s[o][a][i][l]}).map(function(c,l){return{classScore:c,label:l}}).reduce(function(c,l){return c.classScore>l.classScore?c:l})]}})})},t.DEFAULT_FILTER_SIZES=[3,16,32,64,128,256,512,1024,1024],t})(Xt),$g=(function(r){re(t,r);function t(e){e===void 0&&(e=!0);var n=this,o=Object.assign({},{withSeparableConvs:e,iouThreshold:Lg,classes:["face"]},e?{anchors:Ug,meanRgb:Vg}:{anchors:Wg,withClassScores:!0});return n=r.call(this,o)||this,n}return Object.defineProperty(t.prototype,"withSeparableConvs",{get:function(){return this.config.withSeparableConvs},enumerable:!0,configurable:!0}),Object.defineProperty(t.prototype,"anchors",{get:function(){return this.config.anchors},enumerable:!0,configurable:!0}),t.prototype.locateFaces=function(e,n){return Q(this,void 0,void 0,function(){var o;return Z(this,function(a){switch(a.label){case 0:return[4,this.detect(e,n)];case 1:return o=a.sent(),[2,o.map(function(i){return new Bt(i.score,i.relativeBox,{width:i.imageWidth,height:i.imageHeight})})]}})})},t.prototype.getDefaultModelName=function(){return this.withSeparableConvs?Gg:zg},t.prototype.extractParamsFromWeigthMap=function(e){return r.prototype.extractParamsFromWeigthMap.call(this,e)},t})(Bc),Ca=(function(r){re(t,r);function t(){var e=r!==null&&r.apply(this,arguments)||this;return e._name="TinyFaceDetectorOptions",e}return t})(pi),xr=(function(){function r(){}return r.prototype.then=function(t){return Q(this,void 0,void 0,function(){var e;return Z(this,function(n){switch(n.label){case 0:return e=t,[4,this.run()];case 1:return[2,e.apply(void 0,[n.sent()])]}})})},r.prototype.run=function(){return Q(this,void 0,void 0,function(){return Z(this,function(t){throw new Error("ComposableTask - run is not implemented")})})},r})();function bo(r,t,e,n,o){return o===void 0&&(o=function(a){var i=a.alignedRect;return i}),Q(this,void 0,void 0,function(){var a,i,s,u,c;return Z(this,function(l){switch(l.label){case 0:return a=r.map(function(h){return rg(h)?o(h):h.detection}),s=n,s?[3,5]:t instanceof Ie?[4,ii(t,a)]:[3,2];case 1:return u=l.sent(),[3,4];case 2:return[4,ai(t,a)];case 3:u=l.sent(),l.label=4;case 4:s=u,l.label=5;case 5:return i=s,[4,e(i)];case 6:return c=l.sent(),i.forEach(function(h){return h instanceof Ie&&h.dispose()}),[2,c]}})})}function di(r,t,e,n,o){return Q(this,void 0,void 0,function(){var a=this;return Z(this,function(i){return[2,bo([r],t,function(s){return Q(a,void 0,void 0,function(){return Z(this,function(u){return[2,e(s[0])]})})},n,o)]})})}function Yg(r){return K(function(){return lt(Me(r,3).reverse(),3)})}var Fr=2,ro=12;function Jg(r,t){var e=yo(r,t),n=si(r,t);function o(c,l){var h=Ne(r(c));return t.push({paramPath:l}),h}function a(c,l,h){h===void 0&&(h=!1);var f=e(c[0],c[1],3,l+"/conv1"),p=o(c[1],l+"/prelu1_alpha"),d=e(c[1],c[2],3,l+"/conv2"),v=o(c[2],l+"/prelu2_alpha"),m=e(c[2],c[3],h?2:3,l+"/conv3"),g=o(c[3],l+"/prelu3_alpha");return{conv1:f,prelu1_alpha:p,conv2:d,prelu2_alpha:v,conv3:m,prelu3_alpha:g}}function i(){var c=a([3,10,16,32],"pnet"),l=e(32,2,1,"pnet/conv4_1"),h=e(32,4,1,"pnet/conv4_2");return Ke(Ke({},c),{conv4_1:l,conv4_2:h})}function s(){var c=a([3,28,48,64],"rnet",!0),l=n(576,128,"rnet/fc1"),h=o(128,"rnet/prelu4_alpha"),f=n(128,2,"rnet/fc2_1"),p=n(128,4,"rnet/fc2_2");return Ke(Ke({},c),{fc1:l,prelu4_alpha:h,fc2_1:f,fc2_2:p})}function u(){var c=a([3,32,64,64],"onet"),l=e(64,128,2,"onet/conv4"),h=o(128,"onet/prelu4_alpha"),f=n(1152,256,"onet/fc1"),p=o(256,"onet/prelu5_alpha"),d=n(256,2,"onet/fc2_1"),v=n(256,4,"onet/fc2_2"),m=n(256,10,"onet/fc2_3");return Ke(Ke({},c),{conv4:l,prelu4_alpha:h,fc1:f,prelu5_alpha:p,fc2_1:d,fc2_2:v,fc2_3:m})}return{extractPNetParams:i,extractRNetParams:s,extractONetParams:u}}function Qg(r){var t=Yt(r),e=t.extractWeights,n=t.getRemainingWeights,o=[],a=Jg(e,o),i=a.extractPNetParams,s=a.extractRNetParams,u=a.extractONetParams,c=i(),l=s(),h=u();if(n().length!==0)throw new Error("weights remaing after extract: "+n().length);return{params:{pnet:c,rnet:l,onet:h},paramMappings:o}}function Zg(r,t){var e=ln(r,t);function n(l){var h=e(l+"/weights",4,l+"/filters"),f=e(l+"/bias",1);return{filters:h,bias:f}}function o(l){var h=e(l+"/weights",2),f=e(l+"/bias",1);return{weights:h,bias:f}}function a(l){return e(l,1)}function i(l){var h=n(l+"/conv1"),f=a(l+"/prelu1_alpha"),p=n(l+"/conv2"),d=a(l+"/prelu2_alpha"),v=n(l+"/conv3"),m=a(l+"/prelu3_alpha");return{conv1:h,prelu1_alpha:f,conv2:p,prelu2_alpha:d,conv3:v,prelu3_alpha:m}}function s(){var l=i("pnet"),h=n("pnet/conv4_1"),f=n("pnet/conv4_2");return Ke(Ke({},l),{conv4_1:h,conv4_2:f})}function u(){var l=i("rnet"),h=o("rnet/fc1"),f=a("rnet/prelu4_alpha"),p=o("rnet/fc2_1"),d=o("rnet/fc2_2");return Ke(Ke({},l),{fc1:h,prelu4_alpha:f,fc2_1:p,fc2_2:d})}function c(){var l=i("onet"),h=n("onet/conv4"),f=a("onet/prelu4_alpha"),p=o("onet/fc1"),d=a("onet/prelu5_alpha"),v=o("onet/fc2_1"),m=o("onet/fc2_2"),g=o("onet/fc2_3");return Ke(Ke({},l),{conv4:h,prelu4_alpha:f,fc1:p,prelu5_alpha:d,fc2_1:v,fc2_2:m,fc2_3:g})}return{extractPNetParams:s,extractRNetParams:u,extractONetParams:c}}function ey(r){var t=[],e=Zg(r,t),n=e.extractPNetParams,o=e.extractRNetParams,a=e.extractONetParams,i=n(),s=o(),u=a();return $t(r,t),{params:{pnet:i,rnet:s,onet:u},paramMappings:t}}function _a(r,t){var e=t[0],n=t[1];return{height:Math.floor(e*r),width:Math.floor(n*r)}}function ty(r,t,e){for(var n=e[0],o=e[1],a=ro/r,i=[],s=Math.min(n,o)*a,u=0;s>=12;)i.push(a*Math.pow(t,u)),s=s*t,u+=1;return i}var vi=(function(r){re(t,r);function t(e,n,o,a){return r.call(this,{left:e,top:n,right:o,bottom:a},!0)||this}return t})(sn);function Lc(r){return K(function(){return Ye(Be(r,j(127.5)),j(.0078125))})}function Gn(r,t){return K(function(){return ue(Re(r),Ye(t,Yr(Re(Yr(r)))))})}function mi(r,t,e){return e===void 0&&(e=!1),K(function(){var n=gt(r,t.conv1,"valid");return n=Gn(n,t.prelu1_alpha),n=We(n,e?[2,2]:[3,3],[2,2],"same"),n=gt(n,t.conv2,"valid"),n=Gn(n,t.prelu2_alpha),n=e?n:We(n,[3,3],[2,2],"valid"),n=gt(n,t.conv3,"valid"),n=Gn(n,t.prelu3_alpha),n})}function ny(r,t){return K(function(){var e=mi(r,t,!0),n=gt(e,t.conv4_1,"valid"),o=ht(ho(n,3),3),a=qt(Be(n,o),3),i=gt(e,t.conv4_2,"valid");return{prob:a,regions:i}})}function ry(r,t){return K(function(){var e=_a(t,r.shape.slice(1)),n=e.height,o=e.width,a=Ka.resizeBilinear(r,[n,o]),i=Lc(a);return an(i,[0,2,1,3])})}function oy(r,t,e,n){for(var o=[],a=r.arraySync(),i=0;i<r.shape[0];i++)for(var s=0;s<r.shape[1];s++)a[i][s]>=n&&o.push(new ye(s,i));var u=o.map(function(c){var l=new mo(Math.round((c.y*Fr+1)/e),Math.round((c.x*Fr+1)/e),Math.round((c.y*Fr+ro)/e),Math.round((c.x*Fr+ro)/e)),h=a[c.y][c.x],f=t.arraySync(),p=new vi(f[c.y][c.x][0],f[c.y][c.x][1],f[c.y][c.x][2],f[c.y][c.x][3]);return{cell:l,score:h,region:p}});return u}function ay(r,t,e,n,o){o.stage1=[];var a=t.map(function(f){return K(function(){var p={scale:f},d=ry(r,f),v=Date.now(),m=ny(d,n),g=m.prob,x=m.regions;p.pnet=Date.now()-v;var b=Me(Me(g,3)[1])[0],y=Me(x)[0];return{scoresTensor:b,regionsTensor:y,scale:f,statsForScale:p}})}),i=a.map(function(f){var p=f.scoresTensor,d=f.regionsTensor,v=f.scale,m=f.statsForScale,g=oy(p,d,v,e);if(p.dispose(),d.dispose(),!g.length)return o.stage1.push(m),[];var x=Date.now(),b=cr(g.map(function(y){return y.cell}),g.map(function(y){return y.score}),.5);return m.nms=Date.now()-x,m.numBoxes=b.length,o.stage1.push(m),b.map(function(y){return g[y]})}),s=i.reduce(function(f,p){return f.concat(p)},[]),u=[],c=[];if(s.length>0){var l=Date.now(),h=cr(s.map(function(f){return f.cell}),s.map(function(f){return f.score}),.7);o.stage1_nms=Date.now()-l,c=h.map(function(f){return s[f].score}),u=h.map(function(f){return s[f]}).map(function(f){var p=f.cell,d=f.region;return new mo(p.left+d.left*p.width,p.top+d.top*p.height,p.right+d.right*p.width,p.bottom+d.bottom*p.height).toSquare().round()})}return{boxes:u,scores:c}}function Wc(r,t,e){var n=e.width,o=e.height;return Q(this,void 0,void 0,function(){var a,i,s,u=this;return Z(this,function(c){switch(c.label){case 0:return a=xn(r),[4,Promise.all(t.map(function(l){return Q(u,void 0,void 0,function(){var h,f,p,d,v,m,g,x;return Z(this,function(b){return h=l.padAtBorders(r.height,r.width),f=h.y,p=h.ey,d=h.x,v=h.ex,m=d-1,g=f-1,x=a.getImageData(m,g,v-m,p-g),[2,Je.isNodejs()?oi(x):createImageBitmap(x)]})})}))];case 1:return i=c.sent(),s=[],i.forEach(function(l){var h=go({width:n,height:o}),f=xn(h);f.drawImage(l,0,0,n,o);for(var p=f.getImageData(0,0,n,o).data,d=[],v=0;v<p.length;v+=4)d.push(p[v+2]),d.push(p[v+1]),d.push(p[v]);s.push(d)}),[2,s.map(function(l){var h=K(function(){var f=an(Ze(l,[1,n,o,3]),[0,2,1,3]).toFloat();return Lc(f)});return h})]}})})}function iy(r,t){return K(function(){var e=mi(r,t),n=mt(e,[e.shape[0],t.fc1.weights.shape[0]]),o=Dt(n,t.fc1),a=Gn(o,t.prelu4_alpha),i=Dt(a,t.fc2_1),s=ht(ho(i,1),1),u=qt(Be(i,s),1),c=Dt(a,t.fc2_2),l=Me(u,1)[1];return{scores:l,regions:c}})}function sy(r,t,e,n,o){return Q(this,void 0,void 0,function(){var a,i,s,u,c,l,h,f,p,d,v,m,g,x;return Z(this,function(b){switch(b.label){case 0:return a=Date.now(),[4,Wc(r,t,{width:24,height:24})];case 1:return i=b.sent(),o.stage2_extractImagePatches=Date.now()-a,a=Date.now(),s=i.map(function(y){var w=iy(y,n);return y.dispose(),w}),o.stage2_rnet=Date.now()-a,u=s.length>1?Pe(s.map(function(y){return y.scores})):s[0].scores,h=(l=Array).from,[4,u.data()];case 2:return c=h.apply(l,[b.sent()]),u.dispose(),f=c.map(function(y,w){return{score:y,idx:w}}).filter(function(y){return y.score>e}).map(function(y){var w=y.idx;return w}),p=f.map(function(y){return t[y]}),d=f.map(function(y){return c[y]}),v=[],m=[],p.length>0&&(a=Date.now(),g=cr(p,d,.7),o.stage2_nms=Date.now()-a,x=g.map(function(y){var w=s[f[y]].regions.arraySync();return new vi(w[0][0],w[0][1],w[0][2],w[0][3])}),m=g.map(function(y){return d[y]}),v=g.map(function(y,w){return p[y].calibrate(x[w])})),s.forEach(function(y){y.regions.dispose(),y.scores.dispose()}),[2,{boxes:v,scores:m}]}})})}function uy(r,t){return K(function(){var e=mi(r,t);e=We(e,[2,2],[2,2],"same"),e=gt(e,t.conv4,"valid"),e=Gn(e,t.prelu4_alpha);var n=mt(e,[e.shape[0],t.fc1.weights.shape[0]]),o=Dt(n,t.fc1),a=Gn(o,t.prelu5_alpha),i=Dt(a,t.fc2_1),s=ht(ho(i,1),1),u=qt(Be(i,s),1),c=Dt(a,t.fc2_2),l=Dt(a,t.fc2_3),h=Me(u,1)[1];return{scores:h,regions:c,points:l}})}function cy(r,t,e,n,o){return Q(this,void 0,void 0,function(){var a,i,s,u,c,l,h,f,p,d,v,m,g,x,b;return Z(this,function(y){switch(y.label){case 0:return a=Date.now(),[4,Wc(r,t,{width:48,height:48})];case 1:return i=y.sent(),o.stage3_extractImagePatches=Date.now()-a,a=Date.now(),s=i.map(function(w){var C=uy(w,n);return w.dispose(),C}),o.stage3_onet=Date.now()-a,u=s.length>1?Pe(s.map(function(w){return w.scores})):s[0].scores,h=(l=Array).from,[4,u.data()];case 2:return c=h.apply(l,[y.sent()]),u.dispose(),f=c.map(function(w,C){return{score:w,idx:C}}).filter(function(w){return w.score>e}).map(function(w){var C=w.idx;return C}),p=f.map(function(w){var C=s[w].regions.arraySync();return new vi(C[0][0],C[0][1],C[0][2],C[0][3])}),d=f.map(function(w,C){return t[w].calibrate(p[C])}),v=f.map(function(w){return c[w]}),m=[],g=[],x=[],d.length>0&&(a=Date.now(),b=cr(d,v,.7,!1),o.stage3_nms=Date.now()-a,m=b.map(function(w){return d[w]}),g=b.map(function(w){return v[w]}),x=b.map(function(w,C){return Array(5).fill(0).map(function(S,k){var R=s[w].points.arraySync();return new ye(R[0][k]*(m[C].width+1)+m[C].left,R[0][k+5]*(m[C].height+1)+m[C].top)})})),s.forEach(function(w){w.regions.dispose(),w.scores.dispose(),w.points.dispose()}),[2,{boxes:m,scores:g,points:x}]}})})}var ly=(function(r){re(t,r);function t(){return r.call(this,"Mtcnn")||this}return t.prototype.load=function(e){return Q(this,void 0,void 0,function(){return Z(this,function(n){return console.warn("mtcnn is deprecated and will be removed soon"),[2,r.prototype.load.call(this,e)]})})},t.prototype.loadFromDisk=function(e){return Q(this,void 0,void 0,function(){return Z(this,function(n){return console.warn("mtcnn is deprecated and will be removed soon"),[2,r.prototype.loadFromDisk.call(this,e)]})})},t.prototype.forwardInput=function(e,n){return n===void 0&&(n={}),Q(this,void 0,void 0,function(){var o,a,i,s,u,c,l,h,f,p,d,v,m,g,x,b,y,w,C,S,k;return Z(this,function(R){switch(R.label){case 0:if(o=this.params,!o)throw new Error("Mtcnn - load model before inference");if(a=e.canvases[0],!a)throw new Error("Mtcnn - inputCanvas is not defined, note that passing tensors into Mtcnn.forwardInput is not supported yet.");return i={},s=Date.now(),u=K(function(){return Yg(ht(Za.fromPixels(a)).toFloat())}),c=function(E){return u.dispose(),i.total=Date.now()-s,E},l=u.shape.slice(1),h=l[0],f=l[1],p=new Mc(n),d=p.minFaceSize,v=p.scaleFactor,m=p.maxNumScales,g=p.scoreThresholds,x=p.scaleSteps,b=(x||ty(d,v,[h,f])).filter(function(E){var T=_a(E,[h,f]);return Math.min(T.width,T.height)>ro}).slice(0,m),i.scales=b,i.pyramid=b.map(function(E){return _a(E,[h,f])}),y=Date.now(),[4,ay(u,b,g[0],o.pnet,i)];case 1:return w=R.sent(),i.total_stage1=Date.now()-y,w.boxes.length?(i.stage2_numInputBoxes=w.boxes.length,y=Date.now(),[4,sy(a,w.boxes,g[1],o.rnet,i)]):[2,c({results:[],stats:i})];case 2:return C=R.sent(),i.total_stage2=Date.now()-y,C.boxes.length?(i.stage3_numInputBoxes=C.boxes.length,y=Date.now(),[4,cy(a,C.boxes,g[2],o.onet,i)]):[2,c({results:[],stats:i})];case 3:return S=R.sent(),i.total_stage3=Date.now()-y,k=S.boxes.map(function(E,T){return li(ni({},new Bt(S.scores[T],new ti(E.left/f,E.top/h,E.width/f,E.height/h),{height:h,width:f})),new Um(S.points[T].map(function(A){return A.sub(new ye(E.left,E.top)).div(new ye(E.width,E.height))}),{width:E.width,height:E.height}))}),[2,c({results:k,stats:i})]}})})},t.prototype.forward=function(e,n){return n===void 0&&(n={}),Q(this,void 0,void 0,function(){var o;return Z(this,function(a){switch(a.label){case 0:return o=this.forwardInput,[4,Ve(e)];case 1:return[4,o.apply(this,[a.sent(),n])];case 2:return[2,a.sent().results]}})})},t.prototype.forwardWithStats=function(e,n){return n===void 0&&(n={}),Q(this,void 0,void 0,function(){var o;return Z(this,function(a){switch(a.label){case 0:return o=this.forwardInput,[4,Ve(e)];case 1:return[2,o.apply(this,[a.sent(),n])]}})})},t.prototype.getDefaultModelName=function(){return"mtcnn_model"},t.prototype.extractParamsFromWeigthMap=function(e){return ey(e)},t.prototype.extractParams=function(e){return Qg(e)},t})(Xt),hy=.4,fy=[new ye(1.603231,2.094468),new ye(6.041143,7.080126),new ye(2.882459,3.518061),new ye(4.266906,5.178857),new ye(9.041765,10.66308)],py=[117.001,114.697,97.404],dy=(function(r){re(t,r);function t(){var e=this,n={withSeparableConvs:!0,iouThreshold:hy,classes:["face"],anchors:fy,meanRgb:py,isFirstLayerConv2d:!0,filterSizes:[3,16,32,64,128,256,512]};return e=r.call(this,n)||this,e}return Object.defineProperty(t.prototype,"anchors",{get:function(){return this.config.anchors},enumerable:!0,configurable:!0}),t.prototype.locateFaces=function(e,n){return Q(this,void 0,void 0,function(){var o;return Z(this,function(a){switch(a.label){case 0:return[4,this.detect(e,n)];case 1:return o=a.sent(),[2,o.map(function(i){return new Bt(i.score,i.relativeBox,{width:i.imageWidth,height:i.imageHeight})})]}})})},t.prototype.getDefaultModelName=function(){return"tiny_face_detector_model"},t.prototype.extractParamsFromWeigthMap=function(e){return r.prototype.extractParamsFromWeigthMap.call(this,e)},t})(Bc),Qe={ssdMobilenetv1:new Oc,tinyFaceDetector:new dy,tinyYolov2:new $g,mtcnn:new ly,faceLandmark68Net:new Dc,faceLandmark68TinyNet:new mg,faceRecognitionNet:new _g,faceExpressionNet:new ng,ageGenderNet:new fg},Uc=(function(r){re(t,r);function t(e,n,o){var a=r.call(this)||this;return a.parentTask=e,a.input=n,a.extractedFaces=o,a}return t})(xr),gi=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n,o=this;return Z(this,function(a){switch(a.label){case 0:return[4,this.parentTask];case 1:return e=a.sent(),[4,bo(e,this.input,function(i){return Q(o,void 0,void 0,function(){return Z(this,function(s){switch(s.label){case 0:return[4,Promise.all(i.map(function(u){return Qe.faceExpressionNet.predictExpressions(u)}))];case 1:return[2,s.sent()]}})})},this.extractedFaces)];case 2:return n=a.sent(),[2,e.map(function(i,s){return Rc(i,n[s])})]}})})},t.prototype.withAgeAndGender=function(){return new wi(this,this.input)},t})(Uc),yi=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n;return Z(this,function(o){switch(o.label){case 0:return[4,this.parentTask];case 1:return e=o.sent(),e?[4,di(e,this.input,function(a){return Qe.faceExpressionNet.predictExpressions(a)},this.extractedFaces)]:[2];case 2:return n=o.sent(),[2,Rc(e,n)]}})})},t.prototype.withAgeAndGender=function(){return new Ci(this,this.input)},t})(Uc),xi=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.withAgeAndGender=function(){return new _i(this,this.input)},t.prototype.withFaceDescriptors=function(){return new Ii(this,this.input)},t})(gi),bi=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.withAgeAndGender=function(){return new Ei(this,this.input)},t.prototype.withFaceDescriptor=function(){return new Ri(this,this.input)},t})(yi),Vc=(function(r){re(t,r);function t(e,n,o){var a=r.call(this)||this;return a.parentTask=e,a.input=n,a.extractedFaces=o,a}return t})(xr),wi=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n,o=this;return Z(this,function(a){switch(a.label){case 0:return[4,this.parentTask];case 1:return e=a.sent(),[4,bo(e,this.input,function(i){return Q(o,void 0,void 0,function(){return Z(this,function(s){switch(s.label){case 0:return[4,Promise.all(i.map(function(u){return Qe.ageGenderNet.predictAgeAndGender(u)}))];case 1:return[2,s.sent()]}})})},this.extractedFaces)];case 2:return n=a.sent(),[2,e.map(function(i,s){var u=n[s],c=u.age,l=u.gender,h=u.genderProbability;return Fc(Pc(i,l,h),c)})]}})})},t.prototype.withFaceExpressions=function(){return new gi(this,this.input)},t})(Vc),Ci=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n,o,a,i;return Z(this,function(s){switch(s.label){case 0:return[4,this.parentTask];case 1:return e=s.sent(),e?[4,di(e,this.input,function(u){return Qe.ageGenderNet.predictAgeAndGender(u)},this.extractedFaces)]:[2];case 2:return n=s.sent(),o=n.age,a=n.gender,i=n.genderProbability,[2,Fc(Pc(e,a,i),o)]}})})},t.prototype.withFaceExpressions=function(){return new yi(this,this.input)},t})(Vc),_i=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.withFaceExpressions=function(){return new xi(this,this.input)},t.prototype.withFaceDescriptors=function(){return new Ii(this,this.input)},t})(wi),Ei=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.withFaceExpressions=function(){return new bi(this,this.input)},t.prototype.withFaceDescriptor=function(){return new Ri(this,this.input)},t})(Ci),zc=(function(r){re(t,r);function t(e,n){var o=r.call(this)||this;return o.parentTask=e,o.input=n,o}return t})(xr),Ii=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n;return Z(this,function(o){switch(o.label){case 0:return[4,this.parentTask];case 1:return e=o.sent(),[4,bo(e,this.input,function(a){return Promise.all(a.map(function(i){return Qe.faceRecognitionNet.computeFaceDescriptor(i)}))},null,function(a){return a.landmarks.align(null,{useDlibAlignment:!0})})];case 2:return n=o.sent(),[2,n.map(function(a,i){return Nc(e[i],a)})]}})})},t.prototype.withFaceExpressions=function(){return new xi(this,this.input)},t.prototype.withAgeAndGender=function(){return new _i(this,this.input)},t})(zc),Ri=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n;return Z(this,function(o){switch(o.label){case 0:return[4,this.parentTask];case 1:return e=o.sent(),e?[4,di(e,this.input,function(a){return Qe.faceRecognitionNet.computeFaceDescriptor(a)},null,function(a){return a.landmarks.align(null,{useDlibAlignment:!0})})]:[2];case 2:return n=o.sent(),[2,Nc(e,n)]}})})},t.prototype.withFaceExpressions=function(){return new bi(this,this.input)},t.prototype.withAgeAndGender=function(){return new Ei(this,this.input)},t})(zc),Gc=(function(r){re(t,r);function t(e,n,o){var a=r.call(this)||this;return a.parentTask=e,a.input=n,a.useTinyLandmarkNet=o,a}return Object.defineProperty(t.prototype,"landmarkNet",{get:function(){return this.useTinyLandmarkNet?Qe.faceLandmark68TinyNet:Qe.faceLandmark68Net},enumerable:!0,configurable:!0}),t})(xr),vy=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n,o,a,i,s=this;return Z(this,function(u){switch(u.label){case 0:return[4,this.parentTask];case 1:return e=u.sent(),n=e.map(function(c){return c.detection}),this.input instanceof Ie?[4,ii(this.input,n)]:[3,3];case 2:return a=u.sent(),[3,5];case 3:return[4,ai(this.input,n)];case 4:a=u.sent(),u.label=5;case 5:return o=a,[4,Promise.all(o.map(function(c){return s.landmarkNet.detectLandmarks(c)}))];case 6:return i=u.sent(),o.forEach(function(c){return c instanceof Ie&&c.dispose()}),[2,e.map(function(c,l){return li(c,i[l])})]}})})},t.prototype.withFaceExpressions=function(){return new xi(this,this.input)},t.prototype.withAgeAndGender=function(){return new _i(this,this.input)},t.prototype.withFaceDescriptors=function(){return new Ii(this,this.input)},t})(Gc),my=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n,o,a,i;return Z(this,function(s){switch(s.label){case 0:return[4,this.parentTask];case 1:return e=s.sent(),e?(n=e.detection,this.input instanceof Ie?[4,ii(this.input,[n])]:[3,3]):[2];case 2:return a=s.sent(),[3,5];case 3:return[4,ai(this.input,[n])];case 4:a=s.sent(),s.label=5;case 5:return o=a,[4,this.landmarkNet.detectLandmarks(o[0])];case 6:return i=s.sent(),o.forEach(function(u){return u instanceof Ie&&u.dispose()}),[2,li(e,i)]}})})},t.prototype.withFaceExpressions=function(){return new bi(this,this.input)},t.prototype.withAgeAndGender=function(){return new Ei(this,this.input)},t.prototype.withFaceDescriptor=function(){return new Ri(this,this.input)},t})(Gc),Hc=(function(r){re(t,r);function t(e,n){n===void 0&&(n=new xo);var o=r.call(this)||this;return o.input=e,o.options=n,o}return t})(xr),jc=(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n,o,a;return Z(this,function(i){switch(i.label){case 0:return e=this,n=e.input,o=e.options,o instanceof Mc?[4,Qe.mtcnn.forward(n,o)]:[3,2];case 1:return[2,i.sent().map(function(s){return s.detection})];case 2:if(a=o instanceof Ca?function(s){return Qe.tinyFaceDetector.locateFaces(s,o)}:o instanceof xo?function(s){return Qe.ssdMobilenetv1.locateFaces(s,o)}:o instanceof pi?function(s){return Qe.tinyYolov2.locateFaces(s,o)}:null,!a)throw new Error("detectFaces - expected options to be instance of TinyFaceDetectorOptions | SsdMobilenetv1Options | MtcnnOptions | TinyYolov2Options");return[2,a(n)]}})})},t.prototype.runAndExtendWithFaceDetections=function(){var e=this;return new Promise(function(n){return Q(e,void 0,void 0,function(){var o;return Z(this,function(a){switch(a.label){case 0:return[4,this.run()];case 1:return o=a.sent(),[2,n(o.map(function(i){return ni({},i)}))]}})})})},t.prototype.withFaceLandmarks=function(e){return e===void 0&&(e=!1),new vy(this.runAndExtendWithFaceDetections(),this.input,e)},t.prototype.withFaceExpressions=function(){return new gi(this.runAndExtendWithFaceDetections(),this.input)},t.prototype.withAgeAndGender=function(){return new wi(this.runAndExtendWithFaceDetections(),this.input)},t})(Hc);(function(r){re(t,r);function t(){return r!==null&&r.apply(this,arguments)||this}return t.prototype.run=function(){return Q(this,void 0,void 0,function(){var e,n;return Z(this,function(o){switch(o.label){case 0:return[4,new jc(this.input,this.options)];case 1:return e=o.sent(),n=e[0],e.forEach(function(a){a.score>n.score&&(n=a)}),[2,n]}})})},t.prototype.runAndExtendWithFaceDetection=function(){var e=this;return new Promise(function(n){return Q(e,void 0,void 0,function(){var o;return Z(this,function(a){switch(a.label){case 0:return[4,this.run()];case 1:return o=a.sent(),[2,n(o?ni({},o):void 0)]}})})})},t.prototype.withFaceLandmarks=function(e){return e===void 0&&(e=!1),new my(this.runAndExtendWithFaceDetection(),this.input,e)},t.prototype.withFaceExpressions=function(){return new yi(this.runAndExtendWithFaceDetection(),this.input)},t.prototype.withAgeAndGender=function(){return new Ci(this.runAndExtendWithFaceDetection(),this.input)},t})(Hc);function Ss(r,t){return t===void 0&&(t=new xo),new jc(r,t)}function gy(r,t){if(r.length!==t.length)throw new Error("euclideanDistance: arr1.length !== arr2.length");var e=Array.from(r),n=Array.from(t);return Math.sqrt(e.map(function(o,a){return o-n[a]}).reduce(function(o,a){return o+Math.pow(a,2)},0))}(function(){function r(t,e){e===void 0&&(e=.6),this._distanceThreshold=e;var n=Array.isArray(t)?t:[t];if(!n.length)throw new Error("FaceRecognizer.constructor - expected atleast one input");var o=1,a=function(){return"person "+o++};this._labeledDescriptors=n.map(function(i){if(i instanceof Dr)return i;if(i instanceof Float32Array)return new Dr(a(),[i]);if(i.descriptor&&i.descriptor instanceof Float32Array)return new Dr(a(),[i.descriptor]);throw new Error("FaceRecognizer.constructor - expected inputs to be of type LabeledFaceDescriptors | WithFaceDescriptor<any> | Float32Array | Array<LabeledFaceDescriptors | WithFaceDescriptor<any> | Float32Array>")})}return Object.defineProperty(r.prototype,"labeledDescriptors",{get:function(){return this._labeledDescriptors},enumerable:!0,configurable:!0}),Object.defineProperty(r.prototype,"distanceThreshold",{get:function(){return this._distanceThreshold},enumerable:!0,configurable:!0}),r.prototype.computeMeanDistance=function(t,e){return e.map(function(n){return gy(n,t)}).reduce(function(n,o){return n+o},0)/(e.length||1)},r.prototype.matchDescriptor=function(t){var e=this;return this.labeledDescriptors.map(function(n){var o=n.descriptors,a=n.label;return new Cs(a,e.computeMeanDistance(t,o))}).reduce(function(n,o){return n.distance<o.distance?n:o})},r.prototype.findBestMatch=function(t){var e=this.matchDescriptor(t);return e.distance<this.distanceThreshold?e:new Cs("unknown",e.distance)},r.prototype.toJSON=function(){return{distanceThreshold:this.distanceThreshold,labeledDescriptors:this.labeledDescriptors.map(function(t){return t.toJSON()})}},r.fromJSON=function(t){var e=t.labeledDescriptors.map(function(n){return Dr.fromJSON(n)});return new r(e,t.distanceThreshold)},r})();const xy=r=>{var k,R;const{visible:t,onOk:e,onCancel:n,withImage:o}=r,[a,i]=_t.useState(!1),[s,u]=Ro.useState(!1),c=_t.useRef(null),l=_t.useRef(null),h=_t.useRef(null),f=_t.useRef(null),[p,d]=Ro.useState(0),[v,m]=Ro.useState([]),[g,x]=_t.useState(),[b,y]=_t.useState();_t.useEffect(()=>{if(!t||a)return;(async()=>{const T=`${Yc}/iam/models`;Promise.all([Qe.tinyFaceDetector.loadFromUri(T),Qe.faceLandmark68Net.loadFromUri(T),Qe.faceRecognitionNet.loadFromUri(T)]).then(()=>{i(!0)}).catch(()=>{Vt("error",ze.t("login:Model loading failure")),n()})})()},[t,a]),_t.useEffect(()=>{if(!o)return t?(d(0),a&&navigator.mediaDevices.getUserMedia({video:{facingMode:"user"}}).then(E=>{f.current=E,u(!0)}).catch(E=>{C(E)})):(clearInterval(h.current),h.current=null,u(!1)),()=>{clearInterval(h.current),h.current=null,u(!1)}},[t,a]),_t.useEffect(()=>{var E;if(!o)if(s){let T=0;const A=setInterval(()=>{T++,c.current&&(c.current.srcObject=f.current,c.current.play(),clearInterval(A)),T>=30&&(clearInterval(A),n())},100)}else(E=f.current)==null||E.getTracks().forEach(T=>T.stop()),c.current&&(c.current.srcObject=null)},[s]);const w=()=>{if(o)return;let E=0,T=0;h.current||(h.current=setInterval(async()=>{if(a&&c.current&&t){const A=await Ss(c.current,new Ca).withFaceLandmarks().withFaceDescriptors();if(E++,E%50===0?Vt("info",ze.t("login:Please ensure sufficient lighting and align your face in the center of the recognition box")):E>300&&(Vt("error",ze.t("login:Face recognition failed")),n()),A.length===1){const P=A[0];d(Math.round(P.detection.score*100));const O=Array.from(P.descriptor);P.detection.score>.9&&(T++,(P.detection.score>.99||T>10)&&(clearInterval(h.current),e(O)))}else d(P=>Math.round(P/2))}},100))},C=E=>{n(),E instanceof DOMException&&(E.name==="NotFoundError"||E.name==="DevicesNotFoundError"?Vt("error",ze.t("login:Please ensure that you have a camera device for facial recognition")):E.name==="NotAllowedError"||E.name==="PermissionDeniedError"?Vt("error",ze.t("login:Please provide permission to access the camera")):E.name==="NotReadableError"||E.name==="TrackStartError"?Vt("error",ze.t("login:The camera is currently in use by another webpage")):E.name==="TypeError"?Vt("error",ze.t("login:Please load the webpage using HTTPS, otherwise the camera cannot be accessed")):Vt("error",E.message))},S=E=>new Promise((T,A)=>{const P=new FileReader;P.readAsDataURL(E),P.onload=()=>T(P.result),P.onerror=O=>A(O)});return o?t?ve.jsx("div",{className:"fixed inset-0 z-50 flex items-center justify-center bg-black/80",children:ve.jsxs("div",{className:"bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-[350px]",children:[ve.jsx("h2",{className:"text-lg font-semibold text-white mb-4",children:ze.t("login:Face Recognition")}),ve.jsxs("div",{className:"space-y-3",children:[ve.jsx("div",{className:"border-2 border-dashed border-white/20 rounded-lg p-6 text-center cursor-pointer hover:border-white/40 transition-colors",onClick:()=>{const E=document.createElement("input");E.type="file",E.multiple=!0,E.accept="image/*",E.onchange=async T=>{const A=T.target;if(A.files){const P=[...v];for(const O of Array.from(A.files)){const B=await S(O);O.base64=B,P.push(O)}m(P),x([])}},E.click()},children:ve.jsx("p",{className:"text-gray-400 text-sm",children:ze.t("general:Click to Upload")})}),v.length>0&&ve.jsx("div",{className:"space-y-1",children:v.map((E,T)=>ve.jsxs("div",{className:"flex items-center justify-between text-sm text-gray-300 px-2 py-1 bg-white/5 rounded",children:[ve.jsx("span",{className:"truncate",children:E.name}),ve.jsx("button",{onClick:()=>{const A=v.filter((P,O)=>O!==T);m(A),x([])},className:"text-gray-500 hover:text-red-400 ml-2",children:"×"})]},T))}),a&&ve.jsx("button",{className:"w-full px-4 py-2 text-sm border border-white/20 text-white rounded-lg hover:bg-white/10 transition-colors",onClick:async()=>{var T,A,P;let E=0;for(const O of v){const B=v.indexOf(O),V=new Image;V.src=O.base64;const W=await Ss(V,new Ca).withFaceLandmarks().withFaceDescriptors();((T=W[0])==null?void 0:T.detection.score)>.9&&((A=W[0])==null?void 0:A.detection.score)>E&&(E=(P=W[0])==null?void 0:P.detection.score,x(W[0]),y(B))}E<.9&&Vt("error",ze.t("login:Face recognition failed"))},children:ze.t("general:Generate")})]}),g&&g.length!==0&&b!==void 0&&ve.jsxs("div",{className:"mt-3",children:[ve.jsxs("div",{className:"text-sm text-gray-400",children:[ze.t("application:Select"),": ",(k=v[b])==null?void 0:k.name]}),ve.jsx("img",{src:(R=v[b])==null?void 0:R.base64,alt:"selected",className:"w-full mt-2 rounded"})]}),ve.jsxs("div",{className:"flex justify-end gap-2 mt-6",children:[ve.jsx("button",{onClick:()=>{e(Array.from(g.descriptor))},disabled:!g||(g==null?void 0:g.length)===0,className:"px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed",children:ze.t("general:OK")}),ve.jsx("button",{onClick:n,className:"px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors",children:ze.t("general:Cancel")})]})]})}):null:!t||!s?null:ve.jsx("div",{className:"fixed inset-0 z-50 flex items-center justify-center bg-black/80",children:ve.jsxs("div",{className:"bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-[350px]",children:[ve.jsx("h2",{className:"text-lg font-semibold text-white mb-4",children:ze.t("login:Face Recognition")}),ve.jsx("div",{className:"w-full bg-white/10 rounded-full h-2 mb-4",children:ve.jsx("div",{className:"bg-white h-2 rounded-full transition-all duration-200",style:{width:`${p}%`}})}),ve.jsx("div",{className:"mt-5 mb-12 flex flex-col justify-center items-center relative",children:a?ve.jsxs("div",{className:"flex justify-center items-center relative",children:[ve.jsx("video",{ref:c,onPlay:w,className:"rounded-full h-[220px] w-[220px] object-cover align-middle"}),ve.jsx("div",{className:"absolute w-[240px] h-[240px] top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2",children:ve.jsx("svg",{width:"240",height:"240",fill:"none",children:ve.jsx("circle",{strokeDasharray:"700",strokeDashoffset:700-6.9115*p,strokeWidth:"4",cx:"120",cy:"120",r:"110",stroke:"#5734d3",transform:"rotate(-90, 120, 120)",strokeLinecap:"round",style:{transition:"all .2s linear"}})})}),ve.jsx("canvas",{ref:l,className:"absolute"})]}):ve.jsxs("div",{className:"flex justify-center items-center py-8",children:[ve.jsx($c,{className:"w-8 h-8 text-white animate-spin"}),ve.jsx("span",{className:"ml-2 text-gray-400 text-sm",children:ze.t("login:Loading")})]})}),ve.jsx("div",{className:"flex justify-end gap-2 mt-6",children:ve.jsx("button",{onClick:n,className:"px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors",children:ze.t("general:Cancel")})})]})})};export{xy as default};
