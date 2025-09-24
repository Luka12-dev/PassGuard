(() => {
  'use strict';

  // UI elements
  const pwInput = document.getElementById('password');
  const strengthFill = document.getElementById('strengthFill');
  const feedback = document.getElementById('feedback');

  const lenRange = document.getElementById('length');
  const lenVal = document.getElementById('lenVal');
  const generateBtn = document.getElementById('generateBtn');
  const generated = document.getElementById('generated');
  const copyBtn = document.getElementById('copyBtn');
  const optLower = document.getElementById('optLower');
  const optUpper = document.getElementById('optUpper');
  const optDigits = document.getElementById('optDigits');
  const optSymbols = document.getElementById('optSymbols');

  // WASM hooks
  const wasm = {
    ready: false,
    calc_entropy: null,
    dict_check: null
  };

  lenVal.textContent = lenRange.value;
  lenRange.addEventListener('input', () => (lenVal.textContent = lenRange.value));

  // Debounce helper
  function debounce(fn, wait = 300) {
    let t = null;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), wait);
    };
  }

  // Initialize WASM if available (supports modularized createPWModule and non-modular Module)
  async function initWasm() {
    try {
      if (typeof createPWModule === 'function') {
        // modularized build: createPWModule() -> Promise(Module)
        const Module = await createPWModule();
        setupModule(Module);
        console.log('WASM (modular) initialized');
        return;
      }
    } catch (e) {
      console.warn('createPWModule failed:', e);
    }

    // fallback to global Module (non-modular emsdk output)
    try {
      if (window.Module && typeof Module.cwrap === 'function') {
        setupModule(Module);
        console.log('WASM (global) initialized');
        return;
      }
    } catch (e) {
      console.warn('Global Module not available:', e);
    }

    console.log('WASM not found, using JS fallback analyzers');
  }

  function setupModule(Module) {
    try {
      wasm.calc_entropy = Module.cwrap('calc_entropy', 'number', ['string']);
      wasm.dict_check = Module.cwrap('dict_check', 'number', ['string']);
      wasm.ready = true;
    } catch (e) {
      console.warn('Failed to wrap WASM functions:', e);
    }
  }

  // Entropy calculations (JS fallback)
  function charsetPoolEntropy(password) {
    if (!password || password.length === 0) return 0;
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^A-Za-z0-9]/.test(password)) pool += 32; // approximate symbols
    pool = Math.max(pool, 1);
    return password.length * Math.log2(pool);
  }

  function shannonEntropy(password) {
    if (!password || password.length === 0) return 0;
    const freq = Object.create(null);
    for (let ch of password) freq[ch] = (freq[ch] || 0) + 1;
    const len = password.length;
    let h = 0;
    for (let k in freq) {
      const p = freq[k] / len;
      h -= p * Math.log2(p);
    }
    // Shannon entropy per symbol times length = bits
    return h * len;
  }

  function jsEntropy(password) {
    // Use the stronger of two entropy heuristics
    const poolBits = charsetPoolEntropy(password);
    const shannonBits = shannonEntropy(password);
    return Math.max(poolBits, shannonBits);
  }

  // Map bits -> 0..100 score
  function bitsToScore(bits) {
    const max = 128; // ceiling for normalization (arbitrary but reasonable)
    return Math.round(Math.min(100, (bits / max) * 100));
  }

  // Human-friendly label
  function bitsToText(bits, isCommon) {
    if (isCommon) return 'Password is on common-password list - very weak.';
    if (bits < 28) return 'Very weak';
    if (bits < 36) return 'Weak';
    if (bits < 60) return 'Moderate';
    if (bits < 90) return 'Strong';
    return 'Very strong';
  }

  // Format estimated cracking time using logs to avoid overflow
  function estimateCrackTime(bits, guessesPerSecond = 1e9) {
    // years = 2^bits / guessesPerSecond / secondsPerYear
    const secondsPerYear = 31557600; // ~365.25 days
    const log10_2 = Math.LOG10E * Math.log(2); // log10(2)
    const log10_years = bits * Math.LOG10E * Math.log(2) - Math.log10(guessesPerSecond) - Math.log10(secondsPerYear);
    if (!isFinite(log10_years)) return { label: '>1M years', years: Infinity };

    if (log10_years < 6) {
      // less than 10^6 years -> compute exact value
      const years = Math.pow(10, log10_years);
      if (years < 1) {
        const days = Math.round(years * 365);
        return { label: `${days} days`, years };
      }
      if (years < 2) return { label: '≈ 1 year', years };
      if (years < 1000) return { label: `${Math.round(years)} years`, years };
      return { label: `${Math.round(years / 1000)}k years`, years };
    } else {
      // huge number, present compact
      const k = Math.pow(10, log10_years - 3);
      return { label: `≈ ${Math.round(k / 1000)}M years`, years: Infinity };
    }
  }

  // Update strength UI
  function setStrength(percent, styleStr) {
    strengthFill.style.width = `${Math.min(100, percent)}%`;
    strengthFill.style.background = styleStr;
  }

  // Color decision (keeps previous variable names but single gradients)
  function pickColor(score) {
    if (score > 75) return 'linear-gradient(90deg,var(--good),var(--accent))';
    if (score > 45) return 'linear-gradient(90deg,var(--warn),var(--good))';
    return 'linear-gradient(90deg,var(--bad),var(--warn))';
  }

  // Main update logic (tries WASM, falls back to JS)
  function analyzePassword(password) {
    if (!password) {
      setStrength(0, 'transparent');
      feedback.textContent = 'Enter a password to analyze.';
      return;
    }

    let bits = 0;
    let isCommon = false;

    if (wasm.ready && wasm.calc_entropy) {
      try {
        bits = wasm.calc_entropy(password); // expected double
        isCommon = wasm.dict_check ? !!wasm.dict_check(password) : false;
      } catch (e) {
        // fallback if something goes wrong
        bits = jsEntropy(password);
      }
    } else {
      bits = jsEntropy(password);
    }

    const score = bitsToScore(bits);
    const color = pickColor(score);
    setStrength(score, color);

    const estimate = estimateCrackTime(bits);
    feedback.textContent = `${bits.toFixed(1)} bits - ${bitsToText(bits, isCommon)} • estimate: ${estimate.label}`;
  }

  const debouncedAnalyze = debounce((val) => analyzePassword(val), 200);

  pwInput.addEventListener('input', (e) => debouncedAnalyze(e.target.value));

  function secureGenerate(length, opts) {
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const symbols = '!@#$%^&*()-_=+[]{};:,.<>/?|~';

    const pools = [];
    if (opts.lower) pools.push(lower);
    if (opts.upper) pools.push(upper);
    if (opts.digits) pools.push(digits);
    if (opts.symbols) pools.push(symbols);

    // If nothing selected, default to lower+upper+digits
    if (pools.length === 0) pools.push(lower, upper, digits);

    // Build initial array ensuring at least one from each pool
    const out = [];
    for (let pool of pools) {
      out.push(randomChar(pool));
    }

    // Fill the rest from the combined pool
    const combined = pools.join('');
    while (out.length < length) out.push(randomChar(combined));

    // Shuffle using crypto-safe RNG and return string
    shuffleArray(out);
    return out.slice(0, length).join('');
  }

  function randomChar(pool) {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return pool[arr[0] % pool.length];
  }

  // Fisher-Yates shuffle using crypto RNG
  function shuffleArray(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const r = crypto.getRandomValues(new Uint32Array(1))[0];
      const j = r % (i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
  }

  // Generator button
  generateBtn.addEventListener('click', () => {
    const length = Number(lenRange.value) || 12;
    const opts = { lower: optLower.checked, upper: optUpper.checked, digits: optDigits.checked, symbols: optSymbols.checked };
    const pw = secureGenerate(length, opts);
    generated.value = pw;
    // place generated into main input and analyze immediately
    pwInput.value = pw;
    analyzePassword(pw);
  });

  copyBtn.addEventListener('click', async () => {
    if (!generated.value) return;
    try {
      await navigator.clipboard.writeText(generated.value);
      const old = copyBtn.textContent;
      copyBtn.textContent = 'Copied!';
      setTimeout(() => (copyBtn.textContent = old), 1200);
    } catch (e) {
      console.warn('Copy failed', e);
    }
  });

  // If user edits the generated field manually, re-run analysis
  generated.addEventListener('input', (e) => {
    pwInput.value = e.target.value;
    debouncedAnalyze(e.target.value);
  });

  initWasm();

  window.__pwAnalyzer = {
    analyze: analyzePassword,
    initWasm
  };
})();