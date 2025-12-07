(function (global, factory) {
  if (typeof module === "object" && typeof module.exports === "object") {
    // Node / CommonJS
    module.exports = factory();
  } else if (typeof define === "function" && define.amd) {
    // AMD
    define([], factory);
  } else {
    // Browser global
    global.MyLibrary = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : this, function () {





  // ===== Your library code here =====
  class RBTree {
    constructor(compareFn) {
      this.compare = compareFn || ((a, b) => a - b);
      this.root = null;
    }
    // Add your RBTree methods here...
  }

  function helperFunction() {
    return "hello world";
  }

  // Expose public API
  return { RBTree, helperFunction };












  
});
