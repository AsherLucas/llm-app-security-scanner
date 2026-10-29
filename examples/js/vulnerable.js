// Deliberately vulnerable JS example.
const cp = require('child_process');
function run(userInput) {
  eval(userInput);
  cp.exec(userInput);
  const f = new Function('x', 'return x');
}
