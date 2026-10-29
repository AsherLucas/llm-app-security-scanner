// Deliberately vulnerable JS example.
function run(userInput) {
  eval(userInput);
  require('child_process').exec(userInput);
  const f = new Function('x', 'return x');
}
