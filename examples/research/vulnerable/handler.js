// Owned fixture for static analysis only.
function calculate(expression) {
  return eval(expression);
}
function execute(command) {
  require('child_process').exec(command);
}
