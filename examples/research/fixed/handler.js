// Fixed twin. No service is started by this file.
function calculate(expression) {
  return JSON.parse(expression);
}
function execute(directory) {
  require('child_process').execFile('git', ['-C', directory, 'status']);
}
