'use strict'

const { fix } = require('../modules/ai-commands');

exports.command = 'fix'
exports.desc = 'Run validate and plan; if either fails, get the AI\'s cause and a suggested fix'
exports.builder = (yargs) => {
  return yargs
    .option('provider', {
      alias: 'p',
      describe: 'Provider: terraform (default) or tofu/opentofu',
      type: 'string',
      default: 'terraform',
    })
    .option('write', {
      describe: 'Write the suggested fixes into the files without asking',
      type: 'boolean',
      default: false,
    })
    .option('log', {
      describe: 'Diagnose a saved error log instead of running terraform (e.g. from CI)',
      type: 'string',
    })
    .epilog([
      'Needs ANTHROPIC_API_KEY (or TERIAC_AI_PROVIDER=bedrock|vertex). Plan flags go after --',
      '',
      'Examples:',
      '  teriac fix',
      '  teriac fix --log ci-output.txt',
      '  teriac fix --write -- -var-file=prod.tfvars',
    ].join('\n'))
}

exports.handler = async (argv) => {
  await fix({ provider: argv.provider, extraArgs: argv._.slice(1), write: argv.write, log: argv.log });
}
