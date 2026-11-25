'use strict'

const { explain } = require('../modules/ai-commands');

exports.command = 'explain'
exports.desc = 'Plan, then get a plain-English AI review of the changes (or why the plan failed)'
exports.builder = (yargs) => {
  return yargs
    .option('provider', {
      alias: 'p',
      describe: 'Provider: terraform (default) or tofu/opentofu',
      type: 'string',
      default: 'terraform',
    })
    .option('write', {
      describe: 'If the plan fails, write the suggested fixes into the files without asking',
      type: 'boolean',
      default: false,
    })
    .epilog([
      'Needs ANTHROPIC_API_KEY (or TERIAC_AI_PROVIDER=bedrock|vertex). Plan flags go after --',
      'Sensitive values and things that look like secrets are hidden before anything is sent.',
      '',
      'Examples:',
      '  teriac explain',
      '  teriac explain -- -var="env=prod"',
    ].join('\n'))
}

exports.handler = async (argv) => {
  await explain({ provider: argv.provider, extraArgs: argv._.slice(1), write: argv.write });
}
