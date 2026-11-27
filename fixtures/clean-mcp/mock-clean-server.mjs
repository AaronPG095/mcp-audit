import readline from 'node:readline';

const rugPull = process.env.MOCK_RUG_PULL === '1';

const tools = [
  {
    name: 'add_numbers',
    description: rugPull
      ? 'Adds two numbers together and returns the sum (updated description).'
      : 'Adds two numbers together and returns the sum.',
    inputSchema: {
      type: 'object',
      properties: {
        a: { type: 'number', description: 'First addend' },
        b: { type: 'number', description: 'Second addend' },
      },
      required: ['a', 'b'],
    },
  },
  {
    name: 'search_docs',
    description: 'Searches local project documentation by keyword.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query string' },
      },
      required: ['query'],
    },
  },
];

const resources = [
  {
    uri: 'docs://getting-started',
    name: 'Getting Started',
    description: 'Project onboarding guide.',
    mimeType: 'text/markdown',
  },
];

const prompts = [
  {
    name: 'summarize_diff',
    description: rugPull
      ? 'Summarizes a git diff into bullet points (mutated).'
      : 'Summarizes a git diff into concise bullet points.',
    arguments: [
      {
        name: 'diff',
        description: 'Unified diff text',
        required: true,
      },
    ],
  },
];

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let req;
  try {
    req = JSON.parse(trimmed);
  } catch {
    return;
  }

  if (req.method === 'notifications/initialized') {
    return;
  }

  if (req.method === 'tools/call') {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: req.id ?? null,
        error: { code: -32601, message: 'tools/call must never be invoked by mcp-audit' },
      }) + '\n',
    );
    process.exit(42);
  }

  if (req.method === 'initialize') {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {}, resources: {} },
          serverInfo: { name: 'mock-clean-server', version: '1.0.0' },
        },
      }) + '\n',
    );
    return;
  }

  if (req.method === 'tools/list') {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: req.id,
        result: { tools },
      }) + '\n',
    );
    return;
  }

  if (req.method === 'resources/list') {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: req.id,
        result: { resources },
      }) + '\n',
    );
    return;
  }

  if (req.method === 'prompts/list') {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: req.id,
        result: { prompts },
      }) + '\n',
    );
    return;
  }

  process.stdout.write(
    JSON.stringify({
      jsonrpc: '2.0',
      id: req.id ?? null,
      error: { code: -32601, message: `Method not found: ${req.method}` },
    }) + '\n',
  );
});
