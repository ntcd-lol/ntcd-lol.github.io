const fs = require('fs');
const path = require('path');
const matter = require('gray-matter');

const DOCS_DIR = process.env.DOCS_DIR || './docs';
const OUTPUT = process.env.OUTPUT || './manifest.json';

function parseMarkdownToBlocks(content) {
  const blocks = [];
  const lines = content.split('\n');
  let currentType = 'prose';
  let currentBuffer = [];
  let currentLang = null;

  const flush = () => {
    const text = currentBuffer.join('\n').trim();
    if (!text) return;
    if (currentType === 'code') {
      blocks.push({ type: 'code', language: currentLang, content: text });
    } else {
      // detect headings
      const headingMatch = text.match(/^(#{1,6})\s+(.+)$/);
      if (headingMatch) {
        blocks.push({
          type: 'heading',
          level: headingMatch[1].length,
          content: headingMatch[2].trim()
        });
        // remaining prose after heading? (heading usually on own line)
        const rest = text.replace(/^#{1,6}\s+.+\n?/, '').trim();
        if (rest) blocks.push({ type: 'prose', content: rest });
      } else {
        blocks.push({ type: 'prose', content: text });
      }
    }
    currentBuffer = [];
  };

  for (const line of lines) {
    const fenceMatch = line.match(/^```(\w*)$/);
    if (fenceMatch) {
      if (currentType === 'prose') {
        flush();
        currentType = 'code';
        currentLang = fenceMatch[1] || 'text';
      } else {
        flush();
        currentType = 'prose';
        currentLang = null;
      }
      continue;
    }
    currentBuffer.push(line);
  }
  flush();

  return blocks;
}

function buildManifest() {
  const sections = [];
  const files = fs.readdirSync(DOCS_DIR).filter(f => f.endsWith('.md'));

  for (const file of files) {
    const raw = fs.readFileSync(path.join(DOCS_DIR, file), 'utf8');
    const { data, content } = matter(raw);
    const id = file.replace(/\.md$/, '').replace(/\//g, '-');
    sections.push({
      id: data.id || id,
      title: data.title || id,
      sourceFile: file,
      blocks: parseMarkdownToBlocks(content)
    });
  }

  // sort by frontmatter order if present, else by id
  sections.sort((a, b) => (a.order || 0) - (b.order || 0) || a.id.localeCompare(b.id));

  const manifest = {
    project: 'pse-lua',
    owner: 'ntcd-lol',
    generatedAt: new Date().toISOString(),
    sections
  };

  fs.writeFileSync(OUTPUT, JSON.stringify(manifest, null, 2));
  console.log(`Manifest written to ${OUTPUT} (${sections.length} sections)`);
}

buildManifest();
