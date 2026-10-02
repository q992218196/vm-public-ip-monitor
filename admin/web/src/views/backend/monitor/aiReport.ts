import MarkdownIt from 'markdown-it'
import DOMPurify from 'dompurify'

const markdown = new MarkdownIt({ html: false, linkify: false, typographer: false, breaks: true })
// Evidence and AI output are untrusted. Images must not make network requests; links remain plain labels.
markdown.renderer.rules.image = (tokens, index) => markdown.utils.escapeHtml(tokens[index].content)
markdown.renderer.rules.link_open = () => '<span>'
markdown.renderer.rules.link_close = () => '</span>'

export function renderAiReport(content: string): string {
    const wrapped = content.trim().match(/^\x60\x60\x60(?:markdown|md)\s*\r?\n([\s\S]*)\r?\n\x60\x60\x60$/i)
    return DOMPurify.sanitize(markdown.render(wrapped ? wrapped[1] : content), {
        ALLOWED_TAGS: [
            'h1',
            'h2',
            'h3',
            'h4',
            'h5',
            'h6',
            'p',
            'br',
            'strong',
            'em',
            's',
            'ul',
            'ol',
            'li',
            'blockquote',
            'pre',
            'code',
            'hr',
            'table',
            'thead',
            'tbody',
            'tr',
            'th',
            'td',
            'span',
        ],
        ALLOWED_ATTR: ['start'],
        ALLOW_DATA_ATTR: false,
        ALLOW_ARIA_ATTR: false,
    })
}
