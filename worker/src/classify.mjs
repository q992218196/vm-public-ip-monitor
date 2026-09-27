// Rules are explainable hints. A homepage is not a finding about an entire site.
const rules = [
  ['疑似博彩', ['在线博彩', '真人赌场', '体育投注', 'online casino']],
  ['疑似成人内容', ['成人视频', '成人视频', '色情视频', 'porn videos', 'adult videos']],
  ['管理后台', ['管理后台', '管理员登录', 'admin login', 'dashboard login', 'phpmyadmin']],
  ['电商', ['购物车', '加入购物车', 'add to cart', 'checkout']],
  ['论坛', ['论坛', '发帖', 'discourse', 'phpbb']],
  ['博客', ['博客', 'wordpress', 'posted on', 'blog']],
  ['API 服务', ['swagger ui', 'openapi', 'api documentation']],
  ['默认页／停放页', ['welcome to nginx', 'apache2 debian default', 'domain for sale', '域名出售']],
  ['下载站', ['下载中心', '软件下载', 'download center']],
  ['企业官网', ['关于我们', '联系我们', 'about us', 'our company']],
];
export function classify(title, text) {
  const hay = `${title}\n${text}`.toLowerCase();
  for (const [category, words] of rules) {
    const hits = words.filter(w => hay.includes(w));
    if (hits.length) return {category, classification: {method: 'keyword-rules-v1', confidence: Math.min(0.8, 0.45 + 0.1 * hits.length), reasons: hits.map(w => `页面包含：${w}`)}};
  }
  return {category: '未分类', classification: {method: 'keyword-rules-v1', confidence: 0, reasons: ['未命中规则；需要人工检查']}};
}
