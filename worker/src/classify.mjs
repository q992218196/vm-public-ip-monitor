// These labels are review hints from one rendered page, never legal findings.
const reviewRules = [
  ['疑似博彩', ['在线博彩', '真人赌场', '体育投注', '百家乐', '老虎机', 'online casino', 'sports betting']],
  ['疑似成人内容', ['成人视频', '色情视频', '成人直播', 'porn video', 'adult video', 'live sex']],
  ['疑似诈骗引流', ['刷单返佣', '稳赚不赔', '保本高收益', '先交保证金', 'guaranteed returns']],
  ['支付平台线索', ['支付平台', '在线支付服务', '第三方支付', '支付网关', '电子钱包', 'payment gateway', 'payment platform', 'digital wallet']],
  ['贷款平台线索', ['贷款平台', '在线贷款', '网络借贷', '借款申请', '贷款申请', 'loan application', 'online lending', 'personal loans']],
];
const siteRules = [
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
  for (const [category, words] of reviewRules) {
    const hits = words.filter(word => hay.includes(word));
    if (hits.length) return {category, classification: {method: 'keyword-rules-v2', confidence: Math.min(0.78, 0.55 + 0.08 * hits.length), review_required: true, reasons: hits.map(word => `首页文本命中：${word}`)}};
  }
  for (const [category, words] of siteRules) {
    const hits = words.filter(word => hay.includes(word));
    if (hits.length) return {category, classification: {method: 'keyword-rules-v2', confidence: Math.min(0.8, 0.5 + 0.08 * hits.length), review_required: false, reasons: hits.map(word => `首页文本命中：${word}`)}};
  }
  return {category: '未分类', classification: {method: 'keyword-rules-v2', confidence: 0, review_required: false, reasons: ['首页文本未命中规则']}};
}
