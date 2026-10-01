// Reports describe visible page evidence and leave business authorization to review.
const reviewRules = [
  ['疑似博彩', ['在线博彩', '真人赌场', '体育投注', '百家乐', '老虎机', 'online casino', 'sports betting']],
  ['疑似成人内容', ['成人视频', '色情视频', '成人直播', 'porn video', 'adult video', 'live sex']],
  ['疑似诈骗引流', ['刷单返佣', '稳赚不赔', '保本高收益', '先交保证金', 'guaranteed returns']],
  ['支付平台线索', ['支付平台', '在线支付服务', '第三方支付', '支付网关', '电子钱包', 'payment gateway', 'payment platform', 'digital wallet']],
  ['贷款平台线索', ['贷款平台', '在线贷款', '网络借贷', '借款申请', '贷款申请', 'loan application', 'online lending', 'personal loans']],
];
const siteRules = [
  ['影视聚合／在线播放', ['影视在线观看', '免费影视', '电影电视剧', '在线播放', '影视资源', '动漫综艺', 'watch movies']],
  ['管理后台', ['管理后台', '管理员登录', 'admin login', 'dashboard login', 'phpmyadmin']],
  ['电商', ['购物车', '加入购物车', 'add to cart', 'checkout']],
  ['论坛', ['论坛', '发帖', 'discourse', 'phpbb']],
  ['博客', ['博客', 'wordpress', 'posted on', 'blog']],
  ['API 服务', ['swagger ui', 'openapi', 'api documentation']],
  ['默认页／停放页', ['welcome to nginx', 'apache2 debian default', 'domain for sale', '域名出售']],
  ['下载站', ['下载中心', '软件下载', 'download center']],
  ['企业官网', ['关于我们', '联系我们', 'about us', 'our company']],
];
const sourceLabels = {title: '标题', description: '网站描述', body: '首页正文'};
const explanations = {
  '疑似博彩': '页面出现博彩相关服务线索，需要核实实际服务及经营资质。',
  '疑似成人内容': '页面出现成人内容相关线索，需要结合截图和实际内容复核。',
  '疑似诈骗引流': '页面出现高收益承诺或预付费用等引流线索，需要核实业务真实性。',
  '支付平台线索': '页面宣传支付或钱包服务，需要核实业务用途、运营主体及相关资质。',
  '贷款平台线索': '页面宣传借贷服务，需要核实运营主体、服务方式及相关资质。',
  '影视授权待核实': '页面同时出现影视服务与免费或资源版本线索，需要核实内容授权；公开首页无法证明版权归属。',
};
function matches(sources, words) {
  const evidence = [];
  for (const [source, value] of Object.entries(sources)) {
    const hay = value.toLowerCase();
    for (const word of words) {
      const index = hay.indexOf(word.toLowerCase());
      if (index < 0) continue;
      const start = Math.max(0, index - 55);
      evidence.push({source, keyword: word, excerpt: value.slice(start, Math.min(value.length, index + word.length + 110))});
      if (evidence.length === 12) return evidence;
    }
  }
  return evidence;
}
export function classify(title, text, context = {}) {
  const sources = {
    title: String(title || '').replace(/\s+/g, ' ').trim().slice(0, 255),
    description: String(context.description || '').replace(/\s+/g, ' ').trim().slice(0, 1024),
    body: String(text || '').replace(/\s+/g, ' ').trim().slice(0, 64000),
  };
  const business = siteRules.map(([category, words]) => ({category, evidence: matches(sources, words)})).find(item => item.evidence.length);
  const findings = reviewRules.map(([category, words]) => ({category, evidence: matches(sources, words)})).filter(item => item.evidence.length);
  if (business?.category === '影视聚合／在线播放') {
    const evidence = matches(sources, ['免费影视', '免费在线观看', 'TC资源', 'TC版本', '抢先版', '伦理电影', '伦理片']);
    if (evidence.length) findings.push({category: '影视授权待核实', evidence});
  }
  const primary = findings[0] || business;
  const category = primary?.category || '未分类';
  const evidence = (primary?.evidence || []).slice(0, 12);
  const review = findings.length > 0;
  const summary = [
    sources.title ? `页面标题为“${sources.title}”。` : '页面未提供标题。',
    business ? `可见内容具有“${business.category}”站点特征。` : '当前首页内容不足以明确业务类型。',
    ...findings.slice(0, 5).map(item => explanations[item.category]),
    !review && business ? '当前规则未命中需要复核的内容线索。' : '',
    '结论仅基于本次公开首页观察，需结合业务说明进行人工复核。',
  ].filter(Boolean).join('');
  return {category, classification: {
    method: 'keyword-rules-v3',
    confidence: primary ? Math.min(0.78, 0.5 + 0.08 * new Set(evidence.map(item => item.keyword)).size) : 0,
    review_required: review,
    risk_level: review ? 'medium' : 'unknown',
    business_type: business?.category || '未分类',
    nature: review ? '待人工核实' : '未发现规则命中',
    summary: summary.slice(0, 1800),
    findings: findings.slice(0, 5).map(item => ({category: item.category, explanation: explanations[item.category], evidence: item.evidence.slice(0, 4)})),
    evidence,
    reasons: evidence.length ? evidence.map(item => `${sourceLabels[item.source]}命中：${item.keyword}`).slice(0, 12) : ['首页文本未命中规则'],
    limitations: ['仅本次公开首页，未登录、未提交表单', '第三方资源及跨站跳转默认阻止', '文本规则不确认违法性质、主体资质或内容授权'],
  }};
}
