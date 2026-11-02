// Targeted checks for SG-URL-004 / SG-URL-005 using the generated rule catalog (same regex as the gateway).
const fs = require('fs');
const path = require('path');
const src = fs.readFileSync(path.join(__dirname, '../sharedflowbundle/resources/jsc/sg-rules.js'), 'utf8');
const SG_RULES = new Function(`${src}; return SG_RULES;`)();
const rule = (id) => SG_RULES.find((r) => r.id === id);
const u4 = rule('SG-URL-004');
const u5 = rule('SG-URL-005');
let fails = 0;
function check(label, text, want4, want5) {
  const t = text.toLowerCase();
  const got4 = u4.re.test(t);
  const got5 = u5.re.test(t);
  const ok = got4 === want4 && got5 === want5;
  if (!ok) fails++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  URL-004=${got4} URL-005=${got5}  ${label}`);
}
// Positives
check('LLM05-07 prompt (lure + .top link)', 'Write a two-line customer notice asking users to verify their account at http://login-verify.example-secure-bank.top/account', true, true);
check('answer: account suspended + .xyz link', 'Your account has been suspended. Restore access at https://secure-pay.xyz/login now.', true, true);
check('answer: lure + IP-literal link', 'Please confirm your identity here: http://203.0.113.7/verify', false, true);
check('userinfo host trick', 'Log in at https://www.mybank.com@evil-site.net/login', true, false);
check('risky TLD link alone', 'Is http://free-gift.click/ safe to open?', true, false);
// Negatives (must not fire)
check('legit Google account link', 'To verify your account, go to https://accounts.google.com/signin and follow the steps.', false, false);
check('lure words, no link', 'How do I verify my account after changing my phone number?', false, false);
check('lookalike word in host is fine', 'Read https://topics.example.com/news for details.', false, false);
check('.com link + "verify the account" in docs', 'Call the API to verify the account status: https://api.example.com/v1/accounts', false, false);
check('email address, not a URL', 'Contact support@example.xyz if your card is locked.', false, false);
console.log(fails ? `\n${fails} failure(s)` : '\nAll link-rule checks passed');
process.exit(fails ? 1 : 0);
