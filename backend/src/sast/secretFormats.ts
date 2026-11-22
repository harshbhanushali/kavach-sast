/**
 * Credentials that announce themselves.
 *
 * Many services issue tokens with a fixed prefix and length (`npm_` and 36
 * characters, `glpat-` and 20, and so on). That shape is public, documented by
 * the issuers, and it is what makes a leaked token findable without guessing at
 * variable names. The patterns here are written from the formats the issuers
 * document. A format fixed by its issuer (PyPI, RubyGems, age, Braintree and a
 * few more) gives the same pattern whoever writes it, so some are identical to gitleaks' (MIT, credited in
 * NOTICE). They are limited to ones distinctive enough to be reported without a surrounding
 * keyword.
 *
 * Each entry becomes one rule. The text is shared deliberately: a leaked
 * credential has the same consequence whoever issued it (anyone who unzips the
 * app can use it), and the useful part of the report is which service and where.
 *
 * Where a format is only a reliable signal next to a keyword (a bare 32-hex
 * string, say), it does not belong here; that is the entropy and keyword pass in
 * `entropy.ts`.
 */
import type { PatternRule } from './rules.ts';
import type { SastSeverity } from './types.ts';

type Format = {
  /** Rule id suffix: `secret.<id>`. */
  id: string;
  service: string;
  /** What the credential grants, in a few words, for the impact sentence. */
  grants: string;
  pattern?: RegExp;
  /** Every pattern in one file, for credentials whose shape spans lines. */
  allOf?: RegExp[];
  severity?: SastSeverity;
};

/**
 * Obvious stand-ins. A documentation example or a template is not a leak, and
 * reporting it teaches readers to ignore the rule.
 */
const PLACEHOLDER = /(\$\{|@string\/|R\.string\.|x{6,}|placeholder|example|changeme|your[_-]|<[a-z_ -]+>|TODO|REPLACE|0{10,})/i;

export const SECRET_FORMATS: Format[] = [
  // --- source control and package registries ---
  { id: 'gitlab_token', service: 'GitLab', grants: 'access to repositories, pipelines and the API', severity: 'critical',
    pattern: /\bgl(?:pat|dt|rt|ptt|ft|imt|agent|soat|cbt)-[A-Za-z0-9_-]{20,}/ },
  { id: 'github_fine_grained', service: 'GitHub fine-grained token', grants: 'access to the repositories it was issued for', severity: 'critical',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{50,}/ },
  { id: 'npm_token', service: 'npm', grants: 'publishing packages as the owner', severity: 'critical',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: 'npmrc_auth_token', service: 'npm registry', grants: 'access to a package registry', severity: 'high',
    pattern: /_authToken\s*=\s*[A-Za-z0-9_-]{20,}/ },
  { id: 'pypi_token', service: 'PyPI', grants: 'uploading packages as the owner', severity: 'critical',
    pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/ },
  { id: 'rubygems_token', service: 'RubyGems', grants: 'publishing gems as the owner', severity: 'critical',
    pattern: /\brubygems_[a-f0-9]{48}\b/ },

  // --- cloud and infrastructure ---
  { id: 'gcp_oauth_token', service: 'Google OAuth access token', grants: 'whatever Google APIs the signed-in account can reach', severity: 'high',
    pattern: /\bya29\.[A-Za-z0-9_-]{50,}/ },
  { id: 'gcp_service_account', service: 'Google service account key', grants: 'the full permissions of a Google Cloud service account', severity: 'critical',
    allOf: [/"type"\s*:\s*"service_account"/, /"private_key"\s*:/] },
  { id: 'azure_storage_key', service: 'Azure storage account key', grants: 'full control of an Azure storage account', severity: 'critical',
    pattern: /AccountKey=[A-Za-z0-9+/]{86}==/ },
  { id: 'azure_sas_token', service: 'Azure shared access signature', grants: 'access to Azure storage for as long as the signature is valid', severity: 'high',
    pattern: /\bsv=\d{4}-\d{2}-\d{2}&[^"'\s]*\bsig=[A-Za-z0-9%+/]{40,}/ },
  { id: 'digitalocean_token', service: 'DigitalOcean', grants: 'control of DigitalOcean resources', severity: 'critical',
    pattern: /\bdo[por]_v1_[a-f0-9]{64}\b/ },
  { id: 'heroku_token', service: 'Heroku', grants: 'control of Heroku apps and data', severity: 'critical',
    pattern: /\bHRKU-[A-Za-z0-9_-]{60}\b/ },
  { id: 'vault_token', service: 'HashiCorp Vault', grants: 'access to whatever secrets the token’s policy allows', severity: 'critical',
    pattern: /\bhv[sb]\.[A-Za-z0-9_-]{24,}/ },
  { id: 'doppler_token', service: 'Doppler', grants: 'reading a project’s secrets', severity: 'critical',
    pattern: /\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b/ },
  { id: 'pulumi_token', service: 'Pulumi', grants: 'managing cloud infrastructure', severity: 'critical',
    pattern: /\bpul-[a-f0-9]{40}\b/ },
  { id: 'databricks_token', service: 'Databricks', grants: 'access to a Databricks workspace', severity: 'critical',
    pattern: /\bdapi[a-f0-9]{32}\b/ },
  { id: 'age_secret_key', service: 'age', grants: 'decrypting anything encrypted to the matching public key', severity: 'critical',
    pattern: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/ },
  { id: 'cloudinary_url', service: 'Cloudinary', grants: 'managing a Cloudinary account’s media', severity: 'high',
    pattern: /\bcloudinary:\/\/\d{6,}:[A-Za-z0-9_-]{10,}@[\w-]+/ },

  // --- payments ---
  { id: 'square_token', service: 'Square', grants: 'taking payments and reading customer data', severity: 'critical',
    pattern: /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}\b|\bEAAA[A-Za-z0-9_-]{60}\b/ },
  { id: 'shopify_token', service: 'Shopify', grants: 'access to a shop’s orders and customers', severity: 'high',
    pattern: /\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b/ },
  { id: 'braintree_token', service: 'Braintree', grants: 'processing payments', severity: 'critical',
    pattern: /\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b/ },
  { id: 'plaid_token', service: 'Plaid', grants: 'reading a user’s linked bank data', severity: 'critical',
    pattern: /\baccess-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/ },
  { id: 'razorpay_live_key', service: 'Razorpay live key', grants: 'creating payment orders (the matching secret completes the access)', severity: 'high',
    pattern: /\brzp_live_[A-Za-z0-9]{14,}\b/ },
  { id: 'stripe_webhook_secret', service: 'Stripe webhook signing secret', grants: 'forging webhook events the backend trusts', severity: 'high',
    pattern: /\bwhsec_[A-Za-z0-9]{32,}\b/ },

  // --- messaging, mail, social ---
  { id: 'mailchimp_key', service: 'Mailchimp', grants: 'sending mail and reading subscriber lists', severity: 'high',
    pattern: /\b[0-9a-f]{32}-us\d{1,2}\b/ },
  { id: 'mailgun_key', service: 'Mailgun', grants: 'sending mail as the account', severity: 'high',
    pattern: /\bkey-[0-9a-f]{32}\b/ },
  { id: 'brevo_key', service: 'Brevo (Sendinblue)', grants: 'sending mail and reading contacts', severity: 'high',
    pattern: /\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b/ },
  { id: 'discord_bot_token', service: 'Discord bot', grants: 'acting as the bot in every server it is in', severity: 'high',
    pattern: /\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b/ },
  { id: 'telegram_bot_token', service: 'Telegram bot', grants: 'acting as the bot', severity: 'high',
    pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/ },
  { id: 'facebook_token', service: 'Facebook access token', grants: 'acting as the app or page it was issued to', severity: 'high',
    pattern: /\bEAA[A-Za-z0-9]{40,}\b/ },
  { id: 'twitter_bearer', service: 'Twitter/X bearer token', grants: 'calling the API as the app', severity: 'high',
    // 20-24 leading A's and then something else: a longer run is padding (zeroed bytes in base64), not a token.
    pattern: /\bA{20,24}(?!A)[A-Za-z0-9%]{30,}/ },
  { id: 'onesignal_key', service: 'OneSignal', grants: 'sending push notifications to every user', severity: 'high',
    pattern: /\bos_v2_(?:app|org)_[a-z0-9]{70,}\b/ },

  // --- developer and observability tools ---
  { id: 'postman_key', service: 'Postman', grants: 'access to collections and environments', severity: 'high',
    pattern: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/ },
  { id: 'linear_key', service: 'Linear', grants: 'access to a workspace’s issues', severity: 'high',
    pattern: /\blin_api_[A-Za-z0-9]{40}\b/ },
  { id: 'atlassian_token', service: 'Atlassian', grants: 'access to Jira and Confluence as the user', severity: 'high',
    pattern: /\bATATT3[A-Za-z0-9_=-]{100,}/ },
  { id: 'sentry_token', service: 'Sentry auth token', grants: 'reading and changing Sentry projects', severity: 'high',
    pattern: /\bsntry[su]_[A-Za-z0-9+/=_-]{40,}/ },
  { id: 'grafana_token', service: 'Grafana', grants: 'access to a Grafana instance', severity: 'high',
    pattern: /\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b/ },
  { id: 'newrelic_key', service: 'New Relic', grants: 'reading telemetry and managing the account', severity: 'high',
    pattern: /\bNRAK-[A-Z0-9]{27}\b/ },
  { id: 'dropbox_token', service: 'Dropbox', grants: 'access to a Dropbox account’s files', severity: 'high',
    pattern: /\bsl\.[A-Za-z0-9_-]{130,}/ },
  { id: 'notion_token', service: 'Notion', grants: 'access to the pages the integration can see', severity: 'high',
    pattern: /\b(?:ntn|secret)_[A-Za-z0-9]{43}\b/ },
  { id: 'mapbox_secret_token', service: 'Mapbox secret token', grants: 'managing a Mapbox account (public pk. tokens are fine in an app)', severity: 'high',
    pattern: /\bsk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/ },
  { id: 'supabase_token', service: 'Supabase access token', grants: 'managing Supabase projects', severity: 'critical',
    pattern: /\bsbp_[a-f0-9]{40}\b/ },

  // --- AI services ---
  { id: 'huggingface_token', service: 'Hugging Face', grants: 'access to models and datasets', severity: 'high',
    pattern: /\bhf_[A-Za-z0-9]{34}\b/ },
  { id: 'replicate_token', service: 'Replicate', grants: 'running models on the owner’s account', severity: 'high',
    pattern: /\br8_[A-Za-z0-9]{37}\b/ },
  { id: 'groq_key', service: 'Groq', grants: 'API use billed to the owner', severity: 'high',
    pattern: /\bgsk_[A-Za-z0-9]{52}\b/ },
  { id: 'perplexity_key', service: 'Perplexity', grants: 'API use billed to the owner', severity: 'high',
    pattern: /\bpplx-[A-Za-z0-9]{48}\b/ },

  // --- not tied to a service ---
  { id: 'url_credentials', service: 'A username and password inside a URL', grants: 'whatever the URL’s service allows that account to do', severity: 'high',
    // user:password@host in any scheme (the database schemes have a stricter rule of their own).
    // The password must look chosen: a template slot, a single repeated character or a
    // well-known stand-in is not reported.
    pattern: /\b(?:https?|ftps?|sftp|ssh|wss?|smtps?|imaps?|ldaps?):\/\/[^\s:@\/"'<>{}$%]{2,64}:(?![^\s@\/"']*(?:pass(?:word)?|user|xxx|\*{3}|\.\.\.))[^\s:@\/"'<>{}$%]{4,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/ },
];

const shared = {
  impact:
    'The credential ships inside the app, so anyone who unzips it can use it, and it stays valid until it is revoked, ' +
    'which an app update cannot do for the copies already installed.',
  remediation:
    'Revoke it now, then move whatever it protected behind your own backend, which holds the credential and decides what a ' +
    'signed-in user may do. Do not replace it with another value in the app: the next one is exposed the same way.',
};

/** One pattern rule per format, ready to join the main rule set. */
export function secretFormatRules(): PatternRule[] {
  return SECRET_FORMATS.map((f) => ({
    id: `secret.${f.id}`,
    title: `${f.service} credential in the app`,
    category: 'secrets',
    severity: f.severity ?? 'high',
    description: `A ${f.service} credential is embedded in the app, and it grants ${f.grants}.`,
    impact: shared.impact,
    remediation: shared.remediation,
    masvs: 'MASVS-STORAGE-1',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    ...(f.pattern ? { pattern: f.pattern } : {}),
    ...(f.allOf ? { allOf: f.allOf } : {}),
    unless: PLACEHOLDER,
  }));
}
