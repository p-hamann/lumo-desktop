import EXPERIMENTAL_CONNECTOR_PRESETS from './experimental-connector-presets.json';

/**
 * Public description of the connectors this app knows how to set up.
 *
 * Shared by the settings page and the connector bridge, so the web app sees the same
 * categories the settings page groups by. Holds display data only: anything needed to
 * authorize a connector (scopes, client ids, secrets, headers) stays in the settings page and
 * must never be added here, because the bridge hands this catalog to the Lumo web app.
 */

export type ConnectorCategoryId =
  | 'device'
  | 'communication'
  | 'files'
  | 'work'
  | 'sales'
  | 'finance'
  | 'support'
  | 'recruiting'
  | 'observability'
  | 'data'
  | 'developer'
  | 'compliance'
  | 'research'
  | 'home'
  | 'custom';

export interface ConnectorCategory {
  id: ConnectorCategoryId;
  label: string;
}

export interface ConnectorCatalogEntry {
  /** Manifest id the connector registers under once added. */
  id: string;
  /** MCP server id, for entries backed by an MCP server. */
  server_id?: string;
  category: ConnectorCategoryId;
  icon: string;
  iconSrc: string;
  name: string;
  description: string;
  /** Endpoint of an HTTP MCP server. */
  url?: string;
}

export const CONNECTOR_CATEGORIES: ConnectorCategory[] = [
  { id: 'device', label: 'This device' },
  { id: 'communication', label: 'Communication' },
  { id: 'files', label: 'Files & storage' },
  { id: 'work', label: 'Work & projects' },
  { id: 'sales', label: 'Sales & CRM' },
  { id: 'finance', label: 'Finance' },
  { id: 'support', label: 'Support' },
  { id: 'recruiting', label: 'Recruiting' },
  { id: 'observability', label: 'Observability' },
  { id: 'data', label: 'Data & analytics' },
  { id: 'developer', label: 'Developer tools' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'research', label: 'Research' },
  { id: 'home', label: 'Home & entertainment' },
  { id: 'custom', label: 'Custom' },
];

export const BUILTIN_CONNECTORS: ConnectorCatalogEntry[] = [
  {
    id: 'filesystem',
    category: 'device',
    icon: '📁',
    iconSrc: 'images/connectors/filesystem.svg',
    name: 'Filesystem',
    description: 'Search and read files in folders you allow on this device.',
  },
  {
    id: 'bash',
    category: 'device',
    icon: '⌨️',
    iconSrc: 'images/connectors/bash.svg',
    name: 'Shell',
    description: 'Run shell commands inside folders you allow on this device.',
  },
  {
    id: 'proton_mail',
    category: 'communication',
    icon: '✉️',
    iconSrc: 'images/connectors/proton-mail.svg',
    name: 'Proton Mail',
    description: 'Search, read, sort, and send encrypted email through Proton Mail Bridge.',
  },
  {
    id: 'luminance',
    category: 'work',
    icon: '⚖️',
    iconSrc: 'images/connectors/luminance.svg',
    name: 'Luminance',
    description:
      'Search and manage contracts, matters, documents, and annotations in your Luminance instance.',
  },
];

export const FEATURED_MCP_SERVERS: ConnectorCatalogEntry[] = [
  {
    id: 'mcp-chrome-devtools',
    server_id: 'chrome-devtools',
    category: 'developer',
    icon: '🧭',
    iconSrc: 'images/connectors/chrome-devtools.svg',
    name: 'Chrome DevTools',
    description:
      'Let Lumo control and inspect a live Chrome browser. Requires Chrome stable, Node.js, and npm installed on your system.',
  },
  {
    id: 'mcp-slack',
    server_id: 'slack',
    category: 'communication',
    icon: '💬',
    iconSrc: 'images/connectors/slack.svg',
    name: 'Slack',
    description: 'Search messages, read channels, and post to Slack.',
    url: 'https://mcp.slack.com/mcp',
  },
  {
    id: 'mcp-atlassian',
    server_id: 'atlassian',
    category: 'work',
    icon: '📄',
    iconSrc: 'images/connectors/atlassian.svg',
    name: 'Atlassian Rovo',
    description: 'Search, read, and manage Atlassian (Jira & Confluence) content.',
    url: 'https://mcp.atlassian.com/v2/mcp',
  },
  {
    id: 'mcp-dropbox',
    server_id: 'dropbox',
    category: 'files',
    icon: '📦',
    iconSrc: 'images/connectors/dropbox.svg',
    name: 'Dropbox',
    description: 'Browse, search, and read your Dropbox files.',
    url: 'https://mcp.dropbox.com/mcp',
  },
  {
    id: 'mcp-google-drive',
    server_id: 'google-drive',
    category: 'files',
    icon: '📁',
    iconSrc: 'images/connectors/google-drive.svg',
    name: 'Google Drive',
    description: 'Search and read files in your Google Drive.',
    url: 'https://drivemcp.googleapis.com/mcp/v1',
  },
  {
    id: 'mcp-polixis',
    server_id: 'polixis',
    category: 'compliance',
    icon: '🔗',
    iconSrc: 'images/connectors/polixis.svg',
    name: 'Polixis',
    description: 'Risk intelligence and screening via Polixis.',
    url: 'https://api-polixis.polixis.com/mcp',
  },
  {
    id: 'mcp-greenhouse',
    server_id: 'greenhouse',
    category: 'recruiting',
    icon: '🌱',
    iconSrc: 'images/connectors/greenhouse.svg',
    name: 'Greenhouse',
    description: 'Search candidates, jobs, and recruiting data in Greenhouse.',
    url: 'https://mcp.greenhouse.io/mcp',
  },
  {
    id: 'mcp-figma',
    server_id: 'figma',
    category: 'work',
    icon: '🎨',
    iconSrc: 'images/connectors/figma.svg',
    name: 'Figma',
    description:
      'Design context from Figma files—frames, components, and Dev Mode metadata for code generation.',
    url: 'http://127.0.0.1:3845/mcp',
  },
  {
    id: 'mcp-zendesk',
    server_id: 'zendesk',
    category: 'support',
    icon: '🎫',
    iconSrc: 'images/connectors/zendesk.svg',
    name: 'Zendesk',
    description:
      'Search tickets and Help Center articles using your own Zendesk permissions (Support & Guide APIs).',
  },
  {
    id: 'mcp-grafana',
    server_id: 'grafana',
    category: 'observability',
    icon: '📊',
    iconSrc: 'images/connectors/grafana.svg',
    name: 'Grafana',
    description:
      'Query metrics, logs, dashboards, and alerts in Grafana Cloud or any Grafana instance.',
    url: 'https://mcp.grafana.com/mcp',
  },
  {
    id: 'mcp-linear',
    server_id: 'linear',
    category: 'work',
    icon: '📐',
    iconSrc: 'images/connectors/linear-logo.svg',
    name: 'Linear',
    description: 'Find, create, and update Linear issues, projects, and comments.',
    url: 'https://mcp.linear.app/mcp',
  },
  {
    id: 'mcp-granola',
    server_id: 'granola',
    category: 'work',
    icon: '📝',
    iconSrc: 'images/connectors/granola-ai.svg',
    name: 'Granola',
    description: 'Search and read your Granola meeting notes and transcripts.',
    url: 'https://mcp.granola.ai/mcp',
  },
  {
    id: 'mcp-wispr-flow',
    server_id: 'wispr-flow',
    category: 'work',
    icon: '🎙️',
    iconSrc: 'images/connectors/wispr-flow.svg',
    name: 'Wispr Flow',
    description: 'Find meeting notes, transcripts, and calendar context from Wispr Flow.',
    url: 'https://api.wisprflow.ai/connect/mcp',
  },
  {
    id: 'mcp-brandfetch',
    server_id: 'brandfetch',
    category: 'work',
    icon: '🏷️',
    iconSrc: 'images/connectors/brandfetch.svg',
    name: 'Brandfetch',
    description: 'Search brands and get their logos, colors, fonts, and company data.',
    url: 'https://mcp.brandfetch.io/mcp',
  },
  {
    id: 'mcp-asana',
    server_id: 'asana',
    category: 'work',
    icon: '✅',
    iconSrc: 'images/connectors/asana-logo.svg',
    name: 'Asana',
    description: 'Search and manage Asana tasks and projects, using an Asana MCP app of your own.',
    url: 'https://mcp.asana.com/v2/mcp',
  },
  {
    id: 'mcp-github',
    server_id: 'github',
    category: 'developer',
    icon: '🐙',
    iconSrc: 'images/connectors/github-logo.svg',
    name: 'GitHub',
    description:
      'Work with repositories, issues, pull requests, and Actions, signed in with a personal access token.',
    url: 'https://api.githubcopilot.com/mcp/',
  },
  {
    id: 'mcp-pagerduty',
    server_id: 'pagerduty',
    category: 'observability',
    icon: '🚨',
    iconSrc: 'images/connectors/pagerduty-logo.svg',
    name: 'PagerDuty',
    description: 'Look up incidents, services, schedules, and on-call, signed in with an API token.',
    url: 'https://mcp.pagerduty.com/mcp',
  },
  {
    id: 'mcp-datadog',
    server_id: 'datadog',
    category: 'observability',
    icon: '🐶',
    iconSrc: 'images/connectors/datadog-logo.svg',
    name: 'Datadog',
    description: 'Search logs, metrics, traces, monitors, and incidents in Datadog.',
    url: 'https://mcp.datadoghq.com/v1/mcp',
  },
  {
    id: 'mcp-snowflake',
    server_id: 'snowflake',
    category: 'data',
    icon: '❄️',
    iconSrc: 'images/connectors/snowflake-logo.svg',
    name: 'Snowflake',
    description:
      'Query your Snowflake data through a Snowflake-managed MCP server, signed in with a programmatic access token.',
  },
  {
    id: 'mcp-databricks',
    server_id: 'databricks',
    category: 'data',
    icon: '🧱',
    iconSrc: 'images/connectors/databricks-logo.svg',
    name: 'Databricks',
    description: 'Run SQL on your Databricks workspace, signed in with a personal access token.',
  },
  {
    id: 'mcp-bigquery',
    server_id: 'bigquery',
    category: 'data',
    icon: '📊',
    iconSrc: 'images/connectors/bigquery-logo.svg',
    name: 'BigQuery',
    description: 'Explore datasets and run queries in BigQuery with your Google account.',
    url: 'https://bigquery.googleapis.com/mcp',
  },
  {
    id: 'mcp-salesforce',
    server_id: 'salesforce',
    category: 'sales',
    icon: '☁️',
    iconSrc: 'images/connectors/salesforce.svg',
    name: 'Salesforce',
    description:
      'Read and update Salesforce records through a Salesforce Hosted MCP server, using an External Client App of your own.',
  },
  {
    id: 'mcp-stripe',
    server_id: 'stripe',
    category: 'finance',
    icon: '💳',
    iconSrc: 'images/connectors/stripe.svg',
    name: 'Stripe',
    description: 'Look up customers, payments, invoices, and subscriptions in your Stripe account.',
    url: 'https://mcp.stripe.com',
  },
  {
    id: 'mcp-alpha-vantage',
    server_id: 'alpha-vantage',
    category: 'finance',
    icon: '📈',
    iconSrc: 'images/connectors/alphavantage.svg',
    name: 'Alpha Vantage',
    description: 'Get stock, forex, crypto, and economic market data from Alpha Vantage.',
    url: 'https://mcp.alphavantage.co/mcp',
  },
  {
    id: 'mcp-tavily',
    server_id: 'tavily',
    category: 'research',
    icon: '🔎',
    iconSrc: 'images/connectors/tavily.svg',
    name: 'Tavily',
    description: 'Search the web, and extract, crawl, and map pages with Tavily.',
    url: 'https://mcp.tavily.com/mcp',
  },
  {
    id: 'mcp-alphaxiv',
    server_id: 'alphaxiv',
    category: 'research',
    icon: '📄',
    iconSrc: 'images/connectors/alphaxiv.svg',
    name: 'alphaXiv',
    description: 'Search arXiv papers and read their discussions and summaries on alphaXiv.',
    url: 'https://api.alphaxiv.org/mcp/v1',
  },
  {
    id: 'mcp-papernexus',
    server_id: 'papernexus',
    category: 'research',
    icon: '🕸️',
    iconSrc: 'images/connectors/papernexus.svg',
    name: 'Paper Nexus',
    description: 'Explore research papers through their citation networks, and read your Paper Nexus library.',
    url: 'https://papernex.us/mcp',
  },
  {
    id: 'mcp-pubmed',
    server_id: 'pubmed',
    category: 'research',
    icon: '📚',
    iconSrc: 'images/connectors/pubmed.svg',
    name: 'PubMed',
    description: 'Search biomedical literature and read article metadata and abstracts from PubMed.',
    url: 'https://pubmed.mcp.claude.com/mcp',
  },
  {
    id: 'mcp-biorxiv',
    server_id: 'biorxiv',
    category: 'research',
    icon: '🧬',
    iconSrc: 'images/connectors/biorxiv.svg',
    name: 'bioRxiv',
    description: 'Search and read bioRxiv and medRxiv preprints in the life and health sciences.',
    url: 'https://hcls.mcp.claude.com/biorxiv/mcp',
  },
  {
    id: 'mcp-clinical-trials',
    server_id: 'clinical-trials',
    category: 'research',
    icon: '🩺',
    iconSrc: 'images/connectors/clinicaltrials.svg',
    name: 'Clinical Trials',
    description: 'Search and read study records from the ClinicalTrials.gov registry.',
    url: 'https://hcls.mcp.claude.com/clinical_trials/mcp',
  },
  {
    id: 'mcp-chembl',
    server_id: 'chembl',
    category: 'research',
    icon: '⚗️',
    iconSrc: 'images/connectors/chembl.svg',
    name: 'ChEMBL',
    description: 'Look up bioactive molecules, drug targets, and assay data in ChEMBL.',
    url: 'https://hcls.mcp.claude.com/chembl/mcp',
  },
  {
    id: 'mcp-open-targets',
    server_id: 'open-targets',
    category: 'research',
    icon: '🎯',
    iconSrc: 'images/connectors/open-targets.svg',
    name: 'Open Targets',
    description: 'Explore target–disease associations and evidence for drug target discovery.',
    url: 'https://mcp.platform.opentargets.org/mcp',
  },
  {
    id: 'mcp-sonos',
    server_id: 'sonos',
    category: 'home',
    icon: '🔊',
    iconSrc: 'images/connectors/sonos.svg',
    name: 'Sonos',
    description:
      'Play music, set volume, and group or move audio between the speakers in your Sonos system.',
    url: 'https://mcp.ws.sonos.com/mcp',
  },
];

const CATALOG_BY_ID = new Map(
  [...BUILTIN_CONNECTORS, ...FEATURED_MCP_SERVERS].map((entry) => [entry.id, entry])
);

/** Connectors the user added themselves fall in `custom`. */
export const categoryOf = (id: string): ConnectorCategoryId =>
  CATALOG_BY_ID.get(id)?.category ?? 'custom';

/** Settings tab value that opens the connectors tab on one connector. */
export const SETTINGS_CONNECTOR_TAB_PREFIX = 'connectors/';

/** Experimental presets stay hidden unless the frontend flag is enabled. */
export const getFeaturedMcpServers = (experimentalConnectors: boolean): ConnectorCatalogEntry[] =>
  FEATURED_MCP_SERVERS.filter(
    (entry) => experimentalConnectors || !EXPERIMENTAL_CONNECTOR_PRESETS.includes(entry.server_id ?? '')
  );
