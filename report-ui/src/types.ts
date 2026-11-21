// The JSON contract between the Python report builders and this UI.
//
// Python owns every count, label, and sentence; this UI only lays them out with
// Cloudscape components. The producers are `build_report_data()` in
// report_template.py (kind "assessment") and `changes_page_data()` in
// assessment_history/render_changes.py (kind "changes").

/** Trusted rich text: plain strings, bold runs, and HTTPS links. */
export type RichSegment = string | { strong: Rich } | { link: string; href: string };
export type Rich = RichSegment[];

export type Tone = 'error' | 'warning' | 'success' | 'info' | 'neutral';

export interface Metric {
  label: string;
  value: string;
  description: string;
  tone: Tone;
}

export interface NavGroup {
  heading: string;
  areas: string[];
}

export interface Area {
  slug: string;
  name: string;
  icon: string | null;
  selected: boolean;
  total: number;
  failed: number;
  passed: number;
  na: number;
  countText: string;
  cardStatus: string;
  sectionTitle: string;
  scope: Rich | null;
}

export interface Finding {
  account: string;
  region: string;
  checkId: string;
  finding: string;
  details: string;
  resolution: string;
  reference: string | null;
  severity: string;
  status: string;
  service: string;
}

export interface RiskCard {
  label: string;
  total: number;
  high: number;
  medium: number;
  low: number;
}

export interface SeverityRate {
  key: string;
  label: string;
  passRate: number;
  passRateText: string;
  description: string;
}

export interface ScopeChip {
  label: string;
  icon: string | null;
  selected: boolean;
}

export interface Option {
  value: string;
  label: string;
}

export interface AssessmentReport {
  kind: 'assessment';
  mode: 'single' | 'multi';
  title: string;
  subtitle: string;
  heading: string;
  timestamp: string;
  generated: string;
  accountInfo: string;
  headerAccountInfo: string;
  githubUrl: string;
  selectionNotice: { notSelected: string[]; text: string } | null;
  overview: Metric[];
  alerts: { count: number; finding: string; area: string; level: 'high' | 'medium' }[];
  severityLegend: { severity: string; meaning: string; action: Rich }[];
  risk: {
    severity: SeverityRate[];
    overall: SeverityRate;
    accounts: RiskCard[] | null;
    regions: RiskCard[] | null;
  };
  areas: Area[];
  navGroups: NavGroup[];
  filters: {
    accounts: string[] | null;
    regions: string[] | null;
    areas: Option[];
    severities: Option[];
    statuses: Option[];
    defaultStatus: string;
  };
  findings: Finding[];
  methodology: {
    notes: Rich;
    scopeGroups: { label: string | null; chips: ScopeChip[] }[];
    source: Rich;
  };
  footer: Rich;
}

export interface ChangeRow {
  account: string;
  region: string;
  checkId: string;
  finding: string;
  severity: string;
  service: string;
  change: string;
  changeSlug: string;
  rank: number;
  tone: Tone;
  statuses: string;
  details: { label: string; text: string }[];
  resolution: string;
  reference: string | null;
}

export interface ChangesReport {
  kind: 'changes';
  title: string;
  heading: string;
  subtitle: string;
  accountId: string;
  generated: string;
  meta: string[];
  mainReport: string | null;
  /** Null when the changes CSV isn't published beside the page (the sample). */
  csvName: string | null;
  sameFolderNote: string;
  githubUrl: string;
  tiles: { label: string; value: string; description: string; tone: Tone }[];
  tileNote: string;
  notes: string[];
  changedCount: number;
  navGroups: { heading: string; areas: { slug: string; name: string; icon: string | null; count: string }[] }[];
  areaTable: {
    columns: string[];
    rows: { type: 'group' | 'area' | 'total'; label: string; counts: number[] | null; note: string | null }[];
  };
  rows: ChangeRow[];
  filters: {
    regions: Option[];
    areas: Option[];
    severities: Option[];
    changes: Option[];
    defaultChange: string;
  };
  methodology: {
    states: { change: string; tone: Tone; meaning: string }[];
    matching: string[];
    previousRun: string;
  };
  footer: Rich;
}

export type ReportData = AssessmentReport | ChangesReport;
