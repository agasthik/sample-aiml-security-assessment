import { useEffect, useMemo, useState } from 'react';
import { useCollection } from '@cloudscape-design/collection-hooks';
import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Cards from '@cloudscape-design/components/cards';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import Link from '@cloudscape-design/components/link';
import Pagination from '@cloudscape-design/components/pagination';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Select, { SelectProps } from '@cloudscape-design/components/select';
import { SideNavigationProps } from '@cloudscape-design/components/side-navigation';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table, { TableProps } from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';
import CollectionPreferences, { CollectionPreferencesProps } from '@cloudscape-design/components/collection-preferences';
import {
  Counter,
  DetailText,
  IconLabel,
  matchesText,
  MetaLine,
  Navigation,
  PageFooter,
  ReferenceLink,
  ReportShell,
  RichText,
  scrollToSection,
  SeverityBadge,
  StatusLabel,
  useActiveSection,
} from './common';
import { Area, AssessmentReport, Finding, Option, RiskCard } from './types';

const ALL = '';
const SEVERITY_RANK: Record<string, number> = { high: 0, medium: 1, low: 2 };
const STATUS_RANK: Record<string, number> = { failed: 0, passed: 1 };

interface Filters {
  account: string;
  region: string;
  area: string;
  severity: string;
  status: string;
}

function toSelectOption(value: string, options: Option[], allLabel: string): SelectProps.Option {
  if (value === ALL) return { value: ALL, label: allLabel };
  const match = options.find(option => option.value === value);
  return { value, label: match ? match.label : value };
}

function FilterSelect(props: {
  label: string;
  allLabel: string;
  value: string;
  options: Option[];
  onChange: (value: string) => void;
  testId: string;
}) {
  return (
    <div className="report-filter-select">
      <Select
        inlineLabelText={props.label}
        data-testid={props.testId}
        selectedOption={toSelectOption(props.value, props.options, props.allLabel)}
        options={[{ value: ALL, label: props.allLabel }, ...props.options]}
        onChange={({ detail }) => props.onChange(detail.selectedOption.value ?? ALL)}
      />
    </div>
  );
}

function FindingDetailsPanel({ item, data }: { item: Finding; data: AssessmentReport }) {
  const area = data.areas.find(candidate => candidate.slug === item.service);
  return (
    <SpaceBetween size="l">
      <KeyValuePairs
        columns={2}
        items={[
          { label: 'Severity', value: <SeverityBadge severity={item.severity} /> },
          { label: 'Status', value: <StatusLabel status={item.status} /> },
          { label: 'Check ID', value: <Box variant="code">{item.checkId || '-'}</Box> },
          { label: 'Assessment area', value: area ? <IconLabel icon={area.icon} size={16}>{area.name}</IconLabel> : item.service },
          { label: 'Account ID', value: <Box variant="code">{item.account || '-'}</Box> },
          { label: 'Region', value: <Box variant="code">{item.region || '-'}</Box> },
        ]}
      />
      <DetailText label="Details" text={item.details} />
      <DetailText label="Resolution" text={item.resolution} />
      <div>
        <Box variant="awsui-key-label">Reference</Box>
        <ReferenceLink href={item.reference} />
      </div>
    </SpaceBetween>
  );
}

const PAGE_SIZES = [25, 50, 100, 250].map(value => ({ value, label: `${value} findings` }));

function FindingsTable(props: {
  data: AssessmentReport;
  filters: Filters;
  setFilters: (filters: Filters) => void;
  defaults: Filters;
  selected: Finding | null;
  onSelect: (item: Finding | null) => void;
}) {
  const { data, filters, setFilters, defaults } = props;
  const rowKeys = useMemo(() => new Map(data.findings.map((item, index) => [item, String(index)])), [data.findings]);
  // Check, finding, severity and status come first so they stay in view when
  // the details panel narrows the table; readers can reorder or hide columns.
  const columnOrder = ['checkId', 'finding', 'severity', 'status', 'region', ...(data.mode === 'multi' ? ['account'] : [])];
  const [preferences, setPreferences] = useState<CollectionPreferencesProps.Preferences>({
    pageSize: 50,
    wrapLines: true,
    contentDisplay: columnOrder.map(id => ({ id, visible: true })),
  });

  const filtered = useMemo(
    () =>
      data.findings.filter(item => {
        if (filters.account && item.account !== filters.account) return false;
        if (filters.region && item.region.toLowerCase() !== filters.region.toLowerCase()) return false;
        if (filters.area && item.service !== filters.area) return false;
        if (filters.severity && item.severity.toLowerCase() !== filters.severity) return false;
        if (filters.status && item.status.toLowerCase() !== filters.status) return false;
        return true;
      }),
    [data.findings, filters]
  );

  const { items, collectionProps, filterProps, paginationProps, filteredItemsCount, actions } = useCollection(filtered, {
    filtering: {
      filteringFunction: (item, text) =>
        matchesText(
          [item.account, item.region, item.checkId, item.finding, item.details, item.resolution, item.severity, item.status],
          text
        ),
      empty: (
        <Box textAlign="center" color="inherit" padding="l">
          <b>No findings to display</b>
        </Box>
      ),
      noMatch: (
        <Box textAlign="center" color="inherit" padding="l">
          <SpaceBetween size="xs">
            <b>No matches</b>
            <Button onClick={() => reset()}>Reset filters</Button>
          </SpaceBetween>
        </Box>
      ),
    },
    pagination: { pageSize: preferences.pageSize },
    sorting: {},
  });

  // Any filter change, from this table or from an area section's buttons,
  // starts the results on their first page.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    actions.setCurrentPage(1);
  }, [filters]);

  function update(change: Partial<Filters>) {
    setFilters({ ...filters, ...change });
  }
  function reset() {
    setFilters(defaults);
    actions.setFiltering('');
    actions.setCurrentPage(1);
  }

  const columns: TableProps.ColumnDefinition<Finding>[] = [
    {
      id: 'account',
      header: 'Account ID',
      cell: item => <Box variant="code">{item.account}</Box>,
      sortingField: 'account',
      width: 150,
    },
    {
      id: 'region',
      header: 'Region',
      cell: item => <Box variant="code">{item.region}</Box>,
      sortingField: 'region',
      width: 140,
    },
    {
      id: 'checkId',
      header: 'Check ID',
      cell: item => <Box variant="code">{item.checkId}</Box>,
      sortingField: 'checkId',
      width: 110,
    },
    {
      id: 'finding',
      header: 'Finding',
      cell: item => item.finding,
      sortingComparator: (a, b) => a.finding.toLowerCase().localeCompare(b.finding.toLowerCase()),
      width: 320,
      minWidth: 200,
    },
    {
      id: 'severity',
      header: 'Severity',
      cell: item => <SeverityBadge severity={item.severity} />,
      sortingComparator: (a, b) =>
        (SEVERITY_RANK[a.severity.toLowerCase()] ?? 3) - (SEVERITY_RANK[b.severity.toLowerCase()] ?? 3),
      width: 130,
    },
    {
      id: 'status',
      header: 'Status',
      cell: item => <StatusLabel status={item.status} />,
      sortingComparator: (a, b) =>
        (STATUS_RANK[a.status.toLowerCase()] ?? 2) - (STATUS_RANK[b.status.toLowerCase()] ?? 2),
      width: 110,
    },
  ];
  const visibleColumns = columns.filter(column => data.mode === 'multi' || column.id !== 'account');

  const statusSuffix = filters.status ? ` · ${toSelectOption(filters.status, data.filters.statuses, '').label}` : '';
  return (
    <Table
      {...collectionProps}
      data-testid="findings-table"
      variant="container"
      items={items}
      columnDefinitions={visibleColumns}
      columnDisplay={preferences.contentDisplay}
      trackBy={item => rowKeys.get(item) ?? ''}
      selectionType="single"
      selectedItems={props.selected ? [props.selected] : []}
      onSelectionChange={({ detail }) => props.onSelect(detail.selectedItems[0] ?? null)}
      ariaLabels={{
        selectionGroupLabel: 'Finding selection',
        itemSelectionLabel: (_selection, item) => `Show details for ${item.checkId} ${item.finding}`,
        allItemsSelectionLabel: () => 'Select all',
      }}
      wrapLines={preferences.wrapLines}
      stripedRows={preferences.stripedRows}
      resizableColumns
      header={
        <Header
          variant="h2"
          counter={`(${filteredItemsCount ?? 0}/${data.findings.length})`}
          description={`Report rows matching the filters${statusSuffix}. Select a finding to see its details, resolution, and AWS reference.`}
          actions={
            <Button iconName="undo" onClick={reset}>
              Reset
            </Button>
          }
        >
          All Security Findings
        </Header>
      }
      filter={
        <div className="report-filter-bar">
          <div className="report-filter-search">
            <TextFilter
              {...filterProps}
              filteringPlaceholder="Search findings"
              filteringAriaLabel="Search findings"
              countText={`${filteredItemsCount ?? 0} matches`}
            />
          </div>
          {data.filters.accounts ? (
            <FilterSelect
              label="Account"
              allLabel="All Accounts"
              testId="filter-account"
              value={filters.account}
              options={data.filters.accounts.map(value => ({ value, label: value }))}
              onChange={account => update({ account })}
            />
          ) : null}
          {data.filters.regions ? (
            <FilterSelect
              label="Region"
              allLabel="All Regions"
              testId="filter-region"
              value={filters.region}
              options={data.filters.regions.map(value => ({ value, label: value }))}
              onChange={region => update({ region })}
            />
          ) : null}
          <FilterSelect
            label="Assessment Area"
            allLabel="All Assessment Areas"
            testId="filter-area"
            value={filters.area}
            options={data.filters.areas}
            onChange={area => update({ area })}
          />
          <FilterSelect
            label="Severity"
            allLabel="All Severities"
            testId="filter-severity"
            value={filters.severity}
            options={data.filters.severities}
            onChange={severity => update({ severity })}
          />
          <FilterSelect
            label="Status"
            allLabel="All Statuses"
            testId="filter-status"
            value={filters.status}
            options={data.filters.statuses}
            onChange={status => update({ status })}
          />
        </div>
      }
      pagination={<Pagination {...paginationProps} />}
      preferences={
        <CollectionPreferences
          title="Preferences"
          confirmLabel="Confirm"
          cancelLabel="Cancel"
          preferences={preferences}
          onConfirm={({ detail }) => setPreferences(detail)}
          pageSizePreference={{ title: 'Page size', options: PAGE_SIZES }}
          wrapLinesPreference={{ label: 'Wrap lines', description: 'Show long finding titles on several lines.' }}
          stripedRowsPreference={{ label: 'Striped rows', description: 'Add alternating shading to rows.' }}
          contentDisplayPreference={{
            title: 'Columns',
            description: 'Choose and order the visible columns.',
            options: visibleColumns.map(column => ({ id: column.id ?? '', label: String(column.header), alwaysVisible: column.id === 'finding' })),
          }}
        />
      }
    />
  );
}

function RiskCards({ title, items, testId }: { title: string; items: RiskCard[]; testId: string }) {
  return (
    <Cards
      data-testid={testId}
      items={items}
      trackBy="label"
      cardsPerRow={[{ cards: 1 }, { minWidth: 500, cards: 2 }, { minWidth: 900, cards: 4 }]}
      header={<Header variant="h3">{title}</Header>}
      cardDefinition={{
        header: item => <Box variant="code">{item.label}</Box>,
        sections: [
          {
            id: 'total',
            content: item => (
              <Box variant="awsui-value-large" color={item.high > 0 ? 'text-status-error' : item.medium > 0 ? 'text-status-warning' : 'text-status-success'}>
                {item.total}
              </Box>
            ),
          },
          {
            id: 'split',
            content: item => (
              <SpaceBetween direction="horizontal" size="xs">
                <StatusIndicator type="error">{item.high} High</StatusIndicator>
                <StatusIndicator type="warning">{item.medium} Med</StatusIndicator>
                <StatusIndicator type="info">{item.low} Low</StatusIndicator>
              </SpaceBetween>
            ),
          },
        ],
      }}
    />
  );
}

function AreaSection(props: { area: Area; onView: (area: string, status: string) => void }) {
  const { area } = props;
  return (
    <section id={area.slug} className="report-section" data-area={area.slug}>
      <Container
        header={
          <Header
            variant="h2"
            actions={
              area.selected ? (
                <SpaceBetween direction="horizontal" size="xs">
                  <Button onClick={() => props.onView(area.slug, 'failed')}>View failed findings</Button>
                  <Button onClick={() => props.onView(area.slug, '')}>View all rows</Button>
                </SpaceBetween>
              ) : undefined
            }
          >
            <IconLabel icon={area.icon} size={28}>
              {area.sectionTitle}
            </IconLabel>
          </Header>
        }
      >
        {area.selected ? (
          <SpaceBetween size="l">
            {area.scope ? (
              <Box color="text-body-secondary">
                <RichText value={area.scope} />
              </Box>
            ) : null}
            <ColumnLayout columns={4} variant="text-grid" minColumnWidth={140}>
              <Counter label="Failed" value={area.failed} description="Open findings" tone="error" />
              <Counter label="Passed" value={area.passed} description="Controls met" tone="success" />
              <Counter label="N/A" value={area.na} description="Not applicable" />
              <Counter label="Total" value={area.total} description="Rows in report" />
            </ColumnLayout>
          </SpaceBetween>
        ) : (
          <SpaceBetween size="xs">
            <StatusIndicator type="stopped">Not selected</StatusIndicator>
            <Box color="text-body-secondary">This service was not assessed. No conclusion about its security posture is available.</Box>
          </SpaceBetween>
        )}
      </Container>
    </section>
  );
}

export function AssessmentReportPage({ data }: { data: AssessmentReport }) {
  const defaults: Filters = { account: ALL, region: ALL, area: ALL, severity: ALL, status: data.filters.defaultStatus };
  const [filters, setFilters] = useState<Filters>(defaults);
  const [selected, setSelected] = useState<Finding | null>(null);
  const areasBySlug = useMemo(() => new Map(data.areas.map(area => [area.slug, area])), [data.areas]);
  const sectionIds = ['overview', 'risk', 'findings', ...data.areas.map(area => area.slug), 'methodology'];
  const active = useActiveSection(sectionIds);

  // Keeps the reader's account, Region, severity and search choices; only the
  // area and status change.
  function viewFindings(area: string, status: string) {
    setFilters(current => ({ ...current, area, status }));
    scrollToSection('#findings');
  }

  const navItems: SideNavigationProps.Item[] = [
    {
      type: 'section-group',
      title: 'Navigation',
      items: [
        { type: 'link', text: 'Overview', href: '#overview' },
        { type: 'link', text: 'Risk Distribution', href: '#risk' },
        { type: 'link', text: 'Security Findings', href: '#findings', info: <Box variant="small">{data.findings.length}</Box> },
        { type: 'link', text: 'Methodology', href: '#methodology' },
      ],
    },
    ...data.navGroups.map(
      (group): SideNavigationProps.Item => ({
        type: 'section-group',
        title: group.heading,
        items: group.areas
          .map(slug => areasBySlug.get(slug))
          .filter((area): area is Area => Boolean(area))
          .map(area => ({
            type: 'link' as const,
            text: area.name,
            href: `#${area.slug}`,
            info: <Box variant="small">{area.countText}</Box>,
          })),
      })
    ),
  ];

  const navigation = (
    <Navigation
      header={data.subtitle}
      items={navItems}
      activeHref={`#${active}`}
      onFollow={scrollToSection}
      footer={
        <SpaceBetween size="xxs">
          <span>Generated: {data.generated}</span>
          <span>{data.accountInfo}</span>
          <Link href={data.githubUrl} external fontSize="body-s">
            GitHub Repository
          </Link>
        </SpaceBetween>
      }
    />
  );

  const content = (
    <ContentLayout
      header={
        <Header variant="h1" description={<MetaLine items={[data.timestamp, data.headerAccountInfo]} />}>
          {data.heading}
        </Header>
      }
    >
      <SpaceBetween size="xxl">
        <section id="overview" className="report-section">
          <SpaceBetween size="l">
            {data.selectionNotice ? (
              <div id="service-selection">
                <Alert type="info" header="Assessment selection">
                  <SpaceBetween size="xs">
                    <span>
                      <strong>Not selected:</strong> {data.selectionNotice.notSelected.join(', ')}.
                    </span>
                    <span>{data.selectionNotice.text}</span>
                  </SpaceBetween>
                </Alert>
              </div>
            ) : null}
            <Container header={<Header variant="h2">Summary</Header>} data-testid="overview-metrics">
              <ColumnLayout columns={3} variant="text-grid" minColumnWidth={180}>
                {data.overview.map(metric => (
                  <Counter key={metric.label} label={metric.label} value={metric.value} description={metric.description} tone={metric.tone} />
                ))}
              </ColumnLayout>
            </Container>
            <ColumnLayout columns={2} minColumnWidth={360}>
              <Container header={<Header variant="h2">Priority Recommendations</Header>} fitHeight>
                {data.alerts.length ? (
                  <SpaceBetween size="s">
                    {data.alerts.map((alert, index) => (
                      <SpaceBetween key={index} direction="horizontal" size="s" alignItems="center">
                        <StatusIndicator type={alert.level === 'high' ? 'error' : 'warning'}>
                          <Box variant="strong" color="inherit">
                            {alert.count}
                          </Box>
                        </StatusIndicator>
                        <div>
                          <Box variant="strong">{alert.finding}</Box>
                          <Box variant="small" display="block" color="text-body-secondary">
                            {alert.area}
                          </Box>
                        </div>
                      </SpaceBetween>
                    ))}
                  </SpaceBetween>
                ) : (
                  <StatusIndicator type="success">No critical findings</StatusIndicator>
                )}
              </Container>
              <Table
                variant="container"
                header={
                  <Header
                    variant="h2"
                    actions={
                      <Link href="#methodology" onFollow={event => { event.preventDefault(); scrollToSection('#methodology'); }}>
                        View full methodology
                      </Link>
                    }
                  >
                    Severity Legend
                  </Header>
                }
                items={data.severityLegend}
                wrapLines
                columnDefinitions={[
                  { id: 'severity', header: 'Severity', cell: item => <SeverityBadge severity={item.severity} />, width: 140 },
                  { id: 'meaning', header: 'Meaning', cell: item => item.meaning },
                  { id: 'action', header: 'Recommended Action', cell: item => <RichText value={item.action} /> },
                ]}
              />
            </ColumnLayout>
          </SpaceBetween>
        </section>

        <section id="risk" className="report-section">
          <Container header={<Header variant="h2" description="Direct service scored control results by severity">Risk Distribution</Header>}>
            <SpaceBetween size="xl">
              <ColumnLayout columns={4} minColumnWidth={180} data-testid="severity-pass-rates">
                {[...data.risk.severity, data.risk.overall].map(rate => (
                  <div key={rate.key} data-severity={rate.key}>
                    <ProgressBar
                      value={rate.passRate}
                      label={rate.key === 'overall' ? rate.label : <SeverityBadge severity={rate.label} />}
                      description={rate.description}
                      additionalInfo={`${rate.passRateText} passed`}
                      resultText={rate.passRateText}
                    />
                  </div>
                ))}
              </ColumnLayout>
              {data.risk.accounts ? <RiskCards title="Direct Failed Rows by Account" items={data.risk.accounts} testId="risk-accounts" /> : null}
              {data.risk.regions ? <RiskCards title="Direct Failed Rows by Region / Scope" items={data.risk.regions} testId="risk-regions" /> : null}
              <Cards
                data-testid="risk-areas"
                items={data.areas}
                trackBy="slug"
                cardsPerRow={[{ cards: 1 }, { minWidth: 500, cards: 2 }, { minWidth: 900, cards: 4 }]}
                header={<Header variant="h3">Findings by Assessment Area</Header>}
                cardDefinition={{
                  header: area => (
                    <Link
                      href={`#${area.slug}`}
                      fontSize="heading-s"
                      onFollow={event => {
                        event.preventDefault();
                        scrollToSection(`#${area.slug}`);
                      }}
                    >
                      <IconLabel icon={area.icon} size={18}>
                        {area.name}
                      </IconLabel>
                    </Link>
                  ),
                  sections: [
                    { id: 'total', content: area => <Box variant="awsui-value-large">{area.countText}</Box> },
                    {
                      id: 'status',
                      content: area =>
                        area.selected ? (
                          <Box color="text-body-secondary">{area.cardStatus}</Box>
                        ) : (
                          <StatusIndicator type="stopped">{area.cardStatus}</StatusIndicator>
                        ),
                    },
                  ],
                }}
              />
            </SpaceBetween>
          </Container>
        </section>

        <section id="findings" className="report-section">
          <FindingsTable data={data} filters={filters} setFilters={setFilters} defaults={defaults} selected={selected} onSelect={setSelected} />
        </section>

        {data.areas.map(area => (
          <AreaSection key={area.slug} area={area} onView={viewFindings} />
        ))}

        <section id="methodology" className="report-section">
          <SpaceBetween size="l">
            <Container header={<Header variant="h2">Assessment Methodology</Header>}>
              <SpaceBetween size="l">
                <div>
                  <Box variant="h3">Assessment Notes</Box>
                  <Box color="text-body-secondary">
                    <RichText value={data.methodology.notes} />
                  </Box>
                </div>
                <div>
                  <Box variant="h3">Assessment Scope</Box>
                  <SpaceBetween size="m">
                    {data.methodology.scopeGroups.map((group, index) => (
                      <div key={index} data-scope-group={group.label ?? 'services'}>
                        {group.label ? <Box variant="awsui-key-label">{group.label}</Box> : null}
                        <SpaceBetween direction="horizontal" size="xs">
                          {group.chips.map(chip => (
                            <Badge key={chip.label} color={chip.selected ? 'blue' : 'grey'}>
                              <IconLabel icon={chip.icon} size={14}>
                                {chip.label}
                              </IconLabel>
                            </Badge>
                          ))}
                        </SpaceBetween>
                      </div>
                    ))}
                    <Box color="text-body-secondary" fontSize="body-s">
                      <RichText value={data.methodology.source} />
                    </Box>
                  </SpaceBetween>
                </div>
              </SpaceBetween>
            </Container>
          </SpaceBetween>
        </section>
      </SpaceBetween>
    </ContentLayout>
  );

  return (
    <ReportShell
      subtitle={data.subtitle}
      githubUrl={data.githubUrl}
      navigation={navigation}
      content={content}
      footer={<PageFooter value={data.footer} />}
      detail={{
        title: selected ? selected.finding || selected.checkId : null,
        content: selected ? <FindingDetailsPanel item={selected} data={data} /> : null,
        onClose: () => setSelected(null),
      }}
    />
  );
}
