import { useEffect, useMemo, useState } from 'react';
import { useCollection } from '@cloudscape-design/collection-hooks';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import Link from '@cloudscape-design/components/link';
import Pagination from '@cloudscape-design/components/pagination';
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
  matchesText,
  MetaLine,
  Navigation,
  PageFooter,
  ReferenceLink,
  ReportShell,
  scrollToSection,
  setLocationHash,
  SeverityBadge,
  TONE_STATUS,
  useActiveSection,
} from './common';
import { ChangeRow, ChangesReport, Option } from './types';

const ALL = '';
const SEVERITY_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, informational: 3 };

interface Filters {
  region: string;
  area: string;
  severity: string;
  change: string;
}

function selectOption(value: string, options: Option[], allLabel: string | null): SelectProps.Option {
  if (value === ALL && allLabel !== null) return { value: ALL, label: allLabel };
  const match = options.find(option => option.value === value);
  return { value, label: match ? match.label : value };
}

function FilterSelect(props: {
  label: string;
  allLabel: string | null;
  value: string;
  options: Option[];
  onChange: (value: string) => void;
  testId: string;
}) {
  const options = props.allLabel === null ? props.options : [{ value: ALL, label: props.allLabel }, ...props.options];
  return (
    <div className="report-filter-select">
      <Select
        inlineLabelText={props.label}
        data-testid={props.testId}
        selectedOption={selectOption(props.value, props.options, props.allLabel)}
        options={options}
        onChange={({ detail }) => props.onChange(detail.selectedOption.value ?? ALL)}
      />
    </div>
  );
}

function ChangeDetailsPanel({ item, data }: { item: ChangeRow; data: ChangesReport }) {
  const area = data.filters.areas.find(option => option.value === item.service);
  return (
    <SpaceBetween size="l">
      <KeyValuePairs
        columns={2}
        items={[
          { label: 'Change', value: <StatusIndicator type={TONE_STATUS[item.tone]}>{item.change}</StatusIndicator> },
          { label: 'Previous → current', value: item.statuses },
          { label: 'Severity', value: <SeverityBadge severity={item.severity} /> },
          { label: 'Check ID', value: <Box variant="code">{item.checkId || '-'}</Box> },
          { label: 'Assessment area', value: area ? area.label : item.service },
          { label: 'Region', value: <Box variant="code">{item.region || '-'}</Box> },
          { label: 'Account ID', value: <Box variant="code">{item.account || '-'}</Box> },
        ]}
      />
      {item.details.map(detail => (
        <DetailText key={detail.label} label={detail.label} text={detail.text} />
      ))}
      <DetailText label="Resolution" text={item.resolution} />
      <div>
        <Box variant="awsui-key-label">Reference</Box>
        <ReferenceLink href={item.reference} />
      </div>
    </SpaceBetween>
  );
}

const PAGE_SIZES = [25, 50, 100, 250].map(value => ({ value, label: `${value} rows` }));

function ChangesTable(props: {
  data: ChangesReport;
  filters: Filters;
  setFilters: (filters: Filters) => void;
  defaults: Filters;
  selected: ChangeRow | null;
  onSelect: (row: ChangeRow | null) => void;
}) {
  const { data, filters, setFilters, defaults } = props;
  const rowKeys = useMemo(() => new Map(data.rows.map((row, index) => [row, String(index)])), [data.rows]);
  // Check, finding, severity and change come first so they stay in view when
  // the details panel narrows the table; readers can reorder or hide columns.
  const [preferences, setPreferences] = useState<CollectionPreferencesProps.Preferences>({
    pageSize: 50,
    wrapLines: true,
    contentDisplay: ['checkId', 'finding', 'severity', 'change', 'region', 'account'].map(id => ({ id, visible: true })),
  });

  const filtered = useMemo(
    () =>
      data.rows.filter(row => {
        if (filters.region && row.region.toLowerCase() !== filters.region) return false;
        if (filters.area && row.service !== filters.area) return false;
        if (filters.severity && row.severity.toLowerCase() !== filters.severity) return false;
        if (filters.change === 'changes') return row.changeSlug !== 'not-failing';
        if (filters.change !== 'all' && row.changeSlug !== filters.change) return false;
        return true;
      }),
    [data.rows, filters]
  );

  const { items, collectionProps, filterProps, paginationProps, filteredItemsCount, actions } = useCollection(filtered, {
    filtering: {
      filteringFunction: (row, text) =>
        matchesText(
          [row.account, row.region, row.checkId, row.finding, row.severity, row.change, row.statuses, row.resolution, ...row.details.map(d => d.text)],
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
    sorting: { defaultState: { sortingColumn: { sortingComparator: (a: ChangeRow, b: ChangeRow) => a.rank - b.rank } } },
  });

  // Any filter change, from this table or from the area navigation, starts
  // the results on their first page.
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

  const columns: TableProps.ColumnDefinition<ChangeRow>[] = [
    { id: 'account', header: 'Account ID', cell: row => <Box variant="code">{row.account}</Box>, sortingField: 'account', width: 150 },
    { id: 'region', header: 'Region', cell: row => <Box variant="code">{row.region}</Box>, sortingField: 'region', width: 140 },
    { id: 'checkId', header: 'Check ID', cell: row => <Box variant="code">{row.checkId}</Box>, sortingField: 'checkId', width: 110 },
    {
      id: 'finding',
      header: 'Finding',
      cell: row => row.finding,
      sortingComparator: (a, b) => a.finding.toLowerCase().localeCompare(b.finding.toLowerCase()),
      width: 320,
      minWidth: 200,
    },
    {
      id: 'severity',
      header: 'Severity',
      cell: row => <SeverityBadge severity={row.severity} />,
      sortingComparator: (a, b) => (SEVERITY_RANK[a.severity.toLowerCase()] ?? 99) - (SEVERITY_RANK[b.severity.toLowerCase()] ?? 99),
      width: 130,
    },
    {
      id: 'change',
      header: 'Change',
      cell: row => (
        <SpaceBetween size="xxxs">
          <StatusIndicator type={TONE_STATUS[row.tone]}>{row.change}</StatusIndicator>
          <Box variant="small" color="text-body-secondary">
            {row.statuses}
          </Box>
        </SpaceBetween>
      ),
      sortingComparator: (a, b) => a.rank - b.rank,
      width: 210,
    },
  ];

  return (
    <Table
      {...collectionProps}
      data-testid="changes-table"
      variant="container"
      items={items}
      columnDefinitions={columns}
      columnDisplay={preferences.contentDisplay}
      trackBy={row => rowKeys.get(row) ?? ''}
      selectionType="single"
      selectedItems={props.selected ? [props.selected] : []}
      onSelectionChange={({ detail }) => props.onSelect(detail.selectedItems[0] ?? null)}
      ariaLabels={{
        selectionGroupLabel: 'Finding selection',
        itemSelectionLabel: (_selection, row) => `Show details for ${row.checkId} ${row.finding}`,
        allItemsSelectionLabel: () => 'Select all',
      }}
      wrapLines={preferences.wrapLines}
      stripedRows={preferences.stripedRows}
      resizableColumns
      header={
        <Header
          variant="h2"
          counter={`(${filteredItemsCount ?? 0}/${data.rows.length})`}
          description="Compared findings. Select a finding to see both runs' details. Not failing rows are hidden by default; choose All Findings to show them."
          actions={
            <Button iconName="undo" onClick={reset}>
              Reset
            </Button>
          }
        >
          Changes
        </Header>
      }
      filter={
        <div className="report-filter-bar">
          <div className="report-filter-search">
            <TextFilter {...filterProps} filteringPlaceholder="Search findings" filteringAriaLabel="Search findings" countText={`${filteredItemsCount ?? 0} matches`} />
          </div>
          <FilterSelect label="Region" allLabel="All Regions" testId="filter-region" value={filters.region} options={data.filters.regions} onChange={region => update({ region })} />
          <FilterSelect label="Assessment Area" allLabel="All Assessment Areas" testId="filter-area" value={filters.area} options={data.filters.areas} onChange={area => update({ area })} />
          <FilterSelect label="Severity" allLabel="All Severities" testId="filter-severity" value={filters.severity} options={data.filters.severities} onChange={severity => update({ severity })} />
          <FilterSelect label="Change" allLabel={null} testId="filter-change" value={filters.change} options={data.filters.changes} onChange={change => update({ change })} />
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
            options: columns.map(column => ({ id: column.id ?? '', label: String(column.header), alwaysVisible: column.id === 'finding' })),
          }}
        />
      }
    />
  );
}

export function ChangesReportPage({ data }: { data: ChangesReport }) {
  const defaults: Filters = { region: ALL, area: ALL, severity: ALL, change: data.filters.defaultChange };
  const [filters, setFilters] = useState<Filters>(defaults);
  const [selected, setSelected] = useState<ChangeRow | null>(null);
  const active = useActiveSection(['overview', 'changes', 'methodology']);
  const areaSlugs = useMemo(() => new Set(data.navGroups.flatMap(group => group.areas.map(area => area.slug))), [data.navGroups]);

  function follow(href: string) {
    if (href.startsWith('#area:')) {
      const area = href.slice('#area:'.length);
      if (!areaSlugs.has(area)) return;
      setFilters(current => ({ ...current, area, change: 'changes' }));
      scrollToSection('#changes');
      setLocationHash(href);
      return;
    }
    scrollToSection(href);
  }

  // An area link is highlighted while the reader is in the Changes section
  // with that area's filter applied; elsewhere the scrolled-to section is.
  const activeHref = active === 'changes' && filters.area && areaSlugs.has(filters.area) ? `#area:${filters.area}` : `#${active}`;

  const navItems: SideNavigationProps.Item[] = [
    {
      type: 'section-group',
      title: 'Navigation',
      items: [
        { type: 'link', text: 'Overview', href: '#overview' },
        { type: 'link', text: 'Changes', href: '#changes', info: <Box variant="small">{data.changedCount}</Box> },
        { type: 'link', text: 'Methodology', href: '#methodology' },
      ],
    },
    ...data.navGroups.map(
      (group): SideNavigationProps.Item => ({
        type: 'section-group',
        title: group.heading,
        items: group.areas.map(area => ({
          type: 'link' as const,
          text: area.name,
          href: `#area:${area.slug}`,
          info: <Box variant="small">{area.count}</Box>,
        })),
      })
    ),
  ];

  const relatedFiles = (
    <SpaceBetween size="xxs">
      <span>Generated: {data.generated}</span>
      <span>Account: {data.accountId}</span>
      <Box variant="strong" fontSize="body-s" color="inherit">
        Related files
      </Box>
      {data.mainReport ? (
        <Link href={data.mainReport} fontSize="body-s">
          {data.mainReport}
        </Link>
      ) : null}
      {data.csvName ? (
        <Link href={data.csvName} fontSize="body-s">
          {data.csvName}
        </Link>
      ) : null}
      <span>{data.sameFolderNote}</span>
      <Link href={data.githubUrl} external fontSize="body-s">
        GitHub Repository
      </Link>
    </SpaceBetween>
  );

  const content = (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={
            <MetaLine
              items={[
                ...data.meta,
                ...(data.mainReport
                  ? [
                      <Link key="main" href={data.mainReport} fontSize="body-s">
                        Open main report
                      </Link>,
                    ]
                  : []),
              ]}
            />
          }
        >
          {data.heading}
        </Header>
      }
    >
      <SpaceBetween size="xxl">
        <section id="overview" className="report-section">
          <SpaceBetween size="l">
            <Container header={<Header variant="h2" description={data.tileNote}>Summary</Header>} data-testid="change-tiles">
              <ColumnLayout columns={3} variant="text-grid" minColumnWidth={180}>
                {data.tiles.map(tile => (
                  <Counter
                    key={tile.label}
                    label={<StatusIndicator type={TONE_STATUS[tile.tone]}>{tile.label}</StatusIndicator>}
                    value={tile.value}
                    description={tile.description}
                    tone={tile.tone}
                  />
                ))}
              </ColumnLayout>
            </Container>
            {data.notes.length ? (
              <div id="notes">
                <Container header={<Header variant="h2">Notes</Header>}>
                  <ul className="report-list">
                    {data.notes.map((note, index) => (
                      <li key={index}>{note}</li>
                    ))}
                  </ul>
                </Container>
              </div>
            ) : null}
            <Table
              data-testid="area-table"
              variant="container"
              header={<Header variant="h2">Changes by Assessment Area</Header>}
              items={data.areaTable.rows}
              wrapLines
              columnDefinitions={[
                {
                  id: 'area',
                  header: 'Assessment Area',
                  cell: row =>
                    row.type === 'group' ? (
                      <Box variant="awsui-key-label">{row.label}</Box>
                    ) : row.type === 'total' ? (
                      <Box variant="strong">{row.label}</Box>
                    ) : (
                      row.label
                    ),
                  minWidth: 220,
                },
                ...data.areaTable.columns.map((column, index): TableProps.ColumnDefinition<(typeof data.areaTable.rows)[number]> => ({
                  id: `c${index}`,
                  header: column,
                  cell: row => {
                    if (row.type === 'group') return null;
                    if (!row.counts) return index === 0 ? <Box color="text-body-secondary">{row.note}</Box> : null;
                    const value = row.counts[index];
                    return row.type === 'total' ? <Box variant="strong">{value}</Box> : value;
                  },
                })),
              ]}
            />
          </SpaceBetween>
        </section>

        <section id="changes" className="report-section">
          <ChangesTable data={data} filters={filters} setFilters={setFilters} defaults={defaults} selected={selected} onSelect={setSelected} />
        </section>

        <section id="methodology" className="report-section">
          <SpaceBetween size="l">
            <Table
              variant="container"
              header={<Header variant="h2">Change States</Header>}
              items={data.methodology.states}
              wrapLines
              columnDefinitions={[
                { id: 'change', header: 'Change', cell: s => <StatusIndicator type={TONE_STATUS[s.tone]}>{s.change}</StatusIndicator>, width: 240 },
                { id: 'meaning', header: 'Meaning', cell: s => s.meaning },
              ]}
            />
            <Container header={<Header variant="h2">How Findings Are Matched</Header>}>
              <SpaceBetween size="m">
                <ol className="report-list">
                  {data.methodology.matching.map((step, index) => (
                    <li key={index}>{step}</li>
                  ))}
                </ol>
                <Box color="text-body-secondary">{data.methodology.previousRun}</Box>
              </SpaceBetween>
            </Container>
          </SpaceBetween>
        </section>
      </SpaceBetween>
    </ContentLayout>
  );

  const navigation = (
    <Navigation
      header={data.subtitle}
      items={navItems}
      activeHref={activeHref}
      onFollow={follow}
      footer={relatedFiles}
    />
  );

  return (
    <ReportShell
      subtitle={data.subtitle}
      githubUrl={data.githubUrl}
      navigation={navigation}
      content={content}
      footer={<PageFooter value={data.footer} />}
      onHash={follow}
      detail={{
        title: selected ? selected.finding || selected.checkId : null,
        content: selected ? <ChangeDetailsPanel item={selected} data={data} /> : null,
        onClose: () => setSelected(null),
      }}
    />
  );
}

