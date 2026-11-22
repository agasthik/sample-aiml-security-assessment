import React, { useCallback, useEffect, useRef, useState } from 'react';
import { applyMode, Mode } from '@cloudscape-design/global-styles';
import AppLayout, { AppLayoutProps } from '@cloudscape-design/components/app-layout';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Link from '@cloudscape-design/components/link';
import SideNavigation, { SideNavigationProps } from '@cloudscape-design/components/side-navigation';
import SpaceBetween from '@cloudscape-design/components/space-between';
import SplitPanel from '@cloudscape-design/components/split-panel';
import StatusIndicator, { StatusIndicatorProps } from '@cloudscape-design/components/status-indicator';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import { identifierPieces, splitDetailList } from './detailText';
import { Rich, Tone } from './types';

// ---------------------------------------------------------------------------
// Theme. The choice is kept under the same localStorage key the reports have
// always used, so a reader's light/dark choice carries across report files.
// ---------------------------------------------------------------------------

const THEME_KEY = 'theme';

function storedMode(): Mode {
  try {
    return localStorage.getItem(THEME_KEY) === 'dark' ? Mode.Dark : Mode.Light;
  } catch {
    return Mode.Light;
  }
}

export function useThemeMode(): [Mode, () => void] {
  const [mode, setMode] = useState<Mode>(storedMode);
  useEffect(() => {
    applyMode(mode);
    try {
      localStorage.setItem(THEME_KEY, mode);
    } catch {
      // Storage can be unavailable for file:// pages in some browsers.
    }
  }, [mode]);
  const toggle = useCallback(() => setMode(m => (m === Mode.Dark ? Mode.Light : Mode.Dark)), []);
  return [mode, toggle];
}

const MOON_ICON = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" focusable="false" aria-hidden="true">
    <path
      d="M6 .278a.768.768 0 0 1 .08.858 7.208 7.208 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277.527 0 1.04-.055 1.533-.16a.787.787 0 0 1 .81.316.733.733 0 0 1-.031.893A8.349 8.349 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.752.752 0 0 1 6 .278z"
      className="filled"
      style={{ fill: 'currentColor', stroke: 'none' }}
    />
  </svg>
);

const SUN_ICON = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" focusable="false" aria-hidden="true">
    <circle cx="8" cy="8" r="3" fill="none" />
    <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.05 3.05l1.41 1.41M11.54 11.54l1.41 1.41M3.05 12.95l1.41-1.41M11.54 4.46l1.41-1.41" />
  </svg>
);

const SHIELD_LOGO =
  'data:image/svg+xml,' +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#232f3e"/>' +
      '<path d="M16 5l9 3.5v6.5c0 5.8-3.8 10.6-9 12-5.2-1.4-9-6.2-9-12V8.5z" fill="#ff9900"/>' +
      '<path d="M12 16l3 3 5-6" fill="none" stroke="#232f3e" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>'
  );

// ---------------------------------------------------------------------------
// Page shell: TopNavigation (theme toggle top right) over an AppLayout whose
// navigation drawer is a SideNavigation.
// ---------------------------------------------------------------------------

/** A finding's details, shown in the AppLayout split panel. */
export interface DetailPanel {
  /** The chosen row's title, or null when no row is chosen (panel closed). */
  title: string | null;
  content: React.ReactNode;
  onClose: () => void;
}

const SPLIT_PANEL_POSITION_KEY = 'splitPanelPosition';
const SPLIT_PANEL_SIZE_KEY = 'splitPanelSize';
const DEFAULT_SIDE_PANEL_SIZE = 440;

function storedValue(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function storeValue(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage can be unavailable for file:// pages in some browsers.
  }
}

/** Split panel position and size, remembered across report files like the theme. */
function useSplitPanelLayout() {
  const [position, setPosition] = useState<'side' | 'bottom'>(() =>
    storedValue(SPLIT_PANEL_POSITION_KEY) === 'bottom' ? 'bottom' : 'side'
  );
  const [size, setSize] = useState<number | undefined>(() => {
    const value = Number(storedValue(SPLIT_PANEL_SIZE_KEY));
    return Number.isFinite(value) && value > 0 ? value : DEFAULT_SIDE_PANEL_SIZE;
  });
  const preferences: AppLayoutProps.SplitPanelPreferences = { position };
  return {
    preferences,
    position,
    size,
    onPreferencesChange: (next: AppLayoutProps.SplitPanelPreferences) => {
      setPosition(next.position);
      storeValue(SPLIT_PANEL_POSITION_KEY, next.position);
    },
    onResize: (next: number) => {
      setSize(next);
      storeValue(SPLIT_PANEL_SIZE_KEY, String(next));
    },
  };
}

const SPLIT_PANEL_I18N = {
  closeButtonAriaLabel: 'Close finding details',
  openButtonAriaLabel: 'Open finding details',
  preferencesTitle: 'Details panel preferences',
  preferencesPositionLabel: 'Details panel position',
  preferencesPositionDescription: 'Show finding details beside the table or below it.',
  preferencesPositionSide: 'Side',
  preferencesPositionBottom: 'Bottom',
  preferencesConfirm: 'Confirm',
  preferencesCancel: 'Cancel',
  preferencesCloseAriaLabel: 'Close preferences',
  resizeHandleAriaLabel: 'Resize finding details',
  resizeHandleTooltipText: 'Drag or select to resize',
};

export function ReportShell(props: {
  subtitle: string;
  githubUrl: string;
  navigation: React.ReactNode;
  content: React.ReactNode;
  footer: React.ReactNode;
  detail?: DetailPanel;
  /** Opens a `#fragment` from the address bar; defaults to scrolling to that section. */
  onHash?: (href: string) => void;
}) {
  const [mode, toggleMode] = useThemeMode();
  // On narrow screens AppLayout draws the navigation over the content, so it
  // starts closed there; readers open it with the menu button.
  const [navigationOpen, setNavigationOpen] = useState(() => !isNarrowViewport());
  useHashNavigation(props.onHash ?? scrollToSection);
  const splitLayout = useSplitPanelLayout();
  const detail = props.detail;
  const detailOpen = Boolean(detail && detail.title !== null);
  // Opening the details beside the table collapses the section navigation once,
  // so the table keeps its key columns in view; readers can reopen it.
  const wasOpen = useRef(false);
  useEffect(() => {
    if (detailOpen && !wasOpen.current && splitLayout.position === 'side') {
      setNavigationOpen(false);
    }
    wasOpen.current = detailOpen;
  }, [detailOpen, splitLayout.position]);
  const dark = mode === Mode.Dark;
  return (
    <>
      <div id="report-top-nav" className="report-top-nav">
        <TopNavigation
          identity={{ href: '#overview', title: 'AI/ML Security Assessment', logo: { src: SHIELD_LOGO, alt: '' } }}
          utilities={[
            {
              type: 'button',
              text: 'GitHub',
              href: props.githubUrl,
              external: true,
              externalIconAriaLabel: '(opens in a new tab)',
            },
            {
              type: 'button',
              iconSvg: dark ? SUN_ICON : MOON_ICON,
              ariaLabel: dark ? 'Switch to light mode' : 'Switch to dark mode',
              title: dark ? 'Light mode' : 'Dark mode',
              onClick: toggleMode,
              disableUtilityCollapse: true,
            },
          ]}
          i18nStrings={{ overflowMenuTriggerText: 'More', overflowMenuTitleText: 'All' }}
        />
      </div>
      <AppLayout
        headerSelector="#report-top-nav"
        footerSelector="#report-footer"
        navigation={props.navigation}
        navigationOpen={navigationOpen}
        onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
        toolsHide
        contentType="default"
        maxContentWidth={1600}
        content={props.content}
        splitPanel={
          detail && detail.title !== null ? (
            <SplitPanel header={detail.title} i18nStrings={SPLIT_PANEL_I18N} data-testid="finding-details">
              {detail.content}
            </SplitPanel>
          ) : undefined
        }
        splitPanelOpen={detailOpen}
        onSplitPanelToggle={({ detail: toggle }) => {
          if (!toggle.open) props.detail?.onClose();
        }}
        splitPanelPreferences={splitLayout.preferences}
        onSplitPanelPreferencesChange={({ detail: next }) => splitLayout.onPreferencesChange(next)}
        splitPanelSize={splitLayout.size}
        onSplitPanelResize={({ detail: next }) => splitLayout.onResize(next.size)}
        ariaLabels={{ navigation: 'Report sections', navigationToggle: 'Open sections', navigationClose: 'Close sections' }}
      />
      {props.footer}
    </>
  );
}

// Matches the AppLayout mobile breakpoint, below which the navigation overlays the page.
const NARROW_VIEWPORT_QUERY = '(max-width: 688px)';

function isNarrowViewport(): boolean {
  try {
    return window.matchMedia(NARROW_VIEWPORT_QUERY).matches;
  } catch {
    return false;
  }
}

/**
 * Follow the address bar's `#fragment`. The page is drawn after the browser's
 * own jump to the fragment, so the target is looked up again once React has
 * rendered (and on later hash changes).
 */
function useHashNavigation(onHash: (href: string) => void) {
  const latest = useRef(onHash);
  latest.current = onHash;
  useEffect(() => {
    const follow = () => {
      if (window.location.hash.length > 1) {
        latest.current(decodeURIComponent(window.location.hash));
      }
    };
    const frame = window.requestAnimationFrame(follow);
    window.addEventListener('hashchange', follow);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener('hashchange', follow);
    };
  }, []);
}

/** Put a section's fragment in the address bar without adding a history entry. */
export function setLocationHash(href: string) {
  try {
    if (window.location.hash !== href) {
      window.history.replaceState(window.history.state, '', href);
    }
  } catch {
    // Some browsers refuse history changes for file:// pages.
  }
}

/** Scroll to a section anchor and show its fragment in the address bar, without adding history. */
export function scrollToSection(href: string) {
  const target = document.getElementById(href.replace(/^#/, ''));
  if (target) {
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setLocationHash(href);
  }
}

/** The id of the section currently at the top of the viewport. */
export function useActiveSection(ids: string[]): string {
  const [active, setActive] = useState(ids[0] ?? '');
  const key = ids.join('|');
  useEffect(() => {
    const onScroll = () => {
      let current = ids[0] ?? '';
      for (const id of ids) {
        const el = document.getElementById(id);
        if (el && el.getBoundingClientRect().top <= 140) {
          current = id;
        }
      }
      setActive(current);
    };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return active;
}

export function Navigation(props: {
  header: string;
  items: SideNavigationProps.Item[];
  activeHref: string;
  onFollow: (href: string) => void;
  footer: React.ReactNode;
}) {
  return (
    <>
      <SideNavigation
        header={{ href: '#overview', text: props.header }}
        activeHref={props.activeHref}
        items={props.items}
        onFollow={event => {
          if (event.detail.external) {
            return;
          }
          event.preventDefault();
          props.onFollow(event.detail.href);
        }}
      />
      <Box padding={{ horizontal: 'xl', vertical: 'l' }} fontSize="body-s" color="text-body-secondary">
        {props.footer}
      </Box>
    </>
  );
}

// ---------------------------------------------------------------------------
// Small building blocks.
// ---------------------------------------------------------------------------

export function RichText({ value }: { value: Rich | null | undefined }) {
  if (!value) {
    return null;
  }
  return (
    <>
      {value.map((segment, index) => {
        if (typeof segment === 'string') {
          return <React.Fragment key={index}>{segment}</React.Fragment>;
        }
        if ('strong' in segment) {
          return (
            <strong key={index}>
              <RichText value={segment.strong} />
            </strong>
          );
        }
        return (
          <Link key={index} href={segment.href} external externalIconAriaLabel="(opens in a new tab)">
            {segment.link}
          </Link>
        );
      })}
    </>
  );
}

export function AreaIcon({ src, size = 20 }: { src: string | null; size?: number }) {
  if (!src) {
    return null;
  }
  return (
    <img
      className="report-area-icon"
      src={src}
      alt=""
      width={size}
      height={size}
      style={{ borderRadius: Math.max(3, Math.round(size / 5)) }}
    />
  );
}

export function IconLabel({ icon, children, size }: { icon: string | null; children: React.ReactNode; size?: number }) {
  return (
    <span className="report-icon-label">
      <AreaIcon src={icon} size={size} />
      <span>{children}</span>
    </span>
  );
}

const SEVERITY_BADGE: Record<string, 'severity-high' | 'severity-medium' | 'severity-low' | 'severity-neutral'> = {
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_BADGE[severity.toLowerCase()] ?? 'severity-neutral';
  return <Badge color={color}>{severity || 'Informational'}</Badge>;
}

export function statusType(status: string): StatusIndicatorProps.Type {
  const key = status.toLowerCase();
  if (key === 'passed') return 'success';
  if (key === 'failed') return 'error';
  return 'stopped';
}

export const TONE_STATUS: Record<Tone, StatusIndicatorProps.Type> = {
  error: 'error',
  warning: 'warning',
  success: 'success',
  info: 'info',
  neutral: 'stopped',
};

export const TONE_COLOR: Record<Tone, 'text-status-error' | 'text-status-warning' | 'text-status-success' | 'text-status-info' | 'inherit'> = {
  error: 'text-status-error',
  warning: 'text-status-warning',
  success: 'text-status-success',
  info: 'text-status-info',
  neutral: 'inherit',
};

export function StatusLabel({ status }: { status: string }) {
  return <StatusIndicator type={statusType(status)}>{status}</StatusIndicator>;
}

/** A Cloudscape "counter" tile: key label, large value, short description. */
export function Counter(props: { label: React.ReactNode; value: React.ReactNode; description?: React.ReactNode; tone?: Tone }) {
  return (
    <div>
      <Box variant="awsui-key-label">{props.label}</Box>
      <Box variant="awsui-value-large" color={TONE_COLOR[props.tone ?? 'neutral']}>
        {props.value}
      </Box>
      {props.description ? (
        <Box variant="small" display="block" color="text-body-secondary">
          {props.description}
        </Box>
      ) : null}
    </div>
  );
}

export function PageFooter({ value }: { value: Rich }) {
  return (
    <div id="report-footer">
      <Box padding={{ vertical: 's', horizontal: 'l' }} textAlign="center" fontSize="body-s" color="text-body-secondary">
        <RichText value={value} />
      </Box>
    </div>
  );
}

export function MetaLine({ items }: { items: React.ReactNode[] }) {
  return (
    <SpaceBetween direction="horizontal" size="l">
      {items.map((item, index) => (
        <Box key={index} color="text-body-secondary" fontSize="body-s">
          {item}
        </Box>
      ))}
    </SpaceBetween>
  );
}

/** Case-insensitive search across the given fields of a row. */
export function matchesText(fields: (string | null | undefined)[], text: string): boolean {
  if (!text) return true;
  const needle = text.toLowerCase();
  return fields.some(field => (field ?? '').toLowerCase().includes(needle));
}

/** Finding text with AWS identifiers (names, ARNs, IDs, actions) shown as inline code. */
export function IdentifierText({ text }: { text: string }) {
  return (
    <>
      {identifierPieces(text).map((piece, index) =>
        'text' in piece ? (
          <React.Fragment key={index}>{piece.text}</React.Fragment>
        ) : (
          <span key={index} className="report-identifier" data-quote={piece.quote || undefined}>
            <Box variant="awsui-inline-code">{piece.code}</Box>
          </span>
        )
      )}
    </>
  );
}

/** A labelled block of finding text in the details panel. */
export function DetailText({ label, text }: { label: string; text: string }) {
  const paragraphs = (text || '-').split(/\n{2,}/);
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <SpaceBetween size="xs">
        {paragraphs.map((paragraph, index) => {
          const blocks = paragraph.includes('\n') ? null : splitDetailList(paragraph);
          if (!blocks) {
            return (
              <div key={index} className="report-prewrap">
                <IdentifierText text={paragraph} />
              </div>
            );
          }
          return (
            <div key={index} className="report-detail-list">
              {blocks.map((block, blockIndex) =>
                'text' in block ? (
                  <div key={blockIndex} className="report-prewrap">
                    <IdentifierText text={block.text} />
                  </div>
                ) : (
                  <div key={blockIndex}>
                    <div className="report-prewrap">
                      <IdentifierText text={block.lead} />
                    </div>
                    <ul className="report-list">
                      {block.items.map((item, itemIndex) => (
                        <li key={itemIndex} className="report-prewrap">
                          <IdentifierText text={item} />
                        </li>
                      ))}
                    </ul>
                  </div>
                )
              )}
            </div>
          );
        })}
      </SpaceBetween>
    </div>
  );
}

export function ReferenceLink({ href }: { href: string | null }) {
  return href ? (
    <Link href={href} external externalIconAriaLabel="(opens in a new tab)">
      View AWS documentation
    </Link>
  ) : (
    <Box color="text-body-secondary">-</Box>
  );
}
