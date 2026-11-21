import React from 'react';
import { createRoot } from 'react-dom/client';
import '@cloudscape-design/global-styles/index.css';
import './report.css';
import { AssessmentReportPage } from './AssessmentReport';
import { ChangesReportPage } from './ChangesReport';
import { ReportData } from './types';

function readData(): ReportData {
  const element = document.getElementById('report-data');
  if (!element || !element.textContent) {
    throw new Error('This report has no embedded data.');
  }
  return JSON.parse(element.textContent) as ReportData;
}

function failureMessage(error: unknown): string {
  return `The report could not be displayed: ${error instanceof Error ? error.message : String(error)}`;
}

/** Shows the failure text instead of a blank page when drawing the report throws. */
class ReportErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: unknown }> {
  state: { error: unknown } = { error: null };

  static getDerivedStateFromError(error: unknown) {
    return { error: error ?? new Error('Unknown error') };
  }

  render() {
    return this.state.error ? <p className="report-load-error">{failureMessage(this.state.error)}</p> : this.props.children;
  }
}

function App({ data }: { data: ReportData }) {
  return data.kind === 'changes' ? <ChangesReportPage data={data} /> : <AssessmentReportPage data={data} />;
}

const root = document.getElementById('root');
if (root) {
  try {
    const data = readData();
    // Cloudscape measures the top navigation once, so load the inlined Open
    // Sans faces first; otherwise titles are measured in a fallback font.
    const fonts = document.fonts
      ? Promise.all(['400 14px "Open Sans"', '700 18px "Open Sans"'].map(font => document.fonts.load(font))).catch(() => [])
      : Promise.resolve([]);
    fonts
      .then(() =>
        createRoot(root).render(
          <ReportErrorBoundary>
            <App data={data} />
          </ReportErrorBoundary>
        )
      )
      .catch(error => {
        root.textContent = failureMessage(error);
      });
  } catch (error) {
    root.textContent = failureMessage(error);
  }
}
