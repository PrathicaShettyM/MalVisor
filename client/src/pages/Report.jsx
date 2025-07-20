import { useEffect, useState } from "react";
import { useParams, useLocation } from "react-router-dom";

export default function Report() {
  const { reportId } = useParams();
  const location = useLocation();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const passedReport = location.state?.report;
    if (passedReport) {
      setReport(passedReport); // ✅ Directly show passed report
      setLoading(false);
    } else {
      // Fallback: fetch real report
      fetch(`http://localhost:5000/report/${reportId}`)
        .then((res) => {
          if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
          }
          return res.json();
        })
        .then((data) => {
          if (data.error) {
            setError(data.error);
          } else {
            setReport(data);
          }
          setLoading(false);
        })
        .catch((err) => {
          setError(`Failed to load report: ${err.message}`);
          setLoading(false);
        });
    }
  }, [reportId, location.state]);

  if (loading) return <div className="p-6 text-center">Loading...</div>;
  if (error) return <div className="p-6 text-center text-red-600">Error: {error}</div>;
  if (!report) return <div className="p-6 text-center">No report data available</div>;

  const {
    malwareFamily = "Unknown",
    severityScore = "N/A",
    fileHashes = {},
    entropy = {},
    strings = [],
    peFeatures = {},
    modelFeatures = {},
    verdict,
    filename,
  } = report;

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold text-purple-700 mb-4">
        Malware Analysis Report
      </h1>

      <div className="bg-white shadow-lg rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Summary</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-gray-600">Filename</p>
            <p className="font-medium">{filename || "Unknown"}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Malware Family</p>
            <p className="font-medium">{malwareFamily}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Severity Score</p>
            <p className="font-medium">{severityScore}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Report ID</p>
            <p className="font-medium">{reportId}</p>
          </div>
        </div>
        {verdict && (
          <div className="mt-4 p-3 rounded-lg bg-red-50 border border-red-200">
            <p className="text-red-700 font-semibold">Verdict: {verdict}</p>
          </div>
        )}
      </div>

      <div className="space-y-6">
        {Object.keys(fileHashes).length > 0 && (
          <Section title="File Hashes" data={fileHashes} />
        )}
        {Object.keys(entropy).length > 0 && (
          <Section title="Entropy by Section" data={entropy} />
        )}
        {strings.length > 0 && (
          <StringSection strings={strings} />
        )}
        {Object.keys(peFeatures).length > 0 && (
          <JsonSection title="PE Features" data={peFeatures} />
        )}
        {Object.keys(modelFeatures).length > 0 && (
          <JsonSection title="Model Features" data={modelFeatures} />
        )}
      </div>
    </div>
  );
}

function Section({ title, data }) {
  return (
    <div className="bg-white shadow-lg rounded-lg p-6">
      <h3 className="text-lg font-semibold text-gray-700 mb-3">{title}</h3>
      <div className="bg-gray-50 p-4 rounded border">
        {Object.entries(data).map(([key, val]) => (
          <div key={key} className="flex justify-between items-center py-1 border-b border-gray-200 last:border-b-0">
            <span className="font-medium text-gray-700">{key}:</span>
            <span className="text-gray-600 font-mono text-sm">{val}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function StringSection({ strings }) {
  return (
    <div className="bg-white shadow-lg rounded-lg p-6">
      <h3 className="text-lg font-semibold text-gray-700 mb-3">
        Strings ({strings.length})
      </h3>
      <div className="bg-gray-50 p-4 rounded border max-h-60 overflow-y-auto">
        {strings.map((s, i) => (
          <div key={i} className="py-1 px-2 mb-1 bg-white rounded text-sm font-mono text-blue-900 border">
            {s}
          </div>
        ))}
      </div>
    </div>
  );
}

function JsonSection({ title, data }) {
  return (
    <div className="bg-white shadow-lg rounded-lg p-6">
      <h3 className="text-lg font-semibold text-gray-700 mb-3">{title}</h3>
      <div className="bg-gray-100 p-4 rounded border overflow-x-auto">
        <pre className="text-sm text-gray-800 whitespace-pre-wrap">
          {JSON.stringify(data, null, 2)}
        </pre>
      </div>
    </div>
  );
}