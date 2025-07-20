export default function AnalysisResult({ result }) {
  if (!result) return null;

  return (
    <div className="mt-4 p-4 border rounded bg-gray-50">
      <p><strong>Malware Family:</strong> {result.predicted_family}</p>
      <p><strong>Severity Score:</strong> {result.severity}</p>
      <p><strong>Report ID:</strong> {result.report_id}</p>
    </div>
  );
}
