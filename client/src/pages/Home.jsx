import { useState } from 'react';
import Navbar from '../layout/Navbar';
import Footer from '../layout/Footer';
import jsPDF from 'jspdf';


export default function Home() {
  const [filename, setFilename] = useState(null);
  const [result, setResult] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState({ upload: false, analyze: false });
  const [expanded, setExpanded] = useState({
    strings: false,
    modelFeatures: false,
    peFeatures: false,
  });

  const toggleSection = (section) => {
    setExpanded((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
      setFilename(file.name);
      setResult(null);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    const formData = new FormData();
    formData.append('file', selectedFile);
    setLoading((prev) => ({ ...prev, upload: true }));

    try {
      const res = await fetch('http://localhost:5000/upload', {
        method: 'POST',
        body: formData,
      });

      const text = await res.text();
      const data = JSON.parse(text || '{}');

      if (res.ok) {
        console.log("Upload response:", data);
        setFilename(data.filename || selectedFile.name);
        setResult(null);
        alert("File uploaded successfully!");
      } else {
        alert(data.error || "Upload failed.");
      }
    } catch (err) {
      alert("Error uploading file.");
      console.error(err);
    } finally {
      setLoading((prev) => ({ ...prev, upload: false }));
    }
  };

  const analyze = async () => {
    if (!filename) return;

    setLoading((prev) => ({ ...prev, analyze: true }));

    try {
      const response = await fetch('http://localhost:5000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ filename }),
      });

      const text = await response.text();
      const data = JSON.parse(text || '{}');

      if (response.ok) {
        setResult(data);
        alert("Malware analysis completed!");
      } else {
        alert(data.error || "Analysis failed.");
      }
    } catch (err) {
      alert("Error during analysis request.");
      console.error(err);
    } finally {
      setLoading((prev) => ({ ...prev, analyze: false }));
    }
  };

  const generatePDF = () => {
  const doc = new jsPDF();
  let y = 10;

  doc.setFontSize(16);
  doc.text("MalVisor - Malware Analysis Report", 10, y);
  y += 10;

  doc.setFontSize(12);
  doc.text(`Malware Family: ${result.malwareFamily || "Unknown"}`, 10, y);
  y += 7;
  doc.text(`Severity Score: ${result.severityScore || "N/A"}`, 10, y);
  y += 7;
  doc.text(`Report ID: ${result.report_id || "N/A"}`, 10, y);
  y += 7;
  doc.text(`Filename: ${result.filename || "N/A"}`, 10, y);
  y += 7;
  doc.text(`Verdict: ${result.verdict || "N/A"}`, 10, y);
  y += 10;

  if (result.fileHashes) {
    doc.setFont(undefined, 'bold');
    doc.text("File Hashes:", 10, y);
    doc.setFont(undefined, 'normal');
    y += 7;
    for (const [type, hash] of Object.entries(result.fileHashes)) {
      doc.text(`${type.toUpperCase()}: ${hash}`, 12, y);
      y += 6;
    }
    y += 4;
  }

  if (result.entropy) {
    doc.setFont(undefined, 'bold');
    doc.text("Entropy by Section:", 10, y);
    doc.setFont(undefined, 'normal');
    y += 7;
    for (const [section, entropy] of Object.entries(result.entropy)) {
      doc.text(`${section}: ${entropy}`, 12, y);
      y += 6;
    }
    y += 4;
  }

  if (result.peFeatures) {
    doc.setFont(undefined, 'bold');
    doc.text("PE Features:", 10, y);
    doc.setFont(undefined, 'normal');
    y += 7;
    doc.text(`Entry Point: ${result.peFeatures.entry_point || "N/A"}`, 12, y);
    y += 6;
    doc.text(`Timestamp: ${result.peFeatures.timestamp || "N/A"}`, 12, y);
    y += 6;

    if (result.peFeatures.imported_libraries?.length) {
      doc.text("Imported Libraries:", 12, y);
      y += 6;
      result.peFeatures.imported_libraries.forEach(lib => {
        doc.text(`- ${lib}`, 14, y);
        y += 5;
      });
    }

    if (result.peFeatures.section_names?.length) {
      y += 4;
      doc.text("Section Names:", 12, y);
      y += 6;
      result.peFeatures.section_names.forEach(sec => {
        doc.text(`- ${sec}`, 14, y);
        y += 5;
      });
    }

    y += 4;
  }

  if (result.modelFeatures) {
    doc.setFont(undefined, 'bold');
    doc.text("Model Features:", 10, y);
    doc.setFont(undefined, 'normal');
    y += 7;
    for (const [key, val] of Object.entries(result.modelFeatures)) {
      doc.text(`${key}: ${String(val)}`, 12, y);
      y += 6;
    }
    y += 4;
  }

  // Only show up to 10 strings in the PDF
  if (result.strings?.length) {
    doc.setFont(undefined, 'bold');
    doc.text(`Strings (showing first 10):`, 10, y);
    doc.setFont(undefined, 'normal');
    y += 7;
    result.strings.slice(0, 10).forEach(str => {
      doc.text(`- ${str}`, 12, y);
      y += 5;
    });
  }

  doc.save(`MalVisor_Report_${filename || "analysis"}.pdf`);
};


return (
  <>
    <Navbar />
    <div className="min-h-screen bg-gray-50 text-gray-800 px-4 py-10">
      <div className="max-w-3xl mx-auto text-center mb-12">
        <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-800 to-blue-600 bg-clip-text text-transparent mb-4">Welcome to MalVisor</h1>
        <p className="text-lg">Automated static malware analysis for PE files (.exe/.dll).</p>
      </div>

      <div className="max-w-4xl mx-auto grid grid-cols-1 sm:grid-cols-2 gap-6 mb-12">
        {[
          ["PE Header Analysis", "Extracts and analyzes PE file headers for suspicious patterns."],
          ["Import Table Insights", "Detects potentially dangerous API imports (like `CreateRemoteThread`, `LoadLibrary`)."],
          ["Entropy & Section Checks", "Flags high entropy sections often used for packing or obfuscation."],
          ["Machine Learning Ready", "Supports output that can be fed into ML classifiers for behavioral prediction."],
        ].map(([title, desc], i) => (
          <div key={i} className="bg-white rounded-xl shadow p-6">
            <h2 className="text-xl font-semibold mb-2">{title}</h2>
            <p>{desc}</p>
          </div>
        ))}
      </div>

      <div className="max-w-xl mx-auto bg-white shadow-lg rounded-2xl p-8 mb-12">
        <h2 className="text-2xl font-bold text-center bg-gradient-to-r from-blue-800 to-blue-600 bg-clip-text text-transparent mb-4">Upload File for Analysis</h2>
        <p className="text-center text-gray-600 mb-6">
          Only upload PE files with <code className="bg-gray-100 px-1 rounded">.exe</code> or <code className="bg-gray-100 px-1 rounded">.dll</code> extensions.
        </p>

        <div className="flex flex-col items-center">
          <label
            htmlFor="file-upload"
            className="w-full cursor-pointer flex flex-col items-center justify-center border-2 border-dashed border-blue-600 rounded-xl p-6 text-blue-800 bg-gradient-to-br from-blue-50 to-blue-100 hover:from-blue-100 hover:to-blue-150 transition"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10 mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a2 2 0 002 2h12a2 2 0 002-2v-1M12 12v6m0 0l-3-3m3 3l3-3m0-6a4 4 0 10-8 0 4 4 0 008 0z" />
            </svg>
            <span className="text-sm font-medium">Click to upload a `.exe` or `.dll` file</span>
            <input
              id="file-upload"
              type="file"
              className="hidden"
              accept=".exe,.dll"
              onChange={handleFileChange}
            />
          </label>

          {selectedFile && (
            <p className="mt-2 text-sm text-gray-600">Selected: {selectedFile.name}</p>
          )}

          <button
            onClick={handleUpload}
            disabled={!selectedFile || loading.upload}
            className={`mt-4 ${loading.upload ? 'bg-gradient-to-r from-blue-400 to-blue-500' : 'bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800'} text-white font-semibold px-5 py-2 rounded-full transition shadow-md`}
          >
            {loading.upload ? "Uploading..." : "Upload"}
          </button>

          {filename && (
            <button
              onClick={analyze}
              disabled={loading.analyze}
              className={`mt-4 ${loading.analyze ? 'bg-gradient-to-r from-green-400 to-green-500' : 'bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800'} text-white font-semibold px-5 py-2 rounded-full transition shadow-md`}
            >
              {loading.analyze ? "Analyzing..." : "Analyze File"}
            </button>
          )}
        </div>
      </div>

      {result && (
        <div className="max-w-4xl mx-auto bg-white shadow-xl rounded-2xl p-6 mt-10">
          <h2 className="text-2xl font-bold bg-gradient-to-r from-blue-800 to-blue-600 bg-clip-text text-transparent mb-4">Malware Analysis Report</h2>

          <div className="mb-4">
            <p><strong>Malware Family:</strong> {result.malwareFamily || "Unknown"}</p>
            <p><strong>Severity Score:</strong> {result.severityScore || "N/A"}</p>
            <p><strong>Report ID:</strong> {result.report_id || "N/A"}</p>
            <p><strong>Filename:</strong> {result.filename || "N/A"}</p>
            {result.verdict && (
              <p className={`font-semibold ${result.verdict.includes('MALICIOUS') ? 'text-red-600' : 'text-green-600'}`}>
                <strong>Verdict:</strong> {result.verdict}
              </p>
            )}
          </div>

          {result.fileHashes && Object.keys(result.fileHashes).length > 0 && (
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-gray-700">File Hashes</h3>
              <ul className="list-disc ml-5 text-sm">
                {Object.entries(result.fileHashes).map(([type, hash]) => (
                  <li key={type}><strong>{type.toUpperCase()}:</strong> {hash}</li>
                ))}
              </ul>
            </div>
          )}

          {result.entropy && Object.keys(result.entropy).length > 0 && (
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-gray-700">Entropy by Section</h3>
              <ul className="list-disc ml-5 text-sm">
                {Object.entries(result.entropy).map(([section, entropy]) => (
                  <li key={section}><strong>{section}:</strong> {entropy}</li>
                ))}
              </ul>
            </div>
          )}

          {result.strings && result.strings.length > 0 && (
            <div className="mb-4">
              <h3
                className="text-lg font-semibold text-gray-700 cursor-pointer hover:underline"
                onClick={() => toggleSection("strings")}
              >
                Strings ({result.strings.length}) {expanded.strings ? "▲" : "▼"}
              </h3>
              {expanded.strings && (
                <div className="bg-gray-100 rounded p-3 max-h-64 overflow-y-auto text-sm">
                  <ul className="list-disc ml-5">
                    {result.strings.map((str, idx) => (
                      <li key={idx} className="break-words">{str}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {result.peFeatures && Object.keys(result.peFeatures).length > 0 && (
            <div className="mb-4">
              <h3
                className="text-lg font-semibold text-gray-700 cursor-pointer hover:underline"
                onClick={() => toggleSection("peFeatures")}
              >
                PE Features {expanded.peFeatures ? "▲" : "▼"}
              </h3>
              {expanded.peFeatures && (
                <div className="mt-2 text-sm">
                  <p><strong>Entry Point:</strong> {result.peFeatures.entry_point || "N/A"}</p>
                  <p><strong>Timestamp:</strong> {result.peFeatures.timestamp || "N/A"}</p>

                  {result.peFeatures.imported_libraries && result.peFeatures.imported_libraries.length > 0 && (
                    <>
                      <p className="font-semibold mt-2">Imported Libraries:</p>
                      <ul className="list-disc ml-5">
                        {result.peFeatures.imported_libraries.map((lib, idx) => (
                          <li key={idx}>{lib}</li>
                        ))}
                      </ul>
                    </>
                  )}

                  {result.peFeatures.section_names && result.peFeatures.section_names.length > 0 && (
                    <>
                      <p className="font-semibold mt-2">Section Names:</p>
                      <ul className="list-disc ml-5">
                        {result.peFeatures.section_names.map((sec, idx) => (
                          <li key={idx}>{sec}</li>
                        ))}
                      </ul>
                    </>
                  )}
                </div>
              )}
            </div>
          )}

          {result.modelFeatures && Object.keys(result.modelFeatures).length > 0 && (
            <div className="mb-4">
              <h3
                className="text-lg font-semibold text-gray-700 cursor-pointer hover:underline"
                onClick={() => toggleSection("modelFeatures")}
              >
                Model Features {expanded.modelFeatures ? "▲" : "▼"}
              </h3>
              {expanded.modelFeatures && (
                <div className="bg-gray-100 rounded p-3 max-h-64 overflow-y-auto text-sm">
                  <ul className="list-disc ml-5">
                    {Object.entries(result.modelFeatures).map(([key, val]) => (
                      <li key={key}><strong>{key}:</strong> {String(val)}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* ✅ Download PDF Button */}
          <div className="text-center mt-6">
            <button
              onClick={generatePDF}
              className="bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white font-semibold px-6 py-2 rounded-full transition shadow-md"
            >
              Download PDF Report
            </button>
          </div>
        </div>
      )}
    </div>
    <Footer />
  </>
);


}