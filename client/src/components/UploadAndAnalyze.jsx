import { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function AnalyzePage() {
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const handleUploadAndAnalyze = async () => {
    if (!file) {
      setError("Please select a file first");
      return;
    }

    setError(null);
    setIsUploading(true);

    try {
      // Upload
      const formData = new FormData();
      formData.append("file", file);

      const uploadRes = await fetch("http://localhost:5000/upload", {
        method: "POST",
        body: formData,
      });

      if (!uploadRes.ok) {
        throw new Error(`Upload failed: ${uploadRes.status}`);
      }

      const uploadData = await uploadRes.json();
      
      if (uploadData.error) {
        throw new Error(uploadData.error);
      }

      const { filename } = uploadData;
      setIsUploading(false);
      setIsAnalyzing(true);

      // Analyze
      const analyzeRes = await fetch("http://localhost:5000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename }),
      });

      if (!analyzeRes.ok) {
        throw new Error(`Analysis failed: ${analyzeRes.status}`);
      }

      const report = await analyzeRes.json();
      
      if (report.error) {
        throw new Error(report.error);
      }

      setIsAnalyzing(false);

      // ✅ Simple navigation with full report in location.state
      navigate(`/report/${report.report_id}`, { state: { report } });

    } catch (err) {
      setError(err.message);
      setIsUploading(false);
      setIsAnalyzing(false);
    }
  };

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setFile(selectedFile);
    setError(null);
  };

  return (
    <div className="p-6 max-w-md mx-auto">
      <h1 className="text-2xl font-bold text-purple-700 mb-6">
        Upload & Analyze File
      </h1>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Select File
          </label>
          <input
            type="file"
            onChange={handleFileChange}
            className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-purple-50 file:text-purple-700 hover:file:bg-purple-100"
            accept=".exe,.dll,.bin"
          />
        </div>

        {file && (
          <div className="p-3 bg-gray-50 rounded-lg">
            <p className="text-sm text-gray-700">
              <strong>Selected:</strong> {file.name}
            </p>
            <p className="text-sm text-gray-500">
              Size: {(file.size / 1024).toFixed(2)} KB
            </p>
          </div>
        )}

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-700 text-sm">{error}</p>
          </div>
        )}

        <button
          onClick={handleUploadAndAnalyze}
          disabled={!file || isUploading || isAnalyzing}
          className={`w-full py-3 px-4 rounded-lg font-medium transition-colors ${
            !file || isUploading || isAnalyzing
              ? "bg-gray-300 text-gray-500 cursor-not-allowed"
              : "bg-purple-600 text-white hover:bg-purple-700"
          }`}
        >
          {isUploading
            ? "Uploading..."
            : isAnalyzing
            ? "Analyzing..."
            : "Upload & Analyze"}
        </button>

        {(isUploading || isAnalyzing) && (
          <div className="flex items-center justify-center space-x-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-purple-600"></div>
            <span className="text-sm text-gray-600">
              {isUploading ? "Uploading file..." : "Analyzing file..."}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}