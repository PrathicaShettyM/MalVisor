import { useState } from "react";
import Navbar from "../layout/Navbar";
import Footer from "../layout/Footer";
import { toast } from "react-toastify";
import * as pdfjsLib from "pdfjs-dist";
import workerUrl from "pdfjs-dist/build/pdf.worker.mjs?url";

pdfjsLib.GlobalWorkerOptions.workerSrc = workerUrl;

import ReactMarkdown from "react-markdown";

const AskAI = () => {
  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState("");
  const [report, setReport] = useState(null);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async function () {
      try {
        const typedarray = new Uint8Array(this.result);
        const loadingTask = pdfjsLib.getDocument(typedarray);
        const pdf = await loadingTask.promise;

        let fullText = "";
        for (let i = 1; i <= pdf.numPages; i++) {
          const page = await pdf.getPage(i);
          const content = await page.getTextContent();
          const strings = content.items.map((item) => item.str).join(" ");
          fullText += strings + "\n";
        }

        setReport(fullText);
        toast.success("PDF parsed successfully!");
      } catch (err) {
        console.error("PDF parse error:", err);
        toast.error("Failed to parse PDF.");
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const handleAsk = async () => {
    if (!question.trim()) return toast.error("Please enter a question.");
    if (!report) return toast.error("Please upload a report first.");

    setLoading(true);
    setResponse("");

    try {
      const res = await fetch("http://localhost:5000/ask-ai", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          question,
          report,
        }),
        credentials: "include"
      });

      const data = await res.json();

      if (!res.ok) throw new Error(data.message || "Something went wrong");

      setResponse(data.response || "No response received.");
    } catch (err) {
      console.error("AskAI error:", err);
      toast.error("Failed to connect to AI server.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Navbar />
      <div className="min-h-screen p-8 bg-gray-100 text-black">
        <h1 className="text-3xl font-bold text-center text-indigo-700 mb-6">
          Ask AI about Malware Reports 🧠
        </h1>

        <div className="max-w-3xl mx-auto bg-white p-6 rounded-xl shadow-md">
          <label className="block mb-2 font-semibold">Upload PDF Report:</label>
          <input
            type="file"
            accept="application/pdf"
            onChange={handleFileUpload}
            className="mb-6 border rounded px-3 py-2 w-full"
          />

          <label className="block mb-2 font-semibold">Your Question:</label>
          <textarea
            className="w-full p-3 border rounded h-28 mb-4"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g., Explain this report in simple terms, or What is AgentTesla?"
          />

          <button
            onClick={handleAsk}
            disabled={loading}
            className="bg-purple-600 text-white px-6 py-2 rounded hover:bg-purple-700 transition"
          >
            {loading ? "Asking..." : "Ask AI"}
          </button>

          {response && (
            <div className="mt-6 p-4 border rounded bg-gray-50">
              <h2 className="font-semibold text-lg mb-2 text-purple-700">AI Response:</h2>
              
            <div>
                <ReactMarkdown>{response}</ReactMarkdown>
            </div>

              </div>
          )}
        </div>
      </div>
      <Footer />
    </>
  );
};

export default AskAI;
