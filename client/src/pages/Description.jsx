import React, { useState } from 'react';
import { ShieldCheck, Target, Database, Upload, Cpu, BarChart3, FileSearch, Lock, Zap, Brain, CheckCircle, AlertTriangle } from 'lucide-react';

import Navbar from '../layout/Navbar';
import Footer from '../layout/Footer';

const Description = () => {
  const [currentCard, setCurrentCard] = useState(0);

  const cards = [
    {
      title: "The Gaps We Aim to Solve",
      icon: Target,
      gradient: "from-red-500 to-pink-600",
      iconBg: "bg-red-100",
      iconColor: "text-red-600",
      content: {
        subtitle: "Bridging Critical Security Analysis Gaps",
        sections: [
          {
            title: "Dynamic Analysis Limitations",
            icon: AlertTriangle,
            points: [
              "Expensive and slow execution",
              "Prone to sandbox evasion techniques",
              "Infeasible for bulk analysis in real-world pipelines"
            ]
          },
          {
            title: "Static Analysis Shortcomings",
            icon: FileSearch,
            points: [
              "Most tools lack intelligence — only check headers or basic rules",
              "Often don't classify malware families",
              "Fail to estimate severity levels"
            ]
          },
          {
            title: "Our Solution",
            icon: CheckCircle,
            points: [
              "Transparent, ML-powered static analysis",
              "Detect malware without execution",
              "Intelligent family classification",
              "Automated severity assessment"
            ]
          }
        ]
      }
    },
    {
      title: "EMBER Dataset Integration",
      icon: Database,
      gradient: "from-blue-500 to-cyan-600",
      iconBg: "bg-blue-100",
      iconColor: "text-blue-600",
      content: {
        subtitle: "Endgame Malware Benchmark for Research",
        description: "Leveraging one of the most comprehensive datasets for static malware analysis to power our ML models.",
        features: [
          {
            icon: BarChart3,
            title: "1M+ PE Files",
            desc: "Extensive dataset with labeled benign and malicious samples"
          },
          {
            icon: Brain,
            title: "Rich Features",
            desc: "PE metadata, imports/exports, strings, entropy, and section analysis"
          },
          {
            icon: Zap,
            title: "ML Benchmark",
            desc: "Industry-standard dataset for training and validation"
          }
        ]
      }
    },
    {
      title: "File Upload & Preprocessing",
      icon: Upload,
      gradient: "from-green-500 to-emerald-600",
      iconBg: "bg-green-100",
      iconColor: "text-green-600",
      content: {
        subtitle: "Secure & Efficient File Processing Pipeline",
        steps: [
          {
            step: "01",
            title: "Secure Upload",
            icon: Lock,
            desc: "Users submit PE files through our React-based secure interface with real-time validation"
          },
          {
            step: "02", 
            title: "Validation",
            icon: CheckCircle,
            desc: "Backend ensures file integrity, format compliance, and security checks"
          },
          {
            step: "03",
            title: "Sandboxed Storage",
            icon: ShieldCheck,
            desc: "Files temporarily stored in isolated environment for safe analysis"
          }
        ]
      }
    },
    {
      title: "Static Feature Extraction",
      icon: Cpu,
      gradient: "from-purple-500 to-indigo-600",
      iconBg: "bg-purple-100",
      iconColor: "text-purple-600",
      content: {
        subtitle: "Advanced PE File Analysis Engine",
        toolInfo: {
          title: "Powered by pefile Library",
          desc: "Industry-standard Python library for comprehensive PE file parsing and analysis"
        },
        features: [
          { 
            name: "Import Analysis", 
            desc: "Malware often imports unusual or excessive system APIs to perform malicious activities. By analyzing the Import Address Table (IAT), we can identify suspicious API calls related to process injection, registry manipulation, network communication, or file system tampering. Legitimate software typically has predictable import patterns, while malware may import functions for keylogging, screen capture, or privilege escalation.", 
            icon: "📥" 
          },
          { 
            name: "Entropy Calculation", 
            desc: "Entropy measures the randomness of data within a file. Packed or encrypted malware exhibits high entropy values (close to 8.0) due to compression or obfuscation techniques used to evade detection. Normal executables have lower entropy with recognizable patterns. High entropy in specific sections often indicates the presence of encrypted payloads, packed code, or embedded resources that malware uses to hide its true functionality.", 
            icon: "🔢" 
          },
          { 
            name: "Section Analysis", 
            desc: "PE files are divided into sections (.text, .data, .rdata, etc.) with specific purposes. Malware often creates unusual sections, modifies section characteristics, or has mismatched section sizes. Suspicious indicators include executable data sections, writable code sections, sections with unusual names, or sections with abnormal virtual vs raw size ratios. These anomalies suggest code injection, self-modifying code, or attempts to hide malicious payloads.", 
            icon: "📊" 
          },
          { 
            name: "Size Profiling", 
            desc: "File size patterns can reveal malicious intent. Extremely small files (< 10KB) might be droppers or loaders, while unusually large files could contain embedded payloads or multiple malware components. Malware authors often pad files to specific sizes to evade size-based detection rules or create files that are suspiciously uniform in size across campaigns. Size analysis helps identify file inflation techniques and payload embedding strategies.", 
            icon: "📏" 
          },
          { 
            name: "Header Inspection", 
            desc: "PE headers contain critical metadata about file structure and execution parameters. Malware often manipulates headers to evade detection or enable malicious functionality. Suspicious indicators include modified timestamps, unusual subsystem values, corrupted optional headers, invalid entry points, or manipulated characteristics flags. Header analysis can reveal packing, process hollowing preparation, or attempts to masquerade as system files through timestamp forgery.", 
            icon: "🔍" 
          },
          { 
            name: "Signature Validation", 
            desc: "Digital signatures provide authenticity verification through cryptographic certificates. Malware typically lacks valid signatures or uses stolen, expired, or self-signed certificates. Legitimate software from reputable vendors almost always includes valid signatures. Analyzing certificate chains, validation status, and signer reputation helps distinguish between trusted applications and potential threats. Unsigned executables or those with suspicious certificates require additional scrutiny in security assessments.", 
            icon: "🔐" 
          }
        ]
      }
    }
  ];

  const nextCard = () => {
    setCurrentCard((prev) => (prev + 1) % cards.length);
  };

  const prevCard = () => {
    setCurrentCard((prev) => (prev - 1 + cards.length) % cards.length);
  };

  const currentData = cards[currentCard];

  return (
    <div className="min-h-screen bg-white">
      <Navbar />
      
      {/* Hero Section */}
      <div className="bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 text-white py-16">
        <div className="container mx-auto px-4 text-center">
          <div className="flex justify-center mb-6">
            <div className="p-4 bg-opacity-10 rounded-full backdrop-blur-sm">
              <ShieldCheck className="w-16 h-16" />
            </div>
          </div>
          <h1 className="text-5xl font-bold mb-6 bg-gradient-to-r from-white to-blue-200 bg-clip-text text-transparent">
            Next-Gen Malware Analysis
          </h1>
          <p className="text-xl text-blue-100 max-w-3xl mx-auto leading-relaxed">
            Revolutionizing cybersecurity with AI-powered static analysis, intelligent threat classification, and real-time severity assessment
          </p>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="container mx-auto px-4 py-16">
        {/* Progress Indicator */}
        <div className="flex justify-center mb-12">
          <div className="flex space-x-3">
            {cards.map((_, index) => (
              <div
                key={index}
                className={`w-3 h-3 rounded-full transition-all duration-300 ${
                  index === currentCard 
                    ? `bg-gradient-to-r ${currentData.gradient}` 
                    : 'bg-gray-200'
                }`}
              />
            ))}
          </div>
        </div>

        {/* Card Container */}
        <div className="max-w-6xl mx-auto">
          <div className="bg-white rounded-3xl shadow-2xl border border-gray-100 overflow-hidden">
            {/* Card Header */}
            <div className={`bg-gradient-to-r ${currentData.gradient} p-8 text-white`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className={`p-4 ${currentData.iconBg} rounded-2xl`}>
                    <currentData.icon className={`w-8 h-8 ${currentData.iconColor}`} />
                  </div>
                  <div>
                    <div className="text-sm font-medium opacity-90 mb-1">
                      Step {currentCard + 1} of {cards.length}
                    </div>
                    <h2 className="text-3xl font-bold">{currentData.title}</h2>
                  </div>
                </div>

              </div>
            </div>

            {/* Card Content */}
            <div className="p-8">
              {currentCard === 0 && (
                <div className="space-y-8">
                  <div className="text-center mb-8">
                    <h3 className="text-2xl font-bold text-gray-800 mb-4">{currentData.content.subtitle}</h3>
                    <p className="text-gray-600 max-w-3xl mx-auto">
                      Our solution combines machine learning, heuristics, and static features to offer fast, safe, and intelligent malware analysis.
                    </p>
                  </div>
                  <div className="grid md:grid-cols-3 gap-6">
                    {currentData.content.sections.map((section, idx) => (
                      <div key={idx} className="bg-gray-50 rounded-2xl p-6 hover:shadow-lg transition-shadow">
                        <div className="flex items-center mb-4">
                          <section.icon className="w-6 h-6 text-gray-700 mr-3" />
                          <h4 className="font-bold text-gray-800">{section.title}</h4>
                        </div>
                        <ul className="space-y-2">
                          {section.points.map((point, pidx) => (
                            <li key={pidx} className="text-gray-600 text-sm flex items-start">
                              <span className="w-2 h-2 bg-gray-400 rounded-full mr-3 mt-2 flex-shrink-0"></span>
                              {point}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {currentCard === 1 && (
                <div className="space-y-8">
                  <div className="text-center mb-8">
                    <h3 className="text-2xl font-bold text-gray-800 mb-4">{currentData.content.subtitle}</h3>
                    <p className="text-gray-600 max-w-3xl mx-auto">{currentData.content.description}</p>
                  </div>
                  <div className="grid md:grid-cols-3 gap-6">
                    {currentData.content.features.map((feature, idx) => (
                      <div key={idx} className="text-center p-6 bg-gray-50 rounded-2xl hover:shadow-lg transition-shadow">
                        <div className="flex justify-center mb-4">
                          <div className="p-4 bg-blue-100 rounded-2xl">
                            <feature.icon className="w-8 h-8 text-blue-600" />
                          </div>
                        </div>
                        <h4 className="font-bold text-gray-800 mb-2">{feature.title}</h4>
                        <p className="text-gray-600 text-sm">{feature.desc}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {currentCard === 2 && (
                <div className="space-y-8">
                  <div className="text-center mb-8">
                    <h3 className="text-2xl font-bold text-gray-800 mb-4">{currentData.content.subtitle}</h3>
                  </div>
                  <div className="space-y-6">
                    {currentData.content.steps.map((step, idx) => (
                      <div key={idx} className="flex items-start space-x-6 p-6 bg-gray-50 rounded-2xl hover:shadow-lg transition-shadow">
                        <div className="flex-shrink-0">
                          <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                            <span className="text-green-600 font-bold">{step.step}</span>
                          </div>
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center mb-2">
                            <step.icon className="w-5 h-5 text-gray-700 mr-2" />
                            <h4 className="font-bold text-gray-800">{step.title}</h4>
                          </div>
                          <p className="text-gray-600">{step.desc}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {currentCard === 3 && (
                <div className="space-y-8">
                  <div className="text-center mb-8">
                    <h3 className="text-2xl font-bold text-gray-800 mb-4">{currentData.content.subtitle}</h3>
                    <div className="bg-purple-50 rounded-2xl p-6 max-w-2xl mx-auto">
                      <h4 className="font-bold text-purple-800 mb-2">{currentData.content.toolInfo.title}</h4>
                      <p className="text-purple-700 text-sm">{currentData.content.toolInfo.desc}</p>
                    </div>
                  </div>
                  <div className="grid md:grid-cols-1 lg:grid-cols-2 gap-6">
                    {currentData.content.features.map((feature, idx) => (
                      <div key={idx} className="bg-gray-50 rounded-2xl p-6 hover:shadow-lg transition-shadow border border-gray-100">
                        <div className="flex items-start space-x-4">
                          <div className="flex-shrink-0">
                            <div className="p-3 bg-purple-100 rounded-xl">
                              <span className="text-2xl">{feature.icon}</span>
                            </div>
                          </div>
                          <div className="flex-1">
                            <h4 className="font-bold text-gray-800 mb-3 text-lg">{feature.name}</h4>
                            <p className="text-gray-600 text-sm leading-relaxed">{feature.desc}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Card Footer */}
            <div className="border-t border-gray-100 px-8 py-6">
              <div className="flex justify-between items-center">
                <div className="text-sm text-gray-500">
                  {currentCard + 1} of {cards.length} sections
                </div>
                <div className="flex space-x-3">
                  <button
                    onClick={prevCard}
                    disabled={currentCard === 0}
                    className="px-6 py-3 bg-gray-100 text-gray-600 rounded-xl hover:bg-gray-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>
                  <button
                    onClick={nextCard}
                    disabled={currentCard === cards.length - 1}
                    className={`px-6 py-3 bg-gradient-to-r ${currentData.gradient} text-white rounded-xl hover:shadow-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed`}
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Navigation */}
        <div className="flex justify-center mt-12">
          <div className="bg-gray-50 rounded-2xl p-4">
            <div className="flex space-x-2">
              {cards.map((card, index) => (
                <button
                  key={index}
                  onClick={() => setCurrentCard(index)}
                  className={`px-4 py-2 rounded-xl text-sm font-medium transition-all ${
                    index === currentCard
                      ? `bg-gradient-to-r ${currentData.gradient} text-white shadow-lg`
                      : 'text-gray-600 hover:bg-white hover:shadow-md'
                  }`}
                >
                  {index + 1}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  );
};

export default Description;